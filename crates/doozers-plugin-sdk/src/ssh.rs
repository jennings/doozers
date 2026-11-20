//! Fetching the host key an SSH server presents, as `ssh-keyscan` does.
//!
//! An environment plugin that answers a workspace's first connection to an unknown host can scan
//! the host itself, from the network the workspace runs in, and compare what it sees with what the
//! workspace's `ssh` was offered. [`scan_host_key`] does that scan. It speaks only as much of the
//! SSH transport as it needs: the version exchange, an unencrypted `KEXINIT`, and
//! `curve25519-sha256` up to the server's `KEX_ECDH_REPLY`. It then checks the server's signature
//! over the exchange hash with the host key, which proves the server holds the matching private
//! key. A man in the middle who only replays a key it saw elsewhere can't pass that check. It never
//! authenticates and never sends a password or a public key.
//!
//! ```no_run
//! # async fn demo() -> Result<(), doozers_plugin_sdk::ssh::ScanError> {
//! use std::time::Duration;
//!
//! let blob = doozers_plugin_sdk::ssh::scan_host_key(
//!     "github.com",
//!     22,
//!     "ssh-ed25519",
//!     Duration::from_secs(10),
//! )
//! .await?;
//! // `blob` is the base64-decoded second field of a `known_hosts` line.
//! # let _ = blob;
//! # Ok(())
//! # }
//! ```

mod kex;
mod wire;

use std::io;
use std::time::Duration;

use aws_lc_rs::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use aws_lc_rs::rand::SystemRandom;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

use self::kex::{
    DISCONNECT_BY_APPLICATION, ExchangeInputs, HostKeyKind, MSG_DEBUG, MSG_DISCONNECT, MSG_IGNORE,
    MSG_KEX_ECDH_INIT, MSG_UNIMPLEMENTED,
};
use self::wire::{Reader, WireError};

/// The identification string we send, without its line ending (RFC 4253 section 4.2).
const CLIENT_IDENTIFICATION: &[u8] = b"SSH-2.0-DoozersScan";

/// How many `IGNORE` and `DEBUG` messages are tolerated between the messages that matter.
const MAX_NOISE: usize = 64;

/// The longest excerpt of anything the server sent that an error shows.
const MAX_EXCERPT: usize = 64;

/// Why a host key scan failed. Every message names the step that failed. Text from the server
/// appears only as a short excerpt with everything but printable ASCII escaped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The key type isn't one a scan can ask for.
    #[error(
        "unsupported key type {0}: a scan asks for ssh-ed25519, ecdsa-sha2-nistp256, \
         ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, or ssh-rsa"
    )]
    UnsupportedKeyType(String),
    /// The TCP connection couldn't be made.
    #[error("connect: {0}")]
    Connect(#[source] io::Error),
    /// The server didn't send a usable identification string.
    #[error("banner: {0}")]
    Banner(String),
    /// The key exchange broke down: the connection failed, or the server sent something the
    /// protocol doesn't allow.
    #[error("key exchange: {0}")]
    Kex(String),
    /// The server shares no key exchange method or host key algorithm with the scan.
    #[error("no common algorithm: {0}")]
    NoCommonAlgorithm(String),
    /// The server ended the connection with `SSH_MSG_DISCONNECT`.
    #[error("disconnected by the server: {0}")]
    Disconnected(String),
    /// The host key can't be used: it can't be parsed, or it isn't of the type asked for.
    #[error("host key: {0}")]
    HostKey(String),
    /// The host key's signature over the exchange hash is missing or wrong.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// The scan didn't finish in time.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Fetches the host key of the SSH server at `host`:`port`, as `ssh-keyscan -t <type>` would, and
/// returns it as a key blob: the SSH wire encoding, which `known_hosts` lines hold in base64.
///
/// `key_type` is what OpenSSH's `KnownHostsCommand` passes as `%t`: `ssh-ed25519`,
/// `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, or `ssh-rsa`. A server's
/// RSA key is asked for with the `rsa-sha2-512` and `rsa-sha2-256` signature algorithms; a scan
/// never accepts a SHA-1 signature. Certificates (`*-cert-v01@openssh.com`), `sk-` keys, DSA, and
/// every other name fail with [`ScanError::UnsupportedKeyType`] before anything is sent.
///
/// `host` is a name or an address without brackets. The scan fails with [`ScanError::Timeout`]
/// when connecting and scanning together take longer than `timeout`.
///
/// The key is returned only after the server's signature over the exchange hash verifies against
/// it, so the server holds the key's private half. That doesn't say the key is the right one for
/// the host. Whoever calls this decides that, with a pinned key or, for a first use, by comparing
/// with the key the workspace's `ssh` was offered.
pub async fn scan_host_key(
    host: &str,
    port: u16,
    key_type: &str,
    timeout: Duration,
) -> Result<Vec<u8>, ScanError> {
    let kind = HostKeyKind::from_key_type(key_type)
        .ok_or_else(|| ScanError::UnsupportedKeyType(excerpt(key_type.as_bytes())))?;
    let scan = async {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(ScanError::Connect)?;
        // Best effort: the scan sends a handful of small packets and waits for the answers.
        let _ = stream.set_nodelay(true);
        scan_connection(stream, &kind).await
    };
    tokio::time::timeout(timeout, scan)
        .await
        .unwrap_or(Err(ScanError::Timeout(timeout)))
}

/// Runs the scan over an established connection.
async fn scan_connection<S>(stream: S, kind: &HostKeyKind) -> Result<Vec<u8>, ScanError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let mut line = CLIENT_IDENTIFICATION.to_vec();
    line.extend_from_slice(b"\r\n");
    writer
        .write_all(&line)
        .await
        .map_err(|e| ScanError::Banner(format!("sending ours failed: {e}")))?;
    let server_identification = wire::read_identification(&mut reader)
        .await
        .map_err(banner_error)?;

    let client_kexinit = kex::build_kexinit(kind);
    send(&mut writer, &client_kexinit).await?;
    let server_kexinit = next_message(&mut reader).await?;
    let negotiated = {
        let parsed = kex::parse_kexinit(&server_kexinit)?;
        kex::negotiate(&parsed, kind)?
    };

    let rng = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|_| ScanError::Kex("generating the ephemeral key failed".into()))?;
    let client_public = private
        .compute_public_key()
        .map_err(|_| ScanError::Kex("computing the ephemeral public key failed".into()))?;
    let client_public = client_public.as_ref().to_vec();
    let mut init = vec![MSG_KEX_ECDH_INIT];
    wire::put_string(&mut init, &client_public);
    send(&mut writer, &init).await?;

    if negotiated.skip_guessed_packet {
        next_message(&mut reader).await?;
    }
    let reply_payload = next_message(&mut reader).await?;
    let reply = kex::parse_ecdh_reply(&reply_payload)?;
    if reply.server_public.len() != 32 {
        return Err(ScanError::Kex(
            "the server's ephemeral public key isn't 32 bytes".into(),
        ));
    }
    let shared_secret: [u8; 32] = agree_ephemeral(
        private,
        UnparsedPublicKey::new(&X25519, reply.server_public),
        (),
        |secret| <[u8; 32]>::try_from(secret).map_err(|_| ()),
    )
    .map_err(|()| ScanError::Kex("the server's ephemeral public key is unusable".into()))?;

    let hash = kex::exchange_hash(&ExchangeInputs {
        client_version: CLIENT_IDENTIFICATION,
        server_version: &server_identification,
        client_kexinit: &client_kexinit,
        server_kexinit: &server_kexinit,
        host_key: reply.host_key,
        client_public: &client_public,
        server_public: reply.server_public,
        shared_secret: &shared_secret,
    });
    kex::verify_host_key(kind, reply.host_key, reply.signature, &hash)?;

    // Leave politely so the server doesn't log a connection that dropped mid-exchange. The scan
    // already has what it came for.
    let mut disconnect = vec![MSG_DISCONNECT];
    wire::put_u32(&mut disconnect, DISCONNECT_BY_APPLICATION);
    wire::put_string(&mut disconnect, b"scan complete");
    wire::put_string(&mut disconnect, b"");
    let _ = send(&mut writer, &disconnect).await;
    let _ = writer.shutdown().await;
    Ok(reply.host_key.to_vec())
}

/// Sends one packet.
async fn send<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<(), ScanError> {
    let packet = wire::encode_packet(payload);
    async {
        writer.write_all(&packet).await?;
        writer.flush().await
    }
    .await
    .map_err(|e| ScanError::Kex(format!("sending a packet failed: {e}")))
}

/// Reads the next message that matters: `IGNORE` and `DEBUG` are skipped, `DISCONNECT` and
/// `UNIMPLEMENTED` are errors.
async fn next_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, ScanError> {
    for _ in 0..=MAX_NOISE {
        let payload = wire::read_packet(reader).await.map_err(kex_error)?;
        match payload.first().copied() {
            Some(MSG_IGNORE | MSG_DEBUG) => {}
            Some(MSG_DISCONNECT) => return Err(disconnected(&payload)),
            Some(MSG_UNIMPLEMENTED) => {
                return Err(ScanError::Kex(
                    "the server answered a message with SSH_MSG_UNIMPLEMENTED".into(),
                ));
            }
            _ => return Ok(payload),
        }
    }
    Err(ScanError::Kex(
        "the server sent too many IGNORE or DEBUG messages".into(),
    ))
}

/// The error for a `SSH_MSG_DISCONNECT` payload.
fn disconnected(payload: &[u8]) -> ScanError {
    let mut reader = Reader::new(payload);
    reader.u8();
    let code = reader.u32();
    let description = reader.string().unwrap_or_default();
    let mut text = match code {
        Some(code) => format!("reason code {code}"),
        None => "no reason code".to_owned(),
    };
    if !description.is_empty() {
        text.push_str(": ");
        text.push_str(&excerpt(description));
    }
    ScanError::Disconnected(text)
}

fn banner_error(error: WireError) -> ScanError {
    ScanError::Banner(match error {
        WireError::Io(e) => format!("reading the server's identification failed: {e}"),
        WireError::Eof => {
            "the server closed the connection before it sent an identification".into()
        }
        WireError::TooLong => {
            "the server's identification, or the lines before it, are too long".into()
        }
        WireError::Malformed(what) => format!("the server sent {what}"),
        WireError::Version(line) => {
            format!(
                "the server doesn't speak SSH protocol version 2 ({})",
                excerpt(&line)
            )
        }
    })
}

fn kex_error(error: WireError) -> ScanError {
    ScanError::Kex(match error {
        WireError::Io(e) => format!("reading from the server failed: {e}"),
        WireError::Eof => "the server closed the connection".into(),
        WireError::TooLong => "the server sent a packet longer than 35000 bytes".into(),
        WireError::Malformed(what) => format!("the server sent {what}"),
        WireError::Version(_) => "the server sent an identification string mid-exchange".into(),
    })
}

/// Shows server-controlled bytes in an error: at most 64 of them, with everything but printable
/// ASCII (and the backslash) written as `\xNN`.
pub(crate) fn excerpt(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().min(MAX_EXCERPT));
    for &byte in bytes.iter().take(MAX_EXCERPT) {
        if (0x20..0x7f).contains(&byte) && byte != b'\\' {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    if bytes.len() > MAX_EXCERPT {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests;
