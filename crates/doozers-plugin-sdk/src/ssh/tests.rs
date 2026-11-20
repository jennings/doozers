//! The scan against a fake server over an in-memory stream and over loopback TCP. The real
//! `sshd` is in `tests/ssh_scan.rs`.

use std::time::Duration;

use aws_lc_rs::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use aws_lc_rs::rand::SystemRandom;
use signature::Signer as _;
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519Keypair;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, duplex};
use tokio::net::TcpListener;

use super::kex::{MSG_KEX_ECDH_REPLY, MSG_KEXINIT};
use super::*;

const SERVER_IDENTIFICATION: &[u8] = b"SSH-2.0-FakeServer_1.0";

/// What the fake server does wrong, if anything.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Sends lines before its identification string.
    PreBanner,
    /// Sends `IGNORE` and `DEBUG` messages between the messages that matter.
    Noise,
    /// Signs something other than the exchange hash.
    WrongHash,
    /// Disconnects, with a description that has a terminal escape in it.
    Disconnect,
    /// Claims a packet longer than the protocol allows.
    Oversize,
    /// Sends a `KEXINIT` that says its first key exchange guess follows, which is wrong, with a
    /// junk packet in the guess's place.
    WrongGuess,
}

struct Fake {
    key: PrivateKey,
    host_key_algorithms: &'static [&'static str],
    kex_algorithms: &'static [&'static str],
    fault: Fault,
}

impl Fake {
    fn ed25519() -> Self {
        Self {
            key: PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32])),
            host_key_algorithms: &["ssh-ed25519"],
            kex_algorithms: &["curve25519-sha256"],
            fault: Fault::None,
        }
    }

    fn blob(&self) -> Vec<u8> {
        self.key.public_key().to_bytes().expect("the key encodes")
    }

    fn with(mut self, fault: Fault) -> Self {
        self.fault = fault;
        self
    }
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) {
    writer
        .write_all(&wire::encode_packet(payload))
        .await
        .expect("the fake server writes");
}

async fn send_noise<W: AsyncWrite + Unpin>(writer: &mut W) {
    let mut ignore = vec![MSG_IGNORE];
    wire::put_string(&mut ignore, b"noise");
    send(writer, &ignore).await;
    let mut debug = vec![MSG_DEBUG, 0];
    wire::put_string(&mut debug, b"a debug message");
    wire::put_string(&mut debug, b"");
    send(writer, &debug).await;
}

/// The server side of one exchange. Errors are ignored: the client may hang up at any point.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(stream: S, fake: Fake) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let _ = serve_exchange(&mut reader, &mut writer, &fake).await;
}

async fn serve_exchange<R, W>(reader: &mut R, writer: &mut W, fake: &Fake) -> Option<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if fake.fault == Fault::PreBanner {
        writer
            .write_all(b"Authorized use only\r\nSecond line\r\n")
            .await
            .ok()?;
    }
    writer.write_all(SERVER_IDENTIFICATION).await.ok()?;
    writer.write_all(b"\r\n").await.ok()?;
    let client_identification = wire::read_identification(reader).await.ok()?;

    let mut server_kexinit = vec![MSG_KEXINIT];
    server_kexinit.extend_from_slice(&[9; 16]);
    wire::put_name_list(&mut server_kexinit, fake.kex_algorithms);
    wire::put_name_list(&mut server_kexinit, fake.host_key_algorithms);
    for _ in 0..8 {
        wire::put_name_list(&mut server_kexinit, &["none"]);
    }
    server_kexinit.push(u8::from(fake.fault == Fault::WrongGuess));
    server_kexinit.extend_from_slice(&[0; 4]);
    if fake.fault == Fault::Noise {
        send_noise(writer).await;
    }
    send(writer, &server_kexinit).await;
    if fake.fault == Fault::WrongGuess {
        send(writer, &[MSG_KEX_ECDH_REPLY, 0, 0, 0, 0]).await;
    }

    let client_kexinit = wire::read_packet(reader).await.ok()?;
    if fake.fault == Fault::Disconnect {
        let mut disconnect = vec![MSG_DISCONNECT];
        wire::put_u32(&mut disconnect, 2);
        wire::put_string(&mut disconnect, b"bye \x1b[31mred\x1b[0m");
        wire::put_string(&mut disconnect, b"");
        send(writer, &disconnect).await;
        return Some(());
    }
    let init = wire::read_packet(reader).await.ok()?;
    let mut init = Reader::new(&init);
    assert_eq!(init.u8(), Some(MSG_KEX_ECDH_INIT));
    let client_public = init.string()?.to_vec();
    if fake.fault == Fault::Oversize {
        writer.write_all(&40_000_u32.to_be_bytes()).await.ok()?;
        return Some(());
    }

    let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).ok()?;
    let server_public = private.compute_public_key().ok()?.as_ref().to_vec();
    let secret: [u8; 32] = agree_ephemeral(
        private,
        UnparsedPublicKey::new(&X25519, &client_public),
        (),
        |secret| <[u8; 32]>::try_from(secret).map_err(|_| ()),
    )
    .ok()?;
    let host_key = fake.blob();
    let mut hash = kex::exchange_hash(&ExchangeInputs {
        client_version: &client_identification,
        server_version: SERVER_IDENTIFICATION,
        client_kexinit: &client_kexinit,
        server_kexinit: &server_kexinit,
        host_key: &host_key,
        client_public: &client_public,
        server_public: &server_public,
        shared_secret: &secret,
    });
    if fake.fault == Fault::WrongHash {
        hash[0] ^= 1;
    }
    let signature: ssh_key::Signature = fake.key.try_sign(&hash).expect("the fake server signs");
    let signature = Vec::<u8>::try_from(signature).expect("the signature encodes");

    let mut reply = vec![MSG_KEX_ECDH_REPLY];
    wire::put_string(&mut reply, &host_key);
    wire::put_string(&mut reply, &server_public);
    wire::put_string(&mut reply, &signature);
    if fake.fault == Fault::Noise {
        send_noise(writer).await;
    }
    send(writer, &reply).await;
    Some(())
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("the scan finished")
}

async fn scan(fake: Fake, key_type: &str) -> Result<Vec<u8>, ScanError> {
    let kind = HostKeyKind::from_key_type(key_type).expect("a supported key type");
    let (client, server) = duplex(1 << 16);
    let (result, ()) =
        within(async { tokio::join!(scan_connection(client, &kind), serve(server, fake)) }).await;
    result
}

#[tokio::test]
async fn scan_returns_the_host_key_the_server_signed_with() {
    let fake = Fake::ed25519();
    let expected = fake.blob();
    assert_eq!(scan(fake, "ssh-ed25519").await.expect("scan"), expected);
}

#[tokio::test]
async fn scan_tolerates_lines_before_the_banner_and_ignorable_messages() {
    for fault in [Fault::PreBanner, Fault::Noise] {
        let fake = Fake::ed25519().with(fault);
        let expected = fake.blob();
        assert_eq!(scan(fake, "ssh-ed25519").await.expect("scan"), expected);
    }
}

#[tokio::test]
async fn scan_accepts_the_libssh_name_of_the_key_exchange() {
    let mut fake = Fake::ed25519();
    fake.kex_algorithms = &["curve25519-sha256@libssh.org"];
    let expected = fake.blob();
    assert_eq!(scan(fake, "ssh-ed25519").await.expect("scan"), expected);
}

#[tokio::test]
async fn scan_skips_a_wrong_first_key_exchange_guess() {
    let mut fake = Fake::ed25519().with(Fault::WrongGuess);
    fake.kex_algorithms = &["diffie-hellman-group14-sha256", "curve25519-sha256"];
    let expected = fake.blob();
    assert_eq!(scan(fake, "ssh-ed25519").await.expect("scan"), expected);
}

#[tokio::test]
async fn scan_rejects_a_signature_over_something_else() {
    let error = scan(Fake::ed25519().with(Fault::WrongHash), "ssh-ed25519")
        .await
        .expect_err("scan");
    assert!(matches!(error, ScanError::BadSignature(_)), "{error}");
}

#[test]
fn a_signature_by_another_key_is_rejected() {
    // Someone who replays a public key they saw elsewhere can't sign with its private half.
    let kind = HostKeyKind::from_key_type("ssh-ed25519").expect("supported");
    let presented = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    let other = PrivateKey::from(Ed25519Keypair::from_seed(&[8; 32]));
    let blob = presented.public_key().to_bytes().expect("encodes");
    let hash = [1_u8; 32];
    let sign = |key: &PrivateKey| {
        let signature: ssh_key::Signature = key.try_sign(&hash).expect("signs");
        Vec::<u8>::try_from(signature).expect("encodes")
    };
    let error = kex::verify_host_key(&kind, &blob, &sign(&other), &hash).expect_err("wrong key");
    assert!(matches!(error, ScanError::BadSignature(_)), "{error}");
    kex::verify_host_key(&kind, &blob, &sign(&presented), &hash).expect("the right key");
}

#[tokio::test]
async fn scan_rejects_a_key_of_another_type_than_asked_for() {
    let mut fake = Fake::ed25519();
    fake.host_key_algorithms = &["ecdsa-sha2-nistp256"];
    let error = scan(fake, "ecdsa-sha2-nistp256").await.expect_err("scan");
    assert!(matches!(error, ScanError::HostKey(_)), "{error}");
    assert!(error.to_string().contains("ssh-ed25519"), "{error}");
}

#[tokio::test]
async fn scan_names_the_missing_algorithm() {
    let error = scan(Fake::ed25519(), "ssh-rsa").await.expect_err("scan");
    assert!(matches!(error, ScanError::NoCommonAlgorithm(_)), "{error}");
    assert!(error.to_string().contains("ssh-rsa"), "{error}");
    assert!(error.to_string().contains("ssh-ed25519"), "{error}");

    let mut fake = Fake::ed25519();
    fake.kex_algorithms = &["ecdh-sha2-nistp256"];
    let error = scan(fake, "ssh-ed25519").await.expect_err("scan");
    assert!(matches!(error, ScanError::NoCommonAlgorithm(_)), "{error}");
    assert!(error.to_string().contains("ecdh-sha2-nistp256"), "{error}");
}

#[tokio::test]
async fn scan_reports_a_disconnect_with_the_description_escaped() {
    let error = scan(Fake::ed25519().with(Fault::Disconnect), "ssh-ed25519")
        .await
        .expect_err("scan");
    assert!(matches!(error, ScanError::Disconnected(_)), "{error}");
    let text = error.to_string();
    assert!(!text.contains('\x1b'), "{text:?}");
    assert!(text.contains("bye \\x1b[31mred\\x1b[0m"), "{text}");
    assert!(text.contains("reason code 2"), "{text}");
}

#[tokio::test]
async fn scan_refuses_a_packet_longer_than_the_protocol_allows() {
    let error = scan(Fake::ed25519().with(Fault::Oversize), "ssh-ed25519")
        .await
        .expect_err("scan");
    assert!(matches!(error, ScanError::Kex(_)), "{error}");
    assert!(error.to_string().contains("35000"), "{error}");
}

#[tokio::test]
async fn scan_fails_at_the_banner_for_a_server_that_isnt_ssh() {
    let kind = HostKeyKind::from_key_type("ssh-ed25519").expect("supported");
    let (client, mut server) = duplex(4096);
    let serve = async move {
        server
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\x1b[2J\r\n")
            .await
            .expect("writes");
        // Closing the connection ends the scan.
        drop(server);
    };
    let (result, ()) = within(async { tokio::join!(scan_connection(client, &kind), serve) }).await;
    let error = result.expect_err("scan");
    assert!(matches!(error, ScanError::Banner(_)), "{error}");
    assert!(!error.to_string().contains('\x1b'), "{error}");
}

#[tokio::test]
async fn scan_reports_a_server_that_hangs_up_mid_exchange() {
    let kind = HostKeyKind::from_key_type("ssh-ed25519").expect("supported");
    let (client, server) = duplex(4096);
    let serve = async move {
        let (reader, mut writer) = tokio::io::split(server);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"SSH-2.0-x\r\n").await.expect("writes");
        wire::read_identification(&mut reader)
            .await
            .expect("the client's identification");
        wire::read_packet(&mut reader)
            .await
            .expect("the client's KEXINIT");
        // Hanging up now leaves the scan waiting for the server's KEXINIT.
    };
    let (result, ()) = within(async { tokio::join!(scan_connection(client, &kind), serve) }).await;
    let error = result.expect_err("scan");
    assert!(matches!(error, ScanError::Kex(_)), "{error}");
    assert!(error.to_string().contains("closed"), "{error}");
}

#[tokio::test]
async fn scan_host_key_refuses_other_key_types_without_connecting() {
    for key_type in [
        "ssh-ed25519-cert-v01@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ssh-dss",
        "NONE",
        "",
        "ssh-rsa\x1b[2J",
    ] {
        // Port 1 on a name that can't resolve: a scan that tried to connect would fail with
        // `Connect`, not `UnsupportedKeyType`.
        let error = scan_host_key("nowhere.invalid", 1, key_type, Duration::from_secs(5))
            .await
            .expect_err("refused");
        assert!(
            matches!(error, ScanError::UnsupportedKeyType(_)),
            "{key_type:?}: {error}"
        );
        assert!(!error.to_string().contains('\x1b'), "{error}");
    }
}

#[tokio::test]
async fn scan_host_key_reports_a_refused_connection() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        listener.local_addr().expect("address").port()
    };
    let error = scan_host_key("127.0.0.1", port, "ssh-ed25519", Duration::from_secs(5))
        .await
        .expect_err("nothing listens");
    assert!(matches!(error, ScanError::Connect(_)), "{error}");
}

#[tokio::test]
async fn scan_host_key_times_out_on_a_server_that_never_speaks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().expect("address").port();
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts");
        // Hold the connection open and say nothing.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });
    let started = std::time::Instant::now();
    let error = scan_host_key("127.0.0.1", port, "ssh-ed25519", Duration::from_millis(300))
        .await
        .expect_err("times out");
    assert!(matches!(error, ScanError::Timeout(_)), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10));
    accept.abort();
}

#[tokio::test]
async fn scan_host_key_scans_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().expect("address").port();
    let fake = Fake::ed25519();
    let expected = fake.blob();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accepts");
        serve(stream, fake).await;
    });
    let blob = within(scan_host_key(
        "127.0.0.1",
        port,
        "ssh-ed25519",
        Duration::from_secs(10),
    ))
    .await
    .expect("scan");
    assert_eq!(blob, expected);
    server.await.expect("the fake server finished");
}

#[test]
fn excerpts_are_short_and_printable() {
    assert_eq!(excerpt(b"plain text"), "plain text");
    assert_eq!(excerpt(b"a\\b"), "a\\x5cb");
    assert_eq!(excerpt(b"\x1b[2J\n\xff"), "\\x1b[2J\\x0a\\xff");
    let long = excerpt(&[b'a'; 500]);
    assert_eq!(long, format!("{}...", "a".repeat(64)));
}
