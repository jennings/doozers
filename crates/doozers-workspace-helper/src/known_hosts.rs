//! `known-hosts`: `ssh`'s `KnownHostsCommand` in a workspace.
//!
//! The Docker plugin configures `ssh` to run `known-hosts %H %p %t %K` and to trust nothing else,
//! so the host keys a workspace trusts are the ones the Doozers core stores. The subcommand asks
//! the running `ssh-agent` process what the core trusts for the host, through its second socket,
//! and prints the answer as `known_hosts` lines, with the host exactly as `ssh` gave it.
//!
//! `ssh` runs the command twice for each connection. The first time it only wants the stored keys,
//! to choose which host key algorithms to offer, and passes `NONE` for the key type and the key.
//! The second time it passes the key the server offered. The core records a new host from the
//! second call only.
//!
//! The command fails closed: if the relay isn't there or doesn't answer, it prints a message and
//! exits with status 1, no line is printed, and `ssh` refuses the connection.
//!
//! The request and the answer are each `u32 BE length | payload` on the socket and, unchanged, the
//! payload of a lookup frame (see `agent.rs`):
//!
//! ```text
//! request: u32 BE port | string host | string key type | string key
//! answer:  u32 BE count | count * string key
//! string:  u32 BE length | bytes
//! ```
//!
//! The key type and the key are empty strings for the `NONE` call. The keys of an answer are SSH
//! public key blobs, each starting with its own algorithm name.

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::agent::{DEFAULT_LOOKUP_SOCKET, LOOKUP_TIMEOUT, MAX_LOOKUP};
use crate::{Args, Failure, Outcome};

/// How long the command waits for the answer: a little over the helper's own wait, so the helper
/// gives up first and closes the connection.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(LOOKUP_TIMEOUT.as_secs() + 10);

/// What `ssh` passes for `%t` and `%K` when it only asks which keys are stored.
const NONE: &str = "NONE";

/// `known-hosts [--socket PATH] HOST PORT TYPE KEY`.
pub fn run(mut args: Args) -> Outcome<ExitCode> {
    let socket = args
        .value("--socket")?
        .map_or_else(|| PathBuf::from(DEFAULT_LOOKUP_SOCKET), PathBuf::from);
    let mut rest = std::mem::take(&mut args.0)
        .into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| Failure::usage("the arguments must be UTF-8"))
        })
        .collect::<Outcome<Vec<_>>>()?;
    if rest.len() != 4 {
        return Err(Failure::usage(
            "usage: known-hosts [--socket PATH] HOST PORT TYPE KEY",
        ));
    }
    let key = rest.pop().unwrap_or_default();
    let key_type = rest.pop().unwrap_or_default();
    let port = rest.pop().unwrap_or_default();
    let host = rest.pop().unwrap_or_default();

    let port: u16 = port
        .parse()
        .map_err(|_| Failure::usage(format!("{port:?} is not a port")))?;
    let (key_type, key) = match (key_type == NONE, key == NONE) {
        (true, true) => (String::new(), Vec::new()),
        (false, false) => (
            key_type,
            STANDARD
                .decode(&key)
                .map_err(|_| Failure::usage("the key isn't base64"))?,
        ),
        _ => {
            return Err(Failure::usage(
                "the key type and the key must both be NONE or neither",
            ));
        }
    };

    let request = encode_request(port, &host, &key_type, &key);
    let answer = ask(&socket, &request)?;
    let keys =
        decode_answer(&answer).ok_or_else(|| Failure::other("the relay's answer isn't valid"))?;

    let mut lines = String::new();
    for key in keys {
        let Some(algorithm) = algorithm_of(key) else {
            return Err(Failure::other("the relay sent a key that isn't valid"));
        };
        let _ = writeln!(lines, "{host} {algorithm} {}", STANDARD.encode(key));
    }
    std::io::stdout()
        .write_all(lines.as_bytes())
        .map_err(|e| Failure::other(format!("cannot write the keys: {e}")))?;
    Ok(ExitCode::SUCCESS)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The request payload for `host` and `port` and the key the server offered.
fn encode_request(port: u16, host: &str, key_type: &str, key: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(16 + host.len() + key_type.len() + key.len());
    request.extend_from_slice(&u32::from(port).to_be_bytes());
    put_string(&mut request, host.as_bytes());
    put_string(&mut request, key_type.as_bytes());
    put_string(&mut request, key);
    request
}

/// One SSH `string` from the front of `input`, and what follows it.
fn take_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = input.split_first_chunk::<4>()?;
    let length = u32::from_be_bytes(*length) as usize;
    (rest.len() >= length).then(|| rest.split_at(length))
}

/// The keys of an answer payload, or `None` if it is malformed.
fn decode_answer(answer: &[u8]) -> Option<Vec<&[u8]>> {
    let (count, mut rest) = answer.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    // Every key takes at least its length prefix, so a count that can't fit is malformed.
    if count > rest.len() / 4 {
        return None;
    }
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let (key, after) = take_string(rest)?;
        keys.push(key);
        rest = after;
    }
    rest.is_empty().then_some(keys)
}

/// The algorithm name a public key blob starts with.
fn algorithm_of(key: &[u8]) -> Option<&str> {
    let (algorithm, _) = take_string(key)?;
    std::str::from_utf8(algorithm)
        .ok()
        .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic()))
}

/// Sends `request` to the socket and returns the answer payload.
fn ask(socket: &std::path::Path, request: &[u8]) -> Outcome<Vec<u8>> {
    let unreachable = |error: &std::io::Error| {
        Failure::other(format!(
            "the Doozers relay isn't reachable at {}: {}; refusing the connection",
            socket.display(),
            crate::describe_io(error)
        ))
    };
    let mut stream = UnixStream::connect(socket).map_err(|e| unreachable(&e))?;
    let _ = stream.set_read_timeout(Some(ANSWER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(ANSWER_TIMEOUT));
    let mut framed = Vec::with_capacity(4 + request.len());
    framed.extend_from_slice(&u32::try_from(request.len()).unwrap_or(0).to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed).map_err(|e| unreachable(&e))?;

    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            return Err(Failure::other(
                "the Doozers relay closed the lookup without an answer; refusing the connection",
            ));
        }
        Err(e) => return Err(unreachable(&e)),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_LOOKUP {
        return Err(Failure::other("the relay's answer is too long"));
    }
    let mut answer = vec![0u8; length];
    stream
        .read_exact(&mut answer)
        .map_err(|e| unreachable(&e))?;
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(algorithm: &str, data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, algorithm.as_bytes());
        put_string(&mut blob, data);
        blob
    }

    fn answer(keys: &[Vec<u8>]) -> Vec<u8> {
        let mut answer = u32::try_from(keys.len()).unwrap().to_be_bytes().to_vec();
        for key in keys {
            put_string(&mut answer, key);
        }
        answer
    }

    #[test]
    fn a_request_is_the_port_then_three_strings() {
        assert_eq!(
            encode_request(2222, "[h]:2222", "ssh-ed25519", &[1, 2]),
            [
                0, 0, 8, 174, // port
                0, 0, 0, 8, b'[', b'h', b']', b':', b'2', b'2', b'2', b'2', // host
                0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0,
                0, 0, 2, 1, 2, // key
            ]
        );
        // The `NONE` call has empty strings.
        assert_eq!(encode_request(22, "h", "", &[]).len(), 4 + 5 + 4 + 4);
    }

    #[test]
    fn an_answer_is_a_count_then_keys() {
        let keys = [blob("ssh-ed25519", b"one"), blob("ssh-rsa", b"two")];
        let payload = answer(&keys);
        let decoded = decode_answer(&payload).unwrap();
        assert_eq!(decoded, [keys[0].as_slice(), keys[1].as_slice()]);
        assert_eq!(decode_answer(&answer(&[])).unwrap(), Vec::<&[u8]>::new());
    }

    #[test]
    fn malformed_answers_are_refused() {
        let good = answer(&[blob("ssh-ed25519", b"one")]);
        assert!(decode_answer(&good[..good.len() - 1]).is_none());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_answer(&trailing).is_none());
        // A huge count must not allocate.
        assert!(decode_answer(&u32::MAX.to_be_bytes()).is_none());
        assert!(decode_answer(&[0, 0]).is_none());
    }

    #[test]
    fn the_algorithm_is_the_blobs_first_string() {
        assert_eq!(
            algorithm_of(&blob("ecdsa-sha2-nistp256", b"x")),
            Some("ecdsa-sha2-nistp256")
        );
        assert_eq!(algorithm_of(&blob("", b"x")), None);
        assert_eq!(algorithm_of(&blob("has space", b"x")), None);
        assert_eq!(algorithm_of(&[0, 0, 0, 9, b'a']), None);
        assert_eq!(algorithm_of(&[]), None);
    }
}
