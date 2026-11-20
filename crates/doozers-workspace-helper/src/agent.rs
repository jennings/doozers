//! `ssh-agent`: the workspace end of the SSH agent relay.
//!
//! The helper listens on a Unix socket (`SSH_AUTH_SOCK` in the workspace) and carries every client
//! connection's agent messages over its own standard input and output to the Docker plugin, which
//! relays them to the Doozers core. The helper never looks inside a message.
//!
//! It also listens on a second socket for the `known-hosts` subcommand (see `known_hosts.rs`),
//! which `ssh` runs as its `KnownHostsCommand`. Each connection to it is one lookup: the helper
//! carries the request to the plugin and the answer back, and closes the connection.
//!
//! One frame per message, in both directions:
//!
//! ```text
//! u32 BE length of the rest | u8 kind | u64 BE connection | payload
//! ```
//!
//! - `1` request (helper to plugin): the payload is one agent message without its own length
//!   prefix, from client connection `connection`.
//! - `2` closed (helper to plugin): that connection ended. The payload is empty.
//! - `3` reply (plugin to helper): the payload is one agent message for `connection`.
//!
//! - `4` lookup (helper to plugin): `connection` names the lookup. The payload is the request the
//!   `known-hosts` subcommand sent, which the helper doesn't look inside.
//! - `5` lookup reply (plugin to helper): the payload is the answer for lookup `connection`.
//!
//! Lookup ids are a separate series from connection ids. A frame of an unknown kind from the
//! plugin is skipped. A client that sends a message longer than [`MAX_MESSAGE`] is disconnected.
//! At most [`MAX_LOOKUPS`] lookups wait for the plugin at once, and a lookup that gets no answer in
//! [`LOOKUP_TIMEOUT`] is closed without one, which makes the `known-hosts` subcommand fail.
//!
//! One thread serves each client's requests, another writes its replies from a bounded queue,
//! one thread accepts connections, and the main thread reads replies from standard input and
//! queues them. The helper removes its socket and exits when standard input ends.

use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use crate::{Args, Failure, Outcome};

/// Where the agent socket lives unless `--socket` says otherwise.
const DEFAULT_SOCKET: &str = "/.doozers/run/ssh-agent.sock";

/// Where the known-hosts socket lives unless `--known-hosts-socket` says otherwise.
pub const DEFAULT_LOOKUP_SOCKET: &str = "/.doozers/run/known-hosts.sock";

/// The longest agent message the helper relays (OpenSSH's limit).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// The longest lookup request or answer the helper relays. A host, a key type, and a key of up to
/// 16 KiB, or up to 64 keys of that size, fit with room to spare.
pub const MAX_LOOKUP: usize = 2 * 1024 * 1024;

/// How many lookups may wait for the plugin at once: any process in the workspace can open the
/// socket, so the helper bounds what it holds.
const MAX_LOOKUPS: usize = 64;

/// How long a lookup waits for its answer: the plugin's scan takes up to 10 seconds, and the core
/// may have others ahead of it.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a client of the known-hosts socket has to send its request.
const LOOKUP_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A frame's header after its length: kind and connection id.
const HEADER_LEN: usize = 1 + 8;

/// How long a write to a client may block before the connection is dropped.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many replies may wait for one client before it is closed as not reading. A reply is at
/// most [`MAX_MESSAGE`], so this bounds what a client that never reads can make the helper hold.
const REPLY_QUEUE: usize = 8;

const KIND_REQUEST: u8 = 1;
const KIND_CLOSED: u8 = 2;
const KIND_REPLY: u8 = 3;
const KIND_LOOKUP: u8 = 4;
const KIND_LOOKUP_REPLY: u8 = 5;

/// Encodes one frame.
fn encode_frame(kind: u8, connection: u64, payload: &[u8]) -> Vec<u8> {
    let rest = HEADER_LEN + payload.len();
    let mut frame = Vec::with_capacity(4 + rest);
    frame.extend_from_slice(&u32::try_from(rest).unwrap_or(u32::MAX).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(&connection.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A frame read from the plugin.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    kind: u8,
    connection: u64,
    payload: Vec<u8>,
}

/// Reads one frame. `Ok(None)` is a clean end of input. A frame too short for its header or longer
/// than the longest payload plus its header can't be skipped over safely, so it is an error.
fn read_frame(input: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let rest = u32::from_be_bytes(length) as usize;
    if !(HEADER_LEN..=HEADER_LEN + MAX_LOOKUP).contains(&rest) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("a frame of {rest} bytes is outside the allowed range"),
        ));
    }
    let mut body = vec![0u8; rest];
    input.read_exact(&mut body)?;
    let connection = u64::from_be_bytes(body[1..HEADER_LEN].try_into().unwrap_or_default());
    Ok(Some(Frame {
        kind: body[0],
        connection,
        payload: body.split_off(HEADER_LEN),
    }))
}

/// What the helper writes frames to, one whole frame at a time.
struct Plugin<W: Write> {
    out: Mutex<W>,
}

impl<W: Write> Plugin<W> {
    fn send(&self, kind: u8, connection: u64, payload: &[u8]) -> io::Result<()> {
        let frame = encode_frame(kind, connection, payload);
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        out.write_all(&frame)?;
        out.flush()
    }
}

/// A client connection that can still receive replies: the socket, and the replies waiting for its
/// writer thread.
struct Client {
    stream: Arc<UnixStream>,
    outbound: SyncSender<Vec<u8>>,
}

/// The client connections that can still receive a reply.
type Clients = Mutex<HashMap<u64, Client>>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The lookups waiting for an answer from the plugin, by id.
type Lookups = Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>;

/// `ssh-agent [--socket PATH] [--known-hosts-socket PATH]`.
pub fn run(mut args: Args) -> Outcome<ExitCode> {
    let socket = args
        .value("--socket")?
        .map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from);
    let lookup_socket = args
        .value("--known-hosts-socket")?
        .map_or_else(|| PathBuf::from(DEFAULT_LOOKUP_SOCKET), PathBuf::from);
    args.finish()?;
    // The agent socket is bound last: whoever can connect to it knows both are there.
    let lookup_listener = listen(&lookup_socket)?;
    let listener = listen(&socket)?;

    let plugin = Arc::new(Plugin {
        out: Mutex::new(io::stdout()),
    });
    let clients: Arc<Clients> = Arc::default();
    let lookups: Arc<Lookups> = Arc::default();
    {
        let (plugin, clients) = (Arc::clone(&plugin), Arc::clone(&clients));
        thread::spawn(move || accept(&listener, &plugin, &clients));
    }
    {
        let (plugin, lookups) = (Arc::clone(&plugin), Arc::clone(&lookups));
        thread::spawn(move || accept_lookups(&lookup_listener, &plugin, &lookups));
    }

    let result = route_replies(&mut io::stdin().lock(), &clients, &lookups);
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&lookup_socket);
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => Err(Failure::other(format!(
            "reading from the plugin failed: {error}"
        ))),
    }
}

/// Binds the socket, replacing a stale file, and lets every user in the container connect.
fn listen(socket: &Path) -> Outcome<UnixListener> {
    if let Some(dir) = socket.parent() {
        fs::create_dir_all(dir).map_err(|e| Failure::io(dir, &e))?;
    }
    match fs::remove_file(socket) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(Failure::io(socket, &e)),
    }
    let listener = UnixListener::bind(socket).map_err(|e| Failure::io(socket, &e))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666))
        .map_err(|e| Failure::io(socket, &e))?;
    Ok(listener)
}

fn accept<W: Write + Send + 'static>(
    listener: &UnixListener,
    plugin: &Arc<Plugin<W>>,
    clients: &Arc<Clients>,
) {
    let next = AtomicU64::new(1);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let id = next.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
        let stream = Arc::new(stream);
        let (outbound, queue) = mpsc::sync_channel(REPLY_QUEUE);
        lock(clients).insert(
            id,
            Client {
                stream: Arc::clone(&stream),
                outbound,
            },
        );
        {
            let stream = Arc::clone(&stream);
            thread::spawn(move || write_replies(&stream, &queue));
        }
        let (plugin, clients) = (Arc::clone(plugin), Arc::clone(clients));
        thread::spawn(move || {
            serve_client(id, &stream, &plugin);
            // Dropping the queue's sender ends the writer thread.
            lock(&clients).remove(&id);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            let _ = plugin.send(KIND_CLOSED, id, &[]);
        });
    }
}

/// Forwards one client's messages until it ends, sends something invalid, or the plugin is gone.
fn serve_client<W: Write>(id: u64, mut stream: &UnixStream, plugin: &Plugin<W>) {
    loop {
        let mut length = [0u8; 4];
        if stream.read_exact(&mut length).is_err() {
            return;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MESSAGE {
            return;
        }
        let mut message = vec![0u8; length];
        if stream.read_exact(&mut message).is_err() {
            return;
        }
        if plugin.send(KIND_REQUEST, id, &message).is_err() {
            return;
        }
    }
}

fn accept_lookups<W: Write + Send + 'static>(
    listener: &UnixListener,
    plugin: &Arc<Plugin<W>>,
    lookups: &Arc<Lookups>,
) {
    let next = AtomicU64::new(1);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let id = next.fetch_add(1, Ordering::Relaxed);
        let (plugin, lookups) = (Arc::clone(plugin), Arc::clone(lookups));
        thread::spawn(move || serve_lookup(id, stream, &plugin, &lookups));
    }
}

/// One lookup: reads the request (`u32 BE length | payload`), forwards it, waits for the answer,
/// writes it back the same way, and closes the connection. Any failure, and a lookup the helper
/// has no room for, closes the connection without an answer.
fn serve_lookup<W: Write>(id: u64, mut stream: UnixStream, plugin: &Plugin<W>, lookups: &Lookups) {
    let _ = stream.set_read_timeout(Some(LOOKUP_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
    let mut length = [0u8; 4];
    if stream.read_exact(&mut length).is_err() {
        return;
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_LOOKUP {
        return;
    }
    let mut request = vec![0u8; length];
    if stream.read_exact(&mut request).is_err() {
        return;
    }

    let (answer, answers) = mpsc::channel();
    {
        let mut waiting = lock(lookups);
        if waiting.len() >= MAX_LOOKUPS {
            return;
        }
        waiting.insert(id, answer);
    }
    let sent = plugin.send(KIND_LOOKUP, id, &request);
    let answer = match sent {
        Ok(()) => answers.recv_timeout(LOOKUP_TIMEOUT).ok(),
        Err(_) => None,
    };
    lock(lookups).remove(&id);
    if let Some(answer) = answer {
        let mut reply = Vec::with_capacity(4 + answer.len());
        reply.extend_from_slice(&u32::try_from(answer.len()).unwrap_or(0).to_be_bytes());
        reply.extend_from_slice(&answer);
        let _ = stream.write_all(&reply);
    }
}

/// Delivers the plugin's replies to their clients until its input ends. It only queues a reply:
/// the client's own writer thread writes it, so a client that doesn't read can't hold up anyone
/// else's reply. A client whose queue is full is closed, and its serving thread then sends
/// `closed`.
fn route_replies(input: &mut impl Read, clients: &Clients, lookups: &Lookups) -> io::Result<()> {
    while let Some(frame) = read_frame(input)? {
        if frame.kind == KIND_LOOKUP_REPLY {
            if let Some(waiting) = lock(lookups).get(&frame.connection) {
                let _ = waiting.send(frame.payload);
            }
            continue;
        }
        if frame.kind != KIND_REPLY || frame.payload.len() > MAX_MESSAGE {
            continue;
        }
        let mut clients = lock(clients);
        let Some(client) = clients.get(&frame.connection) else {
            continue;
        };
        let mut reply = Vec::with_capacity(4 + frame.payload.len());
        reply.extend_from_slice(
            &u32::try_from(frame.payload.len())
                .unwrap_or(0)
                .to_be_bytes(),
        );
        reply.extend_from_slice(&frame.payload);
        match client.outbound.try_send(reply) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if let Some(client) = clients.remove(&frame.connection) {
                    let _ = client.stream.shutdown(std::net::Shutdown::Both);
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                clients.remove(&frame.connection);
            }
        }
    }
    Ok(())
}

/// Writes a client's queued replies until the queue closes or the client stops reading, which
/// closes the connection.
fn write_replies(stream: &UnixStream, queue: &Receiver<Vec<u8>>) {
    let mut writer = stream;
    for reply in queue {
        if writer.write_all(&reply).is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let frame = encode_frame(KIND_REPLY, 0x0102_0304_0506_0708, b"abc");
        assert_eq!(
            frame,
            [0, 0, 0, 12, 3, 1, 2, 3, 4, 5, 6, 7, 8, b'a', b'b', b'c']
        );
        let read = read_frame(&mut frame.as_slice()).unwrap().unwrap();
        assert_eq!(
            read,
            Frame {
                kind: KIND_REPLY,
                connection: 0x0102_0304_0506_0708,
                payload: b"abc".to_vec()
            }
        );
    }

    #[test]
    fn a_frame_may_have_an_empty_payload() {
        let frame = encode_frame(KIND_CLOSED, 7, &[]);
        assert_eq!(frame.len(), 4 + 9);
        let read = read_frame(&mut frame.as_slice()).unwrap().unwrap();
        assert_eq!(read.connection, 7);
        assert!(read.payload.is_empty());
    }

    #[test]
    fn frames_follow_each_other_and_input_ends_cleanly() {
        let mut bytes = encode_frame(KIND_REPLY, 1, b"one");
        bytes.extend(encode_frame(9, 2, b"two"));
        let mut input = bytes.as_slice();
        assert_eq!(read_frame(&mut input).unwrap().unwrap().payload, b"one");
        assert_eq!(read_frame(&mut input).unwrap().unwrap().kind, 9);
        assert_eq!(read_frame(&mut input).unwrap(), None);
    }

    #[test]
    fn malformed_frames_are_errors() {
        // Shorter than the header.
        assert!(read_frame(&mut [0u8, 0, 0, 4, 3, 0, 0, 0].as_slice()).is_err());
        // Longer than the longest payload and its header.
        let too_long = u32::try_from(HEADER_LEN + MAX_LOOKUP + 1).unwrap();
        assert!(read_frame(&mut too_long.to_be_bytes().as_slice()).is_err());
        // Cut off in the middle.
        let frame = encode_frame(KIND_REPLY, 1, b"abcdef");
        assert!(read_frame(&mut &frame[..frame.len() - 2]).is_err());
    }

    #[test]
    fn the_longest_message_fits_a_frame() {
        let frame = encode_frame(KIND_REQUEST, 1, &vec![0u8; MAX_MESSAGE]);
        let read = read_frame(&mut frame.as_slice()).unwrap().unwrap();
        assert_eq!(read.payload.len(), MAX_MESSAGE);
    }
}
