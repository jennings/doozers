//! The ssh-agent relay: one `doozers-workspace-helper ssh-agent` exec per relayed workspace.
//!
//! The helper listens on `/.doozers/run/ssh-agent.sock` (`SSH_AUTH_SOCK`) and multiplexes every
//! client connection over its stdin and stdout as frames:
//!
//! ```text
//! u32 BE length of the rest | u8 kind | u64 BE connection | payload
//! ```
//!
//! - `1` request (helper to plugin): one agent message without its length prefix.
//! - `2` closed (helper to plugin): the connection ended; no payload.
//! - `3` reply (plugin to helper): one agent message for the connection.
//! - `4` lookup (helper to plugin): `ssh` asks which host keys to trust. `connection` names the
//!   lookup, and the payload is `u32 BE port | string host | string key type | string key`, where
//!   a `string` is `u32 BE length | bytes` and the key type and key are empty when `ssh` only asks
//!   for the stored keys.
//! - `5` lookup reply (plugin to helper): the payload is `u32 BE count | count * string key`, the
//!   keys as SSH wire blobs.
//!
//! A frame of any kind the plugin doesn't know is skipped. A lookup that doesn't decode is answered
//! with no key at once, which makes `ssh` refuse the connection instead of waiting for the helper's
//! timeout. The helper has its own copy of the format (`agent.rs` and `known_hosts.rs` in the
//! helper crate): the two crates share nothing, because the helper is a static binary with no
//! dependencies.

use bollard::body_full;
use bollard::query_parameters::UploadToContainerOptionsBuilder;
use bytes::{Buf as _, Bytes, BytesMut};
use doozers_types::{
    AgentClosed, AgentRequest, KnownHostsReply, KnownHostsRequest, MAX_AGENT_MESSAGE, MAX_HOST_KEY,
    MAX_KNOWN_HOST, MAX_KNOWN_HOST_KEYS, RelayReply, RelayRequest, WorkspaceId,
};
use futures::StreamExt as _;
use futures::stream::{self, BoxStream};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::DockerEnvironment;
use crate::error::{Error, ErrorExt as _, Result};
use crate::exec::{Attached, Output};
use crate::helper::{self, HELPER_PATH};

/// Helper to plugin: an agent request.
const KIND_REQUEST: u8 = 1;
/// Helper to plugin: a client connection ended.
const KIND_CLOSED: u8 = 2;
/// Plugin to helper: an agent reply.
const KIND_REPLY: u8 = 3;
/// Helper to plugin: a known-hosts lookup.
const KIND_LOOKUP: u8 = 4;
/// Plugin to helper: the answer to a lookup.
const KIND_LOOKUP_REPLY: u8 = 5;

/// The longest payload of any frame: room for the most keys of the longest size a reply holds.
const MAX_PAYLOAD: usize = 2 * 1024 * 1024;

/// The longest key type name a lookup carries.
const MAX_KEY_TYPE: usize = 128;

/// A frame's header after its length: kind and connection.
const HEADER_LEN: usize = 1 + 8;

/// How many decoded requests wait for the core before the helper's output is no longer read.
const QUEUE: usize = 16;

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub kind: u8,
    pub connection: u64,
    pub payload: Bytes,
}

/// A frame the stream can't continue after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameError(String);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Encodes a frame. `None` if the payload is longer than a frame holds.
pub(crate) fn encode_frame(kind: u8, connection: u64, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let rest = u32::try_from(HEADER_LEN + payload.len()).ok()?;
    let mut frame = Vec::with_capacity(4 + HEADER_LEN + payload.len());
    frame.extend_from_slice(&rest.to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(&connection.to_be_bytes());
    frame.extend_from_slice(payload);
    Some(frame)
}

/// Splits the helper's output into frames, however the engine chunks it.
#[derive(Default)]
pub(crate) struct Decoder {
    buffer: BytesMut,
}

impl Decoder {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next complete frame, or `None` until more bytes arrive. A length outside what the
    /// format allows can't be skipped over, so it is an error.
    pub(crate) fn next_frame(&mut self) -> std::result::Result<Option<Frame>, FrameError> {
        let Some(length) = self.buffer.first_chunk::<4>() else {
            return Ok(None);
        };
        let rest = u32::from_be_bytes(*length) as usize;
        if !(HEADER_LEN..=HEADER_LEN + MAX_PAYLOAD).contains(&rest) {
            return Err(FrameError(format!(
                "a frame of {rest} bytes is outside the allowed range"
            )));
        }
        if self.buffer.len() < 4 + rest {
            return Ok(None);
        }
        self.buffer.advance(4);
        let mut body = self.buffer.split_to(rest);
        let kind = body.get_u8();
        let connection = body.get_u64();
        Ok(Some(Frame {
            kind,
            connection,
            payload: body.freeze(),
        }))
    }
}

/// What a frame from the helper means.
#[derive(Debug, PartialEq, Eq)]
enum Incoming {
    /// Something for the core.
    ForCore(RelayRequest),
    /// A lookup that doesn't decode: the helper is answered with no key.
    BadLookup(u64),
    /// Nothing: a kind the plugin doesn't know, or one that isn't the helper's to send.
    Skip,
}

/// What a frame from the helper means to the core, if anything.
fn incoming(frame: Frame) -> Incoming {
    match frame.kind {
        KIND_REQUEST if frame.payload.len() <= MAX_AGENT_MESSAGE => {
            Incoming::ForCore(RelayRequest::Agent(AgentRequest {
                connection: frame.connection,
                message: frame.payload.to_vec(),
            }))
        }
        KIND_CLOSED => Incoming::ForCore(RelayRequest::AgentClosed(AgentClosed {
            connection: frame.connection,
        })),
        KIND_LOOKUP => match decode_lookup(frame.connection, &frame.payload) {
            Some(request) => Incoming::ForCore(RelayRequest::KnownHosts(request)),
            None => Incoming::BadLookup(frame.connection),
        },
        _ => Incoming::Skip,
    }
}

/// One SSH `string` from the front of `input`, and what follows it.
fn take_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = input.split_first_chunk::<4>()?;
    let length = u32::from_be_bytes(*length) as usize;
    (rest.len() >= length).then(|| rest.split_at(length))
}

/// The lookup a kind 4 payload carries, or `None` if it doesn't decode or breaks the limits the
/// core relies on: a host of 1 to [`MAX_KNOWN_HOST`] bytes, a port from 1 to 65535, a key of at
/// most [`MAX_HOST_KEY`] bytes, and a key type exactly when there is a key.
fn decode_lookup(id: u64, payload: &[u8]) -> Option<KnownHostsRequest> {
    let (port, rest) = payload.split_first_chunk::<4>()?;
    let port = u16::try_from(u32::from_be_bytes(*port))
        .ok()
        .filter(|port| *port != 0)?;
    let (host, rest) = take_string(rest)?;
    let (key_type, rest) = take_string(rest)?;
    let (key, rest) = take_string(rest)?;
    if !rest.is_empty()
        || host.is_empty()
        || host.len() > MAX_KNOWN_HOST
        || key.len() > MAX_HOST_KEY
        || key_type.len() > MAX_KEY_TYPE
        || key_type.is_empty() != key.is_empty()
    {
        return None;
    }
    Some(KnownHostsRequest {
        id,
        host: String::from_utf8(host.to_vec()).ok()?,
        port,
        key_type: String::from_utf8(key_type.to_vec()).ok()?,
        key: key.to_vec(),
    })
}

/// The payload of a kind 5 frame for `keys`.
fn encode_answer(keys: &[Vec<u8>]) -> Vec<u8> {
    let mut answer = u32::try_from(keys.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    for key in keys {
        answer.extend_from_slice(&u32::try_from(key.len()).unwrap_or(u32::MAX).to_be_bytes());
        answer.extend_from_slice(key);
    }
    answer
}

impl DockerEnvironment {
    /// Replaces the helper in `container` with this plugin's, once per plugin process per
    /// container. A workspace created before the relay existed has a helper without the
    /// `ssh-agent` subcommand, and `start` doesn't copy the helper again. The new file goes in
    /// under a temporary name and is renamed over the old one, which can't fail with "text file
    /// busy" the way writing to it would (the container's `idle` process runs it). Commands
    /// already running keep the old file open.
    async fn refresh_helper(&self, container: &str) -> Result<()> {
        self.helper_refreshed(container)
            .get_or_try_init(|| async {
                let name = format!("doozers-workspace-helper.{}", uuid::Uuid::new_v4());
                let archive = helper::replacement_archive(self.helper_bytes(), &name)?;
                self.docker()
                    .upload_to_container(
                        container,
                        Some(UploadToContainerOptionsBuilder::default().path("/").build()),
                        body_full(archive),
                    )
                    .await
                    .map_err(|e| {
                        Error::docker("copying the helper into the workspace container", &e)
                    })?;
                let temporary = format!("/.doozers/bin/{name}");
                let moved = self
                    .exec_plain(
                        container,
                        vec![
                            "/bin/sh".to_owned(),
                            "-c".to_owned(),
                            "mv -f \"$1\" \"$2\"".to_owned(),
                            "sh".to_owned(),
                            temporary,
                            HELPER_PATH.to_owned(),
                        ],
                    )
                    .await?;
                if moved.code != 0 {
                    return Err(Error::other(format!(
                        "replacing the helper in the workspace container failed: {}",
                        String::from_utf8_lossy(&moved.stderr).trim()
                    )));
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }
}

impl DockerEnvironment {
    /// Starts the helper's `ssh-agent` in a running workspace and relays between it and the
    /// core. The requests end when the helper does (the container stopped), and dropping them
    /// closes the helper's stdin, which ends it.
    pub(crate) async fn relay_agent(
        &self,
        id: &str,
        replies: BoxStream<'static, RelayReply>,
    ) -> Result<BoxStream<'static, Result<RelayRequest>>> {
        let container = self.running_container(id).await?;
        self.refresh_helper(&container).await?;
        // Covers workspaces that were running before the plugin wrote this configuration, and an
        // `ssh_config` that appeared after it.
        if let Err(error) = self.configure_ssh(&container).await {
            warn!(workspace = id, %error, "cannot write the workspace's ssh configuration");
        }
        let Attached { output, input, .. } = self
            .start_exec(
                &container,
                vec![HELPER_PATH.to_owned(), "ssh-agent".to_owned()],
                true,
            )
            .await?;
        let workspace = WorkspaceId::new(id)?;
        let (requests, queue) = mpsc::channel(QUEUE);
        tokio::spawn(pump(workspace, output, input, replies, requests));
        Ok(stream::unfold(queue, |mut queue| async move {
            let item = queue.recv().await?;
            Some((item, queue))
        })
        .boxed())
    }
}

/// Moves frames between the helper's exec and the core until either side ends. Ends with the
/// helper's input closed.
async fn pump(
    workspace: WorkspaceId,
    mut output: Output,
    mut input: impl AsyncWrite + Unpin,
    mut replies: BoxStream<'static, RelayReply>,
    requests: mpsc::Sender<Result<RelayRequest>>,
) {
    let mut decoder = Decoder::default();
    'relay: loop {
        tokio::select! {
            biased;
            () = requests.closed() => break,
            reply = replies.next() => match reply {
                // The core ended its side: the relay is over.
                None => break,
                Some(reply) => {
                    if let Err(error) = write_reply(&mut input, reply).await {
                        let _ = requests
                            .send(Err(Error::unavailable(format!(
                                "sending a reply to the workspace's ssh-agent: {error}"
                            ))))
                            .await;
                        break;
                    }
                }
            },
            item = output.next() => match item {
                // The helper ended: the container stopped or the exec was killed.
                None => {
                    debug!(%workspace, "the ssh-agent relay's exec ended");
                    break;
                }
                Some(Err(error)) => {
                    let _ = requests
                        .send(Err(Error::unavailable(format!(
                            "reading the workspace's ssh-agent relay: {error}"
                        ))))
                        .await;
                    break;
                }
                Some(Ok(bollard::container::LogOutput::StdErr { message })) => {
                    for line in String::from_utf8_lossy(&message).lines() {
                        debug!(%workspace, "ssh-agent helper: {line}");
                    }
                }
                Some(Ok(bollard::container::LogOutput::StdOut { message })) => {
                    decoder.push(&message);
                    loop {
                        match decoder.next_frame() {
                            Ok(Some(frame)) => match incoming(frame) {
                                Incoming::ForCore(request) => {
                                    if requests.send(Ok(request)).await.is_err() {
                                        break 'relay;
                                    }
                                }
                                Incoming::BadLookup(id) => {
                                    warn!(%workspace, lookup = id, "a known-hosts lookup didn't decode; answering with no key");
                                    let answer = RelayReply::KnownHosts(KnownHostsReply {
                                        id,
                                        keys: Vec::new(),
                                    });
                                    if write_reply(&mut input, answer).await.is_err() {
                                        break 'relay;
                                    }
                                }
                                Incoming::Skip => {}
                            },
                            Ok(None) => break,
                            Err(error) => {
                                warn!(%workspace, %error, "the ssh-agent helper sent a bad frame");
                                let _ = requests
                                    .send(Err(Error::other(format!(
                                        "the workspace's ssh-agent helper sent a bad frame: {error}"
                                    ))))
                                    .await;
                                break 'relay;
                            }
                        }
                    }
                }
                Some(Ok(_)) => {}
            },
        }
    }
    // EOF on the helper's stdin ends it, and it removes its socket.
    let _ = input.shutdown().await;
}

/// Sends one reply to the helper. An agent reply longer than an agent message, and a lookup
/// answer with more keys or longer keys than the protocol allows, are dropped with a warning,
/// since the helper would refuse them. (A dropped lookup answer ends in the helper's timeout, and
/// `ssh` refusing the connection.)
async fn write_reply(
    input: &mut (impl AsyncWrite + Unpin),
    reply: RelayReply,
) -> std::io::Result<()> {
    let frame = match reply {
        RelayReply::Agent(reply) => {
            let frame = (reply.message.len() <= MAX_AGENT_MESSAGE)
                .then(|| encode_frame(KIND_REPLY, reply.connection, &reply.message))
                .flatten();
            if frame.is_none() {
                warn!(
                    connection = reply.connection,
                    bytes = reply.message.len(),
                    "dropping an ssh-agent reply longer than an agent message"
                );
            }
            frame
        }
        RelayReply::KnownHosts(KnownHostsReply { id, keys }) => {
            let fits = keys.len() <= MAX_KNOWN_HOST_KEYS
                && keys.iter().all(|key| key.len() <= MAX_HOST_KEY);
            let frame = fits
                .then(|| encode_frame(KIND_LOOKUP_REPLY, id, &encode_answer(&keys)))
                .flatten();
            if frame.is_none() {
                warn!(
                    lookup = id,
                    "dropping a known-hosts answer that is too long"
                );
            }
            frame
        }
        _ => None,
    };
    let Some(frame) = frame else { return Ok(()) };
    input.write_all(&frame).await?;
    input.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<Frame> {
        let mut decoder = Decoder::default();
        let mut frames = Vec::new();
        for chunk in chunks {
            decoder.push(chunk);
            while let Some(frame) = decoder.next_frame().unwrap() {
                frames.push(frame);
            }
        }
        frames
    }

    #[test]
    fn a_frame_has_a_length_a_kind_a_connection_and_a_payload() {
        let frame = encode_frame(KIND_REPLY, 0x0102_0304_0506_0708, b"abc").unwrap();
        assert_eq!(
            frame,
            [0, 0, 0, 12, 3, 1, 2, 3, 4, 5, 6, 7, 8, b'a', b'b', b'c']
        );
        assert_eq!(
            decode_all(&[&frame]),
            [Frame {
                kind: KIND_REPLY,
                connection: 0x0102_0304_0506_0708,
                payload: Bytes::from_static(b"abc"),
            }]
        );
    }

    #[test]
    fn frames_are_found_however_the_bytes_are_chunked() {
        let mut bytes = encode_frame(KIND_REQUEST, 1, &[11]).unwrap();
        bytes.extend(encode_frame(KIND_CLOSED, 1, &[]).unwrap());
        bytes.extend(encode_frame(KIND_REQUEST, 2, b"second").unwrap());
        let whole = decode_all(&[&bytes]);
        assert_eq!(whole.len(), 3);
        assert_eq!(whole[1].kind, KIND_CLOSED);
        assert!(whole[1].payload.is_empty());
        // One byte at a time, and split mid-header.
        let single: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(decode_all(&single), whole);
        let (a, b) = bytes.split_at(6);
        assert_eq!(decode_all(&[a, b]), whole);
    }

    #[test]
    fn an_incomplete_frame_waits_for_more_bytes() {
        let frame = encode_frame(KIND_REQUEST, 1, b"hello").unwrap();
        let mut decoder = Decoder::default();
        decoder.push(&frame[..frame.len() - 1]);
        assert_eq!(decoder.next_frame().unwrap(), None);
        decoder.push(&frame[frame.len() - 1..]);
        assert_eq!(decoder.next_frame().unwrap().unwrap().payload, "hello");
        assert_eq!(decoder.next_frame().unwrap(), None);
    }

    #[test]
    fn lengths_the_format_forbids_are_errors() {
        // Shorter than kind and connection.
        let mut decoder = Decoder::default();
        decoder.push(&[0, 0, 0, 4, 1, 0, 0, 0]);
        assert!(decoder.next_frame().is_err());
        // Longer than the largest payload and its header.
        let mut decoder = Decoder::default();
        let too_long = u32::try_from(HEADER_LEN + MAX_PAYLOAD + 1).unwrap();
        decoder.push(&too_long.to_be_bytes());
        assert!(decoder.next_frame().is_err());
    }

    #[test]
    fn the_largest_payload_fits_and_a_larger_one_is_not_encoded() {
        let largest = vec![0u8; MAX_PAYLOAD];
        let frame = encode_frame(KIND_LOOKUP_REPLY, 1, &largest).unwrap();
        assert_eq!(decode_all(&[&frame])[0].payload.len(), MAX_PAYLOAD);
        assert!(encode_frame(KIND_LOOKUP_REPLY, 1, &vec![0u8; MAX_PAYLOAD + 1]).is_none());
        // The most keys of the longest size a reply holds fit a frame.
        let answer = encode_answer(&vec![vec![0u8; MAX_HOST_KEY]; MAX_KNOWN_HOST_KEYS]);
        assert!(answer.len() <= MAX_PAYLOAD);
    }

    fn frame(kind: u8, payload: &[u8]) -> Frame {
        Frame {
            kind,
            connection: 7,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    fn string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn lookup_payload(port: u32, host: &str, key_type: &str, key: &[u8]) -> Vec<u8> {
        let mut payload = port.to_be_bytes().to_vec();
        string(&mut payload, host.as_bytes());
        string(&mut payload, key_type.as_bytes());
        string(&mut payload, key);
        payload
    }

    #[test]
    fn requests_and_closes_reach_the_core_and_other_kinds_are_skipped() {
        assert_eq!(
            incoming(frame(KIND_REQUEST, &[11])),
            Incoming::ForCore(RelayRequest::Agent(AgentRequest {
                connection: 7,
                message: vec![11]
            }))
        );
        assert_eq!(
            incoming(frame(KIND_CLOSED, &[])),
            Incoming::ForCore(RelayRequest::AgentClosed(AgentClosed { connection: 7 }))
        );
        // A reply isn't something the helper sends; 6 and 99 are unknown.
        for kind in [KIND_REPLY, KIND_LOOKUP_REPLY, 6, 99] {
            assert_eq!(incoming(frame(kind, b"x")), Incoming::Skip, "kind {kind}");
        }
        // An agent request over the limit never reaches the core.
        assert_eq!(
            incoming(frame(KIND_REQUEST, &vec![0; MAX_AGENT_MESSAGE + 1])),
            Incoming::Skip
        );
    }

    #[test]
    fn a_lookup_decodes_into_a_known_hosts_request_with_the_helpers_id() {
        assert_eq!(
            incoming(frame(
                KIND_LOOKUP,
                &lookup_payload(2222, "[git.example]:2222", "ssh-ed25519", &[1, 2, 3])
            )),
            Incoming::ForCore(RelayRequest::KnownHosts(KnownHostsRequest {
                id: 7,
                host: "[git.example]:2222".into(),
                port: 2222,
                key_type: "ssh-ed25519".into(),
                key: vec![1, 2, 3],
            }))
        );
        // The call that only asks for the stored keys.
        assert_eq!(
            incoming(frame(
                KIND_LOOKUP,
                &lookup_payload(22, "git.example", "", &[])
            )),
            Incoming::ForCore(RelayRequest::KnownHosts(KnownHostsRequest {
                id: 7,
                host: "git.example".into(),
                port: 22,
                key_type: String::new(),
                key: Vec::new(),
            }))
        );
    }

    #[test]
    fn lookups_that_break_the_limits_are_answered_not_relayed() {
        let long_host = "h".repeat(MAX_KNOWN_HOST + 1);
        let long_type = "t".repeat(MAX_KEY_TYPE + 1);
        let long_key = vec![0u8; MAX_HOST_KEY + 1];
        let mut trailing = lookup_payload(22, "git.example", "", &[]);
        trailing.push(0);
        let mut not_utf8 = lookup_payload(22, "x", "", &[]);
        not_utf8[8] = 0xff;
        let cases = [
            lookup_payload(0, "git.example", "", &[]),
            lookup_payload(65536, "git.example", "", &[]),
            lookup_payload(22, "", "", &[]),
            lookup_payload(22, &long_host, "", &[]),
            lookup_payload(22, "git.example", &long_type, &[1]),
            lookup_payload(22, "git.example", "ssh-ed25519", &long_key),
            lookup_payload(22, "git.example", "ssh-ed25519", &[]),
            lookup_payload(22, "git.example", "", &[1]),
            trailing,
            not_utf8,
            vec![0, 0, 0],
            Vec::new(),
        ];
        for payload in cases {
            assert_eq!(
                incoming(frame(KIND_LOOKUP, &payload)),
                Incoming::BadLookup(7),
                "{payload:?}"
            );
        }
    }

    #[test]
    fn an_answer_is_a_count_then_keys() {
        assert_eq!(encode_answer(&[]), [0, 0, 0, 0]);
        assert_eq!(
            encode_answer(&[vec![1, 2], vec![3]]),
            [0, 0, 0, 2, 0, 0, 0, 2, 1, 2, 0, 0, 0, 1, 3]
        );
    }

    #[tokio::test]
    async fn replies_become_frames_and_oversized_ones_are_dropped() {
        let written = |reply| async {
            let mut out = Vec::new();
            write_reply(&mut out, reply).await.unwrap();
            out
        };
        assert_eq!(
            written(RelayReply::Agent(doozers_types::AgentReply {
                connection: 3,
                message: vec![12]
            }))
            .await,
            encode_frame(KIND_REPLY, 3, &[12]).unwrap()
        );
        assert_eq!(
            written(RelayReply::KnownHosts(KnownHostsReply {
                id: 4,
                keys: vec![vec![9]]
            }))
            .await,
            encode_frame(KIND_LOOKUP_REPLY, 4, &[0, 0, 0, 1, 0, 0, 0, 1, 9]).unwrap()
        );
        assert!(
            written(RelayReply::Agent(doozers_types::AgentReply {
                connection: 3,
                message: vec![0; MAX_AGENT_MESSAGE + 1]
            }))
            .await
            .is_empty()
        );
        assert!(
            written(RelayReply::KnownHosts(KnownHostsReply {
                id: 4,
                keys: vec![Vec::new(); MAX_KNOWN_HOST_KEYS + 1]
            }))
            .await
            .is_empty()
        );
        assert!(
            written(RelayReply::KnownHosts(KnownHostsReply {
                id: 4,
                keys: vec![vec![0; MAX_HOST_KEY + 1]]
            }))
            .await
            .is_empty()
        );
    }
}
