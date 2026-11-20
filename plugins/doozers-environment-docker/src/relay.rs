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
//!
//! Kinds 4 and 5 are reserved for known-hosts lookups, and a frame of any kind the plugin doesn't
//! know is skipped. The helper has its own copy of the format (`agent.rs` in the helper crate):
//! the two crates share nothing, because the helper is a static binary with no dependencies.

use bollard::body_full;
use bollard::query_parameters::UploadToContainerOptionsBuilder;
use bytes::{Buf as _, Bytes, BytesMut};
use doozers_types::{
    AgentClosed, AgentRequest, MAX_AGENT_MESSAGE, RelayReply, RelayRequest, WorkspaceId,
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

/// Encodes a frame. `None` if the payload is longer than an agent message.
pub(crate) fn encode_frame(kind: u8, connection: u64, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_AGENT_MESSAGE {
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
        if !(HEADER_LEN..=HEADER_LEN + MAX_AGENT_MESSAGE).contains(&rest) {
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

/// What a frame from the helper means to the core, if anything.
fn request_of(frame: Frame) -> Option<RelayRequest> {
    match frame.kind {
        KIND_REQUEST => Some(RelayRequest::Agent(AgentRequest {
            connection: frame.connection,
            message: frame.payload.to_vec(),
        })),
        KIND_CLOSED => Some(RelayRequest::AgentClosed(AgentClosed {
            connection: frame.connection,
        })),
        _ => None,
    }
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
                            Ok(Some(frame)) => {
                                let Some(request) = request_of(frame) else { continue };
                                if requests.send(Ok(request)).await.is_err() {
                                    break 'relay;
                                }
                            }
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

/// Sends one reply to the helper. A reply longer than an agent message is dropped with a warning,
/// since the helper would refuse it.
async fn write_reply(
    input: &mut (impl AsyncWrite + Unpin),
    reply: RelayReply,
) -> std::io::Result<()> {
    let RelayReply::Agent(reply) = reply else {
        return Ok(());
    };
    let Some(frame) = encode_frame(KIND_REPLY, reply.connection, &reply.message) else {
        warn!(
            connection = reply.connection,
            bytes = reply.message.len(),
            "dropping an ssh-agent reply longer than an agent message"
        );
        return Ok(());
    };
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
        // Longer than the largest message and its header.
        let mut decoder = Decoder::default();
        let too_long = u32::try_from(HEADER_LEN + MAX_AGENT_MESSAGE + 1).unwrap();
        decoder.push(&too_long.to_be_bytes());
        assert!(decoder.next_frame().is_err());
    }

    #[test]
    fn the_largest_message_fits_and_a_larger_one_is_not_encoded() {
        let largest = vec![0u8; MAX_AGENT_MESSAGE];
        let frame = encode_frame(KIND_REPLY, 1, &largest).unwrap();
        assert_eq!(decode_all(&[&frame])[0].payload.len(), MAX_AGENT_MESSAGE);
        assert!(encode_frame(KIND_REPLY, 1, &vec![0u8; MAX_AGENT_MESSAGE + 1]).is_none());
    }

    #[test]
    fn requests_and_closes_reach_the_core_and_other_kinds_are_skipped() {
        let frame = |kind, payload: &'static [u8]| Frame {
            kind,
            connection: 7,
            payload: Bytes::from_static(payload),
        };
        assert_eq!(
            request_of(frame(KIND_REQUEST, &[11])),
            Some(RelayRequest::Agent(AgentRequest {
                connection: 7,
                message: vec![11]
            }))
        );
        assert_eq!(
            request_of(frame(KIND_CLOSED, &[])),
            Some(RelayRequest::AgentClosed(AgentClosed { connection: 7 }))
        );
        // A reply isn't something the helper sends; 4 and 5 are reserved; 99 is unknown.
        for kind in [KIND_REPLY, 4, 5, 99] {
            assert_eq!(request_of(frame(kind, b"x")), None, "kind {kind}");
        }
    }
}
