//! `RemoteEnvironment::relay` against a fake environment service served in this process over a
//! socket pair.

use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use doozers_proto::environment::v1 as pb;
use doozers_proto::environment::v1::environment_service_server::{
    EnvironmentService, EnvironmentServiceServer,
};
use doozers_types::{AgentClosed, AgentReply, AgentRequest, KnownHostsReply, KnownHostsRequest};
use futures::channel::mpsc;
use tokio::sync::Notify;
use tonic::{Request, Response};

use super::*;
use crate::config::Secret;

const SECRET: &str = "s3cr3t-launch-token";
const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Fake {
    /// The workspace of each `open` message.
    opened: Mutex<Vec<String>>,
    /// Notified when the call's request stream ends or breaks: the core ended or cancelled it.
    core_gone: Notify,
}

#[derive(Clone)]
struct FakeService(Arc<Fake>);

fn agent(connection: u64, message: &[u8]) -> pb::RelayRequest {
    pb::RelayRequest {
        message: Some(pb::relay_request::Message::Agent(pb::AgentRequest {
            connection,
            message: message.to_vec(),
        })),
    }
}

/// The workspace id picks the behavior: `refuse`, `gone`, `ends` (one request, then the end),
/// `fail` (one request, then a failure that mentions the secret); anything else mirrors every
/// reply back as a request with the message reversed, and a `closed` after it.
#[tonic::async_trait]
impl EnvironmentService for FakeService {
    type RelayStream = BoxStream<'static, std::result::Result<pb::RelayRequest, Status>>;

    async fn relay(
        &self,
        request: Request<Streaming<pb::RelayReply>>,
    ) -> std::result::Result<Response<Self::RelayStream>, Status> {
        let mut incoming = request.into_inner();
        let first = incoming
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("no open message"))?;
        let Some(pb::relay_reply::Message::Open(open)) = first.message else {
            return Err(Status::invalid_argument("the first message isn't open"));
        };
        self.0
            .opened
            .lock()
            .unwrap()
            .push(open.workspace_id.clone());
        match open.workspace_id.as_str() {
            "refuse" => Err(Status::invalid_argument(format!("refused, token {SECRET}"))),
            "gone" => Err(Status::not_found("there is no workspace gone")),
            "ends" => Ok(Response::new(stream::iter([Ok(agent(1, b"only"))]).boxed())),
            "fail" => Ok(Response::new(
                stream::iter([
                    Ok(agent(1, b"before")),
                    Err(Status::unavailable(format!("lost, token {SECRET}"))),
                    Ok(agent(1, b"after")),
                ])
                .boxed(),
            )),
            _ => {
                let (out, rx) = mpsc::unbounded();
                let fake = Arc::clone(&self.0);
                tokio::spawn(async move {
                    while let Ok(Some(message)) = incoming.message().await {
                        // A known-hosts reply is mirrored as a lookup of the same id whose key is
                        // the first key reversed.
                        if let Some(pb::relay_reply::Message::KnownHosts(reply)) = message.message {
                            let mut key = reply.keys.into_iter().next().unwrap_or_default();
                            key.reverse();
                            let _ = out.unbounded_send(Ok(pb::RelayRequest {
                                message: Some(pb::relay_request::Message::KnownHosts(
                                    pb::KnownHostsRequest {
                                        id: reply.id,
                                        host: "git.example".into(),
                                        port: 22,
                                        key_type: "ssh-ed25519".into(),
                                        key,
                                    },
                                )),
                            }));
                            continue;
                        }
                        let Some(pb::relay_reply::Message::Agent(mut reply)) = message.message
                        else {
                            continue;
                        };
                        reply.message.reverse();
                        let _ = out.unbounded_send(Ok(agent(reply.connection, &reply.message)));
                        let _ = out.unbounded_send(Ok(pb::RelayRequest {
                            message: Some(pb::relay_request::Message::AgentClosed(
                                pb::AgentClosed {
                                    connection: reply.connection,
                                },
                            )),
                        }));
                    }
                    fake.core_gone.notify_one();
                });
                Ok(Response::new(rx.boxed()))
            }
        }
    }

    // Everything else is out of scope for this fake.
    async fn info(
        &self,
        _: Request<pb::InfoRequest>,
    ) -> std::result::Result<Response<pb::InfoResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn create_workspace(
        &self,
        _: Request<pb::CreateWorkspaceRequest>,
    ) -> std::result::Result<Response<pb::CreateWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn delete_workspace(
        &self,
        _: Request<pb::DeleteWorkspaceRequest>,
    ) -> std::result::Result<Response<pb::DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn start_workspace(
        &self,
        _: Request<pb::StartWorkspaceRequest>,
    ) -> std::result::Result<Response<pb::StartWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn stop_workspace(
        &self,
        _: Request<pb::StopWorkspaceRequest>,
    ) -> std::result::Result<Response<pb::StopWorkspaceResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn list_workspaces(
        &self,
        _: Request<pb::ListWorkspacesRequest>,
    ) -> std::result::Result<Response<pb::ListWorkspacesResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    type ExecStream = BoxStream<'static, std::result::Result<pb::ExecResponse, Status>>;
    async fn exec(
        &self,
        _: Request<pb::ExecRequest>,
    ) -> std::result::Result<Response<Self::ExecStream>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn read_file(
        &self,
        _: Request<pb::ReadFileRequest>,
    ) -> std::result::Result<Response<pb::ReadFileResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn write_file(
        &self,
        _: Request<pb::WriteFileRequest>,
    ) -> std::result::Result<Response<pb::WriteFileResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn find(
        &self,
        _: Request<pb::FindRequest>,
    ) -> std::result::Result<Response<pb::FindResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }
    async fn grep(
        &self,
        _: Request<pb::GrepRequest>,
    ) -> std::result::Result<Response<pb::GrepResponse>, Status> {
        Err(Status::unimplemented("not in this test"))
    }

    /// The key is the host's bytes. `gone` and `refuse` fail like their relays do, and `huge`
    /// answers with a key over the limit.
    async fn scan_host_key(
        &self,
        request: Request<pb::ScanHostKeyRequest>,
    ) -> std::result::Result<Response<pb::ScanHostKeyResponse>, Status> {
        let request = request.into_inner();
        match request.host.as_str() {
            "gone" => Err(Status::not_found("there is no workspace gone")),
            "refuse" => Err(Status::invalid_argument(format!("refused, token {SECRET}"))),
            "huge" => Ok(Response::new(pb::ScanHostKeyResponse {
                key: vec![0; doozers_types::MAX_HOST_KEY + 1],
            })),
            host => {
                let mut key = host.as_bytes().to_vec();
                key.extend_from_slice(request.key_type.as_bytes());
                key.extend_from_slice(&request.port.to_be_bytes());
                key.extend_from_slice(request.workspace_id.as_bytes());
                Ok(Response::new(pb::ScanHostKeyResponse { key }))
            }
        }
    }
}

struct Harness {
    environment: RemoteEnvironment,
    fake: Arc<Fake>,
}

async fn harness() -> Harness {
    let (core_end, plugin_end) = StdUnixStream::pair().unwrap();
    plugin_end.set_nonblocking(true).unwrap();
    let io = tokio::net::UnixStream::from_std(plugin_end).unwrap();
    let fake = Arc::new(Fake::default());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(EnvironmentServiceServer::new(FakeService(Arc::clone(
                &fake,
            ))))
            .serve_with_incoming(
                stream::iter([Ok::<_, std::io::Error>(io)]).chain(stream::pending()),
            ),
    );
    let connection = PluginConnection::connect(core_end, &Secret::new("token"))
        .await
        .unwrap();
    Harness {
        environment: RemoteEnvironment::from_parts(
            connection,
            Secrets::new(vec![Secret::new(SECRET)]),
            tracing::Span::none(),
        ),
        fake,
    }
}

fn id(s: &str) -> WorkspaceId {
    WorkspaceId::new(s).unwrap()
}

fn reply(connection: u64, message: &[u8]) -> RelayReply {
    RelayReply::Agent(AgentReply {
        connection,
        message: message.to_vec(),
    })
}

async fn next(
    requests: &mut BoxStream<'static, Result<RelayRequest>>,
) -> Option<Result<RelayRequest>> {
    tokio::time::timeout(WAIT, requests.next()).await.unwrap()
}

#[tokio::test]
async fn relay_opens_the_workspace_then_carries_replies_and_requests() {
    let h = harness().await;
    let (replies, incoming) = mpsc::unbounded();
    let mut requests = h
        .environment
        .relay(&id("ws-1"), incoming.boxed())
        .await
        .unwrap();
    assert_eq!(*h.fake.opened.lock().unwrap(), ["ws-1"]);

    replies.unbounded_send(reply(3, &[1, 2, 3])).unwrap();
    assert_eq!(
        next(&mut requests).await.unwrap().unwrap(),
        RelayRequest::Agent(AgentRequest {
            connection: 3,
            message: vec![3, 2, 1]
        })
    );
    assert_eq!(
        next(&mut requests).await.unwrap().unwrap(),
        RelayRequest::AgentClosed(AgentClosed { connection: 3 })
    );
}

#[tokio::test]
async fn ending_the_replies_or_dropping_the_requests_ends_the_call() {
    let h = harness().await;
    let (replies, incoming) = mpsc::unbounded();
    let mut requests = h
        .environment
        .relay(&id("ws-1"), incoming.boxed())
        .await
        .unwrap();
    // The plugin sees the core's side end.
    drop(replies);
    tokio::time::timeout(WAIT, h.fake.core_gone.notified())
        .await
        .expect("the plugin saw the replies end");
    assert!(next(&mut requests).await.is_none());

    // Dropping the stream the core got cancels the call.
    let (_replies, incoming) = mpsc::unbounded();
    let requests = h
        .environment
        .relay(&id("ws-2"), incoming.boxed())
        .await
        .unwrap();
    drop(requests);
    tokio::time::timeout(WAIT, h.fake.core_gone.notified())
        .await
        .expect("the plugin saw the call cancelled");
}

#[tokio::test]
async fn the_plugin_ending_the_relay_ends_the_stream() {
    let h = harness().await;
    let mut requests = h
        .environment
        .relay(&id("ends"), stream::pending().boxed())
        .await
        .unwrap();
    assert!(matches!(
        next(&mut requests).await,
        Some(Ok(RelayRequest::Agent(_)))
    ));
    assert!(next(&mut requests).await.is_none());
}

#[tokio::test]
async fn failures_are_scrubbed_and_end_the_stream() {
    let h = harness().await;
    // Refused when opening.
    let error = h
        .environment
        .relay(&id("refuse"), stream::pending().boxed())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    assert!(!error.to_string().contains(SECRET), "{error}");
    assert!(error.to_string().contains("refused"), "{error}");

    let error = h
        .environment
        .relay(&id("gone"), stream::pending().boxed())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");

    // Failing in the middle: the failure is the last item.
    let mut requests = h
        .environment
        .relay(&id("fail"), stream::pending().boxed())
        .await
        .unwrap();
    assert!(matches!(
        next(&mut requests).await,
        Some(Ok(RelayRequest::Agent(_)))
    ));
    let error = next(&mut requests).await.unwrap().unwrap_err();
    assert!(matches!(error, Error::Unavailable { .. }), "{error:?}");
    assert!(!error.to_string().contains(SECRET), "{error}");
    assert!(next(&mut requests).await.is_none());
}

#[tokio::test]
async fn known_hosts_replies_and_requests_cross_the_relay() {
    let h = harness().await;
    let (replies, incoming) = mpsc::unbounded();
    let mut requests = h
        .environment
        .relay(&id("ws-1"), incoming.boxed())
        .await
        .unwrap();
    replies
        .unbounded_send(RelayReply::KnownHosts(KnownHostsReply {
            id: 9,
            keys: vec![vec![1, 2, 3]],
        }))
        .unwrap();
    assert_eq!(
        next(&mut requests).await.unwrap().unwrap(),
        RelayRequest::KnownHosts(KnownHostsRequest {
            id: 9,
            host: "git.example".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            key: vec![3, 2, 1],
        })
    );
}

#[tokio::test]
async fn scan_host_key_asks_the_plugin_and_scrubs_its_failures() {
    let h = harness().await;
    let key = h
        .environment
        .scan_host_key(&id("ws-1"), "git.example", 2222, "ssh-ed25519")
        .await
        .unwrap();
    let mut expected = b"git.examplessh-ed25519".to_vec();
    expected.extend_from_slice(&2222u32.to_be_bytes());
    expected.extend_from_slice(b"ws-1");
    assert_eq!(key, expected);

    let error = h
        .environment
        .scan_host_key(&id("ws-1"), "gone", 22, "ssh-ed25519")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");
    let error = h
        .environment
        .scan_host_key(&id("ws-1"), "refuse", 22, "ssh-ed25519")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    assert!(!error.to_string().contains(SECRET), "{error}");
    // A key over the limit is refused rather than passed on.
    let error = h
        .environment
        .scan_host_key(&id("ws-1"), "huge", 22, "ssh-ed25519")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
}
