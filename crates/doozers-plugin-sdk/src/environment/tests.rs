//! `EnvironmentService` and the environment half of `Describe`/`Configure`, in process.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use doozers_proto::environment::v1 as pb;
use doozers_proto::environment::v1::environment_service_client::EnvironmentServiceClient;
use doozers_proto::plugin::v1::plugin_service_client::PluginServiceClient;
use doozers_proto::plugin::v1::plugin_service_server::PluginServiceServer;
use doozers_proto::plugin::v1::{ConfigureRequest, DescribeRequest};
use doozers_types::{
    AgentClosed, AgentReply, AgentRequest, EnvironmentInfo, Error, ExecExit, ExecRequest,
    FindRequest, FindResult, GrepMatch, GrepRequest, GrepResult, ReadFile, RelayReply,
    RelayRequest, StartOutcome, Timestamp, Workspace, WorkspaceDetail, WorkspaceList,
    WorkspaceState,
};
use futures::stream;
use serde_json::json;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::Code;
use tonic::transport::{Channel as GrpcChannel, Server};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;

use super::*;
use crate::base::{Base, OnShutdown};
use crate::convert::environment::{
    exec_event_from_proto, relay_request_from_proto, workspace_from_proto,
};
use crate::dirs::SdkDirs;
use crate::test_support::serve;

const WAIT: Duration = Duration::from_secs(5);

/// What the fake environment saw, shared with the test.
#[derive(Default)]
struct Seen {
    /// The instance and config of each `configure` call.
    configures: Vec<(String, serde_json::Value)>,
    created: Vec<(String, serde_json::Value)>,
    files: BTreeMap<String, Vec<u8>>,
    /// Closes when the stream of the `hang` command is dropped.
    hung_exec: Option<oneshot::Receiver<()>>,
    /// The workspaces `relay` was called for.
    relayed: Vec<String>,
}

struct Fake {
    seen: Arc<Mutex<Seen>>,
}

fn workspace(id: &WorkspaceId) -> Workspace {
    Workspace {
        id: id.clone(),
        description: "fake@sha256:abc".into(),
        working_directory: "/workspace".into(),
        persistence: "/workspace survives".into(),
        created_at: "2026-11-10T12:00:00Z".parse::<Timestamp>().unwrap(),
        state: WorkspaceState::Running,
        disk_used_bytes: Some(4096),
        details: vec![WorkspaceDetail::new("Image", "fake")],
    }
}

/// The errors the fake raises for workspaces named after them.
fn fail_by_name(id: &WorkspaceId) -> Result<()> {
    match id.as_str() {
        "gone" => Err(Error::NotFound("no workspace gone".into())),
        "refuse" => Err(Error::InvalidRequest("refused".into())),
        "offline" => Err(Error::unavailable("the engine is offline")),
        "boom" => Err(Error::other("boom")),
        _ => Ok(()),
    }
}

#[async_trait]
impl Environment for Fake {
    async fn info(&self) -> Result<EnvironmentInfo> {
        Ok(EnvironmentInfo {
            options_schema: json!({"type": "object", "properties": {"image": {"type": "string"}}}),
        })
    }

    async fn create_workspace(
        &self,
        id: &WorkspaceId,
        options: serde_json::Value,
    ) -> Result<Workspace> {
        fail_by_name(id)?;
        self.seen
            .lock()
            .unwrap()
            .created
            .push((id.to_string(), options));
        Ok(workspace(id))
    }

    async fn delete_workspace(&self, id: &WorkspaceId) -> Result<()> {
        fail_by_name(id)
    }

    async fn start_workspace(&self, id: &WorkspaceId) -> Result<StartOutcome> {
        fail_by_name(id)?;
        Ok(StartOutcome::Recreated {
            detail: "packages are gone".into(),
        })
    }

    async fn stop_workspace(&self, id: &WorkspaceId) -> Result<()> {
        fail_by_name(id)
    }

    async fn list_workspaces(&self) -> Result<WorkspaceList> {
        Ok(WorkspaceList {
            workspaces: vec![workspace(&WorkspaceId::new("ws-1").unwrap())],
            free_bytes: Some(1 << 30),
        })
    }

    async fn exec(
        &self,
        id: &WorkspaceId,
        request: ExecRequest,
    ) -> Result<BoxStream<'static, Result<ExecEvent>>> {
        fail_by_name(id)?;
        let exit = |code| {
            Ok(ExecEvent::Exit(ExecExit {
                code,
                timed_out: false,
                dropped_bytes: 3,
            }))
        };
        Ok(match request.command.as_str() {
            "echo" => stream::iter([
                Ok(ExecEvent::Stdout(b"hi\n".to_vec())),
                Ok(ExecEvent::Stderr(b"warn".to_vec())),
                exit(0),
            ])
            .boxed(),
            // Output after the exit event, which the SDK must not send.
            "chatty" => {
                stream::iter([exit(1), Ok(ExecEvent::Stdout(b"too late".to_vec()))]).boxed()
            }
            "no-exit" => stream::iter([Ok(ExecEvent::Stdout(b"x".to_vec()))]).boxed(),
            "fail" => stream::iter([
                Ok(ExecEvent::Stdout(b"x".to_vec())),
                Err(Error::unavailable("the engine went away")),
            ])
            .boxed(),
            // Runs until the stream is dropped, which the test then observes.
            "hang" => {
                let (guard, dropped) = oneshot::channel::<()>();
                self.seen.lock().unwrap().hung_exec = Some(dropped);
                stream::once(async { Ok(ExecEvent::Stdout(b"started".to_vec())) })
                    .chain(stream::pending())
                    .map(move |event| {
                        let _held = &guard;
                        event
                    })
                    .boxed()
            }
            other => return Err(Error::InvalidRequest(format!("unknown command {other:?}"))),
        })
    }

    async fn read_file(&self, id: &WorkspaceId, path: &str, max_bytes: u64) -> Result<ReadFile> {
        fail_by_name(id)?;
        let seen = self.seen.lock().unwrap();
        let content = seen
            .files
            .get(path)
            .ok_or_else(|| Error::NotFound(format!("no file {path}")))?;
        let cut = usize::try_from(max_bytes)
            .unwrap_or(usize::MAX)
            .min(content.len());
        Ok(ReadFile {
            content: content[..cut].to_vec(),
            size: content.len() as u64,
        })
    }

    async fn write_file(&self, id: &WorkspaceId, path: &str, content: Vec<u8>) -> Result<()> {
        fail_by_name(id)?;
        self.seen
            .lock()
            .unwrap()
            .files
            .insert(path.to_owned(), content);
        Ok(())
    }

    async fn find(&self, id: &WorkspaceId, request: FindRequest) -> Result<FindResult> {
        fail_by_name(id)?;
        Ok(FindResult {
            paths: vec![format!(
                "{}/{}",
                request.path.unwrap_or_else(|| ".".into()),
                request.pattern
            )],
            truncated: request.limit == 0,
        })
    }

    async fn grep(&self, id: &WorkspaceId, request: GrepRequest) -> Result<GrepResult> {
        fail_by_name(id)?;
        Ok(GrepResult {
            matches: vec![GrepMatch {
                path: request.glob.unwrap_or_default(),
                line: 7,
                text: format!("{} {}", request.pattern, request.case_insensitive),
            }],
            truncated: false,
        })
    }

    /// The key is the host, key type, and port, joined; the workspaces named after the errors fail.
    async fn scan_host_key(
        &self,
        id: &WorkspaceId,
        host: &str,
        port: u16,
        key_type: &str,
    ) -> Result<Vec<u8>> {
        fail_by_name(id)?;
        Ok(format!("{host} {key_type} {port}").into_bytes())
    }

    /// Asks `REQUEST_IDENTITIES` (11) for connection 1, then answers every reply with the reply's
    /// message reversed, and ends when the core ends its replies.
    async fn relay(
        &self,
        id: &WorkspaceId,
        replies: BoxStream<'static, RelayReply>,
    ) -> Result<BoxStream<'static, Result<RelayRequest>>> {
        fail_by_name(id)?;
        self.seen.lock().unwrap().relayed.push(id.to_string());
        let first = RelayRequest::Agent(AgentRequest {
            connection: 1,
            message: vec![11],
        });
        Ok(stream::once(async { Ok(first) })
            .chain(replies.flat_map(|reply| match reply {
                RelayReply::Agent(AgentReply {
                    connection,
                    mut message,
                }) => {
                    message.reverse();
                    stream::iter([
                        Ok(RelayRequest::Agent(AgentRequest {
                            connection,
                            message,
                        })),
                        Ok(RelayRequest::AgentClosed(AgentClosed { connection })),
                    ])
                    .boxed()
                }
                _ => stream::empty().boxed(),
            }))
            .boxed())
    }
}

struct Fixture {
    _data: Arc<tempfile::TempDir>,
    seen: Arc<Mutex<Seen>>,
    plugin: PluginServiceClient<GrpcChannel>,
    env: EnvironmentServiceClient<GrpcChannel>,
    health: HealthClient<GrpcChannel>,
}

/// A fake environment plugin named `fake`. `own_config` is a remote plugin's settings: `None` is a
/// launched plugin, whose settings the core sends.
async fn fixture_with(own_config: Option<serde_json::Value>) -> Fixture {
    let data = Arc::new(tempfile::tempdir().unwrap());
    let dirs = Arc::new(SdkDirs::open(data.path()).unwrap());
    let (health, health_service) = tonic_health::server::health_reporter();
    let context = Context {
        data_dir: data.path().to_owned(),
        blobs: Blobs::new(Arc::clone(&dirs)),
        dirs,
        health,
        shutdown: CancellationToken::new(),
    };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let configure = {
        let seen = Arc::clone(&seen);
        configure_fn(move |ctx: Configure| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .unwrap()
                    .configures
                    .push((ctx.instance().to_owned(), ctx.config().clone()));
                if ctx.config()["fail"] == json!(true) {
                    return Err(Error::InvalidRequest("fail: set".into()));
                }
                Ok(Fake { seen })
            }
        })
    };
    let (kind, routes) = EnvironmentPlugin::new("fake", "0.0.1")
        .ssh_relay()
        .requested_grants(Grants {
            unix: vec!["/var/run/fake.sock".into()],
            ..Grants::default()
        })
        .services(configure, own_config, &context);
    context
        .health
        .set_service_status(kind.service_name(), ServingStatus::NotServing)
        .await;
    let base = Base::new(
        kind,
        context.blobs.clone(),
        OnShutdown::Detach,
        context.shutdown.clone(),
    );
    let grpc = serve(
        Server::builder()
            .add_routes(routes)
            .add_service(PluginServiceServer::new(base))
            .add_service(health_service),
    )
    .await;
    Fixture {
        _data: data,
        seen,
        plugin: PluginServiceClient::new(grpc.clone()),
        env: EnvironmentServiceClient::new(grpc.clone()),
        health: HealthClient::new(grpc),
    }
}

async fn fixture() -> Fixture {
    fixture_with(None).await
}

impl Fixture {
    async fn configure(&mut self, instance: &str, config_json: &str) -> Result<(), Status> {
        self.plugin
            .configure(ConfigureRequest {
                instance: instance.into(),
                config_json: config_json.into(),
            })
            .await?;
        Ok(())
    }

    async fn configured() -> Self {
        let mut f = fixture().await;
        f.configure("sandbox", "{}").await.unwrap();
        f
    }

    async fn exec(&mut self, command: &str) -> Result<tonic::Streaming<pb::ExecResponse>, Status> {
        Ok(self
            .env
            .exec(pb::ExecRequest {
                workspace_id: "ws-1".into(),
                command: command.into(),
                timeout: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
                output_limit: 1024,
            })
            .await?
            .into_inner())
    }

    /// Every event of `command`, then whether the stream ended, or the error that ended it.
    async fn exec_all(&mut self, command: &str) -> (Vec<ExecEvent>, Option<Status>) {
        let mut stream = self.exec(command).await.unwrap();
        let mut events = Vec::new();
        loop {
            match tokio::time::timeout(WAIT, stream.message()).await.unwrap() {
                Ok(Some(response)) => events.push(exec_event_from_proto(response).unwrap()),
                Ok(None) => return (events, None),
                Err(status) => return (events, Some(status)),
            }
        }
    }
}

fn ws(id: &str) -> pb::StartWorkspaceRequest {
    pb::StartWorkspaceRequest {
        workspace_id: id.into(),
    }
}

#[tokio::test]
async fn describe_reports_the_environment_capabilities() {
    let mut f = fixture().await;
    let described = f
        .plugin
        .describe(DescribeRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(described.kind(), PluginKind::Environment);
    assert_eq!(described.name, "fake");
    assert_eq!(described.version, "0.0.1");
    assert_eq!(
        described.requested_grants.unwrap().unix,
        ["/var/run/fake.sock"]
    );
    assert_eq!(
        described.capabilities,
        Some(describe_response::Capabilities::Environment(
            EnvironmentCapabilities { ssh_relay: true }
        ))
    );
}

#[tokio::test]
async fn nothing_is_served_before_configure() {
    let mut f = fixture().await;
    assert_eq!(
        f.env.info(pb::InfoRequest {}).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        f.exec("echo").await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    let health = f
        .health
        .check(HealthCheckRequest {
            service: environment_service_server::SERVICE_NAME.into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        health.status(),
        tonic_health::pb::health_check_response::ServingStatus::NotServing
    );

    f.configure("sandbox", "{}").await.unwrap();
    f.env.info(pb::InfoRequest {}).await.unwrap();
    let health = f
        .health
        .check(HealthCheckRequest {
            service: environment_service_server::SERVICE_NAME.into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        health.status(),
        tonic_health::pb::health_check_response::ServingStatus::Serving
    );
}

#[tokio::test]
async fn a_launched_plugin_gets_the_cores_config() {
    let mut f = fixture().await;
    f.configure("sandbox", r#"{"engine": "fake"}"#)
        .await
        .unwrap();
    assert_eq!(
        f.seen.lock().unwrap().configures,
        [("sandbox".to_owned(), json!({"engine": "fake"}))]
    );

    // Repeated: same answer, no second call. Different: refused.
    f.configure("sandbox", r#"{"engine": "fake"}"#)
        .await
        .unwrap();
    assert_eq!(f.seen.lock().unwrap().configures.len(), 1);
    for (instance, config) in [("other", r#"{"engine": "fake"}"#), ("sandbox", "{}")] {
        let status = f.configure(instance, config).await.unwrap_err();
        assert_eq!(
            status.code(),
            Code::FailedPrecondition,
            "{instance} {config}"
        );
    }
}

#[tokio::test]
async fn a_failed_configure_is_reported_and_can_be_retried() {
    let mut f = fixture().await;
    let status = f
        .configure("sandbox", r#"{"fail": true}"#)
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(status.message(), "fail: set");
    f.configure("sandbox", "{}").await.unwrap();
}

#[tokio::test]
async fn a_remote_plugin_uses_its_own_config_and_refuses_the_cores() {
    let mut f = fixture_with(Some(json!({"engine": "own"}))).await;

    // The core sends an empty config, or none; the plugin's own reaches `configure`.
    for empty in ["{}", "null"] {
        f.configure("sandbox", empty).await.unwrap();
    }
    assert_eq!(
        f.seen.lock().unwrap().configures,
        [("sandbox".to_owned(), json!({"engine": "own"}))],
        "the second Configure is a reconnect, not a rebuild"
    );

    for config in [r#"{"engine": "core"}"#, r#"{"x": null}"#, "[]", "3"] {
        let status = f.configure("sandbox", config).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{config}");
        assert!(
            status.message().contains("its own config file"),
            "{}",
            status.message()
        );
    }

    // Another instance name is a different configuration of an already built plugin.
    let status = f.configure("other", "{}").await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn a_remote_plugin_without_settings_gets_an_empty_config() {
    let mut f = fixture_with(Some(json!({}))).await;
    f.configure("sandbox", "{}").await.unwrap();
    assert_eq!(
        f.seen.lock().unwrap().configures,
        [("sandbox".to_owned(), json!({}))]
    );
}

#[tokio::test]
async fn workspaces_are_managed_through_the_domain_types() {
    let mut f = Fixture::configured().await;

    let info = f.env.info(pb::InfoRequest {}).await.unwrap().into_inner();
    let schema: serde_json::Value = serde_json::from_str(&info.options_schema_json).unwrap();
    assert_eq!(schema["properties"]["image"]["type"], "string");

    let created = f
        .env
        .create_workspace(pb::CreateWorkspaceRequest {
            workspace_id: "ws-1".into(),
            options_json: r#"{"image": "debian"}"#.into(),
        })
        .await
        .unwrap()
        .into_inner();
    let created = workspace_from_proto(created.workspace.unwrap()).unwrap();
    assert_eq!(created, workspace(&WorkspaceId::new("ws-1").unwrap()));
    // No options is `{}`.
    f.env
        .create_workspace(pb::CreateWorkspaceRequest {
            workspace_id: "ws-2".into(),
            options_json: String::new(),
        })
        .await
        .unwrap();
    assert_eq!(
        f.seen.lock().unwrap().created,
        [
            ("ws-1".to_owned(), json!({"image": "debian"})),
            ("ws-2".to_owned(), json!({})),
        ]
    );

    let started = f
        .env
        .start_workspace(ws("ws-1"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(started.outcome(), pb::StartOutcome::Recreated);
    assert_eq!(started.detail, "packages are gone");

    f.env
        .stop_workspace(pb::StopWorkspaceRequest {
            workspace_id: "ws-1".into(),
        })
        .await
        .unwrap();
    f.env
        .delete_workspace(pb::DeleteWorkspaceRequest {
            workspace_id: "ws-1".into(),
        })
        .await
        .unwrap();

    let listed = f
        .env
        .list_workspaces(pb::ListWorkspacesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.workspaces.len(), 1);
    assert_eq!(listed.workspaces[0].workspace_id, "ws-1");
    assert_eq!(listed.free_bytes, Some(1 << 30));
}

#[tokio::test]
async fn invalid_requests_are_refused_before_the_plugin_sees_them() {
    let mut f = Fixture::configured().await;
    for id in ["", "WS", "a b", &"a".repeat(65)] {
        let status = f.env.start_workspace(ws(id)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{id:?}");
    }
    for options in ["[1]", "{", "3"] {
        let status = f
            .env
            .create_workspace(pb::CreateWorkspaceRequest {
                workspace_id: "ws-1".into(),
                options_json: options.into(),
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{options}");
    }
    assert!(f.seen.lock().unwrap().created.is_empty());

    // Exec needs its timeout.
    let status = f
        .env
        .exec(pb::ExecRequest {
            workspace_id: "ws-1".into(),
            command: "echo".into(),
            timeout: None,
            output_limit: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn errors_map_to_their_grpc_codes() {
    let mut f = Fixture::configured().await;
    for (id, code, message) in [
        ("gone", Code::NotFound, "no workspace gone"),
        ("refuse", Code::InvalidArgument, "refused"),
        ("offline", Code::Unavailable, "the engine is offline"),
        ("boom", Code::Unknown, "boom"),
    ] {
        let statuses = [
            f.env
                .create_workspace(pb::CreateWorkspaceRequest {
                    workspace_id: id.into(),
                    options_json: String::new(),
                })
                .await
                .map(drop),
            f.env
                .delete_workspace(pb::DeleteWorkspaceRequest {
                    workspace_id: id.into(),
                })
                .await
                .map(drop),
            f.env.start_workspace(ws(id)).await.map(drop),
            f.env
                .stop_workspace(pb::StopWorkspaceRequest {
                    workspace_id: id.into(),
                })
                .await
                .map(drop),
            f.env
                .read_file(pb::ReadFileRequest {
                    workspace_id: id.into(),
                    path: "a".into(),
                    max_bytes: 1,
                })
                .await
                .map(drop),
            f.env
                .write_file(pb::WriteFileRequest {
                    workspace_id: id.into(),
                    path: "a".into(),
                    content: vec![],
                })
                .await
                .map(drop),
            f.env
                .find(pb::FindRequest {
                    workspace_id: id.into(),
                    ..pb::FindRequest::default()
                })
                .await
                .map(drop),
            f.env
                .grep(pb::GrepRequest {
                    workspace_id: id.into(),
                    ..pb::GrepRequest::default()
                })
                .await
                .map(drop),
        ];
        for status in statuses {
            let status = status.unwrap_err();
            assert_eq!(status.code(), code, "{id}");
            assert!(
                status.message().contains(message),
                "{id}: {}",
                status.message()
            );
        }
    }

    // `exec` fails before its stream starts, or in the middle of it.
    let stream = f
        .env
        .exec(pb::ExecRequest {
            workspace_id: "offline".into(),
            command: "echo".into(),
            timeout: Some(prost_types::Duration::default()),
            output_limit: 0,
        })
        .await;
    assert_eq!(
        stream.err().map(|status| status.code()),
        Some(Code::Unavailable)
    );
    let (events, error) = f.exec_all("fail").await;
    assert_eq!(events, [ExecEvent::Stdout(b"x".to_vec())]);
    let error = error.unwrap();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(error.message().contains("the engine went away"));
}

#[tokio::test]
async fn files_find_and_grep_pass_through() {
    let mut f = Fixture::configured().await;
    f.env
        .write_file(pb::WriteFileRequest {
            workspace_id: "ws-1".into(),
            path: "notes.txt".into(),
            content: b"hello world".to_vec(),
        })
        .await
        .unwrap();
    let read = f
        .env
        .read_file(pb::ReadFileRequest {
            workspace_id: "ws-1".into(),
            path: "notes.txt".into(),
            max_bytes: 5,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!((read.content.as_slice(), read.size), (&b"hello"[..], 11));
    let missing = f
        .env
        .read_file(pb::ReadFileRequest {
            workspace_id: "ws-1".into(),
            path: "nope".into(),
            max_bytes: 5,
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);

    let found = f
        .env
        .find(pb::FindRequest {
            workspace_id: "ws-1".into(),
            pattern: "*.rs".into(),
            path: String::new(),
            limit: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(found.paths, ["./*.rs"]);
    assert!(found.truncated);
    let found = f
        .env
        .find(pb::FindRequest {
            workspace_id: "ws-1".into(),
            pattern: "*.rs".into(),
            path: "src".into(),
            limit: 10,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(found.paths, ["src/*.rs"]);

    let grepped = f
        .env
        .grep(pb::GrepRequest {
            workspace_id: "ws-1".into(),
            pattern: "todo".into(),
            path: String::new(),
            glob: Some("*.rs".into()),
            case_insensitive: true,
            limit: 5,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        grepped.matches,
        [pb::GrepMatch {
            path: "*.rs".into(),
            line: 7,
            text: "todo true".into()
        }]
    );
}

#[tokio::test]
async fn exec_streams_its_events_ending_with_the_exit() {
    let mut f = Fixture::configured().await;
    let (events, error) = f.exec_all("echo").await;
    assert!(error.is_none());
    assert_eq!(
        events,
        [
            ExecEvent::Stdout(b"hi\n".to_vec()),
            ExecEvent::Stderr(b"warn".to_vec()),
            ExecEvent::Exit(ExecExit {
                code: 0,
                timed_out: false,
                dropped_bytes: 3
            }),
        ]
    );

    // Nothing after the exit goes out.
    let (events, error) = f.exec_all("chatty").await;
    assert!(error.is_none());
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        ExecEvent::Exit(ExecExit { code: 1, .. })
    ));
}

#[tokio::test]
async fn an_exec_stream_that_ends_without_an_exit_is_an_error() {
    let mut f = Fixture::configured().await;
    let (events, error) = f.exec_all("no-exit").await;
    assert_eq!(events, [ExecEvent::Stdout(b"x".to_vec())]);
    let error = error.unwrap();
    assert_eq!(error.code(), Code::Internal);
    assert!(
        error.message().contains("without an exit event"),
        "{}",
        error.message()
    );
}

#[tokio::test]
async fn cancelling_exec_drops_the_plugins_stream() {
    let mut f = Fixture::configured().await;
    let mut stream = f.exec("hang").await.unwrap();
    let first = tokio::time::timeout(WAIT, stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        exec_event_from_proto(first).unwrap(),
        ExecEvent::Stdout(b"started".to_vec())
    );
    let dropped = f.seen.lock().unwrap().hung_exec.take().unwrap();

    drop(stream);
    // The plugin's end of the channel closes: nothing is ever sent on it.
    let closed = tokio::time::timeout(WAIT, dropped)
        .await
        .expect("the plugin's stream was dropped when the call was cancelled");
    assert!(closed.is_err());
}

/// Opens `Relay` for `id`: the client's request stream (what the core sends) and the call's result.
async fn open_relay(
    f: &mut Fixture,
    first: pb::RelayReply,
) -> (
    futures::channel::mpsc::UnboundedSender<pb::RelayReply>,
    Result<tonic::Streaming<pb::RelayRequest>, Status>,
) {
    let (core, requests) = futures::channel::mpsc::unbounded();
    core.unbounded_send(first).unwrap();
    let response = f.env.relay(requests).await.map(|r| r.into_inner());
    (core, response)
}

fn open(id: &str) -> pb::RelayReply {
    pb::RelayReply {
        message: Some(pb::relay_reply::Message::Open(pb::RelayOpen {
            workspace_id: id.into(),
        })),
    }
}

fn agent_reply(connection: u64, message: &[u8]) -> pb::RelayReply {
    pb::RelayReply {
        message: Some(pb::relay_reply::Message::Agent(pb::AgentReply {
            connection,
            message: message.to_vec(),
        })),
    }
}

#[tokio::test]
async fn relay_carries_requests_and_replies_through_the_environment() {
    let mut f = Fixture::configured().await;
    let (core, response) = open_relay(&mut f, open("ws-1")).await;
    let mut requests = response.unwrap();
    assert_eq!(f.seen.lock().unwrap().relayed, ["ws-1"]);

    async fn next(requests: &mut tonic::Streaming<pb::RelayRequest>) -> RelayRequest {
        let message = tokio::time::timeout(WAIT, requests.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        relay_request_from_proto(message).unwrap()
    }
    // The environment asks first.
    assert_eq!(
        next(&mut requests).await,
        RelayRequest::Agent(AgentRequest {
            connection: 1,
            message: vec![11]
        })
    );
    // The core's reply reaches the environment, and what it sends back reaches the core.
    core.unbounded_send(agent_reply(1, &[12, 0, 0, 0, 0]))
        .unwrap();
    assert_eq!(
        next(&mut requests).await,
        RelayRequest::Agent(AgentRequest {
            connection: 1,
            message: vec![0, 0, 0, 0, 12]
        })
    );
    assert_eq!(
        next(&mut requests).await,
        RelayRequest::AgentClosed(AgentClosed { connection: 1 })
    );

    // The core ending its side ends the relay.
    drop(core);
    let end = tokio::time::timeout(WAIT, requests.message())
        .await
        .unwrap()
        .unwrap();
    assert!(end.is_none());
}

#[tokio::test]
async fn relay_refuses_a_call_that_does_not_start_with_open() {
    let mut f = Fixture::configured().await;
    let (_core, response) = open_relay(&mut f, agent_reply(1, &[12])).await;
    let status = response.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("open"), "{}", status.message());

    // A call with no message at all.
    let empty = f
        .env
        .relay(stream::empty::<pb::RelayReply>())
        .await
        .unwrap_err();
    assert_eq!(empty.code(), Code::InvalidArgument);
    assert!(f.seen.lock().unwrap().relayed.is_empty());

    // An open for an invalid workspace id.
    let (_core, response) = open_relay(&mut f, open("Not Valid")).await;
    assert_eq!(response.unwrap_err().code(), Code::InvalidArgument);
}

#[tokio::test]
async fn relay_reports_the_environments_errors() {
    let mut f = Fixture::configured().await;
    let (_core, response) = open_relay(&mut f, open("gone")).await;
    assert_eq!(response.unwrap_err().code(), Code::NotFound);
    let (_core, response) = open_relay(&mut f, open("refuse")).await;
    assert_eq!(response.unwrap_err().code(), Code::InvalidArgument);
}

#[tokio::test]
async fn relay_needs_a_configured_plugin() {
    let mut f = fixture().await;
    let (_core, response) = open_relay(&mut f, open("ws-1")).await;
    assert_eq!(response.unwrap_err().code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn scan_host_key_goes_through_the_environment() {
    let mut f = Fixture::configured().await;
    let request = |workspace: &str, port: u32| pb::ScanHostKeyRequest {
        workspace_id: workspace.into(),
        host: "git.example".into(),
        port,
        key_type: "ssh-ed25519".into(),
    };
    let key = f
        .env
        .scan_host_key(request("ws-1", 2222))
        .await
        .unwrap()
        .into_inner()
        .key;
    assert_eq!(key, b"git.example ssh-ed25519 2222");

    assert_eq!(
        f.env
            .scan_host_key(request("gone", 22))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    // A port that isn't one never reaches the environment.
    assert_eq!(
        f.env
            .scan_host_key(request("ws-1", 0))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn scan_host_key_needs_a_configured_plugin() {
    let mut f = fixture().await;
    let status = f
        .env
        .scan_host_key(pb::ScanHostKeyRequest {
            workspace_id: "ws-1".into(),
            host: "git.example".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
}
