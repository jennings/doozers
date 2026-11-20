//! Conversions between `doozers-types`' environment types and the `doozers.environment.v1` wire
//! types, by moving fields, following the mapping table in `Docs/technical/protocols.md`.
//!
//! The same rules as the rest of [`convert`](super): wire to domain validates (ids are checked,
//! unspecified enum values and unset `oneof`s are refused, as [`Error::InvalidRequest`] or
//! [`Error::InvalidId`]), and domain to wire fails only for a variant of a `#[non_exhaustive]`
//! domain enum this version doesn't know. The SDK uses the plugin's direction of each (requests
//! from the wire, responses to it); the other is public for the core's `RemoteEnvironment`
//! adapter and for tests.
//!
//! A path or directory the domain types leave out (`None`) is the empty string on the wire.

use std::time::Duration;

use doozers_proto::environment::v1 as pb;
use doozers_types::{
    AgentClosed, AgentReply, AgentRequest, EnvironmentInfo, ExecEvent, ExecExit, ExecRequest,
    FindRequest, FindResult, GrepMatch, GrepRequest, GrepResult, KnownHostsReply,
    KnownHostsRequest, MAX_AGENT_MESSAGE, MAX_HOST_KEY, MAX_KNOWN_HOST, MAX_KNOWN_HOST_KEYS,
    ReadFile, RelayReply, RelayRequest, Result, StartOutcome, Workspace, WorkspaceDetail,
    WorkspaceId, WorkspaceList, WorkspaceState,
};

use super::{invalid, timestamp_from_proto, timestamp_to_proto};

/// `Duration` to `google.protobuf.Duration`. A duration beyond the wire type's range (more than
/// about 292 billion years) is clamped to its largest.
pub fn duration_to_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).expect("less than 1e9"),
    }
}

/// `google.protobuf.Duration` to `Duration`. A negative duration is invalid.
pub fn duration_from_proto(duration: prost_types::Duration) -> Result<Duration> {
    let seconds = u64::try_from(duration.seconds).ok();
    let nanos = u32::try_from(duration.nanos)
        .ok()
        .filter(|n| *n < 1_000_000_000);
    match (seconds, nanos) {
        (Some(seconds), Some(nanos)) => Ok(Duration::new(seconds, nanos)),
        _ => Err(invalid(format!(
            "duration {}s {}ns is negative or malformed",
            duration.seconds, duration.nanos
        ))),
    }
}

/// `EnvironmentInfo` to an `InfoResponse`.
pub fn info_to_proto(info: &EnvironmentInfo) -> pb::InfoResponse {
    pb::InfoResponse {
        options_schema_json: info.options_schema.to_string(),
    }
}

/// An `InfoResponse` to `EnvironmentInfo`. The schema must be JSON.
pub fn info_from_proto(info: pb::InfoResponse) -> Result<EnvironmentInfo> {
    let options_schema = serde_json::from_str(&info.options_schema_json)
        .map_err(|e| invalid(format!("options_schema_json is not JSON: {e}")))?;
    Ok(EnvironmentInfo { options_schema })
}

/// The options of a `CreateWorkspaceRequest`: a JSON object. An empty string is `{}`.
pub fn options_from_proto(options_json: &str) -> Result<serde_json::Value> {
    if options_json.is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    match serde_json::from_str(options_json) {
        Ok(options @ serde_json::Value::Object(_)) => Ok(options),
        Ok(_) => Err(invalid("options_json must be a JSON object")),
        Err(e) => Err(invalid(format!("options_json is not JSON: {e}"))),
    }
}

/// `Workspace` to its wire form.
pub fn workspace_to_proto(workspace: Workspace) -> Result<pb::Workspace> {
    let state = match workspace.state {
        WorkspaceState::Running => pb::WorkspaceState::Running,
        WorkspaceState::Stopped => pb::WorkspaceState::Stopped,
        other => {
            return Err(invalid(format!(
                "workspace state {other:?} has no wire form"
            )));
        }
    };
    Ok(pb::Workspace {
        workspace_id: workspace.id.into_string(),
        description: workspace.description,
        working_directory: workspace.working_directory,
        persistence: workspace.persistence,
        created_at: Some(timestamp_to_proto(workspace.created_at)),
        state: state.into(),
        disk_used_bytes: workspace.disk_used_bytes,
        details: workspace
            .details
            .into_iter()
            .map(|d| pb::WorkspaceDetail {
                label: d.label,
                value: d.value,
            })
            .collect(),
    })
}

/// A wire `Workspace` to `Workspace`. The id, the creation time, and the state are required.
pub fn workspace_from_proto(workspace: pb::Workspace) -> Result<Workspace> {
    let state = match workspace.state() {
        pb::WorkspaceState::Running => WorkspaceState::Running,
        pb::WorkspaceState::Stopped => WorkspaceState::Stopped,
        pb::WorkspaceState::Unspecified => return Err(invalid("workspace state: unspecified")),
    };
    Ok(Workspace {
        id: WorkspaceId::new(workspace.workspace_id)?,
        description: workspace.description,
        working_directory: workspace.working_directory,
        persistence: workspace.persistence,
        created_at: timestamp_from_proto(
            workspace
                .created_at
                .ok_or_else(|| invalid("workspace created_at: missing"))?,
        )?,
        state,
        disk_used_bytes: workspace.disk_used_bytes,
        details: workspace
            .details
            .into_iter()
            .map(|d| WorkspaceDetail::new(d.label, d.value))
            .collect(),
    })
}

/// `StartOutcome` to a `StartWorkspaceResponse`.
pub fn start_outcome_to_proto(outcome: StartOutcome) -> Result<pb::StartWorkspaceResponse> {
    let (outcome, detail) = match outcome {
        StartOutcome::Running => (pb::StartOutcome::Running, String::new()),
        StartOutcome::Started { detail } => (pb::StartOutcome::Started, detail),
        StartOutcome::Recreated { detail } => (pb::StartOutcome::Recreated, detail),
        other => return Err(invalid(format!("start outcome {other:?} has no wire form"))),
    };
    Ok(pb::StartWorkspaceResponse {
        outcome: outcome.into(),
        detail,
    })
}

/// A `StartWorkspaceResponse` to `StartOutcome`.
pub fn start_outcome_from_proto(response: pb::StartWorkspaceResponse) -> Result<StartOutcome> {
    Ok(match response.outcome() {
        pb::StartOutcome::Running => StartOutcome::Running,
        pb::StartOutcome::Started => StartOutcome::Started {
            detail: response.detail,
        },
        pb::StartOutcome::Recreated => StartOutcome::Recreated {
            detail: response.detail,
        },
        pb::StartOutcome::Unspecified => return Err(invalid("start outcome: unspecified")),
    })
}

/// `WorkspaceList` to a `ListWorkspacesResponse`.
pub fn workspace_list_to_proto(list: WorkspaceList) -> Result<pb::ListWorkspacesResponse> {
    Ok(pb::ListWorkspacesResponse {
        workspaces: list
            .workspaces
            .into_iter()
            .map(workspace_to_proto)
            .collect::<Result<_>>()?,
        free_bytes: list.free_bytes,
    })
}

/// A `ListWorkspacesResponse` to `WorkspaceList`.
pub fn workspace_list_from_proto(response: pb::ListWorkspacesResponse) -> Result<WorkspaceList> {
    Ok(WorkspaceList {
        workspaces: response
            .workspaces
            .into_iter()
            .map(workspace_from_proto)
            .collect::<Result<_>>()?,
        free_bytes: response.free_bytes,
    })
}

/// A workspace id and an `ExecRequest` to the wire request.
pub fn exec_request_to_proto(id: &WorkspaceId, request: ExecRequest) -> pb::ExecRequest {
    pb::ExecRequest {
        workspace_id: id.to_string(),
        command: request.command,
        timeout: Some(duration_to_proto(request.timeout)),
        output_limit: request.output_limit,
    }
}

/// A wire `ExecRequest` to its workspace id and `ExecRequest`. The timeout is required.
pub fn exec_request_from_proto(request: pb::ExecRequest) -> Result<(WorkspaceId, ExecRequest)> {
    let timeout = request.timeout.ok_or_else(|| invalid("timeout: missing"))?;
    Ok((
        WorkspaceId::new(request.workspace_id)?,
        ExecRequest {
            command: request.command,
            timeout: duration_from_proto(timeout)?,
            output_limit: request.output_limit,
        },
    ))
}

/// `ExecEvent` to an `ExecResponse`.
pub fn exec_event_to_proto(event: ExecEvent) -> Result<pb::ExecResponse> {
    use pb::exec_response::Event;
    let event = match event {
        ExecEvent::Stdout(data) => Event::Stdout(data),
        ExecEvent::Stderr(data) => Event::Stderr(data),
        ExecEvent::Exit(exit) => Event::Exit(pb::ExecExit {
            code: exit.code,
            timed_out: exit.timed_out,
            dropped_bytes: exit.dropped_bytes,
        }),
        other => return Err(invalid(format!("exec event {other:?} has no wire form"))),
    };
    Ok(pb::ExecResponse { event: Some(event) })
}

/// An `ExecResponse` to `ExecEvent`. An unset or unknown event is invalid.
pub fn exec_event_from_proto(response: pb::ExecResponse) -> Result<ExecEvent> {
    use pb::exec_response::Event;
    Ok(match response.event {
        Some(Event::Stdout(data)) => ExecEvent::Stdout(data),
        Some(Event::Stderr(data)) => ExecEvent::Stderr(data),
        Some(Event::Exit(exit)) => ExecEvent::Exit(ExecExit {
            code: exit.code,
            timed_out: exit.timed_out,
            dropped_bytes: exit.dropped_bytes,
        }),
        None => return Err(invalid("exec event: missing or unknown")),
    })
}

/// A workspace id and a `FindRequest` to the wire request.
pub fn find_request_to_proto(id: &WorkspaceId, request: FindRequest) -> pb::FindRequest {
    pb::FindRequest {
        workspace_id: id.to_string(),
        pattern: request.pattern,
        path: request.path.unwrap_or_default(),
        limit: request.limit,
    }
}

/// A wire `FindRequest` to its workspace id and `FindRequest`.
pub fn find_request_from_proto(request: pb::FindRequest) -> Result<(WorkspaceId, FindRequest)> {
    Ok((
        WorkspaceId::new(request.workspace_id)?,
        FindRequest {
            pattern: request.pattern,
            path: non_empty(request.path),
            limit: request.limit,
        },
    ))
}

/// `FindResult` to a `FindResponse`.
pub fn find_result_to_proto(result: FindResult) -> pb::FindResponse {
    pb::FindResponse {
        paths: result.paths,
        truncated: result.truncated,
    }
}

/// A `FindResponse` to `FindResult`.
pub fn find_result_from_proto(response: pb::FindResponse) -> FindResult {
    FindResult {
        paths: response.paths,
        truncated: response.truncated,
    }
}

/// A workspace id and a `GrepRequest` to the wire request.
pub fn grep_request_to_proto(id: &WorkspaceId, request: GrepRequest) -> pb::GrepRequest {
    pb::GrepRequest {
        workspace_id: id.to_string(),
        pattern: request.pattern,
        path: request.path.unwrap_or_default(),
        glob: request.glob,
        case_insensitive: request.case_insensitive,
        limit: request.limit,
    }
}

/// A wire `GrepRequest` to its workspace id and `GrepRequest`.
pub fn grep_request_from_proto(request: pb::GrepRequest) -> Result<(WorkspaceId, GrepRequest)> {
    Ok((
        WorkspaceId::new(request.workspace_id)?,
        GrepRequest {
            pattern: request.pattern,
            path: non_empty(request.path),
            glob: request.glob,
            case_insensitive: request.case_insensitive,
            limit: request.limit,
        },
    ))
}

/// `GrepResult` to a `GrepResponse`.
pub fn grep_result_to_proto(result: GrepResult) -> pb::GrepResponse {
    pb::GrepResponse {
        matches: result
            .matches
            .into_iter()
            .map(|m| pb::GrepMatch {
                path: m.path,
                line: m.line,
                text: m.text,
            })
            .collect(),
        truncated: result.truncated,
    }
}

/// A `GrepResponse` to `GrepResult`.
pub fn grep_result_from_proto(response: pb::GrepResponse) -> GrepResult {
    GrepResult {
        matches: response
            .matches
            .into_iter()
            .map(|m| GrepMatch {
                path: m.path,
                line: m.line,
                text: m.text,
            })
            .collect(),
        truncated: response.truncated,
    }
}

/// `ReadFile` to a `ReadFileResponse`.
pub fn read_file_to_proto(file: ReadFile) -> pb::ReadFileResponse {
    pb::ReadFileResponse {
        content: file.content,
        size: file.size,
    }
}

/// A `ReadFileResponse` to `ReadFile`.
pub fn read_file_from_proto(response: pb::ReadFileResponse) -> ReadFile {
    ReadFile {
        content: response.content,
        size: response.size,
    }
}

/// The `RelayOpen` message that starts a relay of workspace `id`.
pub fn relay_open_to_proto(id: &WorkspaceId) -> pb::RelayReply {
    pb::RelayReply {
        message: Some(pb::relay_reply::Message::Open(pb::RelayOpen {
            workspace_id: id.to_string(),
        })),
    }
}

/// The workspace a relay's first message opens. Anything but `open` is invalid.
pub fn relay_open_from_proto(first: pb::RelayReply) -> Result<WorkspaceId> {
    match first.message {
        Some(pb::relay_reply::Message::Open(open)) => {
            WorkspaceId::new(open.workspace_id).map_err(Into::into)
        }
        _ => Err(invalid("the first Relay message must be open")),
    }
}

/// A `RelayReply` to its wire message.
pub fn relay_reply_to_proto(reply: RelayReply) -> Result<pb::RelayReply> {
    let message = match reply {
        RelayReply::Agent(AgentReply {
            connection,
            message,
        }) => pb::relay_reply::Message::Agent(pb::AgentReply {
            connection,
            message,
        }),
        RelayReply::KnownHosts(KnownHostsReply { id, keys }) => {
            pb::relay_reply::Message::KnownHosts(pb::KnownHostsReply { id, keys })
        }
        other => return Err(invalid(format!("relay reply {other:?} has no wire form"))),
    };
    Ok(pb::RelayReply {
        message: Some(message),
    })
}

/// A wire `RelayReply` after the opening one to `RelayReply`. A second `open`, an unset or unknown
/// message, and a message longer than [`MAX_AGENT_MESSAGE`] are invalid.
pub fn relay_reply_from_proto(reply: pb::RelayReply) -> Result<RelayReply> {
    match reply.message {
        Some(pb::relay_reply::Message::Agent(reply)) => {
            check_agent_message(&reply.message)?;
            Ok(RelayReply::Agent(AgentReply {
                connection: reply.connection,
                message: reply.message,
            }))
        }
        Some(pb::relay_reply::Message::KnownHosts(reply)) => {
            if reply.keys.len() > MAX_KNOWN_HOST_KEYS {
                return Err(invalid(format!(
                    "a known-hosts reply of {} keys is over the {MAX_KNOWN_HOST_KEYS}-key limit",
                    reply.keys.len()
                )));
            }
            for key in &reply.keys {
                check_host_key(key)?;
            }
            Ok(RelayReply::KnownHosts(KnownHostsReply {
                id: reply.id,
                keys: reply.keys,
            }))
        }
        Some(pb::relay_reply::Message::Open(_)) => {
            Err(invalid("Relay: open is only the first message"))
        }
        None => Err(invalid("relay reply: missing or unknown")),
    }
}

/// A `RelayRequest` to its wire message.
pub fn relay_request_to_proto(request: RelayRequest) -> Result<pb::RelayRequest> {
    let message = match request {
        RelayRequest::Agent(AgentRequest {
            connection,
            message,
        }) => pb::relay_request::Message::Agent(pb::AgentRequest {
            connection,
            message,
        }),
        RelayRequest::AgentClosed(AgentClosed { connection }) => {
            pb::relay_request::Message::AgentClosed(pb::AgentClosed { connection })
        }
        RelayRequest::KnownHosts(KnownHostsRequest {
            id,
            host,
            port,
            key_type,
            key,
        }) => pb::relay_request::Message::KnownHosts(pb::KnownHostsRequest {
            id,
            host,
            port: u32::from(port),
            key_type,
            key,
        }),
        other => return Err(invalid(format!("relay request {other:?} has no wire form"))),
    };
    Ok(pb::RelayRequest {
        message: Some(message),
    })
}

/// A wire `RelayRequest` to `RelayRequest`. An unset or unknown message, and an agent message
/// longer than [`MAX_AGENT_MESSAGE`], are invalid.
pub fn relay_request_from_proto(request: pb::RelayRequest) -> Result<RelayRequest> {
    match request.message {
        Some(pb::relay_request::Message::Agent(request)) => {
            check_agent_message(&request.message)?;
            Ok(RelayRequest::Agent(AgentRequest {
                connection: request.connection,
                message: request.message,
            }))
        }
        Some(pb::relay_request::Message::AgentClosed(closed)) => {
            Ok(RelayRequest::AgentClosed(AgentClosed {
                connection: closed.connection,
            }))
        }
        Some(pb::relay_request::Message::KnownHosts(request)) => Ok(RelayRequest::KnownHosts(
            known_hosts_request_from_proto(request)?,
        )),
        None => Err(invalid("relay request: missing or unknown")),
    }
}

/// A wire `KnownHostsRequest` to `KnownHostsRequest`. A host over [`MAX_KNOWN_HOST`] bytes, a key
/// over [`MAX_HOST_KEY`], a port outside 1 to 65535, and a key without a type (or a type without a
/// key) are invalid.
fn known_hosts_request_from_proto(request: pb::KnownHostsRequest) -> Result<KnownHostsRequest> {
    if request.host.is_empty() || request.host.len() > MAX_KNOWN_HOST {
        return Err(invalid(format!(
            "a known-hosts host of {} bytes is empty or over the {MAX_KNOWN_HOST}-byte limit",
            request.host.len()
        )));
    }
    check_host_key(&request.key)?;
    if request.key_type.len() > MAX_KEY_TYPE {
        return Err(invalid("a known-hosts key type is too long"));
    }
    if request.key_type.is_empty() != request.key.is_empty() {
        return Err(invalid(
            "a known-hosts request has a key type or a key without the other",
        ));
    }
    Ok(KnownHostsRequest {
        id: request.id,
        host: request.host,
        port: port_from_proto(request.port)?,
        key_type: request.key_type,
        key: request.key,
    })
}

fn port_from_proto(port: u32) -> Result<u16> {
    u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid(format!("{port} is not a port")))
}

fn check_host_key(key: &[u8]) -> Result<()> {
    if key.len() > MAX_HOST_KEY {
        return Err(invalid(format!(
            "a host key of {} bytes is over the {MAX_HOST_KEY}-byte limit",
            key.len()
        )));
    }
    Ok(())
}

/// A workspace id and a host to scan to the wire request.
pub fn scan_host_key_request_to_proto(
    id: &WorkspaceId,
    host: &str,
    port: u16,
    key_type: &str,
) -> pb::ScanHostKeyRequest {
    pb::ScanHostKeyRequest {
        workspace_id: id.to_string(),
        host: host.to_owned(),
        port: u32::from(port),
        key_type: key_type.to_owned(),
    }
}

/// A wire `ScanHostKeyRequest` to the workspace, host, port, and key type to scan.
pub fn scan_host_key_request_from_proto(
    request: pb::ScanHostKeyRequest,
) -> Result<(WorkspaceId, String, u16, String)> {
    if request.host.is_empty() || request.host.len() > MAX_KNOWN_HOST {
        return Err(invalid("the host to scan is empty or too long"));
    }
    if request.key_type.is_empty() || request.key_type.len() > MAX_KEY_TYPE {
        return Err(invalid("the key type to scan is empty or too long"));
    }
    Ok((
        WorkspaceId::new(request.workspace_id)?,
        request.host,
        port_from_proto(request.port)?,
        request.key_type,
    ))
}

/// The scanned host key as a `ScanHostKeyResponse`.
pub fn scan_host_key_to_proto(key: Vec<u8>) -> pb::ScanHostKeyResponse {
    pb::ScanHostKeyResponse { key }
}

/// A `ScanHostKeyResponse` to the key. A key over [`MAX_HOST_KEY`] bytes is invalid.
pub fn scan_host_key_from_proto(response: pb::ScanHostKeyResponse) -> Result<Vec<u8>> {
    check_host_key(&response.key)?;
    Ok(response.key)
}

fn check_agent_message(message: &[u8]) -> Result<()> {
    if message.len() > MAX_AGENT_MESSAGE {
        return Err(invalid(format!(
            "an ssh-agent message of {} bytes is over the {MAX_AGENT_MESSAGE}-byte limit",
            message.len()
        )));
    }
    Ok(())
}

/// The longest SSH algorithm name a relay carries.
const MAX_KEY_TYPE: usize = 128;

/// The wire's empty string is a path that was left out.
fn non_empty(path: String) -> Option<String> {
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests {
    use doozers_types::{Error, Timestamp};

    use super::*;

    fn id(s: &str) -> WorkspaceId {
        WorkspaceId::new(s).unwrap()
    }

    fn workspace() -> Workspace {
        Workspace {
            id: id("ws-1"),
            description: "debian@sha256:abc".into(),
            working_directory: "/workspace".into(),
            persistence: "/workspace survives; the rest is reset".into(),
            created_at: "2026-11-10T12:00:00.5Z".parse::<Timestamp>().unwrap(),
            state: WorkspaceState::Running,
            disk_used_bytes: Some(0),
            details: vec![
                WorkspaceDetail::new("Image", "debian:stable"),
                WorkspaceDetail::new("Container", "doozers-main.ws-1"),
            ],
        }
    }

    #[test]
    fn relay_messages_round_trip() {
        let open = relay_open_to_proto(&id("ws-1"));
        assert_eq!(relay_open_from_proto(open.clone()).unwrap(), id("ws-1"));
        // `open` is only the first message.
        assert!(matches!(
            relay_reply_from_proto(open),
            Err(Error::InvalidRequest(_))
        ));

        let reply = RelayReply::Agent(AgentReply {
            connection: 7,
            message: vec![12, 0, 0, 0, 0],
        });
        let wire = relay_reply_to_proto(reply.clone()).unwrap();
        assert_eq!(relay_reply_from_proto(wire).unwrap(), reply);

        for request in [
            RelayRequest::Agent(AgentRequest {
                connection: 7,
                message: vec![11],
            }),
            RelayRequest::AgentClosed(AgentClosed { connection: 7 }),
            RelayRequest::KnownHosts(KnownHostsRequest {
                id: 3,
                host: "[git.example]:2222".into(),
                port: 2222,
                key_type: "ssh-ed25519".into(),
                key: vec![0, 0, 0, 11],
            }),
            // The preference-list call carries no key.
            RelayRequest::KnownHosts(KnownHostsRequest {
                id: 4,
                host: "git.example".into(),
                port: 22,
                key_type: String::new(),
                key: Vec::new(),
            }),
        ] {
            let wire = relay_request_to_proto(request.clone()).unwrap();
            assert_eq!(relay_request_from_proto(wire).unwrap(), request);
        }

        let reply = RelayReply::KnownHosts(KnownHostsReply {
            id: 3,
            keys: vec![vec![1, 2], vec![3]],
        });
        let wire = relay_reply_to_proto(reply.clone()).unwrap();
        assert_eq!(relay_reply_from_proto(wire).unwrap(), reply);
    }

    #[test]
    fn invalid_known_hosts_messages_are_refused() {
        let request = |edit: fn(&mut pb::KnownHostsRequest)| {
            let mut request = pb::KnownHostsRequest {
                id: 1,
                host: "git.example".into(),
                port: 22,
                key_type: "ssh-ed25519".into(),
                key: vec![1],
            };
            edit(&mut request);
            relay_request_from_proto(pb::RelayRequest {
                message: Some(pb::relay_request::Message::KnownHosts(request)),
            })
        };
        assert!(request(|_| {}).is_ok());
        assert!(request(|r| r.host.clear()).is_err());
        assert!(request(|r| r.host = "h".repeat(MAX_KNOWN_HOST + 1)).is_err());
        assert!(request(|r| r.port = 0).is_err());
        assert!(request(|r| r.port = 65536).is_err());
        assert!(request(|r| r.key = vec![0; MAX_HOST_KEY + 1]).is_err());
        assert!(request(|r| r.key_type.clear()).is_err());
        assert!(request(|r| r.key.clear()).is_err());
        assert!(request(|r| r.key_type = "k".repeat(MAX_KEY_TYPE + 1)).is_err());

        let reply = |keys: Vec<Vec<u8>>| {
            relay_reply_from_proto(pb::RelayReply {
                message: Some(pb::relay_reply::Message::KnownHosts(pb::KnownHostsReply {
                    id: 1,
                    keys,
                })),
            })
        };
        assert!(reply(vec![vec![0; MAX_HOST_KEY]; MAX_KNOWN_HOST_KEYS]).is_ok());
        assert!(reply(vec![Vec::new(); MAX_KNOWN_HOST_KEYS + 1]).is_err());
        assert!(reply(vec![vec![0; MAX_HOST_KEY + 1]]).is_err());
    }

    #[test]
    fn scan_host_key_messages_round_trip_and_refuse_bad_input() {
        let wire = scan_host_key_request_to_proto(&id("ws-1"), "git.example", 22, "ssh-ed25519");
        assert_eq!(
            scan_host_key_request_from_proto(wire.clone()).unwrap(),
            (
                id("ws-1"),
                "git.example".to_owned(),
                22,
                "ssh-ed25519".to_owned()
            )
        );
        for edit in [
            (|r: &mut pb::ScanHostKeyRequest| r.host.clear()) as fn(&mut _),
            |r| r.port = 0,
            |r| r.port = 70000,
            |r| r.key_type.clear(),
            |r| r.workspace_id = "Not Valid".into(),
        ] {
            let mut bad = wire.clone();
            edit(&mut bad);
            assert!(scan_host_key_request_from_proto(bad).is_err());
        }
        assert_eq!(
            scan_host_key_from_proto(scan_host_key_to_proto(vec![1, 2])).unwrap(),
            [1, 2]
        );
        assert!(
            scan_host_key_from_proto(scan_host_key_to_proto(vec![0; MAX_HOST_KEY + 1])).is_err()
        );
    }

    #[test]
    fn invalid_relay_messages_are_refused() {
        // The first message must be `open`, with a valid workspace id.
        for first in [
            pb::RelayReply { message: None },
            pb::RelayReply {
                message: Some(pb::relay_reply::Message::Agent(pb::AgentReply::default())),
            },
            pb::RelayReply {
                message: Some(pb::relay_reply::Message::Open(pb::RelayOpen {
                    workspace_id: "Not Valid".into(),
                })),
            },
        ] {
            assert!(relay_open_from_proto(first).is_err());
        }
        assert!(relay_reply_from_proto(pb::RelayReply { message: None }).is_err());
        assert!(relay_request_from_proto(pb::RelayRequest { message: None }).is_err());

        // An agent message may be 256 KiB, not more.
        let message = |len| pb::RelayRequest {
            message: Some(pb::relay_request::Message::Agent(pb::AgentRequest {
                connection: 1,
                message: vec![0; len],
            })),
        };
        assert!(relay_request_from_proto(message(MAX_AGENT_MESSAGE)).is_ok());
        assert!(relay_request_from_proto(message(MAX_AGENT_MESSAGE + 1)).is_err());
        let reply = pb::RelayReply {
            message: Some(pb::relay_reply::Message::Agent(pb::AgentReply {
                connection: 1,
                message: vec![0; MAX_AGENT_MESSAGE + 1],
            })),
        };
        assert!(relay_reply_from_proto(reply).is_err());
    }

    #[test]
    fn durations_round_trip_and_refuse_negatives() {
        for d in [
            Duration::ZERO,
            Duration::new(90, 500),
            Duration::from_secs(u32::MAX.into()),
        ] {
            assert_eq!(duration_from_proto(duration_to_proto(d)).unwrap(), d);
        }
        assert_eq!(
            duration_to_proto(Duration::MAX),
            prost_types::Duration {
                seconds: i64::MAX,
                nanos: 999_999_999
            }
        );
        for (seconds, nanos) in [(-1, 0), (1, -1), (0, 1_000_000_000)] {
            let error = duration_from_proto(prost_types::Duration { seconds, nanos });
            assert!(
                matches!(error, Err(Error::InvalidRequest(_))),
                "{seconds} {nanos}"
            );
        }
    }

    #[test]
    fn workspaces_round_trip() {
        let wire = workspace_to_proto(workspace()).unwrap();
        assert_eq!(wire.workspace_id, "ws-1");
        assert_eq!(wire.state(), pb::WorkspaceState::Running);
        assert_eq!(
            wire.details,
            vec![
                pb::WorkspaceDetail {
                    label: "Image".into(),
                    value: "debian:stable".into()
                },
                pb::WorkspaceDetail {
                    label: "Container".into(),
                    value: "doozers-main.ws-1".into()
                },
            ]
        );
        assert_eq!(workspace_from_proto(wire.clone()).unwrap(), workspace());

        let unknown_disk = Workspace {
            disk_used_bytes: None,
            details: Vec::new(),
            state: WorkspaceState::Stopped,
            ..workspace()
        };
        let wire = workspace_to_proto(unknown_disk.clone()).unwrap();
        assert_eq!(wire.disk_used_bytes, None);
        assert_eq!(workspace_from_proto(wire).unwrap(), unknown_disk);

        let list = WorkspaceList {
            workspaces: vec![workspace()],
            free_bytes: Some(10),
        };
        let wire = workspace_list_to_proto(list.clone()).unwrap();
        assert_eq!(workspace_list_from_proto(wire).unwrap(), list);
    }

    #[test]
    fn invalid_workspaces_are_refused() {
        let good = workspace_to_proto(workspace()).unwrap();
        let cases = [
            pb::Workspace {
                workspace_id: "Not Valid".into(),
                ..good.clone()
            },
            pb::Workspace {
                created_at: None,
                ..good.clone()
            },
            pb::Workspace {
                state: pb::WorkspaceState::Unspecified.into(),
                ..good.clone()
            },
            pb::Workspace { state: 99, ..good },
        ];
        for case in cases {
            assert!(workspace_from_proto(case.clone()).is_err(), "{case:?}");
        }
    }

    #[test]
    fn start_outcomes_round_trip() {
        for outcome in [
            StartOutcome::Running,
            StartOutcome::Started {
                detail: "was idle".into(),
            },
            StartOutcome::Recreated {
                detail: "packages are gone".into(),
            },
        ] {
            let wire = start_outcome_to_proto(outcome.clone()).unwrap();
            assert_eq!(start_outcome_from_proto(wire).unwrap(), outcome);
        }
        assert!(start_outcome_from_proto(pb::StartWorkspaceResponse::default()).is_err());
    }

    #[test]
    fn exec_requests_and_events_round_trip() {
        let request = ExecRequest {
            command: "make test".into(),
            timeout: Duration::from_secs(120),
            output_limit: 1 << 20,
        };
        let wire = exec_request_to_proto(&id("ws-1"), request.clone());
        assert_eq!(wire.workspace_id, "ws-1");
        assert_eq!(
            exec_request_from_proto(wire.clone()).unwrap(),
            (id("ws-1"), request)
        );
        let no_timeout = pb::ExecRequest {
            timeout: None,
            ..wire
        };
        assert!(exec_request_from_proto(no_timeout).is_err());

        for event in [
            ExecEvent::Stdout(b"out".to_vec()),
            ExecEvent::Stderr(b"err".to_vec()),
            ExecEvent::Exit(ExecExit {
                code: 137,
                timed_out: true,
                dropped_bytes: 5,
            }),
        ] {
            let wire = exec_event_to_proto(event.clone()).unwrap();
            assert_eq!(exec_event_from_proto(wire).unwrap(), event);
        }
        assert!(exec_event_from_proto(pb::ExecResponse::default()).is_err());
    }

    #[test]
    fn find_and_grep_map_an_empty_path_to_none() {
        let find = FindRequest {
            pattern: "**/*.rs".into(),
            path: None,
            limit: 100,
        };
        let wire = find_request_to_proto(&id("ws-1"), find.clone());
        assert_eq!(wire.path, "");
        assert_eq!(find_request_from_proto(wire).unwrap(), (id("ws-1"), find));

        let grep = GrepRequest {
            pattern: "todo".into(),
            path: Some("src".into()),
            glob: Some("*.rs".into()),
            case_insensitive: true,
            limit: 50,
        };
        let wire = grep_request_to_proto(&id("ws-1"), grep.clone());
        assert_eq!(wire.path, "src");
        assert_eq!(grep_request_from_proto(wire).unwrap(), (id("ws-1"), grep));

        let found = FindResult {
            paths: vec!["a.rs".into()],
            truncated: true,
        };
        assert_eq!(
            find_result_from_proto(find_result_to_proto(found.clone())),
            found
        );
        let matched = GrepResult {
            matches: vec![GrepMatch {
                path: "a.rs".into(),
                line: 3,
                text: "// TODO".into(),
            }],
            truncated: false,
        };
        assert_eq!(
            grep_result_from_proto(grep_result_to_proto(matched.clone())),
            matched
        );
        let file = ReadFile {
            content: b"hi".to_vec(),
            size: 10,
        };
        assert_eq!(read_file_from_proto(read_file_to_proto(file.clone())), file);
    }

    #[test]
    fn info_and_options_are_json() {
        let info = EnvironmentInfo {
            options_schema: serde_json::json!({"type": "object"}),
        };
        assert_eq!(info_from_proto(info_to_proto(&info)).unwrap(), info);
        assert!(info_from_proto(pb::InfoResponse::default()).is_err());

        assert_eq!(options_from_proto("").unwrap(), serde_json::json!({}));
        assert_eq!(
            options_from_proto(r#"{"image": "debian"}"#).unwrap(),
            serde_json::json!({"image": "debian"})
        );
        assert!(options_from_proto("[1]").is_err());
        assert!(options_from_proto("{").is_err());
    }
}
