//! The ssh-agent relay against a real Docker API socket: the helper's `ssh-agent` socket inside a
//! workspace, `SSH_AUTH_SOCK`, and the plugin's frames, with the test standing in for the core.
//! Skips, saying why, when no socket answers (`DOOZERS_REQUIRE_DOCKER=1` fails instead) and when
//! the workspace can't install `openssh-client` (no network).

mod support;

use std::time::Duration;

use doozers_environment_docker::SSH_AGENT_SOCKET;
use doozers_types::{AgentReply, AgentRequest, Environment, Error, RelayReply, RelayRequest};
use futures::StreamExt;
use futures::channel::mpsc;
use futures::stream::BoxStream;
use support::{Scope, harness, wid};

/// A fixed Ed25519 public key (`ssh-keygen -lf`: `SHA256:4dNVUviGJdPawKAMQkQJXLcprk1cF6DUOy9xPm7qX9I`).
const KEY_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILraDJseV3LP1mHnzczxZr2oJAIfAV7gts9c1fgeL0S5 relay-test";
const KEY_BYTES: [u8; 32] = [
    186, 218, 12, 155, 30, 87, 114, 207, 214, 97, 231, 205, 204, 241, 102, 189, 168, 36, 2, 31, 1,
    94, 224, 182, 207, 92, 213, 248, 30, 47, 68, 185,
];

const WAIT: Duration = Duration::from_secs(30);

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `SSH2_AGENT_IDENTITIES_ANSWER` (12) listing the fixed key with the comment `relay-test`.
fn identities_answer() -> Vec<u8> {
    let mut blob = Vec::new();
    string(&mut blob, b"ssh-ed25519");
    string(&mut blob, &KEY_BYTES);
    let mut message = vec![12];
    message.extend_from_slice(&1u32.to_be_bytes());
    string(&mut message, &blob);
    string(&mut message, b"relay-test");
    message
}

/// A workspace with `openssh-client`, or `None` (after printing why) if it can't be installed.
async fn workspace_with_ssh(scope: &Scope, id: &str) -> Option<String> {
    let id = scope.workspace(id).await;
    let installed = scope
        .run(&id, "apk add --no-cache openssh-client 2>&1")
        .await;
    if installed.code != 0 {
        eprintln!(
            "skipping: can't install openssh-client in the workspace (no network?): {}",
            installed.stdout.trim()
        );
        return None;
    }
    Some(id)
}

type Requests = BoxStream<'static, doozers_types::Result<RelayRequest>>;

async fn open(scope: &Scope, id: &str) -> (mpsc::UnboundedSender<RelayReply>, Requests) {
    let (replies, incoming) = mpsc::unbounded();
    let requests = scope.env.relay(&wid(id), incoming.boxed()).await.unwrap();
    (replies, requests)
}

/// The next agent request, skipping closed notices.
async fn next_agent_request(requests: &mut Requests) -> Option<AgentRequest> {
    loop {
        match tokio::time::timeout(WAIT, requests.next())
            .await
            .expect("a relay event")
        {
            Some(Ok(RelayRequest::Agent(request))) => return Some(request),
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("the relay failed: {error}"),
            None => return None,
        }
    }
}

#[tokio::test]
async fn ssh_add_lists_the_keys_the_core_answers_with() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay", harness.config()).await;
    let Some(id) = workspace_with_ssh(&scope, "relay-ssh-add").await else {
        return;
    };

    // Every command's environment has the socket, and anyone may use it.
    let (replies, mut requests) = open(&scope, &id).await;
    let env = scope.run(&id, "echo $SSH_AUTH_SOCK").await;
    assert_eq!(env.stdout.trim(), SSH_AGENT_SOCKET);

    let core = async {
        let request = next_agent_request(&mut requests).await.unwrap();
        // SSH_AGENTC_REQUEST_IDENTITIES.
        assert_eq!(request.message, [11]);
        replies
            .unbounded_send(RelayReply::Agent(AgentReply {
                connection: request.connection,
                message: identities_answer(),
            }))
            .unwrap();
    };
    let (ran, ()) = tokio::join!(
        scope.run(&id, "stat -c %a $SSH_AUTH_SOCK && ssh-add -L"),
        core
    );
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stdout, format!("666\n{KEY_LINE}\n"));

    // A client that sends nothing the core likes gets what the core says, here a failure.
    let core = async {
        let request = next_agent_request(&mut requests).await.unwrap();
        replies
            .unbounded_send(RelayReply::Agent(AgentReply {
                connection: request.connection,
                message: vec![5],
            }))
            .unwrap();
    };
    let (ran, ()) = tokio::join!(scope.run(&id, "ssh-add -L"), core);
    assert_ne!(ran.code, 0);

    // Stopping the workspace ends the relay.
    scope.env.stop_workspace(&wid(&id)).await.unwrap();
    let ended =
        tokio::time::timeout(WAIT, async { while requests.next().await.is_some() {} }).await;
    assert!(
        ended.is_ok(),
        "the relay stream didn't end when the workspace stopped"
    );
}

#[tokio::test]
async fn a_workspace_with_a_helper_from_before_the_relay_still_relays() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay-old-helper", harness.config()).await;
    let Some(id) = workspace_with_ssh(&scope, "relay-old-helper").await else {
        return;
    };

    // Put in the container's place a helper that predates `ssh-agent`: it runs commands, which is
    // all the old one did, and knows no other subcommand. It goes in by rename, because the
    // container's `idle` process is running the helper and a write would fail.
    const HELPER: &str = "/.doozers/bin/doozers-workspace-helper";
    let installed = scope
        .run(
            &id,
            &format!(
                "printf '%s\\n' '#!/bin/sh' 'if [ \"$1\" = run ]; then shift 4; exec \"$@\"; fi' \
                 'echo \"unknown subcommand $1\" >&2' 'exit 64' > /tmp/old-helper \
                 && chmod 755 /tmp/old-helper && mv -f /tmp/old-helper {HELPER}"
            ),
        )
        .await;
    assert_eq!(
        installed.code, 0,
        "{}{}",
        installed.stdout, installed.stderr
    );
    let old = scope.run(&id, &format!("{HELPER} ssh-agent")).await;
    assert_eq!(old.code, 64, "the stand-in helper isn't in place: {old:?}");

    // Opening the relay replaces it with the plugin's helper, and the agent works.
    let (replies, mut requests) = open(&scope, &id).await;
    let now = scope
        .run(
            &id,
            &format!("[ \"$(head -c 2 {HELPER})\" != '#!' ] && ls /.doozers/bin | wc -l"),
        )
        .await;
    assert_eq!(
        (now.code, now.stdout.trim()),
        (0, "1"),
        "the helper wasn't replaced cleanly: {now:?}"
    );
    let core = async {
        let request = next_agent_request(&mut requests).await.unwrap();
        assert_eq!(request.message, [11]);
        replies
            .unbounded_send(RelayReply::Agent(AgentReply {
                connection: request.connection,
                message: identities_answer(),
            }))
            .unwrap();
    };
    let (ran, ()) = tokio::join!(scope.run(&id, "ssh-add -L"), core);
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.stdout, format!("{KEY_LINE}\n"));
}

#[tokio::test]
async fn dropping_the_relay_removes_the_socket() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay-drop", harness.config()).await;
    let id = scope.workspace("relay-drop").await;
    let (replies, requests) = open(&scope, &id).await;
    let probe = format!("test -S {SSH_AGENT_SOCKET}");
    for _ in 0..50 {
        if scope.run(&id, &probe).await.code == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        scope.run(&id, &probe).await.code,
        0,
        "the socket never appeared"
    );

    drop(requests);
    drop(replies);
    let mut gone = false;
    for _ in 0..50 {
        if scope.run(&id, &probe).await.code != 0 {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        gone,
        "the helper kept its socket after the relay was dropped"
    );
    let helper = scope.run(&id, "ps -o args | grep -c '[s]sh-agent'").await;
    assert_eq!(helper.stdout.trim(), "0", "the helper is still running");
}

#[tokio::test]
async fn the_core_ending_its_replies_ends_the_relay() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay-end", harness.config()).await;
    let id = scope.workspace("relay-end").await;
    let (replies, mut requests) = open(&scope, &id).await;
    drop(replies);
    let end = tokio::time::timeout(WAIT, requests.next()).await.unwrap();
    assert!(end.is_none());
}

#[tokio::test]
async fn relaying_needs_a_running_workspace() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay-state", harness.config()).await;
    let missing = scope
        .env
        .relay(&wid("nothing-here"), futures::stream::pending().boxed())
        .await
        .err()
        .unwrap();
    assert!(matches!(missing, Error::NotFound(_)), "{missing:?}");

    let id = scope.workspace("relay-stopped").await;
    scope.env.stop_workspace(&wid(&id)).await.unwrap();
    let stopped = scope
        .env
        .relay(&wid(&id), futures::stream::pending().boxed())
        .await
        .err()
        .unwrap();
    assert!(matches!(stopped, Error::InvalidRequest(_)), "{stopped:?}");
}

#[tokio::test]
async fn the_container_environment_has_the_agent_socket() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("relay-env", harness.config()).await;
    let id = scope.workspace("relay-env").await;
    // Set when the container is created, and again for each command.
    let container = scope
        .docker
        .inspect_container(&format!("doozers-{}.{id}", scope.instance), None)
        .await
        .unwrap();
    let env = container.config.unwrap().env.unwrap();
    assert!(
        env.contains(&format!("SSH_AUTH_SOCK={SSH_AGENT_SOCKET}")),
        "{env:?}"
    );
    assert_eq!(
        scope.run(&id, "printenv SSH_AUTH_SOCK").await.stdout.trim(),
        SSH_AGENT_SOCKET
    );
}
