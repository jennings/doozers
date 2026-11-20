//! Known SSH hosts (issue #138) in a real workspace: `ssh` asks the core, through the relay, which
//! host keys to trust, and the core answers with its own `KnownHosts` over a real store.
//!
//! The `sshd` container runs on the engine's default network next to the workspaces, which reach
//! it by address. The plugin scans from the engine host, which can't reach a container's address
//! through a VM (Docker Desktop, Podman machine), so the flow tests have the core verify first uses
//! with a stand-in that scans from inside the workspace (`support::ssh::WorkspaceScanner`), and the
//! plugin's own scan is tested against a port the `sshd` container publishes on the host's loopback.
//! Steps that need the network (installing OpenSSH, pulling an image) skip, saying why, when it is
//! missing; `DOOZERS_REQUIRE_DOCKER=1` turns the skip into a failure.

mod support;

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use doozers_core::ssh::KeyType;
use doozers_environment_docker::{Config, SSH_CONFIG_FILE};
use doozers_types::{
    Environment, EnvironmentInfo, Error, ExecEvent, ExecRequest, FindRequest, FindResult,
    GrepRequest, GrepResult, ReadFile, StartOutcome, UserId, Workspace, WorkspaceId, WorkspaceList,
};
use futures::stream::BoxStream;
use support::ssh::{Core, Sshd, network_failed, wait_for_socket, workspace_with};
use support::{Scope, harness, wid};

/// An environment whose scans see `key`, whatever the host really presents: a plugin that scanned
/// a different server than the workspace reached.
struct Scanning {
    key: Vec<u8>,
}

#[async_trait]
impl Environment for Scanning {
    async fn scan_host_key(
        &self,
        _id: &WorkspaceId,
        _host: &str,
        _port: u16,
        _key_type: &str,
    ) -> doozers_types::Result<Vec<u8>> {
        Ok(self.key.clone())
    }

    async fn info(&self) -> doozers_types::Result<EnvironmentInfo> {
        Err(unused())
    }
    async fn create_workspace(
        &self,
        _: &WorkspaceId,
        _: serde_json::Value,
    ) -> doozers_types::Result<Workspace> {
        Err(unused())
    }
    async fn delete_workspace(&self, _: &WorkspaceId) -> doozers_types::Result<()> {
        Err(unused())
    }
    async fn start_workspace(&self, _: &WorkspaceId) -> doozers_types::Result<StartOutcome> {
        Err(unused())
    }
    async fn stop_workspace(&self, _: &WorkspaceId) -> doozers_types::Result<()> {
        Err(unused())
    }
    async fn list_workspaces(&self) -> doozers_types::Result<WorkspaceList> {
        Err(unused())
    }
    async fn exec(
        &self,
        _: &WorkspaceId,
        _: ExecRequest,
    ) -> doozers_types::Result<BoxStream<'static, doozers_types::Result<ExecEvent>>> {
        Err(unused())
    }
    async fn read_file(&self, _: &WorkspaceId, _: &str, _: u64) -> doozers_types::Result<ReadFile> {
        Err(unused())
    }
    async fn write_file(&self, _: &WorkspaceId, _: &str, _: Vec<u8>) -> doozers_types::Result<()> {
        Err(unused())
    }
    async fn find(&self, _: &WorkspaceId, _: FindRequest) -> doozers_types::Result<FindResult> {
        Err(unused())
    }
    async fn grep(&self, _: &WorkspaceId, _: GrepRequest) -> doozers_types::Result<GrepResult> {
        Err(unused())
    }
}

fn unused() -> Error {
    Error::InvalidRequest("the test environment only scans".to_owned())
}

/// What is needed for most tests: an engine, a workspace with an OpenSSH client whose relay the
/// core answers, and an `sshd` container that accepts the owner's key. `None` after skipping.
struct Fixture {
    scope: Scope,
    core: Core,
    clock: Arc<dyn doozers_core::sessions::Clock>,
    sshd: Sshd,
    ssh: String,
}

impl Fixture {
    async fn new(name: &str) -> Option<Self> {
        Self::with_relay(name, true).await
    }

    /// Like [`new`](Self::new); without `relay` nothing answers the workspace's lookups.
    async fn with_relay(name: &str, relay: bool) -> Option<Self> {
        let harness = harness()?;
        let scope = harness.scope(name, harness.config()).await;
        let id = workspace_with(&scope, "one", "openssh-client").await?;
        let (mut core, clock) = Core::new().await;
        let key = core.generate(KeyType::Ed25519, "laptop").await;
        if relay {
            core.serve(&scope, clock.clone(), &id, Some(core.owner.clone()))
                .await;
            wait_for_socket(&scope, &id).await;
        }
        let sshd = match Sshd::start(
            harness.docker(),
            &format!("doozers-sshd-{}", scope.instance),
            &key.authorized_key(),
        )
        .await
        {
            Ok(sshd) => sshd,
            Err(reason) => {
                network_failed("starting an sshd container", &reason);
                return None;
            }
        };
        let ssh = format!("ssh -o BatchMode=yes -p 2222 tester@{}", sshd.address);
        Some(Self {
            scope,
            core,
            clock,
            sshd,
            ssh,
        })
    }

    /// A second workspace with its own relay, as another conversation's.
    async fn second_workspace(&mut self) -> Option<String> {
        let id = workspace_with(&self.scope, "two", "openssh-client").await?;
        self.core
            .serve(
                &self.scope,
                self.clock.clone(),
                &id,
                Some(self.core.owner.clone()),
            )
            .await;
        wait_for_socket(&self.scope, &id).await;
        Some(id)
    }

    /// Logs in from `workspace`: what ssh printed and whether it worked.
    async fn login(&self, workspace: &str) -> (bool, String) {
        let ran = self
            .scope
            .run(workspace, &format!("{} 'echo logged in' 2>&1", self.ssh))
            .await;
        (ran.code == 0, ran.stdout)
    }

    /// The SHA256 fingerprint of the host key `sshd` has for `type`, as `ssh-keygen -l` prints it.
    async fn fingerprint(&self, key_type: &str) -> String {
        let out = self
            .sshd
            .run(&format!(
                "ssh-keygen -lf /etc/ssh/ssh_host_{key_type}_key.pub"
            ))
            .await;
        out.split_whitespace().nth(1).unwrap_or_default().to_owned()
    }

    async fn rows(&self) -> Vec<doozers_core::ssh::KnownHost> {
        self.core.known_hosts.all().await.unwrap()
    }
}

#[tokio::test]
async fn first_use_records_the_host_and_other_workspaces_use_the_stored_key() {
    let Some(mut f) = Fixture::new("kh-first").await else {
        return;
    };
    assert!(f.rows().await.is_empty());

    let (ok, out) = f.login("one").await;
    assert!(ok, "{out}");
    assert_eq!(out.trim(), "logged in");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.environment, f.scope.instance);
    assert_eq!(row.host, f.sshd.address);
    assert_eq!(row.port, 2222);
    // `ssh` prefers the ed25519 key, and the row is the key the server really has.
    assert_eq!(row.key_type, "ssh-ed25519");
    assert_eq!(row.fingerprint, f.fingerprint("ed25519").await);
    assert_eq!(row.first_workspace.as_deref(), Some("one"));
    assert_eq!(row.first_agent.as_deref(), Some("jeeves"));
    assert_eq!(row.first_user.as_deref(), Some("owner"));
    assert!(row.added_by.is_none());

    // The workspace keeps no trace of the host: nothing in its own known_hosts files.
    let local = f
        .scope
        .run(
            "one",
            "cat ~/.ssh/known_hosts /etc/ssh/ssh_known_hosts 2>&1; echo done",
        )
        .await;
    assert!(!local.stdout.contains(&f.sshd.address), "{}", local.stdout);

    // Another workspace on the instance connects with the stored key: no new row.
    let Some(second) = f.second_workspace().await else {
        return;
    };
    let (ok, out) = f.login(&second).await;
    assert!(ok, "{out}");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].first_workspace.as_deref(), Some("one"));
    assert!(rows[0].last_used_at.is_some(), "the second use is stamped");
}

#[tokio::test]
async fn a_changed_host_key_is_refused_until_the_host_is_deleted() {
    let Some(f) = Fixture::new("kh-changed").await else {
        return;
    };
    let (ok, out) = f.login("one").await;
    assert!(ok, "{out}");
    let old = f.rows().await.remove(0);

    // The server's keys change.
    f.sshd.rotate_host_keys().await;
    let (ok, out) = f.login("one").await;
    assert!(!ok, "ssh trusted a key that isn't the stored one: {out}");
    assert!(
        out.contains("REMOTE HOST IDENTIFICATION HAS CHANGED"),
        "{out}"
    );
    assert!(out.contains("Host key verification failed"), "{out}");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1, "a refused key isn't recorded: {rows:?}");
    assert_eq!(rows[0].fingerprint, old.fingerprint);

    // An admin deletes the host, and the next connection records what it presents now.
    assert!(f.core.known_hosts.delete(old.id).await.unwrap());
    let (ok, out) = f.login("one").await;
    assert!(ok, "{out}");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_ne!(rows[0].fingerprint, old.fingerprint);
    assert_eq!(rows[0].fingerprint, f.fingerprint("ed25519").await);
}

#[tokio::test]
async fn a_pinned_key_is_trusted_before_first_use_and_a_wrong_pin_is_refused() {
    let Some(f) = Fixture::new("kh-pin").await else {
        return;
    };
    // The line an admin would paste: what `ssh-keyscan` prints for the server.
    let scanned = f
        .scope
        .run(
            "one",
            &format!(
                "ssh-keyscan -p 2222 -t ed25519 {} 2>/dev/null",
                f.sshd.address
            ),
        )
        .await;
    let line = scanned.stdout.trim().to_owned();
    assert!(line.contains("ssh-ed25519"), "{line}");
    let owner = UserId::new("owner").unwrap();

    // A key that isn't the server's is pinned first: the connection is refused, and nothing is
    // recorded over the pin.
    let wrong = {
        // Any other ed25519 host key line.
        let key = f
            .sshd
            .run("ssh-keygen -q -t ed25519 -N '' -f /tmp/wrong && cat /tmp/wrong.pub")
            .await;
        let mut fields = key.split_whitespace();
        let (kind, blob) = (fields.next().unwrap(), fields.next().unwrap());
        format!("[{}]:2222 {kind} {blob}", f.sshd.address)
    };
    f.core
        .known_hosts
        .pin(&owner, &f.scope.instance, &wrong)
        .await
        .unwrap();
    let (ok, out) = f.login("one").await;
    assert!(!ok, "{out}");
    assert!(out.contains("Host key verification failed"), "{out}");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].added_by, Some(owner.clone()));

    // Deleted and pinned right, the host is trusted without the workspace recording anything.
    f.core.known_hosts.delete(rows[0].id).await.unwrap();
    f.core
        .known_hosts
        .pin(&owner, &f.scope.instance, &line)
        .await
        .unwrap();
    let (ok, out) = f.login("one").await;
    assert!(ok, "{out}");
    let rows = f.rows().await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].first_workspace.is_none(), "still the pin");
    assert!(rows[0].last_used_at.is_some());
}

#[tokio::test]
async fn a_key_that_differs_from_the_plugins_scan_is_not_recorded() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("kh-liar", harness.config()).await;
    let Some(id) = workspace_with(&scope, "one", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    let key = core.generate(KeyType::Ed25519, "laptop").await;
    // The core is told the host's key is another one: a plugin that scanned a different server.
    let impostor = {
        // Another ed25519 key: the blob is the second field of its `authorized_keys` line.
        let other = core.generate(KeyType::Ed25519, "impostor").await;
        let blob = other
            .public_key
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        base64::engine::general_purpose::STANDARD
            .decode(blob)
            .unwrap()
    };
    core.serve_scanned(
        &scope,
        clock,
        &id,
        Some(core.owner.clone()),
        Arc::new(Scanning { key: impostor }),
    )
    .await;
    wait_for_socket(&scope, &id).await;
    let sshd = match Sshd::start(
        harness.docker(),
        &format!("doozers-sshd-{}", scope.instance),
        &key.authorized_key(),
    )
    .await
    {
        Ok(sshd) => sshd,
        Err(reason) => {
            network_failed("starting an sshd container", &reason);
            return;
        }
    };
    let ran = scope
        .run(
            &id,
            &format!(
                "ssh -o BatchMode=yes -p 2222 tester@{} true 2>&1",
                sshd.address
            ),
        )
        .await;
    assert_ne!(ran.code, 0, "{}", ran.stdout);
    assert!(
        ran.stdout.contains("Host key verification failed"),
        "{}",
        ran.stdout
    );
    assert!(core.known_hosts.all().await.unwrap().is_empty());
}

#[tokio::test]
async fn ssh_fails_closed_when_nothing_answers_the_relay() {
    // No relay at all: the helper's socket doesn't exist, so the known-hosts command fails at
    // once and `ssh` refuses the host, instead of trusting it or waiting.
    let Some(f) = Fixture::with_relay("kh-closed", false).await else {
        return;
    };
    let started = std::time::Instant::now();
    let (ok, out) = f.login("one").await;
    assert!(!ok, "{out}");
    assert!(
        !out.contains("Permission denied"),
        "ssh went on to log in: {out}"
    );
    // `ssh` gives up on the host as soon as its KnownHostsCommand fails.
    assert!(out.contains("KnownHostsCommand failed"), "{out}");
    assert!(out.contains("refusing the connection"), "{out}");
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    assert!(f.rows().await.is_empty());
}

/// The images the issue names, with how to install an OpenSSH client in each.
const IMAGES: [(&str, &str); 4] = [
    (
        "debian:12",
        "apt-get update >/dev/null && apt-get install -y openssh-client >/dev/null",
    ),
    (
        "ubuntu:24.04",
        "apt-get update >/dev/null && apt-get install -y openssh-client >/dev/null",
    ),
    (
        "alpine:3.20",
        "apk add --no-cache openssh-client >/dev/null",
    ),
    ("fedora:41", "dnf install -y openssh-clients >/dev/null"),
];

#[tokio::test]
async fn every_allowed_base_image_reads_the_ssh_configuration_the_plugin_writes() {
    let Some(harness) = harness() else { return };
    let mut config: Config = harness.config();
    config.images.push("fedora:*".to_owned());
    for (n, (image, install)) in IMAGES.into_iter().enumerate() {
        let scope = harness.scope(&format!("kh-img{n}"), config.clone()).await;
        let id = format!("img{n}");
        // Pulling an image the engine lacks needs the network.
        if let Err(error) = scope
            .env
            .create_workspace(&wid(&id), serde_json::json!({ "image": image }))
            .await
        {
            network_failed(
                &format!("creating a workspace from {image}"),
                &error.to_string(),
            );
            continue;
        }
        // The file is there before any client is.
        let file = scope.run(&id, &format!("cat {SSH_CONFIG_FILE}")).await;
        assert_eq!(file.code, 0, "{image}: {}{}", file.stdout, file.stderr);
        assert_eq!(
            file.stdout,
            doozers_environment_docker::SSH_CONFIG,
            "{image}"
        );

        let installed = scope.run(&id, install).await;
        if installed.code != 0 {
            network_failed(
                &format!("installing an OpenSSH client in {image}"),
                &format!("{}{}", installed.stdout, installed.stderr),
            );
            continue;
        }
        // The client's own configuration includes the directory, so its answers show the file's
        // settings.
        let effective = scope.run(&id, "ssh -G example.com 2>&1").await;
        assert_eq!(effective.code, 0, "{image}: {}", effective.stdout);
        for expected in [
            "knownhostscommand /.doozers/bin/doozers-workspace-helper known-hosts %H %p %t %K",
            "userknownhostsfile /dev/null",
            "globalknownhostsfile /dev/null",
            "stricthostkeychecking true",
        ] {
            assert!(
                effective.stdout.lines().any(|l| l == expected),
                "{image}: no {expected:?} in\n{}",
                effective.stdout
            );
        }

        // Where an image's `ssh_config` doesn't include the directory, the plugin adds the line
        // when the container starts again. Take it out, restart, and ask again.
        let stripped = scope
            .run(
                &id,
                "sed -i '/^[[:space:]]*Include/d' /etc/ssh/ssh_config && ! ssh -G example.com | grep -q '^knownhostscommand'",
            )
            .await;
        assert_eq!(
            stripped.code, 0,
            "{image}: {}{}",
            stripped.stdout, stripped.stderr
        );
        scope.env.stop_workspace(&wid(&id)).await.unwrap();
        scope.env.start_workspace(&wid(&id)).await.unwrap();
        let again = scope.run(&id, "ssh -G example.com").await;
        assert!(
            again
                .stdout
                .contains("knownhostscommand /.doozers/bin/doozers-workspace-helper"),
            "{image}: the Include wasn't added back:\n{}",
            again.stdout
        );
        let count = scope
            .run(
                &id,
                "grep -c '^Include /etc/ssh/ssh_config.d/' /etc/ssh/ssh_config",
            )
            .await;
        assert_eq!(count.stdout.trim(), "1", "{image}");
        // And starting again doesn't add it twice.
        scope.env.stop_workspace(&wid(&id)).await.unwrap();
        scope.env.start_workspace(&wid(&id)).await.unwrap();
        let count = scope
            .run(
                &id,
                "grep -c '^Include /etc/ssh/ssh_config.d/' /etc/ssh/ssh_config",
            )
            .await;
        assert_eq!(count.stdout.trim(), "1", "{image}");
        scope.env.delete_workspace(&wid(&id)).await.unwrap();
    }
}

#[tokio::test]
async fn the_plugin_scans_the_host_keys_of_a_server_it_can_reach() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("kh-scan", harness.config()).await;
    let id = scope.workspace("one").await;
    let (core, _clock) = Core::new().await;
    let key = core
        .generate(KeyType::Ed25519, "laptop")
        .await
        .authorized_key();
    let sshd = match Sshd::start(
        harness.docker(),
        &format!("doozers-sshd-{}", scope.instance),
        &key,
    )
    .await
    {
        Ok(sshd) => sshd,
        Err(reason) => {
            network_failed("starting an sshd container", &reason);
            return;
        }
    };
    // The key the plugin scans is the one in the server's files, for each type the scan asks for.
    for (kind, file) in [
        ("ssh-ed25519", "ed25519"),
        ("ecdsa-sha2-nistp256", "ecdsa"),
        ("ssh-rsa", "rsa"),
    ] {
        let line = sshd
            .run(&format!("cat /etc/ssh/ssh_host_{file}_key.pub"))
            .await;
        let blob = line.split_whitespace().nth(1).unwrap();
        let expected = base64::engine::general_purpose::STANDARD
            .decode(blob)
            .unwrap();
        let scanned = scope
            .env
            .scan_host_key(&wid(&id), "127.0.0.1", sshd.published_port, kind)
            .await
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
        assert_eq!(scanned, expected, "{kind}");
    }

    // A key type the scan can't ask for, a closed port, and a workspace that doesn't exist.
    let error = scope
        .env
        .scan_host_key(&wid(&id), "127.0.0.1", sshd.published_port, "ssh-dss")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let error = scope
        .env
        .scan_host_key(&wid(&id), "127.0.0.1", closed, "ssh-ed25519")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unavailable { .. }), "{error:?}");
    let error = scope
        .env
        .scan_host_key(
            &wid("nothing"),
            "127.0.0.1",
            sshd.published_port,
            "ssh-ed25519",
        )
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");
}
