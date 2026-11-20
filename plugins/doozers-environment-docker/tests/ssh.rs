//! SSH from a workspace, through the ssh-agent relay answered by the core's own agent
//! (`doozers_core::ssh::Agent`) over keys in a real secret store.
//!
//! `ssh-keygen -Y sign` signs through the agent socket with no network, once `openssh-client` is
//! installed in the workspace. The `sshd` test starts a second container on the same engine
//! network, running `sshd` with the key's public half in `authorized_keys`, and logs in to it with
//! `ssh -o StrictHostKeyChecking=accept-new`.
//!
//! The tests skip, saying why, when no Docker API socket answers or the engine can't reach the
//! network to install packages. `DOOZERS_REQUIRE_DOCKER=1` turns both into failures: the harness
//! has pulled its image by then, so the engine has a network.

mod support;

use std::sync::Arc;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder,
};
use doozers_core::paths::DataRoot;
use doozers_core::secrets::{KeyFile, LocalSecrets, SecretPath, SecretProvider};
use doozers_core::sessions::{Clock, SystemClock};
use doozers_core::ssh::{Agent, KeyType, SshKey, SshKeys};
use doozers_environment_docker::SSH_AGENT_SOCKET;
use doozers_store::Store;
use doozers_types::{AgentReply, Environment, RelayReply, RelayRequest, UserId};
use futures::StreamExt;
use support::{IMAGE, Scope, harness, wid};

/// Whether a step that needs the network must work, instead of skipping the test.
fn network_required() -> bool {
    std::env::var("DOOZERS_REQUIRE_DOCKER").is_ok_and(|value| !value.is_empty())
}

/// Ends the test for a network step that failed: a skip with the reason, or a failure when the
/// network is required.
fn network_failed(what: &str, detail: &str) {
    assert!(
        !network_required(),
        "DOOZERS_REQUIRE_DOCKER is set, but {what} failed: {detail}"
    );
    eprintln!("skipping: {what} failed (no network?): {detail}");
}

/// The core's side: keys in a secret store, and the agent answering one workspace's relay.
struct Core {
    _dir: tempfile::TempDir,
    owner: UserId,
    keys: SshKeys,
    secrets: Arc<LocalSecrets>,
    relay: tokio::task::JoinHandle<()>,
}

impl Core {
    /// A secret store and keys service in a temporary directory.
    async fn new() -> (Self, Arc<dyn Clock>) {
        let dir = tempfile::tempdir().unwrap();
        let root = DataRoot::new(dir.path(), dir.path()).unwrap();
        let store = Store::open(dir.path().join("doozers.db")).await.unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let secrets = Arc::new(
            LocalSecrets::open(
                store.clone(),
                &KeyFile::new(&root, &root.secret_key_file()),
                clock.clone(),
            )
            .await
            .unwrap(),
        );
        let keys = SshKeys::new(store, secrets.clone(), clock.clone());
        let core = Self {
            _dir: dir,
            owner: UserId::new("owner").unwrap(),
            keys,
            secrets,
            relay: tokio::spawn(async {}),
        };
        (core, clock)
    }

    async fn generate(&self, kind: KeyType, label: &str) -> SshKey {
        self.keys
            .generate(&self.owner, kind, Some(label))
            .await
            .unwrap()
    }

    /// Opens the relay of workspace `id` and answers it with an agent for `user`, as the core's
    /// relay task does.
    async fn serve(
        &mut self,
        scope: &Scope,
        clock: Arc<dyn Clock>,
        id: &str,
        user: Option<UserId>,
    ) {
        let mut agent = Agent::new(self.keys.clone(), clock, wid(id), user);
        let (replies, incoming) = futures::channel::mpsc::unbounded::<RelayReply>();
        let mut requests = scope
            .env
            .relay(&wid(id), incoming.boxed())
            .await
            .expect("opening the relay");
        self.relay.abort();
        self.relay = tokio::spawn(async move {
            while let Some(Ok(request)) = requests.next().await {
                match request {
                    RelayRequest::Agent(request) => {
                        let message = agent.handle(request.connection, &request.message).await;
                        let reply = RelayReply::Agent(AgentReply {
                            connection: request.connection,
                            message,
                        });
                        if replies.unbounded_send(reply).is_err() {
                            break;
                        }
                    }
                    RelayRequest::AgentClosed(closed) => agent.close(closed.connection),
                    _ => {}
                }
            }
        });
    }

    /// The private key text of `key`, as the secret store holds it.
    async fn private_key(&self, key: &SshKey) -> String {
        let path = SecretPath::new(format!("users/{}/ssh-keys/{}", key.user, key.id)).unwrap();
        self.secrets
            .get(&path)
            .await
            .unwrap()
            .expect("the key's secret")
            .expose()
            .to_owned()
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

/// A workspace with an OpenSSH client with `packages` installed, or `None` after skipping.
async fn workspace_with(scope: &Scope, id: &str, packages: &str) -> Option<String> {
    let id = scope.workspace(id).await;
    let installed = scope
        .run(&id, &format!("apk add --no-cache {packages} 2>&1"))
        .await;
    if installed.code != 0 {
        network_failed(
            &format!("installing {packages} in the workspace"),
            installed.stdout.trim(),
        );
        return None;
    }
    Some(id)
}

/// Waits until the helper's socket is there.
async fn wait_for_socket(scope: &Scope, id: &str) {
    let probe = format!("test -S {SSH_AGENT_SOCKET}");
    for _ in 0..100 {
        if scope.run(id, &probe).await.code == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the agent socket never appeared");
}

#[tokio::test]
async fn ssh_keygen_signs_through_the_agent_and_no_private_key_is_in_the_workspace() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-sign", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-sign", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    let ed25519 = core.generate(KeyType::Ed25519, "laptop").await;
    let ecdsa = core.generate(KeyType::EcdsaP256, "ci").await;
    let rsa = core.generate(KeyType::Rsa3072, "legacy").await;
    // Another user's key is in the store too, and is never offered.
    let other = UserId::new("alice").unwrap();
    core.keys
        .generate(&other, KeyType::Ed25519, Some("alices"))
        .await
        .unwrap();
    core.serve(&scope, clock, &id, Some(core.owner.clone()))
        .await;
    wait_for_socket(&scope, &id).await;

    // The agent lists the user's keys, most recently used first.
    let listed = scope.run(&id, "ssh-add -L").await;
    assert_eq!(listed.code, 0, "{}{}", listed.stdout, listed.stderr);
    let comments: Vec<&str> = listed
        .stdout
        .lines()
        .map(|line| line.split(' ').nth(2).unwrap())
        .collect();
    assert_eq!(comments, ["legacy", "ci", "laptop"], "{}", listed.stdout);
    assert!(!listed.stdout.contains("alices"));

    // `ssh-keygen -Y sign` signs through the agent for each key type, and the signature checks out
    // against the public key.
    scope
        .env
        .write_file(&wid(&id), "/tmp/message", b"sign this\n".to_vec())
        .await
        .unwrap();
    for key in [&ed25519, &ecdsa, &rsa] {
        let public = key.authorized_key();
        scope
            .env
            .write_file(
                &wid(&id),
                "/tmp/key.pub",
                format!("{public}\n").into_bytes(),
            )
            .await
            .unwrap();
        scope
            .env
            .write_file(
                &wid(&id),
                "/tmp/allowed",
                format!("owner@doozers namespaces=\"file\" {}\n", key.public_key).into_bytes(),
            )
            .await
            .unwrap();
        let command = "rm -f /tmp/message.sig && \
                       ssh-keygen -Y sign -f /tmp/key.pub -n file /tmp/message && \
                       ssh-keygen -Y verify -f /tmp/allowed -I owner@doozers -n file \
                           -s /tmp/message.sig < /tmp/message";
        let ran = scope.run(&id, command).await;
        assert_eq!(
            ran.code, 0,
            "{} {}{}",
            key.type_label, ran.stdout, ran.stderr
        );
        assert!(
            ran.stdout.contains("Good \"file\" signature"),
            "{}",
            ran.stdout
        );
    }
    // Each signature stamped its key.
    for key in [&ed25519, &ecdsa, &rsa] {
        let used = core.keys.get(&core.owner, key.id).await.unwrap();
        assert!(used.last_used_at.is_some(), "{} was not used", key.label);
    }

    // Another user's key can't be signed with, though its public key is at hand.
    let alices = core.keys.list(&other).await.unwrap().remove(0);
    scope
        .env
        .write_file(
            &wid(&id),
            "/tmp/alice.pub",
            format!("{}\n", alices.authorized_key()).into_bytes(),
        )
        .await
        .unwrap();
    let refused = scope
        .run(
            &id,
            "ssh-keygen -Y sign -f /tmp/alice.pub -n file /tmp/message",
        )
        .await;
    assert_ne!(refused.code, 0, "{}{}", refused.stdout, refused.stderr);

    // No private key material is in the container: not in a file, its environment, or its
    // configuration.
    for key in [&ed25519, &ecdsa, &rsa] {
        let pem = core.private_key(key).await;
        let body = pem.lines().nth(1).expect("a PEM body line").to_owned();
        let found = scope
            .run(
                &id,
                &format!(
                    "grep -rlF -e '{body}' / --exclude-dir=proc --exclude-dir=sys \
                     --exclude-dir=dev 2>/dev/null; echo done"
                ),
            )
            .await;
        assert_eq!(
            found.stdout.trim(),
            "done",
            "key material in {}",
            found.stdout
        );
        let container = scope
            .docker
            .inspect_container(&format!("doozers-{}.{id}", scope.instance), None)
            .await
            .unwrap();
        let config = serde_json::to_string(&container).unwrap();
        assert!(
            !config.contains(&body),
            "key material in the container's configuration"
        );
    }
    let leaked = scope
        .run(&id, "grep -rl 'PRIVATE KEY' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null; echo done")
        .await;
    assert_eq!(leaked.stdout.trim(), "done", "{}", leaked.stdout);

    // A deleted key stops working at once, and the others go on.
    core.keys.delete(&core.owner, ecdsa.id).await.unwrap();
    let listed = scope.run(&id, "ssh-add -L").await;
    assert!(!listed.stdout.contains(" ci"), "{}", listed.stdout);
    assert!(listed.stdout.contains("laptop"), "{}", listed.stdout);
}

#[tokio::test]
async fn a_workspace_without_a_key_user_sees_an_agent_with_no_keys() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-none", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-none", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    core.generate(KeyType::Ed25519, "laptop").await;
    core.serve(&scope, clock, &id, None).await;
    wait_for_socket(&scope, &id).await;
    let listed = scope.run(&id, "ssh-add -L").await;
    assert_ne!(listed.code, 0);
    assert!(
        listed.stdout.contains("The agent has no identities"),
        "{}{}",
        listed.stdout,
        listed.stderr
    );
}

/// A container running `sshd` that accepts one key for the user `tester`. Removed when dropped.
struct Sshd {
    docker: Docker,
    name: String,
    address: String,
}

impl Sshd {
    /// Starts it and waits until it listens; `Err` says what went wrong (an install that
    /// failed, usually for lack of network).
    async fn start(docker: Docker, name: &str, authorized_key: &str) -> Result<Self, String> {
        let script = format!(
            "set -e\n\
             apk add --no-cache openssh >/dev/null\n\
             ssh-keygen -A >/dev/null\n\
             adduser -D tester\n\
             echo \"tester:$(head -c 18 /dev/urandom | base64)\" | chpasswd\n\
             mkdir -p /home/tester/.ssh\n\
             echo '{authorized_key}' > /home/tester/.ssh/authorized_keys\n\
             chown -R tester:tester /home/tester/.ssh\n\
             chmod 700 /home/tester/.ssh\n\
             chmod 600 /home/tester/.ssh/authorized_keys\n\
             exec /usr/sbin/sshd -D -e -p 2222 -o PasswordAuthentication=no \
                 -o KbdInteractiveAuthentication=no\n"
        );
        let body = ContainerCreateBody {
            image: Some(IMAGE.to_owned()),
            cmd: Some(vec!["sh".to_owned(), "-c".to_owned(), script]),
            host_config: Some(HostConfig {
                network_mode: Some("bridge".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(name).build()),
                body,
            )
            .await
            .map_err(|e| format!("creating the sshd container: {e}"))?;
        let mut sshd = Self {
            docker,
            name: name.to_owned(),
            address: String::new(),
        };
        sshd.docker
            .start_container(name, None)
            .await
            .map_err(|e| format!("starting the sshd container: {e}"))?;
        for _ in 0..180 {
            let inspected = sshd
                .docker
                .inspect_container(name, None)
                .await
                .map_err(|e| format!("inspecting the sshd container: {e}"))?;
            let running = inspected
                .state
                .as_ref()
                .and_then(|state| state.running)
                .unwrap_or(false);
            if !running {
                return Err(format!(
                    "the sshd container stopped: {}",
                    sshd.logs().await.trim()
                ));
            }
            if sshd.logs().await.contains("Server listening") {
                sshd.address = inspected
                    .network_settings
                    .and_then(|settings| settings.networks)
                    .and_then(|networks| {
                        networks
                            .into_values()
                            .filter_map(|network| network.ip_address)
                            .find(|address| !address.is_empty())
                    })
                    .ok_or("the sshd container has no address")?;
                return Ok(sshd);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("sshd never listened: {}", sshd.logs().await.trim()))
    }

    async fn logs(&self) -> String {
        let options = LogsOptionsBuilder::default()
            .stdout(true)
            .stderr(true)
            .build();
        let mut stream = self.docker.logs(&self.name, Some(options));
        let mut text = String::new();
        while let Some(Ok(chunk)) = stream.next().await {
            text.push_str(&chunk.to_string());
        }
        text
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let docker = self.docker.clone();
        let name = self.name.clone();
        // A runtime of its own: this may run while the test's runtime is shutting down.
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let options = RemoveContainerOptionsBuilder::default().force(true).build();
                let _ = docker.remove_container(&name, Some(options)).await;
            });
        })
        .join();
    }
}

#[tokio::test]
async fn ssh_logs_in_to_an_sshd_container_with_a_key_that_never_enters_the_workspace() {
    let Some(harness) = harness() else { return };
    let scope = harness.scope("ssh-login", harness.config()).await;
    let Some(id) = workspace_with(&scope, "ssh-login", "openssh-client").await else {
        return;
    };
    let (mut core, clock) = Core::new().await;
    let key = core.generate(KeyType::Ed25519, "laptop").await;
    core.serve(&scope, clock, &id, Some(core.owner.clone()))
        .await;
    wait_for_socket(&scope, &id).await;

    let name = format!("doozers-sshd-{}", scope.instance);
    let sshd = match Sshd::start(harness.docker(), &name, &key.authorized_key()).await {
        Ok(sshd) => sshd,
        Err(reason) => {
            network_failed("starting an sshd container", &reason);
            return;
        }
    };
    let ssh = format!(
        "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -p 2222 tester@{}",
        sshd.address
    );

    // The agent signs for the login.
    assert_eq!(
        core.keys
            .get(&core.owner, key.id)
            .await
            .unwrap()
            .last_used_at,
        None
    );
    let login = scope
        .run(&id, &format!("{ssh} 'echo logged in as $(id -un)'"))
        .await;
    assert_eq!(login.code, 0, "{}{}", login.stdout, login.stderr);
    assert_eq!(login.stdout.trim(), "logged in as tester");
    assert!(
        core.keys
            .get(&core.owner, key.id)
            .await
            .unwrap()
            .last_used_at
            .is_some()
    );

    // A forwarded agent is refused: the server sees no keys, and can't use any to go further.
    let forwarded = scope
        .run(
            &id,
            &format!(
                "{} -A 'ssh-add -L; echo exit $?' 2>&1",
                ssh.replace("-o BatchMode=yes", "")
            ),
        )
        .await;
    assert!(
        forwarded.stdout.contains("The agent has no identities"),
        "{}{}",
        forwarded.stdout,
        forwarded.stderr
    );
    assert!(
        !forwarded.stdout.contains("ssh-ed25519"),
        "{}",
        forwarded.stdout
    );
    let onward = scope
        .run(
            &id,
            &format!(
                "{ssh} -A \"ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -p 2222 \
                 tester@127.0.0.1 true\" 2>&1"
            ),
        )
        .await;
    assert_ne!(onward.code, 0, "{}{}", onward.stdout, onward.stderr);
    assert!(
        onward.stdout.contains("Permission denied"),
        "{}",
        onward.stdout
    );

    // Deleting the key ends the logins at once.
    core.keys.delete(&core.owner, key.id).await.unwrap();
    let denied = scope.run(&id, &format!("{ssh} true 2>&1")).await;
    assert_ne!(denied.code, 0);
    assert!(
        denied.stdout.contains("Permission denied"),
        "{}",
        denied.stdout
    );
    drop(sshd);
}
