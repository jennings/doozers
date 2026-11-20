//! The lookup cases of [`KnownHosts`] against a fake environment that scans what the test says.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use doozers_store::Store;
use ssh_key::HashAlg;
use tempfile::TempDir;

use super::*;
use crate::ssh::KeyType;
use crate::ssh::keys;
use crate::workspaces::fake::{Fake, Scan, TestClock};

const WAIT: Duration = Duration::from_secs(10);

/// An SSH public key blob of a fresh Ed25519 key, and its base64 and fingerprint.
struct Key {
    blob: Vec<u8>,
}

impl Key {
    fn ed25519() -> Self {
        Self::of(KeyType::Ed25519)
    }

    fn of(kind: KeyType) -> Self {
        let private = keys::generate(kind).unwrap();
        Self {
            blob: private.public_key().to_bytes().unwrap(),
        }
    }

    fn base64(&self) -> String {
        STANDARD.encode(&self.blob)
    }

    fn fingerprint(&self) -> String {
        PublicKey::from_bytes(&self.blob)
            .unwrap()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    fn key_type(&self) -> String {
        PublicKey::from_bytes(&self.blob)
            .unwrap()
            .algorithm()
            .as_str()
            .to_owned()
    }

    /// A `known_hosts` line for `hosts`.
    fn line(&self, hosts: &str) -> String {
        format!("{hosts} {} {} a comment", self.key_type(), self.base64())
    }
}

/// Collects what `tracing` logs.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;

    fn make_writer(&'a self) -> Logs {
        self.clone()
    }
}

impl Logs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Gives the process a subscriber that discards everything. Without one, a log call another test
/// makes while no subscriber is set can leave its call site disabled for the test that captures
/// the log.
fn discard_logs_by_default() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(io::sink)
                .with_max_level(tracing::Level::TRACE)
                .finish(),
        );
    });
}

struct Setup {
    _dir: TempDir,
    clock: Arc<TestClock>,
    hosts: KnownHosts,
    env: Arc<Fake>,
}

impl Setup {
    async fn new() -> Self {
        discard_logs_by_default();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("doozers.db")).await.unwrap();
        let clock = TestClock::new();
        let hosts = KnownHosts::new(store.clone(), clock.clone());
        let env = Fake::new(clock.clone());
        Self {
            _dir: dir,
            clock,
            hosts,
            env,
        }
    }

    fn caller(&self) -> Caller {
        Caller {
            environment: "docker".to_owned(),
            workspace: WorkspaceId::new("ws-1").unwrap(),
            agent: Some("jeeves".to_owned()),
            user: Some(UserId::new("owner").unwrap()),
        }
    }

    /// A lookup of `host` (as `ssh` writes `%H`) on `port` offering `key`, or asking for the
    /// stored keys when `key` is `None`.
    async fn lookup(&self, host: &str, port: u16, key: Option<&Key>) -> Vec<Vec<u8>> {
        self.lookup_as(&self.caller(), host, port, key).await
    }

    async fn lookup_as(
        &self,
        caller: &Caller,
        host: &str,
        port: u16,
        key: Option<&Key>,
    ) -> Vec<Vec<u8>> {
        let request = KnownHostsRequest {
            id: 1,
            host: host.to_owned(),
            port,
            key_type: key.map(Key::key_type).unwrap_or_default(),
            key: key.map(|key| key.blob.clone()).unwrap_or_default(),
        };
        self.hosts.lookup(self.env.as_ref(), caller, &request).await
    }

    /// The scan of `host`:`port` finds `key`.
    fn scans(&self, host: &str, port: u16, key: &Key) {
        self.env
            .scan_returns(host, port, Scan::Key(key.blob.clone()));
    }

    async fn rows(&self) -> Vec<KnownHost> {
        self.hosts.all().await.unwrap()
    }
}

fn user(name: &str) -> UserId {
    UserId::new(name).unwrap()
}

#[tokio::test]
async fn a_first_use_the_environment_confirms_is_recorded_and_trusted() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("github.com", 22, &key);

    let keys = setup.lookup("github.com", 22, Some(&key)).await;
    assert_eq!(keys, vec![key.blob.clone()]);

    let rows = setup.rows().await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.environment, "docker");
    assert_eq!(row.host, "github.com");
    assert_eq!(row.port, 22);
    assert_eq!(row.key_type, "ssh-ed25519");
    assert_eq!(row.public_key, key.base64());
    assert_eq!(row.fingerprint, key.fingerprint());
    assert_eq!(row.first_seen_at, setup.clock.now());
    assert_eq!(row.first_workspace.as_deref(), Some("ws-1"));
    assert_eq!(row.first_agent.as_deref(), Some("jeeves"));
    assert_eq!(row.first_user.as_deref(), Some("owner"));
    assert_eq!(row.added_by, None);
    assert_eq!(row.last_used_at, None);

    // The plugin was asked to scan, once, from the workspace, for the key type offered.
    assert_eq!(
        setup.env.scans(),
        [(
            WorkspaceId::new("ws-1").unwrap(),
            "github.com".to_owned(),
            22,
            "ssh-ed25519".to_owned()
        )]
    );
}

#[tokio::test]
async fn a_first_use_records_nothing_the_first_agent_or_user_doesnt_have() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("github.com", 22, &key);
    let caller = Caller {
        agent: None,
        user: None,
        ..setup.caller()
    };
    setup.lookup_as(&caller, "github.com", 22, Some(&key)).await;
    let row = &setup.rows().await[0];
    assert_eq!(row.first_workspace.as_deref(), Some("ws-1"));
    assert_eq!(row.first_agent, None);
    assert_eq!(row.first_user, None);
}

#[tokio::test]
async fn a_key_that_differs_from_the_scan_is_not_recorded() {
    let setup = Setup::new().await;
    let offered = Key::ed25519();
    let scanned = Key::ed25519();
    setup.scans("github.com", 22, &scanned);

    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let keys = {
        let _guard = tracing::subscriber::set_default(subscriber);
        setup.lookup("github.com", 22, Some(&offered)).await
    };
    assert!(keys.is_empty());
    assert!(setup.rows().await.is_empty());
    let logged = logs.text();
    assert!(logged.contains("WARN"), "{logged}");
    assert!(logged.contains("differs"), "{logged}");
    assert!(logged.contains(&offered.fingerprint()), "{logged}");
    assert!(logged.contains(&scanned.fingerprint()), "{logged}");
}

#[tokio::test]
async fn a_scan_that_fails_records_nothing() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    // No scan result is set: the fake can't reach the host.
    assert!(setup.lookup("github.com", 22, Some(&key)).await.is_empty());
    assert!(setup.rows().await.is_empty());
}

#[tokio::test]
async fn a_scan_that_takes_too_long_records_nothing() {
    let mut setup = Setup::new().await;
    setup.hosts = setup
        .hosts
        .clone()
        .with_scan_timeout(Duration::from_millis(100));
    let key = Key::ed25519();
    // The scan waits for a notification that never comes.
    setup.env.scan_returns(
        "github.com",
        22,
        Scan::Gated(Arc::new(tokio::sync::Notify::new()), key.blob.clone()),
    );
    let keys = tokio::time::timeout(WAIT, setup.lookup("github.com", 22, Some(&key)))
        .await
        .unwrap();
    assert!(keys.is_empty());
    assert!(setup.rows().await.is_empty());
}

#[tokio::test]
async fn a_known_host_with_the_stored_key_returns_it_and_stamps_its_use() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("github.com", 22, &key);
    setup.lookup("github.com", 22, Some(&key)).await;
    assert_eq!(setup.rows().await[0].last_used_at, None);

    setup.clock.advance(Duration::from_secs(60));
    let keys = setup.lookup("github.com", 22, Some(&key)).await;
    assert_eq!(keys, vec![key.blob.clone()]);
    assert_eq!(setup.rows().await[0].last_used_at, Some(setup.clock.now()));
    // No second scan: the host is known.
    assert_eq!(setup.env.scans().len(), 1);
}

#[tokio::test]
async fn a_known_host_with_a_different_key_returns_the_stored_keys_and_warns() {
    let setup = Setup::new().await;
    let stored = Key::ed25519();
    let other = Key::ed25519();
    setup.scans("github.com", 22, &stored);
    setup.lookup("github.com", 22, Some(&stored)).await;
    // The scan would now find the new key too. A known host isn't scanned, or recorded again.
    setup.scans("github.com", 22, &other);
    setup.clock.advance(Duration::from_secs(60));

    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let keys = {
        let _guard = tracing::subscriber::set_default(subscriber);
        setup.lookup("github.com", 22, Some(&other)).await
    };
    assert_eq!(
        keys,
        vec![stored.blob.clone()],
        "ssh sees only the stored key, and refuses"
    );
    let rows = setup.rows().await;
    assert_eq!(rows.len(), 1, "the new key isn't recorded");
    assert_eq!(rows[0].last_used_at, None, "a mismatch isn't a use");
    assert_eq!(setup.env.scans().len(), 1);
    let logged = logs.text();
    assert!(logged.contains("host key changed"), "{logged}");
    assert!(logged.contains(&stored.fingerprint()), "{logged}");
    assert!(logged.contains(&other.fingerprint()), "{logged}");
    assert!(logged.contains("ws-1"), "{logged}");
}

#[tokio::test]
async fn asking_for_the_stored_keys_returns_them_and_records_and_stamps_nothing() {
    let setup = Setup::new().await;
    // An unknown host: nothing to return, nothing recorded, no scan.
    assert!(setup.lookup("github.com", 22, None).await.is_empty());
    assert!(setup.rows().await.is_empty());
    assert!(setup.env.scans().is_empty());

    let ed25519 = Key::ed25519();
    let rsa = Key::of(KeyType::Rsa3072);
    for key in [&ed25519, &rsa] {
        setup
            .hosts
            .pin(&user("owner"), "docker", &key.line("github.com"))
            .await
            .unwrap();
    }
    let keys = setup.lookup("github.com", 22, None).await;
    assert_eq!(keys, [ed25519.blob.clone(), rsa.blob.clone()]);
    assert!(
        setup
            .rows()
            .await
            .iter()
            .all(|row| row.last_used_at.is_none()),
        "asking isn't a use"
    );
}

#[tokio::test]
async fn hosts_are_normalized_and_ports_are_separate_hosts() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("git.example", 2222, &key);
    // `ssh` writes `[host]:port` for a port other than 22; the store keeps the lowercased host.
    let keys = setup.lookup("[Git.Example]:2222", 2222, Some(&key)).await;
    assert_eq!(keys, vec![key.blob.clone()]);
    let row = &setup.rows().await[0];
    assert_eq!((row.host.as_str(), row.port), ("git.example", 2222));
    assert_eq!(
        setup.env.scans()[0].1,
        "git.example",
        "the scan gets the host without brackets"
    );

    // The same host on port 22 is a different host, unknown, and scanned on its own.
    assert!(setup.lookup("git.example", 22, Some(&key)).await.is_empty());
    setup.scans("git.example", 22, &key);
    assert_eq!(
        setup.lookup("GIT.EXAMPLE", 22, Some(&key)).await,
        vec![key.blob.clone()]
    );
    assert_eq!(setup.rows().await.len(), 2);
}

#[tokio::test]
async fn each_environment_has_its_own_hosts() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("git.internal", 22, &key);
    setup.lookup("git.internal", 22, Some(&key)).await;

    // Another environment instance, where the same name could be another server, starts empty.
    let other = Caller {
        environment: "sandbox".to_owned(),
        ..setup.caller()
    };
    assert!(
        setup
            .lookup_as(&other, "git.internal", 22, None)
            .await
            .is_empty()
    );
    let changed = Key::ed25519();
    setup.scans("git.internal", 22, &changed);
    assert_eq!(
        setup
            .lookup_as(&other, "git.internal", 22, Some(&changed))
            .await,
        vec![changed.blob.clone()]
    );
    let rows = setup.rows().await;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .map(|row| row.environment.as_str())
            .collect::<Vec<_>>(),
        ["docker", "sandbox"]
    );
}

#[tokio::test]
async fn a_pinned_key_is_trusted_before_first_use_without_a_scan() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    let added = setup
        .hosts
        .pin(&user("owner"), "docker", &key.line("[git.example]:2222"))
        .await
        .unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].host, "git.example");
    assert_eq!(added[0].port, 2222);
    assert_eq!(added[0].added_by, Some(user("owner")));
    assert_eq!(added[0].first_workspace, None);
    assert_eq!(added[0].fingerprint, key.fingerprint());

    let keys = setup.lookup("[git.example]:2222", 2222, Some(&key)).await;
    assert_eq!(keys, vec![key.blob.clone()]);
    assert!(setup.env.scans().is_empty(), "a pinned host isn't scanned");
    assert!(setup.rows().await[0].last_used_at.is_some());

    // A different key for a pinned host is a change, not a new host.
    let other = Key::ed25519();
    setup.scans("git.example", 2222, &other);
    assert_eq!(
        setup.lookup("[git.example]:2222", 2222, Some(&other)).await,
        vec![key.blob.clone()]
    );
    assert_eq!(setup.rows().await.len(), 1);
}

#[tokio::test]
async fn deleting_a_host_lets_the_next_connection_trust_it_again() {
    let setup = Setup::new().await;
    let old = Key::ed25519();
    setup.scans("github.com", 22, &old);
    setup.lookup("github.com", 22, Some(&old)).await;
    let id = setup.rows().await[0].id;

    // The host rotated its key: refused until an admin deletes the old one.
    let new = Key::ed25519();
    setup.scans("github.com", 22, &new);
    assert_eq!(
        setup.lookup("github.com", 22, Some(&new)).await,
        vec![old.blob.clone()]
    );
    assert!(setup.hosts.delete(id).await.unwrap());
    assert!(!setup.hosts.delete(id).await.unwrap());
    assert_eq!(
        setup.lookup("github.com", 22, Some(&new)).await,
        vec![new.blob.clone()]
    );
    let rows = setup.rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].public_key, new.base64());
}

#[tokio::test]
async fn an_offered_key_that_isnt_a_key_of_its_type_is_not_trusted() {
    let setup = Setup::new().await;
    let ed25519 = Key::ed25519();
    let rsa = Key::of(KeyType::Rsa3072);
    setup.scans("github.com", 22, &ed25519);
    let request = |key_type: &str, key: &[u8]| KnownHostsRequest {
        id: 1,
        host: "github.com".into(),
        port: 22,
        key_type: key_type.into(),
        key: key.to_vec(),
    };
    for (key_type, key) in [
        // The type says ed25519 and the blob is RSA.
        ("ssh-ed25519", rsa.blob.as_slice()),
        ("ssh-ed25519", b"not a key".as_slice()),
        // A type the core doesn't record.
        ("ssh-ed25519-cert-v01@openssh.com", ed25519.blob.as_slice()),
        ("ssh-dss", ed25519.blob.as_slice()),
        ("sk-ssh-ed25519@openssh.com", ed25519.blob.as_slice()),
    ] {
        let keys = setup
            .hosts
            .lookup(setup.env.as_ref(), &setup.caller(), &request(key_type, key))
            .await;
        assert!(keys.is_empty(), "{key_type}");
    }
    assert!(setup.rows().await.is_empty());
    assert!(
        setup.env.scans().is_empty(),
        "nothing unverifiable is scanned"
    );
}

#[tokio::test]
async fn a_host_that_isnt_a_name_or_an_address_gets_no_key() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    setup.scans("a b", 22, &key);
    for host in [
        "",
        "[",
        "[]",
        "a b",
        "evil;host",
        "[unterminated:22",
        "-o ProxyCommand=x y",
    ] {
        assert!(
            setup.lookup(host, 22, Some(&key)).await.is_empty(),
            "{host:?}"
        );
    }
    assert!(setup.rows().await.is_empty());
    assert!(setup.env.scans().is_empty());
}

#[tokio::test]
async fn two_first_uses_at_once_record_the_host_once() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    let gate = Arc::new(tokio::sync::Notify::new());
    setup.env.scan_returns(
        "github.com",
        22,
        Scan::Gated(gate.clone(), key.blob.clone()),
    );

    let first = setup.lookup("github.com", 22, Some(&key));
    let second = setup.lookup("github.com", 22, Some(&key));
    let release = async {
        // Both scans are waiting before either is released.
        for _ in 0..500 {
            if setup.env.scans().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        gate.notify_one();
        gate.notify_one();
    };
    let (first, second, ()) =
        tokio::time::timeout(WAIT, async { tokio::join!(first, second, release) })
            .await
            .unwrap();
    assert_eq!(first, vec![key.blob.clone()]);
    assert_eq!(second, vec![key.blob.clone()]);
    assert_eq!(setup.rows().await.len(), 1);
}

#[tokio::test]
async fn the_host_name_forms_ssh_writes() {
    assert_eq!(canonical_host("github.com").as_deref(), Some("github.com"));
    assert_eq!(canonical_host("GitHub.COM").as_deref(), Some("github.com"));
    assert_eq!(
        canonical_host("[127.0.0.1]:2222").as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(canonical_host("[::1]:2222").as_deref(), Some("::1"));
    assert_eq!(canonical_host("::1").as_deref(), Some("::1"));
    assert_eq!(
        canonical_host("[fe80::1%eth0]:22").as_deref(),
        Some("fe80::1%eth0")
    );
    assert_eq!(canonical_host("sshd").as_deref(), Some("sshd"));
    assert_eq!(
        canonical_host("my_host-1.example").as_deref(),
        Some("my_host-1.example")
    );
    for bad in [
        "", "[", "[]", "[]:22", "a b", "a\nb", "a/b", "a;b", "$(x)", "é",
    ] {
        assert_eq!(canonical_host(bad), None, "{bad:?}");
    }
    assert_eq!(canonical_host(&"a".repeat(254)), None);
    assert!(canonical_host(&"a".repeat(253)).is_some());
}

async fn pin(setup: &Setup, line: &str) -> Result<Vec<KnownHost>, KnownHostsError> {
    setup.hosts.pin(&user("owner"), "docker", line).await
}

fn refusal(result: Result<Vec<KnownHost>, KnownHostsError>) -> String {
    match result {
        Err(KnownHostsError::Invalid(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pasted_line_pins_one_host_or_several() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    // A plain line, with a trailing comment and surrounding space.
    let added = pin(&setup, &format!("  {}  \n", key.line("github.com")))
        .await
        .unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!((added[0].host.as_str(), added[0].port), ("github.com", 22));

    // A host list, as `ssh` writes name and address together, and bracketed ports.
    let other = Key::of(KeyType::EcdsaP256);
    let added = pin(&setup, &other.line("Git.Example,[192.0.2.7]:2222,[::1]"))
        .await
        .unwrap();
    let hosts: Vec<_> = added.iter().map(|r| (r.host.as_str(), r.port)).collect();
    assert_eq!(
        hosts,
        [("git.example", 22), ("192.0.2.7", 2222), ("::1", 22)]
    );
    assert!(added.iter().all(|r| r.key_type == "ecdsa-sha2-nistp256"));

    // The same key again is refused; another key for a host is added.
    assert!(matches!(
        pin(&setup, &key.line("github.com")).await,
        Err(KnownHostsError::AlreadyKnown)
    ));
    let rsa = Key::of(KeyType::Rsa3072);
    pin(&setup, &rsa.line("github.com")).await.unwrap();
    // A list with one host already pinned adds the others.
    let added = pin(&setup, &key.line("github.com,gitlab.com"))
        .await
        .unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].host, "gitlab.com");
}

#[tokio::test]
async fn lines_that_cant_be_pinned_are_refused_with_a_reason() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    let (kind, blob) = (key.key_type(), key.base64());
    let cases: Vec<(String, &str)> = vec![
        (String::new(), "paste"),
        ("   ".to_owned(), "paste"),
        (format!("# github.com {kind} {blob}"), "comment"),
        (
            format!("{}\n{}", key.line("a.example"), key.line("b.example")),
            "one known_hosts line",
        ),
        (
            format!("@cert-authority *.example {kind} {blob}"),
            "markers",
        ),
        (format!("@revoked github.com {kind} {blob}"), "markers"),
        (format!("|1|c2FsdA==|aGFzaA== {kind} {blob}"), "hashed"),
        (format!("*.example.com {kind} {blob}"), "wildcard"),
        (format!("git?.example {kind} {blob}"), "wildcard"),
        (format!("github.com,!evil.com {kind} {blob}"), "negated"),
        (format!("[git.example]:abc {kind} {blob}"), "isn't a port"),
        (format!("[git.example]:0 {kind} {blob}"), "isn't a port"),
        (format!("[git.example {kind} {blob}"), "closing"),
        (format!("[git.example]x {kind} {blob}"), "isn't a host"),
        (format!("git!host {kind} {blob}"), "isn't a host"),
        ("github.com".to_owned(), "host, a key type, and a key"),
        (format!("github.com {kind}"), "host, a key type, and a key"),
        (format!("github.com ssh-dss {blob}"), "can't be pinned"),
        (
            format!("github.com ssh-ed25519-cert-v01@openssh.com {blob}"),
            "can't be pinned",
        ),
        (
            format!("github.com sk-ssh-ed25519@openssh.com {blob}"),
            "can't be pinned",
        ),
        (format!("github.com {kind} not-base64!"), "base64"),
        (format!("github.com {kind} AAAA"), "valid SSH public key"),
        (
            format!("github.com ssh-rsa {blob}"),
            "the key is ssh-ed25519",
        ),
    ];
    for (line, expected) in cases {
        let message = refusal(pin(&setup, &line).await);
        assert!(message.contains(expected), "{line:?}: {message}");
    }
    assert!(setup.rows().await.is_empty());
}

#[tokio::test]
async fn pinning_is_per_environment() {
    let setup = Setup::new().await;
    let key = Key::ed25519();
    pin(&setup, &key.line("github.com")).await.unwrap();
    setup
        .hosts
        .pin(&user("owner"), "sandbox", &key.line("github.com"))
        .await
        .unwrap();
    assert_eq!(setup.rows().await.len(), 2);
}
