//! Tests of the ssh-agent protocol the relay answers: which keys are offered and in what order,
//! signatures and the RSA flags, `session-bind@openssh.com` and the refusal of forwarded
//! connections, keys that change between requests, and messages that don't parse.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rsa::signature::Verifier as _;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
use tempfile::TempDir;

use super::agent::Agent;
use super::{KeyType, SshKey, SshKeys, keys};
use crate::workspaces::fake::TestClock;
use doozers_store::Store;
use doozers_types::{UserId, WorkspaceId};

const FAILURE: &[u8] = &[5];
const SUCCESS: &[u8] = &[6];
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

fn user(name: &str) -> UserId {
    UserId::new(name).unwrap()
}

pub(crate) fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `SSH2_AGENTC_SIGN_REQUEST`.
pub(crate) fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut message = vec![13];
    string(&mut message, blob);
    string(&mut message, data);
    message.extend_from_slice(&flags.to_be_bytes());
    message
}

/// `session-bind@openssh.com`, with `signature` as the destination's signature of `session_id`.
pub(crate) fn bind_request(
    host: &PublicKey,
    session_id: &[u8],
    signature: &[u8],
    forwarding: u8,
) -> Vec<u8> {
    raw_bind_request(&host.to_bytes().unwrap(), session_id, signature, forwarding)
}

/// Like [`bind_request`], with the host key given as the bytes to send.
fn raw_bind_request(host: &[u8], session_id: &[u8], signature: &[u8], forwarding: u8) -> Vec<u8> {
    let mut message = vec![27];
    string(&mut message, b"session-bind@openssh.com");
    string(&mut message, host);
    string(&mut message, session_id);
    string(&mut message, signature);
    message.push(forwarding);
    message
}

/// What a `SSH2_AGENT_IDENTITIES_ANSWER` lists: each key's blob and comment.
pub(crate) fn identities(answer: &[u8]) -> Vec<(Vec<u8>, String)> {
    assert_eq!(answer[0], 12, "{answer:?}");
    let count = u32::from_be_bytes(answer[1..5].try_into().unwrap());
    let mut rest = &answer[5..];
    let mut next = || {
        let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let bytes = rest[4..4 + length].to_vec();
        rest = &rest[4 + length..];
        bytes
    };
    let listed = (0..count)
        .map(|_| (next(), String::from_utf8(next()).unwrap()))
        .collect();
    assert!(rest.is_empty(), "trailing bytes in {answer:?}");
    listed
}

/// The signature a `SSH2_AGENT_SIGN_RESPONSE` carries.
fn signature_of(answer: &[u8]) -> Signature {
    assert_eq!(answer[0], 14, "{answer:?}");
    let length = u32::from_be_bytes(answer[1..5].try_into().unwrap()) as usize;
    assert_eq!(answer.len(), 5 + length, "{answer:?}");
    Signature::try_from(&answer[5..]).unwrap()
}

/// The labels a `SSH2_AGENT_IDENTITIES_ANSWER` lists, in order.
pub(crate) fn labels(answer: &[u8]) -> Vec<String> {
    identities(answer)
        .into_iter()
        .map(|(_, label)| label)
        .collect()
}

pub(crate) fn blob(key: &SshKey) -> Vec<u8> {
    PublicKey::from_openssh(&key.public_key)
        .unwrap()
        .to_bytes()
        .unwrap()
}

/// The destination's signature of `session_id`, as a server's host key makes it.
pub(crate) fn host_signature(host: &PrivateKey, session_id: &[u8]) -> Vec<u8> {
    let signature = keys::sign(host, HashAlg::Sha512, session_id).unwrap();
    Vec::<u8>::try_from(signature).unwrap()
}

pub(crate) fn ed25519_host() -> PrivateKey {
    keys::generate(KeyType::Ed25519).unwrap()
}

struct Setup {
    _dir: TempDir,
    clock: Arc<TestClock>,
    keys: SshKeys,
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

impl Setup {
    async fn new() -> Self {
        discard_logs_by_default();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("doozers.db")).await.unwrap();
        let clock = TestClock::new();
        let keys = SshKeys::for_tests(store, dir.path(), clock.clone()).await;
        Self {
            _dir: dir,
            clock,
            keys,
        }
    }

    async fn key(&self, owner: &UserId, kind: KeyType, label: &str) -> SshKey {
        self.keys.generate(owner, kind, Some(label)).await.unwrap()
    }

    /// The agent of a workspace that gets `owner`'s keys.
    fn agent(&self, owner: Option<&UserId>) -> Agent {
        Agent::new(
            self.keys.clone(),
            self.clock.clone(),
            WorkspaceId::new("ws-1").unwrap(),
            owner.cloned(),
        )
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

#[tokio::test]
async fn the_users_keys_are_offered_most_recently_used_first_with_their_labels() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let a = setup.key(&owner, KeyType::Ed25519, "a").await;
    setup.clock.advance(Duration::from_secs(10));
    let b = setup.key(&owner, KeyType::EcdsaP256, "b").await;
    setup.clock.advance(Duration::from_secs(10));
    setup.key(&owner, KeyType::Ed25519, "c").await;
    let mut agent = setup.agent(Some(&owner));

    // Never used: the newest first.
    let answer = agent.handle(1, &[11]).await;
    assert_eq!(labels(&answer), ["c", "b", "a"]);
    let listed = identities(&answer);
    assert_eq!(listed[1].0, blob(&b));
    assert_eq!(listed[2].0, blob(&a));

    // Signing moves a key to the front, on the next request.
    setup.clock.advance(Duration::from_secs(10));
    let signed = agent.handle(1, &sign_request(&blob(&a), b"data", 0)).await;
    assert_eq!(signed[0], 14);
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["a", "c", "b"]);
    setup.clock.advance(Duration::from_secs(10));
    agent.handle(2, &sign_request(&blob(&b), b"data", 0)).await;
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["b", "a", "c"]);
}

#[tokio::test]
async fn another_users_keys_are_never_offered_or_signed_with() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let alice = user("alice");
    setup.key(&owner, KeyType::Ed25519, "mine").await;
    let hers = setup.key(&alice, KeyType::Ed25519, "hers").await;
    let mut agent = setup.agent(Some(&owner));

    assert_eq!(labels(&agent.handle(1, &[11]).await), ["mine"]);
    // Asking for her key by its blob fails, and leaves her key unused.
    let refused = agent
        .handle(1, &sign_request(&blob(&hers), b"data", 0))
        .await;
    assert_eq!(refused, FAILURE);
    let hers = setup.keys.get(&alice, hers.id).await.unwrap();
    assert_eq!(hers.last_used_at, None);

    // The same key held by both users is signed with as the workspace user's own.
    let shared = setup.key(&owner, KeyType::Ed25519, "shared").await;
    assert_ne!(shared.id, hers.id);
    let mut hers_agent = setup.agent(Some(&alice));
    assert_eq!(labels(&hers_agent.handle(1, &[11]).await), ["hers"]);
}

#[tokio::test]
async fn a_workspace_without_a_key_user_offers_no_keys_and_signs_nothing() {
    let setup = Setup::new().await;
    let key = setup.key(&user("owner"), KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(None);
    let answer = agent.handle(1, &[11]).await;
    assert_eq!(answer, [12, 0, 0, 0, 0]);
    let refused = agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await;
    assert_eq!(refused, FAILURE);
}

#[tokio::test]
async fn every_key_type_signs_and_the_signature_verifies() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let mut agent = setup.agent(Some(&owner));
    let data = b"the data the client wants signed";
    for (kind, algorithm, flags) in [
        (KeyType::Ed25519, "ssh-ed25519", 0),
        (KeyType::EcdsaP256, "ecdsa-sha2-nistp256", 0),
        (KeyType::EcdsaP384, "ecdsa-sha2-nistp384", 0),
        (KeyType::EcdsaP521, "ecdsa-sha2-nistp521", 0),
        (KeyType::Rsa3072, "rsa-sha2-256", RSA_SHA2_256),
        (KeyType::Rsa3072, "rsa-sha2-512", RSA_SHA2_512),
    ] {
        let key = setup.key(&owner, kind, &format!("{kind:?}")).await;
        let answer = agent
            .handle(7, &sign_request(&blob(&key), data, flags))
            .await;
        let signature = signature_of(&answer);
        assert_eq!(signature.algorithm().as_str(), algorithm, "{kind:?}");
        let public = PublicKey::from_openssh(&key.public_key).unwrap();
        public
            .key_data()
            .verify(data, &signature)
            .unwrap_or_else(|e| panic!("{kind:?} {algorithm}: {e}"));
        // A different message doesn't verify.
        assert!(public.key_data().verify(b"other", &signature).is_err());
        assert!(
            setup
                .keys
                .get(&owner, key.id)
                .await
                .unwrap()
                .last_used_at
                .is_some(),
            "{kind:?} was not stamped"
        );
    }
}

#[tokio::test]
async fn an_rsa_request_needs_a_sha2_flag_and_sha2_256_wins_when_both_are_set() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Rsa3072, "rsa").await;
    let mut agent = setup.agent(Some(&owner));
    let sign = |flags| sign_request(&blob(&key), b"data", flags);

    // Flag 0 would be SHA-1, and so would the old-signature flag alone: refused, and not stamped.
    assert_eq!(agent.handle(1, &sign(0)).await, FAILURE);
    assert_eq!(agent.handle(1, &sign(1)).await, FAILURE);
    assert_eq!(
        setup.keys.get(&owner, key.id).await.unwrap().last_used_at,
        None
    );

    let both = agent.handle(1, &sign(RSA_SHA2_256 | RSA_SHA2_512)).await;
    assert_eq!(
        signature_of(&both).algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }
    );
    // Flags the relay doesn't know don't turn a SHA-2 request into anything else.
    let extra = agent.handle(1, &sign(RSA_SHA2_512 | 0x100)).await;
    assert_eq!(
        signature_of(&extra).algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512)
        }
    );
}

#[tokio::test]
async fn a_deleted_key_stops_working_on_the_next_request_and_a_new_one_is_offered_at_once() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let old = setup.key(&owner, KeyType::Ed25519, "old").await;
    let mut agent = setup.agent(Some(&owner));
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["old"]);
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&old), b"x", 0)).await[0],
        14
    );

    setup.keys.delete(&owner, old.id).await.unwrap();
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&old), b"x", 0)).await,
        FAILURE
    );
    assert_eq!(agent.handle(1, &[11]).await, [12, 0, 0, 0, 0]);

    setup.key(&owner, KeyType::Ed25519, "new").await;
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["new"]);
    // A key renamed is offered under its new label.
    let keys = setup.keys.list(&owner).await.unwrap();
    setup
        .keys
        .rename(&owner, keys[0].id, "renamed")
        .await
        .unwrap();
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["renamed"]);
}

#[tokio::test]
async fn a_key_whose_secret_is_gone_fails_the_request_and_not_the_relay() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "broken").await;
    let good = setup.key(&owner, KeyType::Ed25519, "good").await;
    let secret =
        crate::secrets::SecretPath::new(format!("users/owner/ssh-keys/{}", key.id)).unwrap();
    // The secret goes behind the row's back.
    let store = &setup.keys.secrets;
    store.delete(&secret).await.unwrap();
    let mut agent = setup.agent(Some(&owner));
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&good), b"x", 0)).await[0],
        14
    );
}

#[tokio::test]
async fn a_bound_connection_signs_and_the_signature_is_logged_with_the_host_key() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "work laptop").await;
    let mut agent = setup.agent(Some(&owner));
    let host = ed25519_host();
    let session_id = b"the session identifier";
    let bind = bind_request(
        host.public_key(),
        session_id,
        &host_signature(&host, session_id),
        0,
    );

    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    assert_eq!(agent.handle(1, &bind).await, SUCCESS);
    assert_eq!(agent.connections(), 1);
    let answer = agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await;
    assert_eq!(answer[0], 14);
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["work laptop"]);

    let logged = logs.text();
    let fingerprint = host.public_key().fingerprint(HashAlg::Sha256).to_string();
    assert!(logged.contains("INFO"), "{logged}");
    assert!(logged.contains("ws-1"), "{logged}");
    assert!(logged.contains("owner"), "{logged}");
    assert!(logged.contains("work laptop"), "{logged}");
    assert!(logged.contains(&fingerprint), "{logged}");

    // Another connection that never bound logs the host as unknown.
    agent.handle(2, &sign_request(&blob(&key), b"x", 0)).await;
    let logged = logs.text();
    assert!(logged.contains("host_key=\"unknown\""), "{logged}");
}

#[tokio::test]
async fn a_bind_to_an_rsa_host_key_verifies() {
    let setup = Setup::new().await;
    let mut agent = setup.agent(None);
    let host = keys::generate(KeyType::Rsa3072).unwrap();
    let session_id = b"another session";
    let bind = bind_request(
        host.public_key(),
        session_id,
        &host_signature(&host, session_id),
        0,
    );
    assert_eq!(agent.handle(1, &bind).await, SUCCESS);
}

#[tokio::test]
async fn a_forwarded_connection_gets_no_keys_and_signs_nothing() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));
    let host = ed25519_host();
    let session_id = b"session";
    let signature = host_signature(&host, session_id);

    // Before any bind, nothing is known: the connection is served (older clients never bind).
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["mine"]);

    // Connection 1 binds as forwarded, connection 2 as a direct connection.
    let forwarded = bind_request(host.public_key(), session_id, &signature, 1);
    let direct = bind_request(host.public_key(), session_id, &signature, 0);
    assert_eq!(agent.handle(1, &forwarded).await, SUCCESS);
    assert_eq!(agent.handle(2, &direct).await, SUCCESS);

    assert_eq!(agent.handle(1, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );
    assert_eq!(labels(&agent.handle(2, &[11]).await), ["mine"]);
    assert_eq!(
        agent.handle(2, &sign_request(&blob(&key), b"x", 0)).await[0],
        14
    );
    assert!(
        setup
            .keys
            .get(&owner, key.id)
            .await
            .unwrap()
            .last_used_at
            .is_some()
    );

    // Any forwarded bind counts: a later direct bind on the same connection doesn't undo it.
    assert_eq!(agent.handle(1, &direct).await, SUCCESS);
    assert_eq!(agent.handle(1, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );

    // A closed connection's state is gone, and a new connection with its number starts fresh.
    agent.close(1);
    assert_eq!(agent.connections(), 1);
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["mine"]);
    agent.close(1);
    agent.close(2);
    agent.close(3);
    assert_eq!(agent.connections(), 0);
}

/// Binds that can't verify: signed by another key, over another session id, not a signature at
/// all, a host key that isn't one, and a 1024-bit RSA host key (OpenSSH accepts those, `ssh-key`
/// doesn't). Each is the message for `forwarding`.
fn unverifiable_binds(forwarding: u8) -> Vec<Vec<u8>> {
    let host = ed25519_host();
    let other = ed25519_host();
    let session_id = b"session";
    let mut small_rsa = Vec::new();
    string(&mut small_rsa, b"ssh-rsa");
    string(&mut small_rsa, &[0x01, 0x00, 0x01]);
    let mut modulus = vec![0x00, 0xC5];
    modulus.extend_from_slice(&[0x5A; 126]);
    string(&mut small_rsa, &modulus);
    vec![
        bind_request(
            host.public_key(),
            session_id,
            &host_signature(&other, session_id),
            forwarding,
        ),
        bind_request(
            host.public_key(),
            session_id,
            &host_signature(&host, b"another"),
            forwarding,
        ),
        bind_request(host.public_key(), session_id, b"junk", forwarding),
        raw_bind_request(b"not a host key", session_id, b"junk", forwarding),
        raw_bind_request(&small_rsa, session_id, b"junk", forwarding),
    ]
}

#[tokio::test]
async fn a_forwarding_bind_restricts_the_connection_whether_or_not_it_verifies() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));

    let binds = unverifiable_binds(1);
    for (connection, bind) in (1..).zip(&binds) {
        // The bind itself fails, as it must, but OpenSSH goes on using the connection, so the
        // connection must be one that gets no keys.
        assert_eq!(agent.handle(connection, bind).await, FAILURE);
        assert_eq!(
            agent.handle(connection, &[11]).await,
            [12, 0, 0, 0, 0],
            "{connection}"
        );
        assert_eq!(
            agent
                .handle(connection, &sign_request(&blob(&key), b"x", 0))
                .await,
            FAILURE,
            "{connection}"
        );
    }
    assert_eq!(agent.connections(), binds.len());
    // A connection that never bound is not affected.
    assert_eq!(labels(&agent.handle(100, &[11]).await), ["mine"]);
}

#[tokio::test]
async fn a_direct_bind_that_doesnt_verify_changes_nothing() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));

    for bind in unverifiable_binds(0) {
        assert_eq!(agent.handle(1, &bind).await, FAILURE);
    }
    assert_eq!(agent.connections(), 0);
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["mine"]);
    assert_eq!(
        agent.handle(1, &sign_request(&blob(&key), b"x", 0)).await[0],
        14
    );
}

#[tokio::test]
async fn requests_the_relay_doesnt_serve_fail() {
    let setup = Setup::new().await;
    let owner = user("owner");
    setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));

    // Add (17), remove (18), remove all (19), add constrained (25), lock (22), unlock (23).
    for kind in [17u8, 18, 19, 22, 23, 25, 99] {
        assert_eq!(
            agent.handle(1, &[kind, 0, 0, 0, 0]).await,
            FAILURE,
            "{kind}"
        );
    }
    // Other extensions, including `query`.
    let mut query = vec![27];
    string(&mut query, b"query");
    assert_eq!(agent.handle(1, &query).await, FAILURE);
    let mut restrict = vec![27];
    string(&mut restrict, b"restrict-destination-v00@openssh.com");
    restrict.extend_from_slice(&[0; 8]);
    assert_eq!(agent.handle(1, &restrict).await, FAILURE);
    // The key is still there and still signs.
    assert_eq!(labels(&agent.handle(1, &[11]).await), ["mine"]);
}

#[tokio::test]
async fn malformed_messages_fail_without_ending_anything() {
    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));
    let good = sign_request(&blob(&key), b"data", 0);

    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        // Identities with trailing bytes.
        vec![11, 0],
        // A sign request cut at every length.
        vec![13],
        vec![13, 0, 0],
        vec![13, 0, 0, 0, 200, 1, 2],
        // A string longer than the message, and one whose length overflows.
        vec![13, 0xff, 0xff, 0xff, 0xff],
        // Trailing bytes after the flags.
        {
            let mut message = good.clone();
            message.push(0);
            message
        },
        // A key blob that isn't a key.
        sign_request(b"not a key", b"data", 0),
        sign_request(&[], &[], 0),
        // Extension without a name, with a cut bind, with a bad forwarding byte.
        vec![27],
        vec![27, 0, 0, 0, 24],
    ];
    for cut in 1..good.len() {
        cases.push(good[..cut].to_vec());
    }
    let host = ed25519_host();
    let signature = host_signature(&host, b"s");
    let bind = bind_request(host.public_key(), b"s", &signature, 0);
    for cut in 1..bind.len() {
        cases.push(bind[..cut].to_vec());
    }
    cases.push(bind_request(host.public_key(), b"s", &signature, 2));
    let mut trailing = bind.clone();
    trailing.push(0);
    cases.push(trailing);

    for case in cases {
        assert_eq!(agent.handle(1, &case).await, FAILURE, "{case:?}");
        // The connection is as good as before.
        assert_eq!(agent.handle(1, &good).await[0], 14);
    }
    assert_eq!(agent.connections(), 0);
}

#[tokio::test]
async fn the_connection_table_is_bounded_and_a_flood_cant_unforward_a_connection() {
    use super::agent::MAX_CONNECTIONS;

    let setup = Setup::new().await;
    let owner = user("owner");
    let key = setup.key(&owner, KeyType::Ed25519, "mine").await;
    let mut agent = setup.agent(Some(&owner));
    let host = ed25519_host();
    let signature = host_signature(&host, b"session");
    let bind = |forwarding| bind_request(host.public_key(), b"session", &signature, forwarding);
    let max = MAX_CONNECTIONS as u64;

    // Connection 0 is forwarded and every other bound connection isn't. A full table makes room for
    // a new bind by dropping the least recently used connection that isn't forwarded.
    assert_eq!(agent.handle(0, &bind(1)).await, SUCCESS);
    for connection in 1..max {
        assert_eq!(agent.handle(connection, &bind(0)).await, SUCCESS);
    }
    assert_eq!(agent.connections(), MAX_CONNECTIONS);
    // Connection 1 is the oldest, unless it is used again.
    agent.handle(1, &[11]).await;
    assert_eq!(agent.handle(max, &bind(0)).await, SUCCESS);
    assert_eq!(agent.connections(), MAX_CONNECTIONS);
    // The forwarded connection is still forwarded, and the evicted one starts fresh.
    assert_eq!(agent.handle(0, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(labels(&agent.handle(2, &[11]).await), ["mine"]);

    // Closing frees room, and an unknown connection number is just a new connection.
    agent.close(max);
    assert_eq!(agent.connections(), MAX_CONNECTIONS - 1);
    agent.close(123_456);

    // A table of forwarded connections only: a new bind is refused and the new connection gets no
    // keys, since it could be a forwarded one that has no room.
    let mut agent = setup.agent(Some(&owner));
    for connection in 0..max {
        assert_eq!(agent.handle(connection, &bind(1)).await, SUCCESS);
    }
    assert_eq!(agent.handle(max, &bind(0)).await, FAILURE);
    assert_eq!(agent.connections(), MAX_CONNECTIONS);
    assert_eq!(agent.handle(max, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(
        agent.handle(max, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );
    // Closing one makes room, but the refused connection stays forwarded, and so does an older
    // connection that has no state (5, which just closed: it could have been the refused one).
    agent.close(5);
    assert_eq!(agent.handle(max, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(
        agent.handle(max, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );
    assert_eq!(agent.handle(5, &[11]).await, [12, 0, 0, 0, 0]);
    // A connection that came after the refusal is an ordinary one again.
    assert_eq!(labels(&agent.handle(max + 1, &[11]).await), ["mine"]);
    // And a later bind, even a direct one, doesn't un-forward the refused connection.
    assert_eq!(agent.handle(max, &bind(0)).await, SUCCESS);
    assert_eq!(agent.handle(max, &[11]).await, [12, 0, 0, 0, 0]);
    assert_eq!(
        agent.handle(max, &sign_request(&blob(&key), b"x", 0)).await,
        FAILURE
    );
}
