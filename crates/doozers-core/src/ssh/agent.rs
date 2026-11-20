//! The ssh-agent protocol of the relay (issue #137): what the core answers when a client in a
//! workspace asks the agent socket for the user's keys or for a signature. The design is in
//! `Docs/technical/ssh.md`.
//!
//! An [`Agent`] answers for one workspace. The workspace's key user ([`Agent::new`]) is the only
//! user whose keys it offers or signs with, and a workspace without one answers every request as
//! an agent with no keys. Each client connection is named by the number the environment gave it,
//! and the agent keeps what it learns from the connection's `session-bind@openssh.com` until the
//! environment says the connection closed ([`Agent::close`]).
//!
//! Supported requests:
//!
//! - `SSH_AGENTC_REQUEST_IDENTITIES`: the user's keys, most recently used first, read from the
//!   store on every request.
//! - `SSH_AGENTC_SIGN_REQUEST`: a signature by one of those keys. A forwarded connection, a key the
//!   user doesn't have, and an RSA request without `rsa-sha2-256` or `rsa-sha2-512` all fail.
//! - `SSH_AGENTC_EXTENSION` `session-bind@openssh.com`: remembers whether the connection is
//!   forwarded, and, if the destination's signature over the session id verifies, its host key.
//!
//! Everything else, and any message that doesn't parse, gets `SSH_AGENT_FAILURE`. A bad message
//! never ends the relay.
//!
//! Every message and connection number comes from a process in the workspace, whose root user can
//! write frames of its own, so the agent trusts none of it. In particular it keeps state for at
//! most [`MAX_CONNECTIONS`] connections: when the table is full, a new `session-bind` evicts the
//! least recently used connection that isn't forwarded, and is refused if every one is forwarded.
//! A connection whose bind was refused for that reason, and every older connection without state,
//! is treated as forwarded for good, and so is any connection without state while the table is
//! full of forwarded ones, so the flood can't un-forward a connection.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use doozers_types::{UserId, WorkspaceId};
use rsa::signature::Verifier as _;
use ssh_key::{HashAlg, PublicKey, Signature};
use tracing::{debug, info, warn};

use super::keys;
use super::{SshKey, SshKeys};
use crate::sessions::Clock;

/// `SSH_AGENT_FAILURE`.
const FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS`.
const SUCCESS: u8 = 6;
/// `SSH2_AGENTC_REQUEST_IDENTITIES`.
const REQUEST_IDENTITIES: u8 = 11;
/// `SSH2_AGENT_IDENTITIES_ANSWER`.
const IDENTITIES_ANSWER: u8 = 12;
/// `SSH2_AGENTC_SIGN_REQUEST`.
const SIGN_REQUEST: u8 = 13;
/// `SSH2_AGENT_SIGN_RESPONSE`.
const SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENTC_EXTENSION`.
const EXTENSION: u8 = 27;

/// `SSH_AGENT_RSA_SHA2_256`.
const RSA_SHA2_256: u32 = 2;
/// `SSH_AGENT_RSA_SHA2_512`.
const RSA_SHA2_512: u32 = 4;

/// The extension that tells the agent which host a connection is for.
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// The most client connections the agent keeps state for.
pub const MAX_CONNECTIONS: usize = 256;

/// What the agent knows about one client connection.
#[derive(Debug, Default)]
struct Connection {
    /// When a request from the connection was last handled: [`Agent::tick`] then.
    touched: u64,
    /// The `SHA256:...` fingerprint of the host key of the latest verified `session-bind`.
    host_key: Option<String>,
    /// Some `session-bind` said the agent is being forwarded. Never cleared.
    forwarded: bool,
}

/// The ssh-agent of one workspace.
pub struct Agent {
    keys: SshKeys,
    clock: Arc<dyn Clock>,
    workspace: WorkspaceId,
    user: Option<UserId>,
    connections: HashMap<u64, Connection>,
    /// Counts requests, to find the least recently used connection.
    tick: u64,
    /// The highest connection number any request has come from.
    highest: u64,
    /// Set when a bind couldn't be recorded: the connection numbers up to this one that have no
    /// state are treated as forwarded.
    unrecorded_up_to: Option<u64>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("workspace", &self.workspace)
            .field("user", &self.user)
            .field("connections", &self.connections.len())
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// The agent of `workspace`, which offers the keys of `user` (none if `None`), reading them
    /// from `keys` and stamping their use with `clock`.
    pub fn new(
        keys: SshKeys,
        clock: Arc<dyn Clock>,
        workspace: WorkspaceId,
        user: Option<UserId>,
    ) -> Self {
        Self {
            keys,
            clock,
            workspace,
            user,
            connections: HashMap::new(),
            tick: 0,
            highest: 0,
            unrecorded_up_to: None,
        }
    }

    /// How many client connections the agent holds state for.
    pub fn connections(&self) -> usize {
        self.connections.len()
    }

    /// Forgets what the agent learned from `connection`, which has closed.
    pub fn close(&mut self, connection: u64) {
        self.connections.remove(&connection);
    }

    /// The answer to one agent message from `connection`, both without their length prefix.
    /// Always a message: a request the agent can't or won't serve gets `SSH_AGENT_FAILURE`.
    pub async fn handle(&mut self, connection: u64, message: &[u8]) -> Vec<u8> {
        self.tick += 1;
        self.highest = self.highest.max(connection);
        if let Some(state) = self.connections.get_mut(&connection) {
            state.touched = self.tick;
        }
        let mut reader = Reader(message);
        let answer = match reader.u8() {
            Some(REQUEST_IDENTITIES) if reader.is_empty() => self.identities(connection).await,
            Some(SIGN_REQUEST) => self.sign(connection, reader).await,
            Some(EXTENSION) => self.extension(connection, reader),
            Some(kind) => {
                debug!(workspace = %self.workspace, kind, "refused an ssh-agent request the relay doesn't serve");
                None
            }
            None => {
                debug!(workspace = %self.workspace, "refused an empty ssh-agent message");
                None
            }
        };
        answer.unwrap_or_else(|| vec![FAILURE])
    }

    /// Whether `connection` must be treated as forwarded: it was bound as forwarded, or the agent
    /// can't rule it out.
    ///
    /// A connection without state is one that never bound, or one whose bind the agent couldn't
    /// record. Connection numbers only grow, so every connection up to the highest number seen when
    /// a bind was refused for lack of room might be the refused one, and stays treated as
    /// forwarded for good: freeing a slot can't turn it into an ordinary connection. Newer
    /// connections are ordinary again once there is room. While the table is full of forwarded
    /// connections, a connection without state could be a forwarded one that has no room yet.
    fn forwarded(&self, connection: u64) -> bool {
        match self.connections.get(&connection) {
            Some(state) => state.forwarded,
            None => {
                self.unrecorded_up_to
                    .is_some_and(|highest| connection <= highest)
                    || (self.connections.len() >= MAX_CONNECTIONS && self.all_forwarded())
            }
        }
    }

    fn all_forwarded(&self) -> bool {
        self.connections.values().all(|state| state.forwarded)
    }

    /// The keys the user has, or none for a forwarded connection or a workspace without a key
    /// user. `None` if the store fails.
    async fn offered(&self, connection: u64) -> Option<Vec<SshKey>> {
        let Some(user) = &self.user else {
            return Some(Vec::new());
        };
        if self.forwarded(connection) {
            return Some(Vec::new());
        }
        match self.keys.agent_keys(user).await {
            Ok(keys) => Some(keys),
            Err(error) => {
                warn!(workspace = %self.workspace, %error, "cannot read the SSH keys for the agent");
                None
            }
        }
    }

    async fn identities(&self, connection: u64) -> Option<Vec<u8>> {
        let offered = self.offered(connection).await?;
        let mut answer = vec![IDENTITIES_ANSWER];
        let mut listed: u32 = 0;
        let mut body = Vec::new();
        for key in &offered {
            let Some(blob) = blob_of(key) else {
                warn!(workspace = %self.workspace, key = %key.id, "an SSH key's public key can't be read; not offered");
                continue;
            };
            put_string(&mut body, &blob);
            put_string(&mut body, key.label.as_bytes());
            listed += 1;
        }
        answer.extend_from_slice(&listed.to_be_bytes());
        answer.extend_from_slice(&body);
        Some(answer)
    }

    async fn sign(&mut self, connection: u64, mut reader: Reader<'_>) -> Option<Vec<u8>> {
        let blob = reader.string()?;
        let data = reader.string()?;
        let flags = reader.u32()?;
        if !reader.is_empty() {
            return None;
        }
        let Some(user) = self.user.clone() else {
            debug!(workspace = %self.workspace, "refused to sign: the workspace has no SSH keys");
            return None;
        };
        let state = self.connections.get(&connection);
        if self.forwarded(connection) {
            warn!(workspace = %self.workspace, %user, "refused to sign for a forwarded agent connection");
            return None;
        }
        let host_key = state.and_then(|state| state.host_key.clone());

        let offered = self.offered(connection).await?;
        let Some(key) = offered
            .into_iter()
            .find(|key| blob_of(key).is_some_and(|candidate| candidate == blob))
        else {
            debug!(workspace = %self.workspace, %user, "refused to sign: the user has no such key");
            return None;
        };
        let hash = if key.algorithm == "ssh-rsa" {
            // OpenSSH 8.8 and later refuse SHA-1 signatures, and so does the relay.
            if flags & RSA_SHA2_256 != 0 {
                HashAlg::Sha256
            } else if flags & RSA_SHA2_512 != 0 {
                HashAlg::Sha512
            } else {
                warn!(workspace = %self.workspace, %user, key = %key.label, flags, "refused an RSA signature without rsa-sha2-256 or rsa-sha2-512");
                return None;
            }
        } else {
            HashAlg::Sha256
        };

        let private = match self.keys.private_key(&user, key.id).await {
            Ok(private) => private,
            Err(error) => {
                warn!(workspace = %self.workspace, %user, key = %key.label, %error, "cannot read an SSH key to sign with");
                return None;
            }
        };
        let data = data.to_vec();
        let signed =
            tokio::task::spawn_blocking(move || keys::sign(&private, hash, &data).and_then(encode))
                .await;
        let signature = match signed {
            Ok(Ok(signature)) => signature,
            Ok(Err(error)) => {
                warn!(workspace = %self.workspace, %user, key = %key.label, %error, "cannot sign with an SSH key");
                return None;
            }
            Err(error) => {
                warn!(workspace = %self.workspace, %user, key = %key.label, %error, "signing with an SSH key failed");
                return None;
            }
        };
        // A key deleted while this request ran must not answer it.
        if let Err(error) = self.keys.touch_used(key.id, self.clock.now()).await {
            warn!(workspace = %self.workspace, %user, key = %key.label, %error, "the SSH key is gone; not signing");
            return None;
        }
        info!(
            workspace = %self.workspace,
            %user,
            key = %key.label,
            host_key = host_key.as_deref().unwrap_or("unknown"),
            "signed for an SSH client in the workspace"
        );
        let mut answer = vec![SIGN_RESPONSE];
        put_string(&mut answer, &signature);
        Some(answer)
    }

    fn extension(&mut self, connection: u64, mut reader: Reader<'_>) -> Option<Vec<u8>> {
        let name = reader.string()?;
        if name != SESSION_BIND {
            debug!(workspace = %self.workspace, "refused an ssh-agent extension the relay doesn't serve");
            return None;
        }
        let host_key = reader.string()?;
        let session_id = reader.string()?;
        let signature = reader.string()?;
        let forwarding = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if !reader.is_empty() {
            return None;
        }
        // Only the host key's fingerprint needs the signature: a bind that says the agent is
        // forwarded restricts the connection whether or not the host key parses (OpenSSH carries
        // on with the connection after a failed bind) or the signature verifies.
        let fingerprint = Self::verified_host_key(host_key, session_id, signature);
        if fingerprint.is_none() {
            warn!(workspace = %self.workspace, forwarding, "refused a session-bind whose host key or signature doesn't verify");
        }
        let recorded = (forwarding || fingerprint.is_some())
            && self.record(connection, forwarding, fingerprint.as_deref());
        (recorded && fingerprint.is_some()).then(|| vec![SUCCESS])
    }

    /// The `SHA256:...` fingerprint of `host_key` if it parses and `signature` is its signature
    /// over `session_id`.
    fn verified_host_key(host_key: &[u8], session_id: &[u8], signature: &[u8]) -> Option<String> {
        let public = PublicKey::from_bytes(host_key).ok()?;
        let signature = Signature::try_from(signature).ok()?;
        public.key_data().verify(session_id, &signature).ok()?;
        Some(public.fingerprint(HashAlg::Sha256).to_string())
    }

    /// Keeps what a `session-bind` said about `connection`. If the table has no room for it, the
    /// connection can't be told apart from a forwarded one later, so it and every connection the
    /// agent has heard from so far that has no state are treated as forwarded
    /// ([`Agent::forwarded`]). `false` if there was no room.
    fn record(&mut self, connection: u64, forwarding: bool, fingerprint: Option<&str>) -> bool {
        if !self.connections.contains_key(&connection)
            && self.connections.len() >= MAX_CONNECTIONS
            && !self.evict_one()
        {
            warn!(workspace = %self.workspace, "refused a session-bind: every connection slot is a forwarded one");
            self.unrecorded_up_to = Some(self.highest);
            return false;
        }
        // A connection the agent couldn't record before stays forwarded if it binds again now.
        let unrecorded = self
            .unrecorded_up_to
            .is_some_and(|highest| connection <= highest);
        let state = self
            .connections
            .entry(connection)
            .or_insert_with(|| Connection {
                forwarded: unrecorded,
                ..Connection::default()
            });
        state.touched = self.tick;
        if let Some(fingerprint) = fingerprint {
            state.host_key = Some(fingerprint.to_owned());
        }
        state.forwarded |= forwarding;
        true
    }
}

impl Agent {
    /// Drops the least recently used connection that isn't forwarded. `false` if there is none.
    fn evict_one(&mut self) -> bool {
        let oldest = self
            .connections
            .iter()
            .filter(|(_, state)| !state.forwarded)
            .min_by_key(|(_, state)| state.touched)
            .map(|(connection, _)| *connection);
        match oldest {
            Some(connection) => {
                self.connections.remove(&connection);
                true
            }
            None => false,
        }
    }
}

/// The wire form of `key`'s public key, or `None` if the stored text doesn't decode.
fn blob_of(key: &SshKey) -> Option<Vec<u8>> {
    let (_, base64) = key.public_key.split_once(' ')?;
    STANDARD.decode(base64).ok()
}

/// The SSH signature blob of `signature`: its algorithm name and its bytes.
fn encode(signature: Signature) -> Result<Vec<u8>, ssh_key::Error> {
    Vec::<u8>::try_from(signature)
}

/// Appends an SSH `string`: a 4-byte length and the bytes.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A cursor over a message. Every read is `None` past the end instead of panicking.
#[derive(Clone, Copy)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.u32()?).ok()?;
        self.take(length)
    }
}
