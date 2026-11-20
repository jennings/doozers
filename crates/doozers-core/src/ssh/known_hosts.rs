//! The SSH host keys workspaces trust (issue #138): what the core answers when `ssh` in a
//! workspace asks, through the relay, which keys it trusts for a host. The design is in
//! `Docs/technical/ssh.md`.
//!
//! [`KnownHosts`] keeps the keys in the `ssh_known_hosts` table, one set per environment instance:
//! instances can sit on different networks, where one name means different servers. A lookup
//! names the environment, the host and port, and the key the server offered:
//!
//! - **The host has keys, and the offered one is among them:** the core returns the stored keys
//!   and stamps the matching key's `last_used_at`.
//! - **The host has keys, and the offered one isn't:** the core returns the stored keys, so `ssh`
//!   refuses with its host identification has changed error, and logs a warning.
//! - **The host has no key:** trust on first use, verified. The core asks the environment to fetch
//!   the host's key itself ([`Environment::scan_host_key`]) and records the offered key only if it
//!   equals what the environment saw. Otherwise a workspace could plant a fake key for
//!   `github.com`, which every workspace on the instance would then trust. A scan that fails or
//!   differs records nothing, logs a warning, and returns no key.
//! - **No key offered** (`ssh` asks for the stored keys to choose the algorithms to offer): the
//!   core returns the stored keys and records and stamps nothing.
//!
//! Every request is workspace input and is treated as untrusted: a host or key that doesn't parse
//! gets no key, and the relay bounds how many lookups run at once. An admin can pin a key before
//! first use ([`KnownHosts::pin`]) and delete one ([`KnownHosts::delete`]), which makes the next
//! connection to the host trust it again.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use doozers_store::{KnownHostId, NewKnownHost, Store};
use doozers_types::{Environment, KnownHostsRequest, UserId, WorkspaceId};
use ssh_key::{HashAlg, PublicKey};
use tracing::{info, warn};

use crate::sessions::Clock;

pub use doozers_store::KnownHostRecord as KnownHost;

/// How long a scan of a host's key may take: a little over the 10 seconds the environment gives
/// the scan itself.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The key types a host key is recorded or pinned with: what a scan can ask for.
const KEY_TYPES: [&str; 5] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

/// The longest host name (RFC 1035).
const MAX_HOST: usize = 253;

/// A known-hosts call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KnownHostsError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] doozers_store::Error),
    /// The line to pin isn't one the core can use. The message says why.
    #[error("{0}")]
    Invalid(String),
    /// Every key in the line is already pinned or recorded for its host.
    #[error("that key is already known for the host")]
    AlreadyKnown,
}

fn invalid(message: impl Into<String>) -> KnownHostsError {
    KnownHostsError::Invalid(message.into())
}

/// Who a lookup is for: the workspace that asked and what the first connection records about it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Caller {
    /// The environment instance the workspace lives in.
    pub environment: String,
    /// The workspace.
    pub workspace: WorkspaceId,
    /// The agent of the workspace's conversation, if it has one.
    pub agent: Option<String>,
    /// The user whose keys the workspace gets, if any.
    pub user: Option<UserId>,
}

impl Caller {
    /// The workspace `workspace` of environment instance `environment`, whose first connections
    /// are recorded as made by `agent` and `user`.
    pub fn new(
        environment: impl Into<String>,
        workspace: WorkspaceId,
        agent: Option<String>,
        user: Option<UserId>,
    ) -> Self {
        Self {
            environment: environment.into(),
            workspace,
            agent,
            user,
        }
    }
}

/// The host keys workspaces trust.
#[derive(Clone)]
pub struct KnownHosts {
    store: Store,
    clock: Arc<dyn Clock>,
    scan_timeout: std::time::Duration,
}

impl std::fmt::Debug for KnownHosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownHosts").finish_non_exhaustive()
    }
}

impl KnownHosts {
    /// The service over `store`, stamping times from `clock`.
    pub fn new(store: Store, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            scan_timeout: SCAN_TIMEOUT,
        }
    }

    /// The same service with scans cut off after `timeout`, for tests.
    #[cfg(test)]
    pub(crate) fn with_scan_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    /// Every stored key, by environment, host, port, then oldest first. For the admin page.
    pub async fn all(&self) -> Result<Vec<KnownHost>, KnownHostsError> {
        Ok(self.store.known_hosts_all().await?)
    }

    /// The key `id`, if there is one.
    pub async fn get(&self, id: KnownHostId) -> Result<Option<KnownHost>, KnownHostsError> {
        Ok(self.store.known_host(id).await?)
    }

    /// Deletes the key `id`, as an admin: once a host has no key left, its next connection is
    /// trusted on first use again. `false` if there was no such key.
    pub async fn delete(&self, id: KnownHostId) -> Result<bool, KnownHostsError> {
        Ok(self.store.known_host_delete(id).await?)
    }

    /// Pins the keys of one `known_hosts` line for `environment`, as `admin`, whether or not the
    /// host has other keys. A line with several comma-separated hosts pins the key for each. Returns
    /// what was added.
    ///
    /// Only a plain line is accepted: hashed names (`|1|...`), markers (`@cert-authority`,
    /// `@revoked`), wildcard and negated patterns, and key types a scan can't verify
    /// (certificates, `sk-` keys, DSA) are refused with a message.
    ///
    /// # Errors
    ///
    /// [`KnownHostsError::Invalid`] for a line that isn't usable;
    /// [`KnownHostsError::AlreadyKnown`] if every key was already stored.
    pub async fn pin(
        &self,
        admin: &UserId,
        environment: &str,
        line: &str,
    ) -> Result<Vec<KnownHost>, KnownHostsError> {
        let parsed = parse_line(line)?;
        let now = self.clock.now();
        let mut added = Vec::new();
        for (host, port) in parsed.hosts {
            let new = NewKnownHost {
                environment: environment.to_owned(),
                host,
                port,
                key_type: parsed.key_type.clone(),
                public_key: parsed.public_key.clone(),
                fingerprint: parsed.fingerprint.clone(),
                first_workspace: None,
                first_agent: None,
                first_user: None,
                added_by: Some(admin.clone()),
            };
            if let Some(record) = self.store.known_host_pin(new, now).await? {
                added.push(record);
            }
        }
        if added.is_empty() {
            return Err(KnownHostsError::AlreadyKnown);
        }
        Ok(added)
    }

    /// The keys, as SSH wire blobs, that `caller`'s workspace trusts for the host of `request`.
    /// Never fails: anything that stops the core from vouching for a key gives none, which makes
    /// `ssh` refuse the connection. `environment` is the plugin the scan is asked of. The relay
    /// calls this for each lookup; it is public so an environment's own tests can answer a relay
    /// the way the core does.
    pub async fn lookup(
        &self,
        environment: &dyn Environment,
        caller: &Caller,
        request: &KnownHostsRequest,
    ) -> Vec<Vec<u8>> {
        let Some(host) = canonical_host(&request.host) else {
            warn!(workspace = %caller.workspace, "refused a known-hosts lookup for a host that isn't a name or an address");
            return Vec::new();
        };
        let port = request.port;
        let stored = match self
            .store
            .known_hosts_for(&caller.environment, &host, port)
            .await
        {
            Ok(stored) => stored,
            Err(error) => {
                warn!(workspace = %caller.workspace, %error, "cannot read the known SSH hosts");
                return Vec::new();
            }
        };
        if request.key.is_empty() {
            return blobs(&stored);
        }
        let Some(offered) = Offered::parse(&request.key_type, &request.key) else {
            warn!(workspace = %caller.workspace, %host, port, "the key the workspace was offered can't be read; not trusting it");
            return blobs(&stored);
        };

        if !stored.is_empty() {
            return self.known(caller, &host, port, &offered, &stored).await;
        }

        // First use: only the key the environment sees for the host itself is trusted.
        let scanned = match tokio::time::timeout(
            self.scan_timeout,
            environment.scan_host_key(&caller.workspace, &host, port, &offered.key_type),
        )
        .await
        {
            Ok(Ok(scanned)) => scanned,
            Ok(Err(error)) => {
                warn!(workspace = %caller.workspace, environment = %caller.environment, %host, port, key = %offered.fingerprint, %error, "cannot verify the host key the workspace was offered; not trusting it");
                return Vec::new();
            }
            Err(_) => {
                warn!(workspace = %caller.workspace, environment = %caller.environment, %host, port, key = %offered.fingerprint, "verifying the host key the workspace was offered took too long; not trusting it");
                return Vec::new();
            }
        };
        if scanned != request.key {
            let seen = PublicKey::from_bytes(&scanned)
                .map(|key| key.fingerprint(HashAlg::Sha256).to_string())
                .unwrap_or_else(|_| "an unreadable key".to_owned());
            warn!(
                workspace = %caller.workspace,
                environment = %caller.environment,
                %host,
                port,
                offered = %offered.fingerprint,
                scanned = %seen,
                "the host key the workspace was offered differs from the one the environment sees; not trusting it"
            );
            return Vec::new();
        }

        let new = NewKnownHost {
            environment: caller.environment.clone(),
            host: host.clone(),
            port,
            key_type: offered.key_type.clone(),
            public_key: offered.base64.clone(),
            fingerprint: offered.fingerprint.clone(),
            first_workspace: Some(caller.workspace.to_string()),
            first_agent: caller.agent.clone(),
            first_user: caller.user.as_ref().map(ToString::to_string),
            added_by: None,
        };
        match self
            .store
            .known_host_record_first_use(new, self.clock.now())
            .await
        {
            Ok(Some(_)) => {
                info!(
                    workspace = %caller.workspace,
                    environment = %caller.environment,
                    %host,
                    port,
                    key = %offered.fingerprint,
                    "trusting a new SSH host on first use"
                );
                vec![request.key.clone()]
            }
            // Another connection recorded the host while the scan ran: judge against its key.
            Ok(None) => match self
                .store
                .known_hosts_for(&caller.environment, &host, port)
                .await
            {
                Ok(stored) if !stored.is_empty() => {
                    self.known(caller, &host, port, &offered, &stored).await
                }
                Ok(_) => Vec::new(),
                Err(error) => {
                    warn!(workspace = %caller.workspace, %error, "cannot read the known SSH hosts");
                    Vec::new()
                }
            },
            Err(error) => {
                warn!(workspace = %caller.workspace, %error, "cannot record the SSH host");
                Vec::new()
            }
        }
    }

    /// A host with stored keys: returns them, and stamps the one that matches the key offered or
    /// warns that none does.
    async fn known(
        &self,
        caller: &Caller,
        host: &str,
        port: u16,
        offered: &Offered,
        stored: &[KnownHost],
    ) -> Vec<Vec<u8>> {
        match stored.iter().find(|row| row.public_key == offered.base64) {
            Some(row) => {
                if let Err(error) = self
                    .store
                    .known_host_touch_used(row.id, self.clock.now())
                    .await
                {
                    warn!(workspace = %caller.workspace, %error, "cannot record the use of a known SSH host");
                }
            }
            None => {
                let known: Vec<_> = stored.iter().map(|row| row.fingerprint.as_str()).collect();
                warn!(
                    workspace = %caller.workspace,
                    environment = %caller.environment,
                    %host,
                    port,
                    offered = %offered.fingerprint,
                    known = %known.join(", "),
                    "the SSH host key changed: the workspace was offered a key that isn't the stored one"
                );
            }
        }
        blobs(stored)
    }
}

/// The stored keys as SSH wire blobs. A row whose key doesn't decode is skipped: nothing the
/// core stores is meant to be unreadable, but a damaged row must not fail the lookup.
fn blobs(stored: &[KnownHost]) -> Vec<Vec<u8>> {
    stored
        .iter()
        .filter_map(|row| STANDARD.decode(&row.public_key).ok())
        .collect()
}

/// The key a server offered, parsed.
struct Offered {
    key_type: String,
    base64: String,
    fingerprint: String,
}

impl Offered {
    /// `None` if the blob isn't a public key of `key_type`, or the type isn't one the core
    /// records.
    fn parse(key_type: &str, blob: &[u8]) -> Option<Self> {
        if !KEY_TYPES.contains(&key_type) {
            return None;
        }
        let key = PublicKey::from_bytes(blob).ok()?;
        if key.algorithm().as_str() != key_type {
            return None;
        }
        Some(Self {
            key_type: key_type.to_owned(),
            base64: STANDARD.encode(blob),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        })
    }
}

/// The host as stored: `ssh`'s `%H` is `[host]:port` for a port other than 22 and the plain host
/// otherwise, and the stored form is the lowercased host alone. `None` for text that isn't a host.
pub(crate) fn canonical_host(given: &str) -> Option<String> {
    let host = match given.strip_prefix('[') {
        Some(rest) => rest.split_once(']')?.0,
        None => given,
    };
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'%'));
    valid.then(|| host.to_ascii_lowercase())
}

/// A `known_hosts` line to pin, parsed.
struct Line {
    hosts: Vec<(String, u16)>,
    key_type: String,
    public_key: String,
    fingerprint: String,
}

fn parse_line(line: &str) -> Result<Line, KnownHostsError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(invalid("paste a known_hosts line: host, key type, and key"));
    }
    if line.lines().count() > 1 {
        return Err(invalid("paste one known_hosts line at a time"));
    }
    if line.starts_with('#') {
        return Err(invalid("that line is a comment"));
    }
    let mut fields = line.split_whitespace();
    let hosts = fields.next().unwrap_or_default();
    if hosts.starts_with('@') {
        return Err(invalid(
            "markers such as @cert-authority and @revoked aren't supported: \
             only a host and its key can be pinned",
        ));
    }
    let (Some(key_type), Some(key)) = (fields.next(), fields.next()) else {
        return Err(invalid(
            "a known_hosts line is a host, a key type, and a key",
        ));
    };
    if hosts.starts_with('|') {
        return Err(invalid(
            "hashed host names (|1|...) can't be pinned: Doozers needs to know which host the key is for",
        ));
    }
    if !KEY_TYPES.contains(&key_type) {
        return Err(invalid(format!(
            "{key_type} keys can't be pinned: use {}",
            KEY_TYPES.join(", ")
        )));
    }
    let blob = STANDARD
        .decode(key)
        .map_err(|_| invalid("the key isn't base64"))?;
    let public = PublicKey::from_bytes(&blob)
        .map_err(|_| invalid("the key isn't a valid SSH public key"))?;
    if public.algorithm().as_str() != key_type {
        return Err(invalid(format!(
            "the line says {key_type}, but the key is {}",
            public.algorithm().as_str()
        )));
    }

    let mut parsed = Vec::new();
    for pattern in hosts.split(',') {
        parsed.push(parse_host(pattern)?);
    }
    parsed.dedup();
    Ok(Line {
        hosts: parsed,
        key_type: key_type.to_owned(),
        public_key: STANDARD.encode(&blob),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// One host of a line: `host` (port 22) or `[host]:port`.
fn parse_host(pattern: &str) -> Result<(String, u16), KnownHostsError> {
    if pattern.starts_with('!') || pattern.contains(['*', '?']) {
        return Err(invalid(format!(
            "{pattern:?} is a wildcard or negated pattern: pin one host at a time"
        )));
    }
    let (host, port) = match pattern.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or_else(|| {
                invalid(format!(
                    "{pattern:?} has an opening bracket but no closing one"
                ))
            })?;
            let port = match after.strip_prefix(':') {
                Some(port) => port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| invalid(format!("{port:?} isn't a port")))?,
                None if after.is_empty() => 22,
                None => return Err(invalid(format!("{pattern:?} isn't a host"))),
            };
            (host, port)
        }
        None => (pattern, 22),
    };
    let host = canonical_host(host)
        .ok_or_else(|| invalid(format!("{pattern:?} isn't a host name or address")))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests;
