//! The toolsets stored in `giles.db`, and the one object that changes them (PLAN sections 7.10 and
//! 11.2): [`ToolsetManager`]. The web pages, the admin RPCs, and the CLI all go through it. See
//! `Docs/technical/toolsets.md`.
//!
//! A stored toolset is a remote MCP server. A web login must not be able to choose a program for
//! Giles to run on the host, its arguments, its environment, or its sandbox grants: installing
//! and running code on the host is the operator's, in `giles.toml`. Connecting to a remote server
//! is not.
//!
//! # Changes
//!
//! One async lock spans each change, as it does for [`Routes`](crate::routes::Routes): validate
//! the spec against the running configuration with its credentials read from the secret store
//! ([`validate_toolset`]), store the credentials, write the row, change the [`LiveConfig`], and
//! then add, replace, or remove the toolset in the [`ToolsetHost`], so the running core never
//! differs from what is stored for more than the change in progress. Nothing is written when the
//! spec is refused.
//!
//! The extra rules beyond `validate_toolset`:
//!
//! - the name `new` is reserved, because it is the address of the form for a new toolset;
//! - a name that a `[toolset.<name>]` table of `giles.toml` uses belongs to that toolset;
//! - the spec has `url` (`validate_toolset` then refuses the keys of a stdio server next to it);
//! - a credential is the value itself, which is stored in the secret store at the toolset's own
//!   path, or a reference to that path, `{ secret = "toolsets/<name>/bearer-token" }`
//!   ([`credentials`](super::credentials)). The row holds only the reference, so a value is never
//!   in the database's toolset rows, the process environment, or `giles toolset show`.
//!
//! # Secrets
//!
//! A stored toolset owns the secrets at `toolsets/<name>/...`. A change that stops referring to
//! one deletes it, removing the toolset deletes them all, and a rename moves them and the
//! references to them. At startup, a bearer token that is still in the row as text, or still
//! refers to `secrets.toml` (the ways before the secret store), is copied to the toolset's own
//! path, and the spec rewritten.
//!
//! Toolsets in `giles.toml` keep working beside the stored ones. They show up in
//! [`list`](ToolsetManager::list) as [`ToolsetSource::File`] and can't be changed here
//! ([`ToolsetManagerError::Unsupported`]).
//!
//! # Startup
//!
//! [`ToolsetManager::start`] validates every stored toolset as a change would and adds the ones
//! that pass. One that doesn't isn't started: it is kept as a failure with the reason, which the
//! admin service lists as a `Failed` instance (the manager is a [`PluginControl`]) and the pages
//! can show. Startup never fails on a stored toolset, and the owner fixes it in the web UI, which
//! needs Giles running. Saving a failed toolset starts it, so does restarting it
//! ([`retry`](ToolsetManager::retry)), and removing it deletes it.
//!
//! # Removal
//!
//! Removing a toolset stops it and takes it out of the registry and the live configuration. A
//! remote toolset has no data directory, and the tool-list cache never offers a remote server's
//! tools, so nothing else is cleaned up. Agents' `tools` and `ask` patterns that name the
//! toolset's tools are left alone.
//!
//! # Renaming
//!
//! A toolset's name is its tool prefix (`<name>__<tool>`) and the start of the globs that agents
//! use in `tools` and `ask`. [`ToolsetManager::rename`] changes both, under the lock and, after
//! that, the agent manager's lock (step 3 rewrites agents' files as an agent edit does, so the two
//! take turns), and [`ToolsetManager::rename_preview`] runs the same checks and says what would
//! change. A remote toolset has no data directory, so no data moves.
//!
//! 1. The new name must be valid and free among the toolsets (the stored ones and those of
//!    `giles.toml`), as for a new toolset. The old
//!    name is exempt, so a stored toolset can be renamed to its own name in another case. Then
//!    every agent's `agent.toml` is read: a glob that matches the toolset's tools without
//!    starting with `<old>__` (`github*`) can't be rewritten safely, and refuses the rename
//!    ([`ToolsetManagerError::Refused`]) with the globs listed. Those checks are the ones of
//!    `giles toolset rename` with Giles stopped, which share their code with this.
//! 2. The toolset is stopped: its tools leave the registry, so a running session that still
//!    lists them gets `tool unavailable`.
//! 3. The `<old>__` globs of each agent are rewritten in its `agent.toml` with the agent edit
//!    machinery (a temporary file renamed into place, only that file).
//! 4. The row is renamed.
//! 5. The toolset is renamed in the live configuration, each rewritten agent replaces the old
//!    one there, and the toolset is started under the new name. A failed stored toolset is
//!    renamed too (it is started if it validates now, and else stays failed under the new name);
//!    a stored toolset whose name a toolset of `giles.toml` took leaves the agents' globs under
//!    the name to that instance.
//!
//! A step that fails undoes the ones before it (the agents' files and the row are put back as
//! they were, the toolset starts again under the old name), and the error says what couldn't be
//! undone. Sessions that run keep the old tool names. Toolsets of `giles.toml` are
//! [`ToolsetManagerError::Unsupported`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use giles_store::{Store, StoredToolset};
use giles_types::Timestamp;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use super::credentials;
use super::host::ToolsetHost;
use super::oauth::OAuthContext;
use crate::admin::{PluginControl, PluginRunState, PluginRuntime};
use crate::config::{
    Builtins, Config, InstanceName, KeyPath, Kind, LiveConfig, LoadOptions, Secret, Secrets,
    ToolsetContext, ToolsetError, ToolsetInstance, ToolsetSpec, validate_toolset,
};
use crate::paths::DataRoot;
use crate::secrets::{SecretError, SecretPath, SecretProvider};

mod rename;
mod sign_in;

pub use self::rename::{AgentGlobChange, GlobChange, RenamePreview, ToolsetRenamed};
pub use self::sign_in::{SIGN_IN_TTL, SignInView};

/// The name the web form for a new toolset has in its address, so no toolset can use it.
pub const RESERVED_TOOLSET_NAME: &str = "new";

/// What [`ToolsetManager::start`] needs.
pub struct ToolsetManagerOptions {
    /// The database the toolsets are stored in.
    pub store: Store,
    /// The data root: `secrets.toml` (for moving old bearer tokens out of it), and the plugins'
    /// data directories that `skills` must not overlap.
    pub root: DataRoot,
    /// Where the toolsets' credentials are kept.
    pub secrets: Arc<dyn SecretProvider>,
    /// The running configuration, which stored toolsets are validated against and added to.
    pub config: LiveConfig,
    /// Where toolsets are started, replaced, and stopped.
    pub host: Arc<ToolsetHost>,
    /// The lock that [`AgentManagerOptions`](crate::agents::AgentManagerOptions) takes as `lock`,
    /// which [`ToolsetManager::rename`] holds while it rewrites agents' `agent.toml` files, so an
    /// edit of an agent waits for the rename and the rename for an edit.
    pub agent_lock: Arc<AsyncMutex<()>>,
}

/// Where a toolset is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolsetSource {
    /// In the database, made in the web UI or with the CLI.
    Stored {
        /// When it was added.
        created_at: Timestamp,
        /// When it was last changed. Give it back to [`ToolsetManager::update`] to refuse the
        /// update if the toolset changed since it was read.
        updated_at: Timestamp,
    },
    /// A `[toolset.<name>]` table of `giles.toml`, which can't be changed here.
    File,
}

/// One toolset, as a page shows it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ToolsetView {
    /// The name, as it was written (also the tool prefix).
    pub name: String,
    /// Where it is configured.
    pub source: ToolsetSource,
    /// The stored spec, to fill the edit form. Credentials are references (`Debug` leaves them
    /// out). `None` for a toolset of `giles.toml`, and for a stored one whose JSON can't be read
    /// ([`failure`](Self::failure) says why).
    pub spec: Option<ToolsetSpec>,
    /// Why a stored toolset isn't running: it failed validation at startup, or the change that
    /// should have started it failed. The reason never contains a secret value. `None` for a
    /// toolset that was started; how it is doing is in the supervision state.
    pub failure: Option<String>,
}

/// What [`ToolsetManager::remove`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Removed {
    /// The removed toolset's name, as it was stored.
    pub name: String,
}

/// Why a toolset wasn't added, changed, or removed. Nothing changed, except for
/// [`Store`](Self::Store), which can leave a change half done (the database says what it was).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolsetManagerError {
    /// The spec or the name is wrong.
    #[error("{}{reason}", key_prefix(.key))]
    Invalid {
        /// The key of the spec with the problem, as the `giles.toml` table writes it (`url`,
        /// `auth.bearer`), so a form can show the reason next to the field. The root if the
        /// problem is with the toolset as a whole: its name, or what it conflicts with.
        key: KeyPath,
        /// What is wrong. Never contains a secret value.
        reason: String,
    },
    /// A toolset with that name is stored already, ignoring ASCII case.
    #[error("there is already a toolset with that name")]
    Exists,
    /// There is no toolset with that name, e.g. it was removed in another tab.
    #[error("there is no such toolset")]
    NotFound,
    /// The toolset was changed since the caller read it.
    #[error("the toolset was changed since it was loaded")]
    Stale,
    /// A rename was refused although the new name is fine: something else stands in its way,
    /// and the reason says what the owner must change first (such as globs of an agent that
    /// match the toolset's tools without starting with `<name>__`, which are listed). Nothing
    /// changed.
    #[error("{reason}")]
    Refused {
        /// What stands in the way, naming each offending glob. Never contains a secret value.
        reason: String,
    },
    /// A step of a rename failed (moving the data, rewriting an agent's `agent.toml`, writing
    /// the row). The steps before it were undone, except what `undo_errors` lists.
    #[error("{}", failed_message(.step, .error, .undo_errors))]
    Failed {
        /// The step that failed.
        step: String,
        /// Why.
        error: String,
        /// Changes that couldn't be undone, which the owner puts right by hand.
        undo_errors: Vec<String>,
    },
    /// The toolset is configured in `giles.toml`, which Giles doesn't write: edit it there.
    #[error("this toolset is configured in giles.toml, so it can only be changed there")]
    Unsupported,
    /// The database failed.
    #[error("cannot store the toolsets: {0}")]
    Store(giles_store::Error),
    /// The secret store failed. The change may be half done, as for [`Store`](Self::Store).
    #[error("cannot keep the toolset's credentials: {0}")]
    Secrets(SecretError),
    /// A user's sign-in to a toolset couldn't start or finish. Nothing was stored.
    #[error("{0}")]
    SignIn(String),
}

fn failed_message(step: &str, error: &str, undo_errors: &[String]) -> String {
    if undo_errors.is_empty() {
        format!("{step}: {error}. Nothing was changed.")
    } else {
        format!(
            "{step}: {error}. Undoing the earlier steps failed too, so the rename is partly \
             done; put these right by hand: {}",
            undo_errors.join("; ")
        )
    }
}

fn key_prefix(key: &KeyPath) -> String {
    if key.is_root() {
        String::new()
    } else {
        format!("{key}: ")
    }
}

impl ToolsetManagerError {
    /// Whether the owner can fix it in the form (else it is a missing toolset or the server's
    /// problem).
    pub fn is_invalid_input(&self) -> bool {
        matches!(
            self,
            Self::Invalid { .. }
                | Self::Exists
                | Self::Stale
                | Self::Unsupported
                | Self::Refused { .. }
        )
    }

    fn invalid(error: ToolsetError) -> Self {
        Self::Invalid {
            key: error.key,
            reason: error.reason,
        }
    }

    fn whole(reason: impl Into<String>) -> Self {
        Self::Invalid {
            key: KeyPath::root(),
            reason: reason.into(),
        }
    }
}

impl From<SecretError> for ToolsetManagerError {
    fn from(error: SecretError) -> Self {
        Self::Secrets(error)
    }
}

impl From<giles_store::Error> for ToolsetManagerError {
    fn from(error: giles_store::Error) -> Self {
        match error {
            giles_store::Error::ToolsetExists => Self::Exists,
            giles_store::Error::NoSuchToolset => Self::NotFound,
            giles_store::Error::StaleToolset => Self::Stale,
            error => Self::Store(error),
        }
    }
}

/// The stored toolsets of this core: what is running and what failed.
#[derive(Debug, Default)]
struct State {
    /// The stored toolsets that are in the live configuration and the host.
    running: BTreeSet<String>,
    /// The stored toolsets that aren't, with the reason.
    failed: BTreeMap<String, String>,
}

/// The stored toolsets, and the one place that changes them. One per core; see the module docs.
pub struct ToolsetManager {
    store: Store,
    root: DataRoot,
    secrets: Arc<dyn SecretProvider>,
    /// Users' sign-ins to the toolsets that sign each user in.
    oauth: Arc<OAuthContext>,
    /// The sign-ins started and not finished, by `state`.
    pending: Mutex<BTreeMap<String, sign_in::Pending>>,
    config: LiveConfig,
    host: Arc<ToolsetHost>,
    /// Held by [`rename`](Self::rename) after `changing`, which keeps agents from being changed
    /// while their files are rewritten. Shared with the agent manager, which never takes
    /// `changing`, so the two locks can't deadlock.
    agent_lock: Arc<AsyncMutex<()>>,
    /// Held for the whole of each change.
    changing: AsyncMutex<()>,
    /// Written only under `changing`; read by the admin service without it.
    state: Mutex<State>,
    /// This manager, for the restart that [`PluginControl::restart`] starts in the background.
    me: Weak<Self>,
}

impl fmt::Debug for ToolsetManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolsetManager").finish_non_exhaustive()
    }
}

/// What a stored name is, to the manager.
enum Target {
    Stored(StoredToolset),
    File,
    Missing,
}

impl ToolsetManager {
    /// Validates every stored toolset and adds the ones that pass to the live configuration and
    /// the host. A toolset that fails isn't started; it is logged and reported as failed (see the
    /// module docs). Call it once the host has started the toolsets of `giles.toml`, before the
    /// sessions recover, so the toolsets are registered in time.
    ///
    /// # Errors
    ///
    /// The database couldn't be read. Never a toolset's fault.
    pub async fn start(options: ToolsetManagerOptions) -> Result<Arc<Self>, giles_store::Error> {
        let ToolsetManagerOptions {
            store,
            root,
            secrets,
            config,
            host,
            agent_lock,
        } = options;
        let oauth = Arc::new(OAuthContext::new(secrets.clone()));
        let manager = Arc::new_cyclic(|me| Self {
            store,
            root,
            secrets,
            oauth,
            pending: Mutex::default(),
            config,
            host,
            agent_lock,
            changing: AsyncMutex::new(()),
            state: Mutex::new(State::default()),
            me: me.clone(),
        });
        {
            let _changing = manager.changing.lock().await;
            manager.move_tokens_into_the_store().await?;
            for row in manager.store.toolsets().await? {
                if let Err(reason) = manager.start_stored(&row).await {
                    warn!(toolset = %row.name, %reason, "a stored toolset is not started");
                    manager.set_failed(&row.name, reason);
                }
            }
        }
        Ok(manager)
    }

    /// Every toolset, stored and from `giles.toml`, ordered by name ignoring case.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::Store`] if the database can't be read.
    pub async fn list(&self) -> Result<Vec<ToolsetView>, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        let mut views: Vec<ToolsetView> = rows.iter().map(|row| self.view_of(row)).collect();
        {
            let state = lock(&self.state);
            views.extend(
                self.config
                    .get()
                    .toolsets
                    .keys()
                    .filter(|name| !state.running.contains(name.as_str()))
                    .map(|name| file_view(name.as_str())),
            );
        }
        views.sort_by(|a, b| {
            let key = |view: &ToolsetView| (view.name.to_ascii_lowercase(), view.name.clone());
            key(a).cmp(&key(b))
        });
        Ok(views)
    }

    /// The toolset called `name`, ignoring ASCII case.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if there is none; [`ToolsetManagerError::Store`] if the
    /// database can't be read.
    pub async fn get(&self, name: &str) -> Result<ToolsetView, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        match self.target(&rows, name) {
            Target::Stored(row) => Ok(self.view_of(&row)),
            Target::File => {
                let config = self.config.get();
                let own = config
                    .toolsets
                    .keys()
                    .find(|other| other.as_str().eq_ignore_ascii_case(name))
                    .map_or(name, InstanceName::as_str);
                Ok(file_view(own))
            }
            Target::Missing => Err(ToolsetManagerError::NotFound),
        }
    }

    /// Adds the toolset `name` with `spec`: validates it, stores it, and starts it.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::Exists`] if a stored toolset has the name, ignoring ASCII case;
    /// [`ToolsetManagerError::Invalid`] if the name or the spec is refused (the key says where),
    /// including a name that a toolset of `giles.toml` uses; [`ToolsetManagerError::Store`] if the
    /// database failed. Nothing is stored unless the toolset is added. If the row is stored but
    /// the toolset can't be started after all, the error is `Invalid` at the root and the toolset
    /// is failed.
    pub async fn add(
        &self,
        name: &str,
        spec: &ToolsetSpec,
    ) -> Result<ToolsetView, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        if rows.iter().any(|row| row.name.eq_ignore_ascii_case(name)) {
            return Err(ToolsetManagerError::Exists);
        }
        let (spec, literals) = self.prepare(name, spec)?;
        let values = self.credential_values(&spec, &literals).await?;
        let instance = self
            .check(name, &spec, None, values)
            .map_err(ToolsetManagerError::invalid)?;
        let json = to_json(&spec)?;
        // Left over from a toolset of the same name whose secrets couldn't all be deleted.
        self.prune(name, &[], false).await?;
        self.put_literals(&literals).await?;
        let row = match self
            .store
            .toolset_insert(name, &json, Timestamp::now())
            .await
        {
            Ok(row) => row,
            Err(error) => {
                if let Err(undo) = self.prune(name, &[], false).await {
                    warn!(toolset = %name, error = %undo, "cannot delete the secrets of a toolset that wasn't added");
                }
                return Err(error.into());
            }
        };
        self.apply(&row.name, instance, false)
            .await
            .map_err(ToolsetManagerError::whole)?;
        Ok(self.view_of(&row))
    }

    /// Replaces the spec of the stored toolset `name`, and restarts it with the new one. A
    /// toolset that failed to start is started. With `expected_updated_at`, the update is
    /// refused if the toolset changed since the caller read that time
    /// (the `updated_at` of its [`ToolsetSource::Stored`]).
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if no stored toolset has the name;
    /// [`ToolsetManagerError::Unsupported`] if the name is a toolset of `giles.toml`;
    /// [`ToolsetManagerError::Stale`]; [`ToolsetManagerError::Invalid`] as for
    /// [`add`](Self::add); [`ToolsetManagerError::Store`]. Nothing changes unless the toolset is
    /// updated.
    pub async fn update(
        &self,
        name: &str,
        spec: &ToolsetSpec,
        expected_updated_at: Option<Timestamp>,
    ) -> Result<ToolsetView, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        let old = match self.target(&rows, name) {
            Target::Stored(row) => row,
            Target::File => return Err(ToolsetManagerError::Unsupported),
            Target::Missing => return Err(ToolsetManagerError::NotFound),
        };
        if expected_updated_at.is_some_and(|expected| expected != old.updated_at) {
            return Err(ToolsetManagerError::Stale);
        }
        let running = lock(&self.state).running.contains(&old.name);
        let replacing = running
            .then(|| InstanceName::new(old.name.as_str()).ok())
            .flatten();
        let (spec, literals) = self.prepare(&old.name, spec)?;
        // A stored credential goes only to the server it was given for. Pointing the toolset at
        // another server takes the credentials typed again, and drops the users' sign-ins.
        let old_url = ToolsetSpec::from_json(&old.spec)
            .ok()
            .and_then(|old| old.url);
        let other_server = credentials::other_server(old_url.as_deref(), spec.url.as_deref());
        if other_server
            && let Some((key, _)) = credentials::reference_keys(&spec)
                .into_iter()
                .find(|(_, path)| !literals.iter().any(|(given, _)| given.as_str() == path))
        {
            return Err(ToolsetManagerError::Invalid {
                key,
                reason: "the URL now points at another server: enter the credential again, so \
                         the stored one isn't sent there"
                    .to_owned(),
            });
        }
        let values = self.credential_values(&spec, &literals).await?;
        let instance = self
            .check(&old.name, &spec, replacing.as_ref(), values)
            .map_err(ToolsetManagerError::invalid)?;
        let json = to_json(&spec)?;
        self.put_literals(&literals).await?;
        let row = self
            .store
            .toolset_update(&old.name, &json, expected_updated_at, Timestamp::now())
            .await?;
        self.prune(
            &row.name,
            &credentials::references(&spec),
            credentials::signs_users_in(&spec) && !other_server,
        )
        .await?;
        self.apply(&row.name, instance, running)
            .await
            .map_err(ToolsetManagerError::whole)?;
        Ok(self.view_of(&row))
    }

    /// Starts the stored toolset `name` again if it isn't running: reads its credentials again and
    /// validates the stored spec against the running configuration, as startup did, and adds the
    /// toolset if it passes. The view says what became of it: no `failure` if it started, else
    /// the reason it still can't (which replaces the old one). A toolset that is running is left
    /// to the host (restarting it is the host's [`PluginControl::restart`]) and returned as it is.
    /// This is what restarting a failed stored toolset does.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if no stored toolset has the name;
    /// [`ToolsetManagerError::Unsupported`] if the name is a toolset of `giles.toml`;
    /// [`ToolsetManagerError::Store`].
    pub async fn retry(&self, name: &str) -> Result<ToolsetView, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        let row = match self.target(&rows, name) {
            Target::Stored(row) => row,
            Target::File => return Err(ToolsetManagerError::Unsupported),
            Target::Missing => return Err(ToolsetManagerError::NotFound),
        };
        let failed = lock(&self.state).failed.contains_key(&row.name);
        if failed && let Err(reason) = self.start_stored(&row).await {
            warn!(toolset = %row.name, %reason, "a stored toolset is still not started");
            self.set_failed(&row.name, reason);
        }
        Ok(self.view_of(&row))
    }

    /// Removes the stored toolset `name`: deletes the row, stops it, and withdraws its tools from
    /// new sessions (a call running on it fails as unavailable, and so does a call to its tool
    /// from a session that still lists it).
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if no stored toolset has the name;
    /// [`ToolsetManagerError::Unsupported`] if the name is a toolset of `giles.toml`;
    /// [`ToolsetManagerError::Store`].
    pub async fn remove(&self, name: &str) -> Result<Removed, ToolsetManagerError> {
        let _changing = self.changing.lock().await;
        let rows = self.store.toolsets().await?;
        let row = match self.target(&rows, name) {
            Target::Stored(row) => row,
            Target::File => return Err(ToolsetManagerError::Unsupported),
            Target::Missing => return Err(ToolsetManagerError::NotFound),
        };
        if !self.store.toolset_remove(&row.name).await? {
            return Err(ToolsetManagerError::NotFound);
        }
        if let Err(error) = self.prune(&row.name, &[], false).await {
            // The row is gone, so the toolset is; its secrets are deleted again when a toolset of
            // the name is added.
            warn!(toolset = %row.name, %error, "cannot delete a removed toolset's secrets");
        }
        let running = {
            let mut state = lock(&self.state);
            state.failed.remove(&row.name);
            state.running.remove(&row.name)
        };
        if running && let Ok(instance) = InstanceName::new(row.name.as_str()) {
            self.config.remove_toolset(&instance);
            self.host.remove(&instance).await;
        }
        info!(toolset = %row.name, "stored toolset removed");
        Ok(Removed { name: row.name })
    }

    /// What `name` is: a stored toolset (the name matches ignoring ASCII case), one of
    /// `giles.toml`, or nothing.
    fn target(&self, rows: &[StoredToolset], name: &str) -> Target {
        if let Some(row) = rows.iter().find(|row| row.name.eq_ignore_ascii_case(name)) {
            return Target::Stored(row.clone());
        }
        let state = lock(&self.state);
        let config = self.config.get();
        let file = config.toolsets.keys().any(|other| {
            other.as_str().eq_ignore_ascii_case(name) && !state.running.contains(other.as_str())
        });
        if file { Target::File } else { Target::Missing }
    }

    fn view_of(&self, row: &StoredToolset) -> ToolsetView {
        let spec = ToolsetSpec::from_json(&row.spec);
        let mut failure = lock(&self.state).failed.get(&row.name).cloned();
        if failure.is_none()
            && let Err(error) = &spec
        {
            failure = Some(damaged(error));
        }
        ToolsetView {
            name: row.name.clone(),
            source: ToolsetSource::Stored {
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
            spec: spec.ok(),
            failure,
        }
    }

    /// Everything that must hold for the toolset `name` with `spec` to be used, as the web UI and
    /// startup both ask it. `replacing` is the toolset's own running instance, when it is edited.
    /// `values` are the credentials the spec refers to, by path ([`credential_values`]).
    ///
    /// [`credential_values`]: Self::credential_values
    fn check(
        &self,
        name: &str,
        spec: &ToolsetSpec,
        replacing: Option<&InstanceName>,
        values: BTreeMap<String, Secret>,
    ) -> Result<ToolsetInstance, ToolsetError> {
        self.check_name(name)?;
        let config = self.config.get();
        remote_only(spec)?;
        let secrets = Secrets::from_store(values);
        // A remote toolset has no command to find, no `{ env = ... }` reference (`remote_only`
        // refused it), and no grants: nothing to look up in the environment or check against
        // the `giles` binary.
        let options = LoadOptions {
            builtins: Builtins::V1,
            env: &no_env,
            giles_exe: None,
        };
        validate_toolset(
            name,
            spec,
            &ToolsetContext {
                root: &self.root,
                secrets: &secrets,
                options: &options,
                config: &config,
                replacing,
            },
        )
    }

    /// What must hold for `name` to be a toolset's name, before the spec is looked at: it isn't
    /// the address of the form for a new toolset and no toolset of `giles.toml` has it. Whether
    /// another stored toolset has it is the caller's business.
    fn check_name(&self, name: &str) -> Result<(), ToolsetError> {
        let whole = |reason: String| ToolsetError {
            key: KeyPath::root(),
            reason,
        };
        if name.eq_ignore_ascii_case(RESERVED_TOOLSET_NAME) {
            return Err(whole(format!(
                "{RESERVED_TOOLSET_NAME:?} can't be a toolset's name: it is the address of the form for a \
                 new toolset"
            )));
        }
        let config = self.config.get();
        // The names before the spec: a name `giles.toml` has is that toolset's whatever the
        // spec says.
        if let Some(other) = self.file_toolset(&config, name) {
            return Err(whole(format!(
                "the name is taken by `[toolset.{other}]` in giles.toml"
            )));
        }
        Ok(())
    }

    /// The toolset of `giles.toml`, the ones that aren't stored, whose name is `name` ignoring
    /// ASCII case. A provider or a channel with the name is another instance and doesn't count.
    fn file_toolset(&self, config: &Config, name: &str) -> Option<String> {
        let state = lock(&self.state);
        config
            .toolsets
            .keys()
            .filter(|other| !state.running.contains(other.as_str()))
            .find(|other| other.as_str().eq_ignore_ascii_case(name))
            .map(ToString::to_string)
    }

    /// Puts a validated `instance` of the stored toolset `name` into the live configuration and
    /// the host: a replacement if `running`, else an addition. A failure leaves the toolset
    /// failed, and says why, with the live configuration as the failure left it: the host
    /// unregisters a toolset it can't start, so the entry is taken out again
    /// ([`withdraw`](Self::withdraw)).
    async fn apply(
        &self,
        name: &str,
        instance: ToolsetInstance,
        running: bool,
    ) -> Result<(), String> {
        let changed = if running {
            self.config
                .replace_toolset(instance.clone())
                .map(drop)
                .map_err(|error| error.to_string())
        } else {
            self.config
                .add_toolset(instance.clone())
                .map(drop)
                .map_err(|error| error.to_string())
        };
        if let Err(reason) = changed {
            // The configuration is as it was. A replaced toolset that it didn't have is still in
            // the host.
            if running {
                self.host.remove(&instance.name).await;
            }
            self.set_failed(name, reason.clone());
            return Err(reason);
        }
        let started = if running {
            self.host.replace(&instance).await
        } else {
            self.host.add(&instance).await
        };
        if let Err(error) = started {
            let reason = error.to_string();
            self.withdraw(name, reason.clone());
            return Err(reason);
        }
        let mut state = lock(&self.state);
        state.failed.remove(name);
        state.running.insert(name.to_owned());
        Ok(())
    }

    /// A stored toolset that is in the live configuration but can't run (the host refused it):
    /// takes it out of the configuration and records `reason`, so it shows as failed, a name
    /// that is free again, and not as a toolset of `giles.toml`.
    pub(super) fn withdraw(&self, name: &str, reason: String) {
        if let Ok(instance) = InstanceName::new(name) {
            self.config.remove_toolset(&instance);
        }
        self.set_failed(name, reason);
    }

    /// Startup: validates the stored `row` and adds it, or says why not.
    async fn start_stored(&self, row: &StoredToolset) -> Result<(), String> {
        let spec = ToolsetSpec::from_json(&row.spec).map_err(|error| damaged(&error))?;
        let (spec, literals) = self
            .prepare(&row.name, &spec)
            .map_err(|error| error.to_string())?;
        if !literals.is_empty() {
            return Err(damaged(&ToolsetError {
                key: KeyPath::root().key("auth"),
                reason: "holds a credential instead of a reference to the secret store".to_owned(),
            }));
        }
        let values = self
            .credential_values(&spec, &[])
            .await
            .map_err(|error| error.to_string())?;
        let instance = self
            .check(&row.name, &spec, None, values)
            .map_err(|error| error.to_string())?;
        self.apply(&row.name, instance, false).await
    }

    /// `spec` as it will be stored for the toolset `name`, with the literal credentials moved out
    /// to be stored at their paths ([`credentials::take_literals`]).
    fn prepare(
        &self,
        name: &str,
        spec: &ToolsetSpec,
    ) -> Result<(ToolsetSpec, Vec<(SecretPath, Secret)>), ToolsetManagerError> {
        let mut spec = spec.clone();
        let literals =
            credentials::take_literals(name, &mut spec).map_err(ToolsetManagerError::invalid)?;
        Ok((spec, literals))
    }

    /// The credentials `spec` refers to, by path: `literals` about to be stored, and the rest read
    /// from the secret store. A missing one is left out, for validation to report.
    async fn credential_values(
        &self,
        spec: &ToolsetSpec,
        literals: &[(SecretPath, Secret)],
    ) -> Result<BTreeMap<String, Secret>, ToolsetManagerError> {
        let mut values: BTreeMap<String, Secret> = literals
            .iter()
            .map(|(path, value)| (path.to_string(), value.clone()))
            .collect();
        for path in credentials::references(spec) {
            if values.contains_key(&path) {
                continue;
            }
            let Ok(secret) = SecretPath::new(path.as_str()) else {
                continue;
            };
            if let Some(value) = self.secrets.get(&secret).await? {
                values.insert(path, value);
            }
        }
        Ok(values)
    }

    /// Stores each literal credential at its path.
    async fn put_literals(
        &self,
        literals: &[(SecretPath, Secret)],
    ) -> Result<(), ToolsetManagerError> {
        for (path, value) in literals {
            self.secrets.put(path, value, None).await?;
        }
        Ok(())
    }

    /// Deletes the secrets the toolset `name` owns, except those at the paths in `keep`, and the
    /// users' tokens if `keep_tokens`.
    async fn prune(
        &self,
        name: &str,
        keep: &[String],
        keep_tokens: bool,
    ) -> Result<(), ToolsetManagerError> {
        for path in credentials::owned(self.secrets.as_ref(), name).await? {
            let token = credentials::token_owner(&path).is_some();
            if !(keep.iter().any(|kept| kept == path.as_str()) || keep_tokens && token) {
                self.secrets.delete(&path).await?;
            }
        }
        Ok(())
    }

    /// Moves the bearer tokens of stored toolsets that are still kept the ways before the secret
    /// store, as text in the row or as a reference to `secrets.toml`, into the store at the
    /// toolset's own path, and rewrites the spec to refer to it there. A toolset whose secret
    /// isn't in `secrets.toml` is left as it is, to fail validation with the reason.
    async fn move_tokens_into_the_store(&self) -> Result<(), giles_store::Error> {
        let mut file: Option<Secrets> = None;
        for row in self.store.toolsets().await? {
            let Ok(mut spec) = ToolsetSpec::from_json(&row.spec) else {
                continue;
            };
            let Some(bearer) = spec
                .auth
                .as_ref()
                .and_then(|auth| auth.get("bearer"))
                .cloned()
            else {
                continue;
            };
            let Ok(own) = credentials::toolset_path(&row.name, credentials::BEARER_TOKEN) else {
                continue;
            };
            let (value, from) = match &bearer {
                toml::Value::String(text) => (Secret::new(text.as_str()), "the toolset's row"),
                other => {
                    let Some(name) = other.get("secret").and_then(toml::Value::as_str) else {
                        continue;
                    };
                    if name == own.as_str() {
                        continue;
                    }
                    let secrets = match &file {
                        Some(secrets) => secrets,
                        None => match Secrets::load(&self.root.secrets_file()) {
                            Ok(secrets) => file.insert(secrets),
                            Err(error) => {
                                warn!(%error, "cannot read secrets.toml to move toolset tokens out of it");
                                continue;
                            }
                        },
                    };
                    let Some(value) = secrets.get(name) else {
                        continue;
                    };
                    (value.clone(), "secrets.toml")
                }
            };
            if let Err(error) = self.secrets.put(&own, &value, None).await {
                warn!(toolset = %row.name, %error, "cannot move a toolset's token into the secret store");
                continue;
            }
            if let Some(auth) = spec.auth.as_mut().and_then(toml::Value::as_table_mut) {
                auth.insert(
                    "bearer".to_owned(),
                    toml::Value::Table(toml::Table::from_iter([(
                        "secret".to_owned(),
                        toml::Value::String(own.to_string()),
                    )])),
                );
            }
            let Ok(json) = serde_json::to_string(&spec) else {
                continue;
            };
            self.store
                .toolset_update(&row.name, &json, None, Timestamp::now())
                .await?;
            info!(toolset = %row.name, from, to = %own, "moved a toolset's bearer token into the secret store");
        }
        Ok(())
    }

    fn set_failed(&self, name: &str, reason: String) {
        let mut state = lock(&self.state);
        state.running.remove(name);
        state.failed.insert(name.to_owned(), reason);
    }
}

/// What the admin service sees of the stored toolsets that aren't running: each one, `Failed`
/// with the reason. The running ones are the toolset host's.
impl PluginControl for ToolsetManager {
    fn plugins(&self) -> Vec<PluginRuntime> {
        lock(&self.state)
            .failed
            .iter()
            .filter_map(|(name, reason)| {
                Some(PluginRuntime {
                    kind: Kind::Toolset,
                    instance: InstanceName::new(name.as_str()).ok()?,
                    binary: None,
                    state: PluginRunState::Failed,
                    restarts: 0,
                    last_error: Some(reason.clone()),
                    version: None,
                    requested_grants: None,
                    tool_count: Some(0),
                })
            })
            .collect()
    }

    /// Tries a failed stored toolset again, in the background ([`retry`](ToolsetManager::retry)):
    /// it starts if it validates now (a secret was added to `secrets.toml`, say), and else stays
    /// failed with the new reason. `true` means the request was accepted; `false` is for an
    /// instance that isn't a failed stored toolset (a running one is the host's, and another
    /// kind isn't a toolset), or when there is no async runtime to run it on.
    fn restart(&self, kind: Kind, instance: &str) -> bool {
        if kind != Kind::Toolset || !lock(&self.state).failed.contains_key(instance) {
            return false;
        }
        let (Some(manager), Ok(runtime)) =
            (self.me.upgrade(), tokio::runtime::Handle::try_current())
        else {
            return false;
        };
        let name = instance.to_owned();
        runtime.spawn(async move {
            if let Err(error) = manager.retry(&name).await {
                warn!(toolset = %name, %error, "cannot restart a stored toolset");
            }
        });
        true
    }
}

/// What a stored toolset must be beyond a valid `[toolset.<name>]` table: a remote server.
/// `validate_toolset` refuses the keys of a stdio server next to `url`, and the shape of `auth`;
/// [`credentials::take_literals`] made its credentials references to the toolset's own secrets.
fn remote_only(spec: &ToolsetSpec) -> Result<(), ToolsetError> {
    if spec.url.is_none() {
        return Err(ToolsetError {
            key: KeyPath::root().key("url"),
            reason: "a stored toolset is a remote server: set `url`. Configure a stdio server as \
                     `[toolset.<name>]` in giles.toml"
                .to_owned(),
        });
    }
    Ok(())
}

/// The environment of a stored toolset's validation: empty, since a remote toolset has nothing to
/// look up there.
fn no_env(_: &str) -> Option<OsString> {
    None
}

fn file_view(name: &str) -> ToolsetView {
    ToolsetView {
        name: name.to_owned(),
        source: ToolsetSource::File,
        spec: None,
        failure: None,
    }
}

fn damaged(error: &ToolsetError) -> String {
    format!("the stored spec can't be read: {error}")
}

/// The spec as stored: the keys of a `[toolset.<name>]` table, as JSON.
fn to_json(spec: &ToolsetSpec) -> Result<String, ToolsetManagerError> {
    serde_json::to_string(spec)
        .map_err(|error| ToolsetManagerError::whole(format!("cannot be stored: {error}")))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
