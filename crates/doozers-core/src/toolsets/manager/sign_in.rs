//! Users' sign-ins to the stored toolsets that sign each user in (`auth.oauth`):
//! [`ToolsetManager::sign_ins`], [`begin_sign_in`](ToolsetManager::begin_sign_in),
//! [`finish_sign_in`](ToolsetManager::finish_sign_in), and
//! [`sign_out`](ToolsetManager::sign_out).
//!
//! A sign-in has two halves. The first discovers the server's authorization server and makes the
//! URL to send the user to; it is remembered, by its `state`, for [`SIGN_IN_TTL`]. The second gets
//! the code back from the user's browser, exchanges it for tokens, and stores them in the user's
//! own space of the secret store. Either half may wait on the network, so neither holds the
//! manager's lock.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use doozers_types::{Timestamp, UserId};
use tracing::info;

use super::{ToolsetManager, ToolsetManagerError, lock};
use crate::admin::PluginControl;
use crate::config::{Auth, InstanceName, Kind, ToolsetSpec, ToolsetTransport};
use crate::toolsets::credentials;
use crate::toolsets::oauth::SignIn;

/// How long a started sign-in waits for the user to come back.
pub const SIGN_IN_TTL: Duration = Duration::from_secs(10 * 60);

/// Sign-ins one user may have waiting at once; their oldest is dropped beyond it, so no user can
/// push out another's.
const MAX_PENDING_PER_USER: usize = 4;

/// Sign-ins waiting at once, across all users; the oldest is dropped beyond it.
const MAX_PENDING: usize = 256;

/// A started sign-in.
pub(super) struct Pending {
    user: UserId,
    toolset: String,
    sign_in: Arc<SignIn>,
    started: Instant,
}

/// A stored toolset that signs each user in, as one user sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignInView {
    /// The toolset's name.
    pub name: String,
    /// When the user's tokens were last stored (signing in, or a refresh), if they are signed in.
    pub signed_in: Option<Timestamp>,
    /// Why the toolset can't be used at all, if it can't: it failed to start.
    pub failure: Option<String>,
}

impl ToolsetManager {
    /// The stored toolsets that sign each user in, ordered by name ignoring case, and whether
    /// `user` is signed in to each.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::Store`] or [`ToolsetManagerError::Secrets`].
    pub async fn sign_ins(&self, user: &UserId) -> Result<Vec<SignInView>, ToolsetManagerError> {
        let rows = self.store.toolsets().await?;
        let mut views = Vec::new();
        for row in rows {
            let Ok(spec) = ToolsetSpec::from_json(&row.spec) else {
                continue;
            };
            if !credentials::signs_users_in(&spec) {
                continue;
            }
            let signed_in = match credentials::user_token_path(user, &row.name) {
                Ok(path) => self
                    .secrets
                    .metadata(&path)
                    .await?
                    .map(|metadata| metadata.updated_at),
                Err(_) => None,
            };
            views.push(SignInView {
                failure: lock(&self.state).failed.get(&row.name).cloned(),
                name: row.name,
                signed_in,
            });
        }
        views.sort_by_key(|view| view.name.to_ascii_lowercase());
        Ok(views)
    }

    /// Starts `user`'s sign-in to the stored toolset `name`, coming back to `redirect_uri` of the
    /// toolset's name as stored. Each toolset has a callback of its own, so a code from another
    /// toolset's authorization server can't be finished as this one's (a mix-up). Returns the
    /// authorization server's URL to send the user's browser to.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if no running stored toolset has the name;
    /// [`ToolsetManagerError::SignIn`] if it doesn't sign users in, or the sign-in can't start.
    pub async fn begin_sign_in(
        &self,
        name: &str,
        user: &UserId,
        redirect_uri: &(dyn Fn(&str) -> String + Sync),
    ) -> Result<String, ToolsetManagerError> {
        let (instance, remote, oauth) = {
            let config = self.config.get();
            let instance = config
                .toolsets
                .values()
                .find(|instance| {
                    instance.name.as_str().eq_ignore_ascii_case(name)
                        && lock(&self.state).running.contains(instance.name.as_str())
                })
                .ok_or(ToolsetManagerError::NotFound)?;
            let ToolsetTransport::Http(remote) = &instance.transport else {
                return Err(not_signing_in(&instance.name));
            };
            let Some(Auth::UserOAuth(oauth)) = &remote.auth else {
                return Err(not_signing_in(&instance.name));
            };
            (instance.name.clone(), remote.clone(), (**oauth).clone())
        };
        let sign_in = self
            .oauth
            .begin_sign_in(
                instance.as_str(),
                &remote.url,
                &oauth,
                user,
                &redirect_uri(instance.as_str()),
            )
            .await
            .map_err(ToolsetManagerError::SignIn)?;
        let url = sign_in.url().to_owned();
        let mut pending = lock(&self.pending);
        pending.retain(|_, waiting| waiting.started.elapsed() < SIGN_IN_TTL);
        let oldest = |pending: &BTreeMap<String, Pending>, mine: bool| {
            pending
                .iter()
                .filter(|(_, waiting)| !mine || waiting.user == *user)
                .min_by_key(|(_, waiting)| waiting.started)
                .map(|(state, _)| state.clone())
        };
        while pending
            .values()
            .filter(|waiting| waiting.user == *user)
            .count()
            >= MAX_PENDING_PER_USER
            && let Some(state) = oldest(&pending, true)
        {
            pending.remove(&state);
        }
        while pending.len() >= MAX_PENDING
            && let Some(state) = oldest(&pending, false)
        {
            pending.remove(&state);
        }
        pending.insert(
            sign_in.state().to_owned(),
            Pending {
                user: user.clone(),
                toolset: instance.to_string(),
                sign_in: Arc::new(sign_in),
                started: Instant::now(),
            },
        );
        Ok(url)
    }

    /// Finishes the sign-in that `state` names with the `code` the authorization server sent
    /// back to the callback of the toolset `name` (and its `iss`, if any): stores `user`'s tokens
    /// and restarts the toolset, so it lists its tools over a signed-in user's connection.
    /// Returns the toolset's name.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::SignIn`] if no sign-in of `user` to `name` waits under `state` (it
    /// expired, was finished, is another user's, or is another toolset's), or the server refused
    /// the code. A sign-in that came back to another toolset's callback is dropped.
    pub async fn finish_sign_in(
        &self,
        name: &str,
        user: &UserId,
        state: &str,
        code: &str,
        issuer: Option<&str>,
    ) -> Result<String, ToolsetManagerError> {
        let waiting = {
            let mut pending = lock(&self.pending);
            match pending.remove(state) {
                Some(waiting)
                    if waiting.user == *user && waiting.started.elapsed() < SIGN_IN_TTL =>
                {
                    waiting
                }
                Some(other) if other.user != *user => {
                    // Someone else's: leave it for them.
                    pending.insert(state.to_owned(), other);
                    return Err(expired());
                }
                _ => return Err(expired()),
            }
        };
        if !waiting.toolset.eq_ignore_ascii_case(name) {
            return Err(ToolsetManagerError::SignIn(format!(
                "this sign-in was for `{}`, but came back to the callback of `{name}`; start it \
                 again",
                waiting.toolset
            )));
        }
        waiting
            .sign_in
            .finish(code, issuer)
            .await
            .map_err(ToolsetManagerError::SignIn)?;
        info!(toolset = %waiting.toolset, %user, "signed in to a toolset");
        self.host.restart(Kind::Toolset, &waiting.toolset);
        Ok(waiting.toolset)
    }

    /// Signs `user` out of the stored toolset `name`: deletes their tokens, and restarts the
    /// toolset, which drops their connection.
    ///
    /// # Errors
    ///
    /// [`ToolsetManagerError::NotFound`] if no stored toolset has the name;
    /// [`ToolsetManagerError::Secrets`].
    pub async fn sign_out(&self, name: &str, user: &UserId) -> Result<String, ToolsetManagerError> {
        let rows = self.store.toolsets().await?;
        let row = rows
            .into_iter()
            .find(|row| row.name.eq_ignore_ascii_case(name))
            .ok_or(ToolsetManagerError::NotFound)?;
        let path =
            credentials::user_token_path(user, &row.name).map_err(ToolsetManagerError::SignIn)?;
        if self.secrets.delete(&path).await? {
            info!(toolset = %row.name, %user, "signed out of a toolset");
            self.host.restart(Kind::Toolset, &row.name);
        }
        Ok(row.name)
    }
}

fn not_signing_in(name: &InstanceName) -> ToolsetManagerError {
    ToolsetManagerError::SignIn(format!(
        "the MCP server `{name}` doesn't sign users in: it has no `auth.oauth`"
    ))
}

fn expired() -> ToolsetManagerError {
    ToolsetManagerError::SignIn(
        "this sign-in has expired or was already used; start it again".to_owned(),
    )
}
