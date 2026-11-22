//! The sign-in methods the login and setup pages offer: the seam each method plugs into.
//!
//! A method that signs in through a link contributes an entry to [`WebApp::login_options`], the way
//! to use it on the login page, and every method that a user can add contributes one to
//! [`WebApp::setup_options`], the way to add it on the setup page. The password has no entry in the
//! first, because its form is on the login page itself
//! ([`password_collapsed`](WebApp::password_collapsed)); its setup page is in
//! [`password_pages`](super::password_pages). The login page always says how to use an invite or
//! recovery link.
//!
//! Adding, changing, or removing a sign-in method is allowed only from a session that came from an
//! invite or recovery link, or one the user re-verified in the last [`STEP_UP_TTL`]
//! ([`WebApp::sign_in_change`]). The Account and setup pages always show the controls; a page
//! that is refused answers with [`sign_in_again`], and [`reverify`](super::reverify) is where
//! they sign in again.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use doozers_store::SignInMethod;

use super::auth::{Login, WebUser};
use super::pages::{WebApp, no_store};
use super::passkey_pages::json_error;
use super::reverify::{Target, reverify_href};

/// A sign-in method a user can add to their account, as the setup page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupOption {
    /// Its name, such as `Passkey`.
    pub label: String,
    /// One sentence on what it is.
    pub description: String,
    /// The page that adds it.
    pub href: String,
}

/// A way to sign in, as the login page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LoginOption {
    /// What the button says, such as `Sign in with a passkey`.
    pub label: String,
    /// The page that signs in with it.
    pub href: String,
}

/// How long after the user signed in again their session may change sign-in methods.
pub(super) const STEP_UP_TTL: Duration = Duration::from_secs(10 * 60);

/// How long after a session began an invite or recovery link's session may change sign-in methods
/// without signing in again. The link proves who the user is when they have nothing else to
/// prove it with, so it is meant for setting up soon after opening it: a 30-day session from a
/// link that was stolen is no more than any other.
pub(super) const LINK_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Whether a session may add, change, or remove a sign-in method, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignInChange {
    /// The session came from an invite or recovery link, lately.
    Link,
    /// The user signed in again, with one of their own methods, within [`STEP_UP_TTL`].
    Reverified,
    /// Neither: the session is a cookie session that didn't sign in again recently, or the login
    /// has no session to sign in again with (a proxy login).
    Refused,
}

/// The answer for a request that may not add, change, or remove a sign-in method yet: 303 to the
/// page where the user signs in again, which leads on to `target` after they do. A proxy login
/// is sent there too: the page says what to do instead, since it has nothing to sign in again
/// with.
pub(super) fn sign_in_again(target: &Target) -> Response {
    no_store(Redirect::to(&reverify_href(target)).into_response())
}

/// What [`sign_in_again`] says as JSON, for the requests `passkey.js` makes: `action` is what
/// the user was doing, such as `add a passkey`.
pub(super) fn sign_in_again_json(user: &WebUser, action: &str) -> Response {
    let message = if matches!(user.login, Login::Cookie(_)) {
        format!("Sign in again to {action}. Reload this page, and Doozers will ask you to.")
    } else {
        "A proxy login can't add a way to sign in. Ask an admin for a recovery link, or run \
         `doozers admin login-link` if you run Doozers."
            .to_owned()
    };
    json_error(StatusCode::FORBIDDEN, &message)
}

impl WebApp {
    /// Whether `user` may add, change, or remove a sign-in method now, and why
    /// ([`SignInChange`]): their cookie session signed in with an invite or recovery link, or the
    /// user signed in again, with a password, passkey, or connected identity provider
    /// of their own, within [`STEP_UP_TTL`]. Those are how a user proves who they are when they
    /// have no other way to, or still have one. A 30-day session that came from anything else,
    /// and didn't sign in again, isn't enough to take over the account's way in, so a stolen cookie
    /// can't do it. The time is the one stored on the session, never one the client sends.
    ///
    /// # Errors
    ///
    /// The store's error, if it can't look the session up.
    pub(super) async fn sign_in_change(
        &self,
        user: &WebUser,
    ) -> doozers_store::Result<SignInChange> {
        let Login::Cookie(token) = &user.login else {
            return Ok(SignInChange::Refused);
        };
        let now = self.inner.clock.now();
        let Some(session) = self.inner.store.web_session(token, now).await? else {
            return Ok(SignInChange::Refused);
        };
        let fresh = session
            .created_at
            .checked_add(LINK_WINDOW)
            .is_ok_and(|end| end > now);
        if fresh
            && matches!(
                session.method,
                SignInMethod::Invite | SignInMethod::Recovery
            )
        {
            return Ok(SignInChange::Link);
        }
        let reverified = session
            .reverified_at
            .and_then(|at| at.checked_add(STEP_UP_TTL).ok())
            .is_some_and(|until| until > now);
        Ok(if reverified {
            SignInChange::Reverified
        } else {
            SignInChange::Refused
        })
    }

    /// Whether `user` may add, change, or remove a sign-in method now ([`Self::sign_in_change`]).
    ///
    /// # Errors
    ///
    /// The store's error, if it can't look the session up.
    pub(super) async fn may_change_sign_in_methods(
        &self,
        user: &WebUser,
    ) -> doozers_store::Result<bool> {
        Ok(self.sign_in_change(user).await? != SignInChange::Refused)
    }

    /// Where the pages that add a sign-in method lead back to: the setup page for a login that came
    /// from a link, which lands there, else the account page, which is where everyone else came
    /// from. The address, and what to call it.
    ///
    /// # Errors
    ///
    /// The store's error, if it can't look the session up.
    pub(super) async fn setup_back(
        &self,
        user: &WebUser,
    ) -> doozers_store::Result<(&'static str, &'static str)> {
        Ok(match self.sign_in_change(user).await? {
            SignInChange::Link => ("/setup", "Back to setup"),
            _ => ("/account", "Back to your account"),
        })
    }

    /// The ways to sign in on the login page that are a link to another page: one for each enabled
    /// identity provider ([`oidc_pages`](super::oidc_pages)). `nonce` is the page's sign-in nonce
    /// ([`nonce_for_form`](super::auth::nonce_for_form)), which a link that starts a sign-in
    /// carries.
    ///
    /// # Errors
    ///
    /// The store's error, if it can't say.
    pub(super) async fn login_options(
        &self,
        nonce: &str,
    ) -> doozers_store::Result<Vec<LoginOption>> {
        self.oidc_login_options(nonce).await
    }

    /// Whether the login page folds the password form away behind "Use a password instead", for
    /// a method that suits the browser better to take its place: true where passkeys are offered,
    /// which put their own sign-in above the form.
    pub(super) fn password_collapsed(&self) -> bool {
        self.inner.passkeys.relying_party().is_ok()
    }

    /// The sign-in methods `user` can add to their account. Every login lists them all: choosing
    /// one sends a login that may not add it yet to sign in again first.
    ///
    /// # Errors
    ///
    /// The store's error, if it can't say.
    pub(super) async fn setup_options(
        &self,
        user: &WebUser,
    ) -> doozers_store::Result<Vec<SetupOption>> {
        let mut options = vec![
            self.passkey_setup_option(user).await?,
            self.password_setup_option(user).await?,
        ];
        options.extend(self.oidc_setup_options(user).await?);
        Ok(options)
    }
}
