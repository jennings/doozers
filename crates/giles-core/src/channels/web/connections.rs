//! The Connections page: the MCP servers that sign each user in (`auth.oauth`), whether the user
//! looking is signed in to each, and the sign-in and sign-out that change it. Any logged-in user
//! sees their own; a sign-in is that user's, and its tokens go to their own space of the secret
//! store ([`ToolsetManager::begin_sign_in`]).
//!
//! Signing in leaves Giles: `/connections/{name}/sign-in` sends the browser to the server's
//! authorization page, which sends it back to `/connections/{name}/callback` with a code. Each
//! toolset has its own callback, checked against the sign-in waiting, so a code another server's
//! authorization server issued can't be finished as this one's. Both are
//! `GET`s, as the redirects are: the page's `form-action 'self'` would stop a form that redirects
//! elsewhere. The sign-in link carries the CSRF token as `?csrf=`, so another site can't start a
//! sign-in (which, with a server that approves silently, would replace the user's tokens); pages
//! send no `Referer`, so the token doesn't leave Giles with the redirect. The callback finishes
//! only a sign-in the same user started, by its `state`. Signing out is a CSRF-checked form post.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, map_response};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use tracing::warn;

use super::WebChannel;
use super::auth::{WebUser, check_csrf};
use super::pages::{WebApp, error_page, no_store};
use super::shell::{Nav, Shell};
use crate::http::{self, RouterBuilder};
use crate::toolsets::{SignInView, ToolsetManager, ToolsetManagerError};

/// The path the authorization server sends the browser back to, for the toolset `name` (as
/// stored).
pub(super) fn callback_path(name: &str) -> String {
    format!("/connections/{name}/callback")
}

#[derive(Clone)]
struct ConnectionPages {
    manager: Arc<ToolsetManager>,
    channel: Arc<WebChannel>,
}

impl ConnectionPages {
    /// The absolute callback URL of the toolset `name`, which the authorization server must
    /// accept.
    fn redirect_uri(&self, name: &str) -> String {
        format!("{}{}", self.channel.link_base(), callback_path(name))
    }
}

impl WebApp {
    /// Adds the Connections page and the sign-in routes to `builder`, signing users in with
    /// `manager`, behind the same authentication middleware as the chat pages. Every answer is
    /// `no-store`.
    pub fn install_connections(
        &self,
        builder: RouterBuilder,
        manager: Arc<ToolsetManager>,
    ) -> RouterBuilder {
        let auth = from_fn_with_state(self.clone(), super::login::authenticate);
        let pages = ConnectionPages {
            manager,
            channel: self.inner.channel.clone(),
        };
        builder.merge(
            Router::new()
                .route("/connections", get(list_page))
                .route("/connections/{name}/callback", get(callback))
                .route("/connections/{name}/sign-in", get(sign_in))
                .route("/connections/{name}/sign-out", post(sign_out))
                .with_state(pages)
                .route_layer(auth)
                .route_layer(map_response(async |response: Response| no_store(response))),
        )
    }
}

#[derive(Template)]
#[template(path = "web/connections.html")]
struct ListPage<'a> {
    shell: Shell,
    csrf: &'a str,
    servers: Vec<ServerRow>,
    notice: Option<String>,
}

/// One server on the page.
struct ServerRow {
    name: String,
    /// When the user's tokens were last stored, if they're signed in.
    signed_in: Option<String>,
    failure: Option<String>,
}

impl From<SignInView> for ServerRow {
    fn from(view: SignInView) -> Self {
        Self {
            name: view.name,
            signed_in: view.signed_in.map(super::toolsets::when),
            failure: view.failure,
        }
    }
}

/// `?signed_in=<name>` or `?signed_out=<name>`, after a change.
#[derive(serde::Deserialize)]
struct Notice {
    signed_in: Option<String>,
    signed_out: Option<String>,
}

async fn list_page(
    State(pages): State<ConnectionPages>,
    user: WebUser,
    Query(notice): Query<Notice>,
) -> Response {
    let servers = match pages.manager.sign_ins(&user.user).await {
        Ok(servers) => servers.into_iter().map(ServerRow::from).collect(),
        Err(err) => return failed(&err),
    };
    let notice = match (notice.signed_in, notice.signed_out) {
        (Some(name), _) => Some(format!("Signed in to {name}.")),
        (None, Some(name)) => Some(format!("Signed out of {name}.")),
        (None, None) => None,
    };
    http::render(&ListPage {
        shell: Shell::new(&user, Nav::Connections),
        csrf: &user.csrf,
        servers,
        notice,
    })
}

/// `?csrf=` on the sign-in link.
#[derive(serde::Deserialize)]
struct SignInQuery {
    csrf: Option<String>,
}

/// Starts the user's sign-in and sends the browser to the authorization server.
async fn sign_in(
    State(pages): State<ConnectionPages>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(query): Query<SignInQuery>,
) -> Response {
    if let Err(rejected) = check_csrf(&user, &headers, query.csrf.as_deref()) {
        return rejected.into_response();
    }
    match pages
        .manager
        .begin_sign_in(&name, &user.user, &|name| pages.redirect_uri(name))
        .await
    {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(err) => failed(&err),
    }
}

/// What the authorization server sends back: a code and the state, or an error.
#[derive(serde::Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(pages): State<ConnectionPages>,
    user: WebUser,
    Path(name): Path<String>,
    Query(callback): Query<Callback>,
) -> Response {
    if let Some(error) = callback.error {
        let detail = callback
            .error_description
            .map(|text| format!(": {text}"))
            .unwrap_or_default();
        return error_page(
            StatusCode::BAD_REQUEST,
            "Not signed in",
            &format!(
                "The server didn't sign you in ({error}{detail}). Start again from Connections."
            ),
        );
    }
    let (Some(code), Some(state)) = (callback.code, callback.state) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Not signed in",
            "The server sent no code back. Start again from Connections.",
        );
    };
    match pages
        .manager
        .finish_sign_in(&name, &user.user, &state, &code, callback.iss.as_deref())
        .await
    {
        Ok(name) => Redirect::to(&format!("/connections?signed_in={name}")).into_response(),
        Err(err) => failed(&err),
    }
}

async fn sign_out(
    State(pages): State<ConnectionPages>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    if let Err(rejected) = check_csrf(&user, &headers, fields.get("csrf").map(String::as_str)) {
        return rejected.into_response();
    }
    match pages.manager.sign_out(&name, &user.user).await {
        Ok(name) => Redirect::to(&format!("/connections?signed_out={name}")).into_response(),
        Err(err) => failed(&err),
    }
}

/// The page for a sign-in that couldn't start or finish, or a server that is gone.
fn failed(err: &ToolsetManagerError) -> Response {
    match err {
        ToolsetManagerError::NotFound => error_page(
            StatusCode::NOT_FOUND,
            "No such MCP server",
            "That MCP server doesn't exist, or isn't running. Go back to Connections.",
        ),
        ToolsetManagerError::SignIn(reason) => {
            error_page(StatusCode::BAD_GATEWAY, "Not signed in", reason)
        }
        err => {
            warn!(error = %err, "a connection change failed");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                &err.to_string(),
            )
        }
    }
}
