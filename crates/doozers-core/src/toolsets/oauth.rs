//! Each user's OAuth sign-in to a remote toolset (`auth.oauth`, PLAN section 7.10 and the MCP
//! authorization spec): the authorization code grant with PKCE, against endpoints discovered from
//! the server's URL, through `rmcp`'s `auth` module.
//!
//! A user's tokens are one secret of their own space, `users/<user>/toolsets/<name>/oauth-token`
//! ([`credentials::user_token_path`]): `rmcp`'s `StoredCredentials` as JSON, written when they
//! sign in and each time a token is refreshed ([`UserTokens`]), with the authorization server's
//! issuer and token endpoint as they were at sign-in. A connection is refused when the server now
//! names another authorization server, so a server that changes hands can't collect the refresh
//! tokens and the client secret.
//!
//! Every OAuth request goes through [`OAuthHttp`], which keeps them to the addresses the MCP
//! server's URL allows ([`address`]).
//!
//! [`UserOAuthToolset`] is the toolset the registry holds for such a server. It is
//! [per-user](Toolset::per_user): each user is offered the tools their own connection lists, and
//! each call goes over the requester's own connection, which sends their token. No user's tools
//! come from, and no user's call carries, another user's credentials.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::Response;
use doozers_store::BlobStore;
use doozers_types::{
    CallContext, Error, Result, Skill, SkillSummary, ToolCall, ToolCallHandle, ToolSpec, Toolset,
    UserId,
};
use futures::StreamExt as _;
use rmcp::transport::auth::{
    AuthError, AuthorizationManager, AuthorizationRequest, AuthorizationSession,
    CredentialRefreshGuard, CredentialStore, OAuthHttpClient, OAuthHttpClientError,
    OAuthHttpClientFuture, OAuthHttpRedirectPolicy, OAuthHttpRequest, StoredCredentials,
};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

use self::address::{Policy, Resolver};
use super::credentials;
use crate::config::{InstanceName, Remote, Secret, UserOAuth};
use crate::mcp::{HttpServer, McpToolset};
use crate::secrets::{SecretError, SecretPath, SecretProvider};

/// How long one OAuth request (discovery, registration, token) may take.
const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest OAuth response body read.
const MAX_OAUTH_BODY: usize = 1 << 20;

/// Redirects followed for a request that allows them (`rmcp` allows them for dynamic client
/// registration only).
const MAX_OAUTH_REDIRECTS: usize = 5;

mod address;

/// The client name a dynamically registered client gets.
const CLIENT_NAME: &str = "Doozers";

/// The HTTP client of the OAuth requests for one MCP server: Doozers' TLS settings
/// ([`tls_client_builder`](crate::net::tls_client_builder): bundled roots only), a timeout, a
/// limit on the body, and only the addresses the server's URL allows ([`address::Policy`]), for
/// the request, each address its host resolves to, and each redirect. Redirects are followed only
/// where `rmcp` asks for it (dynamic client registration), never for a token request, which
/// carries the client secret or a code.
struct OAuthHttp {
    policy: Policy,
    follow: reqwest::Client,
    stop: reqwest::Client,
}

impl OAuthHttp {
    fn for_server(server: &Url) -> Result<Self> {
        let policy = Policy::for_server(server);
        let build = |redirect| {
            crate::net::tls_client_builder()?
                .timeout(OAUTH_TIMEOUT)
                .dns_resolver(Arc::new(Resolver(policy.clone())))
                .redirect(redirect)
                .build()
                .map_err(Error::other)
        };
        let checked = policy.clone();
        let follow = reqwest::redirect::Policy::custom(move |attempt| {
            if !checked.allows_url(attempt.url()) {
                let refused = format!("a redirect to {} is refused", attempt.url());
                attempt.error(refused)
            } else if attempt.previous().len() > MAX_OAUTH_REDIRECTS {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        });
        Ok(Self {
            follow: build(follow)?,
            stop: build(reqwest::redirect::Policy::none())?,
            policy,
        })
    }
}

impl OAuthHttpClient for OAuthHttp {
    fn execute(&self, request: OAuthHttpRequest) -> OAuthHttpClientFuture<'_> {
        Box::pin(async move {
            let client = match request.redirect_policy {
                OAuthHttpRedirectPolicy::Follow => &self.follow,
                _ => &self.stop,
            };
            let request = reqwest::Request::try_from(request.request)
                .map_err(|error| Box::new(error) as OAuthHttpClientError)?;
            if !self.policy.allows_url(request.url()) {
                return Err(format!(
                    "an OAuth request to {} is refused: the MCP server may not send Doozers there",
                    request.url()
                )
                .into());
            }
            let response = client
                .execute(request)
                .await
                .map_err(|error| Box::new(error) as OAuthHttpClientError)?;
            let mut builder = Response::builder().status(response.status());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let mut body = Vec::new();
            let mut chunks = response.bytes_stream();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|error| Box::new(error) as OAuthHttpClientError)?;
                if body.len() + chunk.len() > MAX_OAUTH_BODY {
                    return Err(
                        format!("the response is larger than {MAX_OAUTH_BODY} bytes").into(),
                    );
                }
                body.extend_from_slice(&chunk);
            }
            builder
                .body(body)
                .map_err(|error| Box::new(error) as OAuthHttpClientError)
        })
    }
}

/// What every OAuth connection and sign-in shares: the secret store, and one lock per user and
/// toolset that a token refresh holds, so two connections of one user can't both spend a refresh
/// token that the server rotates.
pub(crate) struct OAuthContext {
    secrets: Arc<dyn SecretProvider>,
    refreshing: Mutex<BTreeMap<SecretPath, Arc<AsyncMutex<()>>>>,
}

impl fmt::Debug for OAuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthContext").finish_non_exhaustive()
    }
}

impl OAuthContext {
    /// The context for sign-ins and connections whose tokens are in `secrets`.
    pub(crate) fn new(secrets: Arc<dyn SecretProvider>) -> Self {
        Self {
            secrets,
            refreshing: Mutex::default(),
        }
    }

    /// The tokens of `user` for the toolset `name`, as `rmcp` stores them, issued by the
    /// authorization server `endpoints` names.
    fn tokens(&self, user: &UserId, name: &str, endpoints: Endpoints) -> Result<UserTokens> {
        let path = credentials::user_token_path(user, name).map_err(Error::InvalidRequest)?;
        let lock = self
            .refreshing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(path.clone())
            .or_default()
            .clone();
        Ok(UserTokens {
            secrets: self.secrets.clone(),
            path,
            user: user.clone(),
            endpoints,
            lock,
        })
    }

    /// An authorization manager for the MCP server at `url` with no client and no tokens yet:
    /// discovery runs on it.
    async fn manager(&self, url: &Url) -> std::result::Result<AuthorizationManager, AuthError> {
        let http: Arc<dyn OAuthHttpClient> = Arc::new(
            OAuthHttp::for_server(url)
                .map_err(|error| AuthError::InternalError(error.to_string()))?,
        );
        AuthorizationManager::new_with_oauth_http_client(url.as_str(), http).await
    }

    /// The users signed in to the toolset `name`, ordered by id.
    ///
    /// # Errors
    ///
    /// The secret store failed.
    pub(crate) async fn signed_in(
        &self,
        name: &str,
    ) -> std::result::Result<Vec<UserId>, SecretError> {
        Ok(credentials::owned(self.secrets.as_ref(), name)
            .await?
            .iter()
            .filter_map(credentials::token_owner)
            .collect())
    }

    /// Starts `user`'s sign-in to the toolset `name` at `url`: discovers the authorization
    /// server, registers a client if `oauth` names none, and makes the authorization URL to send
    /// the user to, which comes back to `redirect_uri`. The tokens are stored only when the sign-in
    /// is finished ([`SignIn::finish`]).
    ///
    /// # Errors
    ///
    /// Why the sign-in can't start, for the user: discovery, registration, or the server's
    /// metadata failed.
    pub(crate) async fn begin_sign_in(
        &self,
        name: &str,
        url: &Url,
        oauth: &UserOAuth,
        user: &UserId,
        redirect_uri: &str,
    ) -> std::result::Result<SignIn, String> {
        let mut manager = self.manager(url).await.map_err(|error| error.to_string())?;
        let resolution = manager
            .resolve_metadata()
            .await
            .map_err(|error| format!("cannot find the server's sign-in endpoints: {error}"))?;
        let endpoints = Endpoints::of(&resolution.metadata);
        let tokens = self
            .tokens(user, name, endpoints)
            .map_err(|error| error.to_string())?;
        manager.set_metadata(resolution.metadata);
        manager.set_credential_store(tokens);
        let mut request = AuthorizationRequest::new(redirect_uri).with_client_name(CLIENT_NAME);
        if !oauth.scopes.is_empty() {
            request = request.with_scopes(oauth.scopes.iter().cloned());
        }
        if let Some(client_id) = &oauth.client_id {
            request = request.with_preregistered_client(client_id.as_str());
        }
        if let Some(secret) = &oauth.client_secret {
            request = request.with_client_secret(secret.expose());
        }
        let session = AuthorizationSession::new(manager, request)
            .await
            .map_err(|(_, error)| format!("cannot start the sign-in: {error}"))?;
        let state = Url::parse(session.get_authorization_url())
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == "state")
                    .map(|(_, value)| value.into_owned())
            })
            .ok_or_else(|| "the authorization URL has no state".to_owned())?;
        Ok(SignIn { state, session })
    }

    /// `user`'s connection to the toolset `name` at `url`, with their stored tokens, or `None`
    /// if they haven't signed in. The connection refreshes the access token as needed and stores
    /// the new tokens.
    async fn connect_user(
        &self,
        name: &InstanceName,
        server: &HttpServer,
        oauth: &UserOAuth,
        user: &UserId,
        blobs: &BlobStore,
    ) -> Result<Option<McpToolset>> {
        let path =
            credentials::user_token_path(user, name.as_str()).map_err(Error::InvalidRequest)?;
        let Some(stored) = stored_tokens(self.secrets.as_ref(), &path)
            .await
            .map_err(auth_error(name))?
        else {
            return Ok(None);
        };
        let mut manager = self.manager(&server.url).await.map_err(auth_error(name))?;
        let resolution = manager.resolve_metadata().await.map_err(auth_error(name))?;
        // The tokens, and the client secret, go only to the authorization server that issued
        // them.
        if Endpoints::of(&resolution.metadata) != stored.endpoints {
            return Err(Error::InvalidRequest(format!(
                "toolset {name}: the server now names another sign-in server than when {user} \
                 signed in, so Doozers won't send their tokens there. Sign in again on the \
                 Connections page if the change is expected"
            )));
        }
        manager.set_metadata(resolution.metadata);
        manager.set_credential_store(self.tokens(user, name.as_str(), stored.endpoints)?);
        // Drops tokens of another issuer, and configures the client the tokens were issued to.
        if !manager
            .initialize_from_store()
            .await
            .map_err(auth_error(name))?
        {
            return Ok(None);
        }
        // A registered confidential client refreshes with its secret.
        if let (Some(client_id), Some(secret)) = (&oauth.client_id, &oauth.client_secret) {
            let (stored, _) = manager.get_credentials().await.map_err(auth_error(name))?;
            if stored == *client_id {
                manager
                    .configure_client(
                        rmcp::transport::auth::OAuthClientConfig::new(
                            client_id.as_str(),
                            server.url.as_str(),
                        )
                        .with_client_secret(secret.expose()),
                    )
                    .map_err(auth_error(name))?;
            }
        }
        McpToolset::connect_http_oauth(name.as_str(), server, manager, blobs.clone())
            .await
            .map(Some)
    }
}

/// A turn a sign-in error into the toolset's error.
fn auth_error(name: &InstanceName) -> impl Fn(AuthError) -> Error + '_ {
    move |error| Error::unavailable(format!("toolset {name}: {error}"))
}

/// A sign-in that was started and waits for the user to come back from the authorization
/// server.
pub(crate) struct SignIn {
    state: String,
    session: AuthorizationSession,
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignIn").finish_non_exhaustive()
    }
}

impl SignIn {
    /// The `state` the authorization server sends back with the code.
    pub(crate) fn state(&self) -> &str {
        &self.state
    }

    /// Where to send the user's browser.
    pub(crate) fn url(&self) -> &str {
        self.session.get_authorization_url()
    }

    /// Exchanges the `code` the authorization server sent back for tokens, and stores them.
    /// `issuer` is the callback's `iss`, if any.
    ///
    /// # Errors
    ///
    /// Why not, for the user.
    pub(crate) async fn finish(
        &self,
        code: &str,
        issuer: Option<&str>,
    ) -> std::result::Result<(), String> {
        self.session
            .handle_callback_with_issuer(code, &self.state, issuer)
            .await
            .map(drop)
            .map_err(|error| format!("the server refused the sign-in: {error}"))
    }
}

/// The authorization server that issued a user's tokens: its issuer, if its metadata names one,
/// and its token endpoint, where refresh tokens and the client secret go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Endpoints {
    issuer: Option<String>,
    token_endpoint: String,
}

impl Endpoints {
    fn of(metadata: &rmcp::transport::auth::AuthorizationMetadata) -> Self {
        Self {
            issuer: metadata.issuer.clone(),
            token_endpoint: metadata.token_endpoint.clone(),
        }
    }
}

/// A user's tokens as the secret holds them: `rmcp`'s credentials and the authorization server
/// that issued them.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredTokens {
    credentials: StoredCredentials,
    #[serde(flatten)]
    endpoints: Endpoints,
}

/// The tokens stored at `path`, if any.
async fn stored_tokens(
    secrets: &dyn SecretProvider,
    path: &SecretPath,
) -> std::result::Result<Option<StoredTokens>, AuthError> {
    let Some(secret) = secrets.get(path).await.map_err(store_error)? else {
        return Ok(None);
    };
    serde_json::from_str(secret.expose())
        .map(Some)
        .map_err(|_| store_error(format!("the tokens at {path} can't be read")))
}

/// One user's tokens for one toolset in the secret store, as `rmcp`'s credential store.
struct UserTokens {
    secrets: Arc<dyn SecretProvider>,
    path: SecretPath,
    user: UserId,
    /// The authorization server the tokens are from, saved with them.
    endpoints: Endpoints,
    /// Held across a refresh and its save.
    lock: Arc<AsyncMutex<()>>,
}

fn store_error(error: impl fmt::Display) -> AuthError {
    AuthError::CredentialStoreError(error.to_string())
}

#[async_trait]
impl CredentialStore for UserTokens {
    async fn load(&self) -> std::result::Result<Option<StoredCredentials>, AuthError> {
        Ok(stored_tokens(self.secrets.as_ref(), &self.path)
            .await?
            .map(|stored| stored.credentials))
    }

    async fn save(&self, credentials: StoredCredentials) -> std::result::Result<(), AuthError> {
        let stored = StoredTokens {
            credentials,
            endpoints: self.endpoints.clone(),
        };
        let json = serde_json::to_string(&stored).map_err(store_error)?;
        self.secrets
            .put(&self.path, &Secret::new(json), Some(&self.user))
            .await
            .map(drop)
            .map_err(store_error)
    }

    async fn clear(&self) -> std::result::Result<(), AuthError> {
        self.secrets
            .delete(&self.path)
            .await
            .map(drop)
            .map_err(store_error)
    }

    /// A refresh token the server rejected is no use: the user signs in again. Tokens stored
    /// since (another connection refreshed first) are kept.
    async fn on_refresh_token_rejected(
        &self,
        rejected: &StoredCredentials,
    ) -> std::result::Result<(), AuthError> {
        let current = self.load().await?;
        if current.is_some_and(|current| current.token_received_at == rejected.token_received_at) {
            self.clear().await?;
        }
        Ok(())
    }

    async fn acquire_refresh_guard(
        &self,
    ) -> std::result::Result<Option<CredentialRefreshGuard>, AuthError> {
        Ok(Some(CredentialRefreshGuard::new(
            self.lock.clone().lock_owned().await,
        )))
    }
}

/// A remote toolset that signs each user in with their own account. Each user's tools are listed,
/// and each call goes, over that user's connection, made when first needed. The first signed-in
/// user's connection, by id, that works is the toolset's status: its server version, and its end
/// for the supervisor.
pub(crate) struct UserOAuthToolset {
    name: InstanceName,
    server: HttpServer,
    oauth: UserOAuth,
    context: Arc<OAuthContext>,
    blobs: BlobStore,
    /// The first user whose connection worked, and the connection.
    first: (UserId, Arc<McpToolset>),
    /// Other users' connections, made when first needed.
    users: AsyncMutex<HashMap<UserId, Arc<McpToolset>>>,
}

impl fmt::Debug for UserOAuthToolset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserOAuthToolset")
            .field("name", &self.name)
            .field("first", &self.first.0)
            .finish_non_exhaustive()
    }
}

impl UserOAuthToolset {
    /// Connects the toolset `name` at `remote` over the connection of the first signed-in user
    /// whose connection works.
    ///
    /// # Errors
    ///
    /// [`Error::Unavailable`] if no user is signed in, or no signed-in user's connection works
    /// (the last one's error).
    pub(crate) async fn connect(
        name: &InstanceName,
        remote: &Remote,
        oauth: &UserOAuth,
        context: Arc<OAuthContext>,
        blobs: BlobStore,
    ) -> Result<Self> {
        let server = HttpServer::new(remote.url.clone());
        let users = context
            .signed_in(name.as_str())
            .await
            .map_err(|error| Error::unavailable(format!("toolset {name}: {error}")))?;
        let mut last = None;
        for user in users {
            match context
                .connect_user(name, &server, oauth, &user, &blobs)
                .await
            {
                Ok(Some(connection)) => {
                    return Ok(Self {
                        name: name.clone(),
                        server,
                        oauth: oauth.clone(),
                        context,
                        blobs,
                        first: (user, Arc::new(connection)),
                        users: AsyncMutex::default(),
                    });
                }
                Ok(None) => {}
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            Error::unavailable(format!(
                "toolset {name}: no one has signed in to it yet; sign in on the Connections page \
                 of the web UI"
            ))
        }))
    }

    /// The version the server reported to the first connection.
    pub(crate) fn server_version(&self) -> Option<String> {
        self.first.1.server_version()
    }

    /// Resolves when the first connection has ended.
    pub(crate) async fn closed(&self) {
        self.first.1.closed().await;
    }

    /// `user`'s connection: the first one, an earlier one that is still open, or a new one.
    /// `None` if they haven't signed in.
    async fn connection(&self, user: &UserId) -> Result<Option<Arc<McpToolset>>> {
        if *user == self.first.0 {
            return Ok(Some(self.first.1.clone()));
        }
        let mut users = self.users.lock().await;
        if let Some(connection) = users.get(user)
            && !connection.is_closed()
        {
            return Ok(Some(connection.clone()));
        }
        users.remove(user);
        let Some(connection) = self
            .context
            .connect_user(&self.name, &self.server, &self.oauth, user, &self.blobs)
            .await?
        else {
            return Ok(None);
        };
        let connection = Arc::new(connection);
        users.insert(user.clone(), connection.clone());
        Ok(Some(connection))
    }
}

#[async_trait]
impl Toolset for UserOAuthToolset {
    /// None: each user's tools are their own ([`user_tools`](Self::user_tools)).
    async fn list_tools(&self) -> Result<Vec<ToolSpec>> {
        Ok(Vec::new())
    }

    fn per_user(&self) -> bool {
        true
    }

    /// The tools `user`'s own connection lists; none if they haven't signed in.
    async fn user_tools(&self, user: &UserId) -> Result<Vec<ToolSpec>> {
        match self.connection(user).await? {
            Some(connection) => connection.list_tools().await,
            None => Ok(Vec::new()),
        }
    }

    /// None: an MCP connection has no skills (the instance's `skills` directories are the
    /// `ManagedToolset`'s).
    async fn list_skills(&self) -> Result<Vec<SkillSummary>> {
        Ok(Vec::new())
    }

    /// Always [`Error::NotFound`] (see [`list_skills`](Self::list_skills)).
    async fn get_skill(&self, name: &str) -> Result<Skill> {
        Err(Error::NotFound(format!(
            "skill {name}: toolset {} has no skills",
            self.name
        )))
    }

    /// Calls the tool over the requester's own connection. A turn without a requester (a config
    /// job) and a requester who hasn't signed in get an error the model sees as the result.
    async fn call(&self, call: ToolCall, ctx: CallContext) -> Result<ToolCallHandle> {
        let Some(user) = &ctx.requester else {
            return Err(Error::InvalidRequest(format!(
                "toolset {}: each user signs in to this MCP server with their own account, and \
                 this turn has no user to act for",
                self.name
            )));
        };
        let Some(connection) = self.connection(user).await? else {
            return Err(Error::InvalidRequest(format!(
                "toolset {}: you haven't signed in to this MCP server. Sign in on the Connections \
                 page of the web UI, then try again",
                self.name
            )));
        };
        connection.call(call, ctx).await
    }
}
