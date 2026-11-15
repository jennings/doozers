//! A stored remote toolset that signs each user in with OAuth, end to end: the manager stores it
//! and its client secret, a user signs in against a fake authorization server (discovery, the
//! authorization URL, the code exchange), the tokens land in the user's space of the secret store,
//! the toolset lists its tools over that user's connection and calls them with the user's access
//! token, an expiring token is refreshed and the new one stored, and signing out and removing the
//! toolset delete the tokens.
#![allow(missing_docs)]

#[path = "support/mcp_server.rs"]
mod mcp_server;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt as _;
use giles_core::config::{Builtins, Config, LoadOptions, ToolsetSpec};
use giles_core::paths::DataRoot;
use giles_core::registry::Registry;
use giles_core::secrets::{KeyFile, LocalSecrets, SecretPath, SecretProvider};
use giles_core::sessions::SystemClock;
use giles_core::toolsets::{ToolsetHost, ToolsetLauncher, ToolsetManager, ToolsetManagerOptions};
use giles_store::{BlobStore, Store};
use giles_types::{AgentId, CallContext, ToolCall, ToolCallEvent, UserId};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::json;

use self::mcp_server::TestServer;

const CLIENT_ID: &str = "giles-client";
const CLIENT_SECRET: &str = "client-secret-31";
const CODE: &str = "code-from-the-browser";
const WAIT: Duration = Duration::from_secs(20);

/// What the fake authorization server issued and saw.
#[derive(Default)]
struct Issuer {
    /// Access tokens the MCP endpoint accepts.
    valid: Vec<String>,
    /// How many tokens were issued; the next one is `access-<n>`.
    issued: usize,
    /// The grant types of the token requests, in order.
    grants: Vec<String>,
    /// The bearer tokens the MCP endpoint was called with.
    seen: Vec<String>,
    /// The metadata names `/stolen-token` as the token endpoint, as a server that changed hands
    /// might.
    moved: bool,
    /// Requests to `/stolen-token`.
    stolen: usize,
}

type Shared = Arc<Mutex<Issuer>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Issuer> {
    shared.lock().unwrap()
}

/// Serves the authorization server and the MCP server (behind the token check) on one origin.
async fn serve() -> (String, Shared) {
    let shared = Shared::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = TestServer::default();
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let resource = json!({
        "resource": format!("{origin}/mcp"),
        "authorization_servers": [origin],
    });
    let metadata = {
        let origin = origin.clone();
        move |State(shared): State<Shared>| {
            let token = if lock(&shared).moved {
                "stolen-token"
            } else {
                "token"
            };
            let metadata = json!({
                "issuer": origin,
                "authorization_endpoint": format!("{origin}/authorize"),
                "token_endpoint": format!("{origin}/{token}"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "scopes_supported": ["files"],
            });
            async move { Json(metadata) }
        }
    };
    let protected = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(
            shared.clone(),
            require_token,
        ));
    let router = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get({
                let resource = resource.clone();
                async move || Json(resource)
            }),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(async move || Json(resource)),
        )
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/token", post(token))
        .route(
            "/stolen-token",
            post(async |State(shared): State<Shared>| {
                lock(&shared).stolen += 1;
                StatusCode::BAD_REQUEST
            }),
        )
        .with_state(shared.clone())
        .merge(protected);
    tokio::spawn(async move { axum::serve(listener, router).await });
    (origin, shared)
}

async fn require_token(State(shared): State<Shared>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);
    let accepted = {
        let mut issuer = lock(&shared);
        if let Some(token) = &token {
            issuer.seen.push(token.clone());
        }
        token.is_some_and(|token| issuer.valid.contains(&token))
    };
    if accepted {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response()
    }
}

/// The token endpoint: the code (with a PKCE verifier) for the first tokens, which expire at once,
/// and the refresh token for later ones, which last an hour. The client must authenticate.
async fn token(
    State(shared): State<Shared>,
    _headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let field = |key: &str| form.get(key).map(String::as_str);
    if field("client_id") != Some(CLIENT_ID) || field("client_secret") != Some(CLIENT_SECRET) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let mut issuer = lock(&shared);
    let grant = field("grant_type").unwrap_or_default().to_owned();
    let expires_in = match grant.as_str() {
        "authorization_code"
            if field("code") == Some(CODE)
                && field("code_verifier").is_some_and(|v| v.len() >= 43) =>
        {
            // Inside the client's refresh margin: the next use refreshes it.
            5
        }
        "refresh_token" if field("refresh_token") == Some("refresh-1") => 3600,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
    };
    issuer.grants.push(grant);
    issuer.issued += 1;
    let access = format!("access-{}", issuer.issued);
    issuer.valid.push(access.clone());
    Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": "refresh-1",
        "scope": "files",
    }))
    .into_response()
}

struct Giles {
    _dir: tempfile::TempDir,
    registry: Arc<Registry>,
    secrets: Arc<dyn SecretProvider>,
    manager: Arc<ToolsetManager>,
}

impl Giles {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = DataRoot::new(dir.path(), Path::new("/tmp")).unwrap();
        root.create_layout().unwrap();
        std::fs::write(
            root.config_file(),
            "[owner]\nidentities = [\"web:owner\"]\n",
        )
        .unwrap();
        let config = Config::load_with(
            &root,
            &LoadOptions {
                builtins: Builtins::V1,
                env: &|_| None,
                giles_exe: None,
            },
        )
        .unwrap();
        let store = Store::open(root.database_file()).await.unwrap();
        let blobs = BlobStore::open(root.blobs_dir(), store.clone())
            .await
            .unwrap();
        let secrets: Arc<dyn SecretProvider> = Arc::new(
            LocalSecrets::open(
                store.clone(),
                &KeyFile::new(&root, &root.secret_key_file()),
                Arc::new(SystemClock),
            )
            .await
            .unwrap(),
        );
        let registry = Arc::new(Registry::new(root.clone(), Arc::new(config)));
        let launcher = ToolsetLauncher::new(
            root.clone(),
            root.secret_key_file(),
            secrets.clone(),
            "/nonexistent/giles".into(),
            Err("no sandbox in this test".to_owned()),
            blobs,
        );
        let host = Arc::new(ToolsetHost::start(launcher, &registry).await);
        let manager = ToolsetManager::start(ToolsetManagerOptions {
            store,
            root,
            secrets: secrets.clone(),
            config: registry.live_config().clone(),
            host,
            agent_lock: Arc::default(),
        })
        .await
        .unwrap();
        Self {
            _dir: dir,
            registry,
            secrets,
            manager,
        }
    }

    async fn secret(&self, path: &str) -> Option<String> {
        self.secrets
            .get(&SecretPath::new(path).unwrap())
            .await
            .unwrap()
            .map(|secret| secret.expose().to_owned())
    }

    /// Waits until new conversations get `tool`.
    async fn offered(&self, tool: &str) {
        tokio::time::timeout(WAIT, async {
            while self.registry.tools().snapshot().get(tool).is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{tool} is never offered"));
    }

    /// Calls `files__echo` as `requester`: the result text, or the error.
    async fn echo(&self, requester: Option<&str>, text: &str) -> Result<String, String> {
        let toolset = self.registry.toolset("files").unwrap();
        let call = ToolCall {
            id: "toolu_1".into(),
            name: "echo".into(),
            input: json!({ "text": text }),
            media: Vec::new(),
        };
        let ctx = CallContext {
            agent: AgentId::new("jeeves").unwrap(),
            requester: requester.map(|user| UserId::new(user).unwrap()),
            conversation: None,
        };
        let mut handle = toolset
            .call(call, ctx)
            .await
            .map_err(|error| error.to_string())?;
        while let Some(event) = tokio::time::timeout(WAIT, handle.events.next())
            .await
            .unwrap()
        {
            if let Ok(ToolCallEvent::Result { content, is_error }) = event {
                let text = serde_json::to_value(&content).unwrap().to_string();
                return if is_error { Err(text) } else { Ok(text) };
            }
        }
        Err("no result".to_owned())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_signs_in_and_their_tokens_are_used_refreshed_and_deleted() {
    let (origin, issuer) = serve().await;
    let giles = Giles::start().await;
    let owner = UserId::new("owner").unwrap();
    let token_path = "users/owner/toolsets/files/oauth-token";

    let spec: ToolsetSpec = serde_json::from_value(json!({
        "url": format!("{origin}/mcp"),
        "auth": { "oauth": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scopes": ["files"],
        } },
    }))
    .unwrap();
    giles.manager.add("files", &spec).await.unwrap();
    assert_eq!(
        giles
            .secret("toolsets/files/oauth-client-secret")
            .await
            .as_deref(),
        Some(CLIENT_SECRET)
    );
    let views = giles.manager.sign_ins(&owner).await.unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].signed_in, None);

    // The sign-in starts with the authorization URL: PKCE, the client, the resource, the state.
    let callback = |name: &str| format!("http://127.0.0.1:1/connections/{name}/callback");
    let url = giles
        .manager
        .begin_sign_in("files", &owner, &callback)
        .await
        .unwrap();
    let url = url::Url::parse(&url).unwrap();
    assert_eq!(
        url.as_str().split('?').next(),
        Some(&*format!("{origin}/authorize"))
    );
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["redirect_uri"], callback("files"));
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["resource"], format!("{origin}/mcp"));
    assert!(query["scope"].contains("files"), "{query:?}");
    let state = query["state"].clone();

    // Another user can't finish it, nor can a made-up state.
    let bob = UserId::new("bob").unwrap();
    assert!(
        giles
            .manager
            .finish_sign_in("files", &bob, &state, CODE, None)
            .await
            .is_err()
    );
    assert!(
        giles
            .manager
            .finish_sign_in("files", &owner, "nope", CODE, None)
            .await
            .is_err()
    );

    // The browser comes back with the code: the tokens are stored, sealed, in the user's space.
    let name = giles
        .manager
        .finish_sign_in("files", &owner, &state, CODE, None)
        .await
        .unwrap();
    assert_eq!(name, "files");
    let stored = giles.secret(token_path).await.expect("tokens stored");
    assert!(stored.contains("access-1"), "{stored}");
    assert!(
        giles.manager.sign_ins(&owner).await.unwrap()[0]
            .signed_in
            .is_some()
    );
    // The state is spent.
    assert!(
        giles
            .manager
            .finish_sign_in("files", &owner, &state, CODE, None)
            .await
            .is_err()
    );

    // The toolset restarts over the owner's connection and offers the server's tools. The first
    // access token was about to expire, so the connection refreshed it and stored the new one.
    giles.offered("files__echo").await;
    let echoed = giles.echo(Some("owner"), "hello").await.unwrap();
    assert!(echoed.contains(r#""text":"hello""#), "{echoed}");
    {
        let issued = lock(&issuer);
        assert_eq!(issued.grants, ["authorization_code", "refresh_token"]);
        assert!(issued.seen.iter().all(|token| token.starts_with("access-")));
        assert_eq!(issued.seen.last().map(String::as_str), Some("access-2"));
    }
    let stored = giles.secret(token_path).await.unwrap();
    assert!(stored.contains("access-2"), "{stored}");

    // No fallback to another user's sign-in, and none for a turn with no user.
    let err = giles.echo(Some("bob"), "hi").await.unwrap_err();
    assert!(err.contains("haven't signed in"), "{err}");
    let err = giles.echo(None, "hi").await.unwrap_err();
    assert!(err.contains("no user"), "{err}");

    // Bob signs in. When the server then names another token endpoint, his tokens and the client
    // secret aren't sent there: his connection is refused.
    let url = giles
        .manager
        .begin_sign_in("files", &bob, &callback)
        .await
        .unwrap();
    let state = url::Url::parse(&url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    giles
        .manager
        .finish_sign_in("files", &bob, &state, CODE, None)
        .await
        .unwrap();
    lock(&issuer).moved = true;
    let err = giles.echo(Some("bob"), "hi").await.unwrap_err();
    assert!(err.contains("another sign-in server"), "{err}");
    assert_eq!(lock(&issuer).stolen, 0);
    assert!(
        giles
            .secret("users/bob/toolsets/files/oauth-token")
            .await
            .is_some()
    );
    giles.manager.sign_out("files", &bob).await.unwrap();

    // Signing out deletes the tokens; removing the toolset deletes its client secret.
    giles.manager.sign_out("files", &owner).await.unwrap();
    assert_eq!(giles.secret(token_path).await, None);
    assert_eq!(
        giles.manager.sign_ins(&owner).await.unwrap()[0].signed_in,
        None
    );
    // A user's waiting sign-ins are capped, and never push out another user's.
    lock(&issuer).moved = false;
    let state_of = |url: String| {
        url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned()
    };
    let bobs = state_of(
        giles
            .manager
            .begin_sign_in("files", &bob, &callback)
            .await
            .unwrap(),
    );
    let mut owners = Vec::new();
    for _ in 0..5 {
        let url = giles
            .manager
            .begin_sign_in("files", &owner, &callback)
            .await
            .unwrap();
        owners.push(state_of(url));
    }
    let err = giles
        .manager
        .finish_sign_in("files", &owner, &owners[0], CODE, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    // A code that comes back to another toolset's callback (an authorization server mix-up) is
    // refused, and the sign-in dropped.
    for (callback_of, reason) in [("notes", "came back to the callback"), ("files", "expired")] {
        let err = giles
            .manager
            .finish_sign_in(callback_of, &owner, &owners[1], CODE, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(reason), "{err}");
    }
    assert_eq!(giles.secret(token_path).await, None);
    giles
        .manager
        .finish_sign_in("files", &bob, &bobs, CODE, None)
        .await
        .unwrap();
    giles.manager.sign_out("files", &bob).await.unwrap();

    giles.manager.remove("files").await.unwrap();
    assert!(giles.secrets.list(None).await.unwrap().is_empty());
}
