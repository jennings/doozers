//! The secrets a stored toolset owns in the secret store, and the credential references of its
//! spec.
//!
//! A stored toolset `<name>` owns the secrets at `toolsets/<name>/...`, `<name>` in lower case
//! (toolset names are unique ignoring case). Its spec refers to them as `{ secret = "<path>" }`,
//! and to no other secret, so a web form can't bind a secret it didn't set. A spec given to the
//! manager may hold a credential as a literal string instead: [`take_literals`] moves it out, to
//! be stored at the toolset's own path, and leaves the reference in its place.
//!
//! A toolset with `auth.oauth` also has each user's tokens, at
//! `users/<user>/toolsets/<name>/oauth-token`: secrets of the user's own space, which the core
//! writes when the user signs in and when a token is refreshed. No spec refers to them.

use doozers_types::UserId;

use crate::config::{KeyPath, Secret, ToolsetError, ToolsetSpec};
use crate::secrets::{SecretError, SecretPath, SecretProvider};

/// The leaf of a toolset's static bearer token.
pub(crate) const BEARER_TOKEN: &str = "bearer-token";

/// The leaf of a toolset's OAuth client secret.
pub(crate) const OAUTH_CLIENT_SECRET: &str = "oauth-client-secret";

/// The leaf of a user's OAuth tokens for a toolset.
pub(crate) const OAUTH_TOKEN: &str = "oauth-token";

/// Where in `auth` a credential sits, and the leaf of the path it's stored at.
const SLOTS: &[(&[&str], &str)] = &[
    (&["bearer"], BEARER_TOKEN),
    (&["oauth", "client_secret"], OAUTH_CLIENT_SECRET),
];

/// The first segment of every toolset's own secrets.
const TOOLSETS: &str = "toolsets";

/// The path segment of the toolset `name`: the name in lower case.
fn segment(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// `toolsets/<name>/<leaf>`.
///
/// # Errors
///
/// The reason, if `name` can't be a path segment (it starts with `-`).
pub(crate) fn toolset_path(name: &str, leaf: &str) -> Result<SecretPath, String> {
    SecretPath::new(format!("{TOOLSETS}/{}/{leaf}", segment(name))).map_err(|_| {
        format!(
            "the toolset `{name}` can't keep secrets: a name that starts with `-` can't name a \
             secret; rename the toolset"
        )
    })
}

/// `users/<user>/toolsets/<name>/oauth-token`: the user's OAuth tokens for the toolset `name`.
///
/// # Errors
///
/// The reason, if the user id or the toolset name can't be a path segment.
pub(crate) fn user_token_path(user: &UserId, name: &str) -> Result<SecretPath, String> {
    SecretPath::new(format!(
        "users/{}/{TOOLSETS}/{}/{OAUTH_TOKEN}",
        user.as_str(),
        segment(name)
    ))
    .map_err(|_| {
        format!(
            "the user `{user}` can't keep a token for the toolset `{name}`: a user id or toolset \
             name must be lower case letters, digits, `-`, `_`, and `.` to name a secret"
        )
    })
}

/// Whether `path` is a user's OAuth tokens for a toolset, and whose.
pub(crate) fn token_owner(path: &SecretPath) -> Option<UserId> {
    match path.as_str().split('/').collect::<Vec<_>>()[..] {
        ["users", user, TOOLSETS, _, OAUTH_TOKEN] => UserId::new(user).ok(),
        _ => None,
    }
}

/// Whether `spec` signs each user in (`auth.oauth`).
pub(crate) fn signs_users_in(spec: &ToolsetSpec) -> bool {
    spec.auth
        .as_ref()
        .and_then(toml::Value::as_table)
        .is_some_and(|auth| auth.contains_key("oauth"))
}

/// The key of the slot `keys` in a spec, under `auth`.
fn slot_key(keys: &[&str]) -> KeyPath {
    keys.iter()
        .fold(KeyPath::root().key("auth"), |path, key| path.key(*key))
}

/// The value at `keys` in `auth`, mutably.
fn slot_mut<'a>(auth: &'a mut toml::Value, keys: &[&str]) -> Option<&'a mut toml::Value> {
    keys.iter()
        .try_fold(auth, |value, key| value.as_table_mut()?.get_mut(*key))
}

/// The value at `keys` in `auth`.
fn slot<'a>(auth: &'a toml::Value, keys: &[&str]) -> Option<&'a toml::Value> {
    keys.iter()
        .try_fold(auth, |value, key| value.as_table()?.get(*key))
}

/// `{ secret = "<path>" }`.
fn reference(path: &SecretPath) -> toml::Value {
    toml::Value::Table(toml::Table::from_iter([(
        "secret".to_owned(),
        toml::Value::String(path.to_string()),
    )]))
}

/// The path of a `{ secret = "<path>" }` table, if `value` is one.
fn referenced(value: &toml::Value) -> Option<&str> {
    let table = value.as_table()?;
    (table.len() == 1).then(|| table.get("secret")?.as_str())?
}

/// Moves the literal credentials out of `spec` for storing: each one is replaced by a reference to
/// the toolset's own path, and returned with that path. Every credential that is already a
/// reference must name the toolset's own path.
///
/// # Errors
///
/// The key and the reason, for a credential that is neither a string nor a reference to the
/// toolset's own path, or a toolset whose name can't name a secret.
pub(crate) fn take_literals(
    name: &str,
    spec: &mut ToolsetSpec,
) -> Result<Vec<(SecretPath, Secret)>, ToolsetError> {
    let mut literals = Vec::new();
    let Some(auth) = spec.auth.as_mut() else {
        return Ok(literals);
    };
    for (keys, leaf) in SLOTS {
        let Some(value) = slot_mut(auth, keys) else {
            continue;
        };
        let key = slot_key(keys);
        let own = toolset_path(name, leaf).map_err(|reason| ToolsetError {
            key: key.clone(),
            reason,
        })?;
        match value {
            toml::Value::String(literal) => {
                literals.push((own.clone(), Secret::new(std::mem::take(literal))));
                *value = reference(&own);
            }
            other if referenced(other) == Some(own.as_str()) => {}
            _ => {
                return Err(ToolsetError {
                    key,
                    reason: format!(
                        "must be the credential itself, or {{ secret = \"{own}\" }} for the one \
                         stored with the toolset"
                    ),
                });
            }
        }
    }
    Ok(literals)
}

/// The keys of `spec`'s credentials that refer to a stored secret, and the paths they refer to.
pub(crate) fn reference_keys(spec: &ToolsetSpec) -> Vec<(KeyPath, String)> {
    let Some(auth) = &spec.auth else {
        return Vec::new();
    };
    SLOTS
        .iter()
        .filter_map(|(keys, _)| {
            let path = referenced(slot(auth, keys)?)?;
            Some((slot_key(keys), path.to_owned()))
        })
        .collect()
}

/// Whether two spec URLs reach different servers: another scheme, host, or port. A URL that
/// doesn't parse is a different server.
pub(crate) fn other_server(old: Option<&str>, new: Option<&str>) -> bool {
    let origin = |url: Option<&str>| {
        url.and_then(|url| url::Url::parse(url).ok())
            .map(|url| url.origin())
            .filter(url::Origin::is_tuple)
    };
    match (origin(old), origin(new)) {
        (Some(old), Some(new)) => old != new,
        _ => true,
    }
}

/// The secret paths `spec`'s credentials refer to.
pub(crate) fn references(spec: &ToolsetSpec) -> Vec<String> {
    let Some(auth) = &spec.auth else {
        return Vec::new();
    };
    SLOTS
        .iter()
        .filter_map(|(keys, _)| referenced(slot(auth, keys)?).map(str::to_owned))
        .collect()
}

/// `spec` with each reference to a secret of the toolset `old` turned into one to the same secret
/// of `new`.
pub(crate) fn retarget(spec: &ToolsetSpec, old: &str, new: &str) -> ToolsetSpec {
    let mut spec = spec.clone();
    if let Some(auth) = spec.auth.as_mut() {
        for (keys, _) in SLOTS {
            let Some(value) = slot_mut(auth, keys) else {
                continue;
            };
            if let Some(path) = referenced(value).and_then(|path| SecretPath::new(path).ok())
                && let Some(moved) = moved(&path, old, new)
            {
                *value = reference(&moved);
            }
        }
    }
    spec
}

/// Where `path`, a secret of the toolset `old`, goes when the toolset is renamed to `new`.
/// `None` if it isn't one of `old`'s, or `new` can't name a secret.
pub(crate) fn moved(path: &SecretPath, old: &str, new: &str) -> Option<SecretPath> {
    let segments: Vec<&str> = path.as_str().split('/').collect();
    let at = toolset_segment(&segments)?;
    if segments[at] != segment(old) {
        return None;
    }
    let new = segment(new);
    let mut renamed: Vec<&str> = segments.clone();
    renamed[at] = &new;
    SecretPath::new(renamed.join("/")).ok()
}

/// The index of the toolset's segment in a toolset secret's path: `toolsets/<name>/<leaf>` or
/// `users/<user>/toolsets/<name>/<leaf>`.
fn toolset_segment(segments: &[&str]) -> Option<usize> {
    match segments {
        [TOOLSETS, _, _] => Some(1),
        ["users", _, TOOLSETS, _, _] => Some(3),
        _ => None,
    }
}

/// Every secret the toolset `name` owns: its own (`toolsets/<name>/...`) and its users'
/// (`users/<user>/toolsets/<name>/...`).
///
/// # Errors
///
/// The secret store failed.
pub(crate) async fn owned(
    secrets: &dyn SecretProvider,
    name: &str,
) -> Result<Vec<SecretPath>, SecretError> {
    let own = segment(name);
    let mut paths = Vec::new();
    for under in [TOOLSETS, "users"] {
        let under = SecretPath::new(under).ok();
        for secret in secrets.list(under.as_ref()).await? {
            let segments: Vec<&str> = secret.path.as_str().split('/').collect();
            if toolset_segment(&segments).is_some_and(|at| segments[at] == own) {
                paths.push(secret.path);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(auth: &str) -> ToolsetSpec {
        ToolsetSpec::from_json(&format!(r#"{{ "url": "https://x/mcp", "auth": {auth} }}"#)).unwrap()
    }

    #[test]
    fn literals_move_out_and_references_must_be_the_toolsets_own() {
        let mut literal = spec(r#"{ "bearer": "s3cr3t" }"#);
        let taken = take_literals("Files", &mut literal).unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0.as_str(), "toolsets/files/bearer-token");
        assert_eq!(taken[0].1.expose(), "s3cr3t");
        assert_eq!(references(&literal), ["toolsets/files/bearer-token"]);
        assert!(!serde_json::to_string(&literal).unwrap().contains("s3cr3t"));

        let mut own = literal.clone();
        assert!(take_literals("files", &mut own).unwrap().is_empty());
        assert_eq!(own, literal);

        for bad in [
            r#"{ "bearer": { "secret": "toolsets/other/bearer-token" } }"#,
            r#"{ "bearer": { "secret": "github" } }"#,
            r#"{ "bearer": { "secret": "users/owner/toolsets/files/bearer-token" } }"#,
            r#"{ "bearer": { "env": "TOKEN" } }"#,
        ] {
            let err = take_literals("files", &mut spec(bad)).unwrap_err();
            assert_eq!(err.key.to_string(), "auth.bearer", "{bad}");
        }
        assert!(take_literals("-x", &mut spec(r#"{ "bearer": "t" }"#)).is_err());
    }

    #[test]
    fn an_oauth_client_secret_is_a_credential_too() {
        let mut spec = spec(r#"{ "oauth": { "client_id": "giles", "client_secret": "cs-1" } }"#);
        let taken = take_literals("Files", &mut spec).unwrap();
        assert_eq!(taken[0].0.as_str(), "toolsets/files/oauth-client-secret");
        assert_eq!(references(&spec), ["toolsets/files/oauth-client-secret"]);
        assert!(signs_users_in(&spec));
        let user = UserId::new("owner").unwrap();
        let path = user_token_path(&user, "Files").unwrap();
        assert_eq!(path.as_str(), "users/owner/toolsets/files/oauth-token");
        assert_eq!(token_owner(&path), Some(user));
        assert_eq!(token_owner(&taken[0].0), None);
        assert!(user_token_path(&UserId::new("Bob").unwrap(), "files").is_err());
    }

    #[test]
    fn a_server_is_its_scheme_host_and_port() {
        let other = |a: &str, b: &str| other_server(Some(a), Some(b));
        assert!(!other("https://x.example/mcp", "https://x.example/other"));
        assert!(!other("https://x.example/mcp", "https://X.example:443/mcp"));
        for (a, b) in [
            ("https://x.example/mcp", "https://y.example/mcp"),
            ("https://x.example/mcp", "http://x.example/mcp"),
            ("https://x.example/mcp", "https://x.example:8443/mcp"),
            ("https://x.example/mcp", "not a url"),
        ] {
            assert!(other(a, b), "{a} {b}");
        }
        assert!(other_server(None, Some("https://x.example/mcp")));
    }

    #[test]
    fn renaming_moves_own_and_user_paths_only() {
        let path = |p: &str| SecretPath::new(p).unwrap();
        assert_eq!(
            moved(&path("toolsets/files/bearer-token"), "Files", "Docs"),
            Some(path("toolsets/docs/bearer-token"))
        );
        assert_eq!(
            moved(
                &path("users/owner/toolsets/files/oauth-token"),
                "files",
                "docs"
            ),
            Some(path("users/owner/toolsets/docs/oauth-token"))
        );
        assert_eq!(
            moved(&path("toolsets/other/bearer-token"), "files", "docs"),
            None
        );
        assert_eq!(moved(&path("providers/files"), "files", "docs"), None);

        let renamed = retarget(
            &spec(r#"{ "bearer": { "secret": "toolsets/files/bearer-token" } }"#),
            "files",
            "Docs",
        );
        assert_eq!(references(&renamed), ["toolsets/docs/bearer-token"]);
    }
}
