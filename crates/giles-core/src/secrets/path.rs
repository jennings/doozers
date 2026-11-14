//! [`SecretPath`]: a secret's name.

use std::fmt;
use std::str::FromStr;

/// The longest secret path, in bytes.
pub const MAX_PATH_LEN: usize = 255;

/// The top-level segment of users' personal spaces: `users/<user>/...`.
const USERS: &str = "users";

/// A secret's name: a slash path such as `providers/anthropic` or `users/alice/github`, the same
/// in every provider.
///
/// Segments use `a-z`, `0-9`, `-`, `_`, and `.`, start with a letter or digit, and are joined by
/// `/`, with no empty segment and no leading or trailing `/`, in at most [`MAX_PATH_LEN`] bytes.
/// Paths are lowercase so case can't make look-alikes, and each one is a valid Vault path as it
/// is. `users` and `users/<user>` are not secrets: they are the personal spaces, whose secrets
/// sit below them. Paths aren't sensitive: they appear in config, logs, and the web UI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretPath(String);

/// A string was rejected as a [`SecretPath`]. Its message quotes the string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid secret path {path:?}: {reason}")]
pub struct SecretPathError {
    path: String,
    reason: &'static str,
}

impl SecretPath {
    /// Validates `path`.
    ///
    /// # Errors
    ///
    /// [`SecretPathError`], saying which rule `path` breaks.
    pub fn new(path: impl Into<String>) -> Result<Self, SecretPathError> {
        let path = path.into();
        match check(&path) {
            Ok(()) => Ok(Self(path)),
            Err(reason) => Err(SecretPathError { path, reason }),
        }
    }

    /// The path as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The user whose personal space holds the secret: `alice` for `users/alice/github`. `None`
    /// for an install-wide secret.
    pub fn owner(&self) -> Option<&str> {
        let mut segments = self.0.split('/');
        match (segments.next(), segments.next()) {
            (Some(USERS), Some(user)) => Some(user),
            _ => None,
        }
    }
}

fn check(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("must not be empty");
    }
    if path.len() > MAX_PATH_LEN {
        return Err("is longer than 255 bytes");
    }
    let mut segments = 0;
    for segment in path.split('/') {
        segments += 1;
        let mut chars = segment.chars();
        match chars.next() {
            None => return Err("has an empty segment (a leading, trailing, or doubled `/`)"),
            Some(c) if !(c.is_ascii_lowercase() || c.is_ascii_digit()) => {
                return Err("each segment must start with a lowercase letter or a digit");
            }
            Some(_) => {}
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c)) {
            return Err("may only use a-z, 0-9, `-`, `_`, and `.` between `/`s");
        }
    }
    if segments <= 2 && path.split('/').next() == Some(USERS) {
        return Err(
            "`users/<user>` is a user's space: name a secret inside it, e.g. \
                    `users/alice/github`",
        );
    }
    Ok(())
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretPath {
    type Err = SecretPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for SecretPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths() {
        for path in [
            "anthropic",
            "providers/anthropic",
            "ssh/prod-db",
            "a/b_c/d.e/0",
            "9lives",
            "users/alice/github",
            "users/alice/mcp/notion/token",
            "user/alice",
            "userss/alice",
        ] {
            assert!(SecretPath::new(path).is_ok(), "{path}");
        }
        assert!(SecretPath::new("a".repeat(MAX_PATH_LEN)).is_ok());
    }

    #[test]
    fn invalid_paths() {
        for path in [
            "",
            "/a",
            "a/",
            "a//b",
            "Providers/anthropic",
            "a/B",
            ".",
            "..",
            "a/../b",
            "a/./b",
            ".hidden",
            "-a",
            "_a",
            "a b",
            "a:b",
            "a\\b",
            "café",
            "users",
            "users/alice",
        ] {
            assert!(SecretPath::new(path).is_err(), "{path:?}");
        }
        assert!(SecretPath::new("a".repeat(MAX_PATH_LEN + 1)).is_err());
    }

    #[test]
    fn the_owner_comes_from_the_users_space() {
        let owner = |p: &str| SecretPath::new(p).unwrap().owner().map(str::to_owned);
        assert_eq!(owner("users/alice/github").as_deref(), Some("alice"));
        assert_eq!(owner("users/alice/a/b").as_deref(), Some("alice"));
        assert_eq!(owner("providers/anthropic"), None);
        assert_eq!(owner("user/alice/x"), None);
    }
}
