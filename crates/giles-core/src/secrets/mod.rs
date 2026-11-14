//! The secret store (PLAN section 7.7): named credentials the core injects into the components
//! that use them, never shown to the model or through any Giles surface.
//!
//! A [`SecretProvider`] holds secrets by [`SecretPath`]. [`LocalSecrets`] is the built-in
//! provider: values sealed with AES-256-GCM in `giles.db`, under a data key wrapped by the key in
//! a [`KeyFile`]. Other providers (HashiCorp Vault, `giles-secret-*` plugins over gRPC) implement
//! the same trait. Who may use or manage a secret is the core's check, made above the provider.
//! The design is in `Docs/technical/secret-store.md`.

mod cipher;
mod key_file;
mod local;
mod path;

use std::fmt;
use std::io;
use std::path::PathBuf;

use async_trait::async_trait;
use giles_types::{Timestamp, UserId};

use crate::config::Secret;

pub use key_file::KeyFile;
pub use local::LocalSecrets;
pub use path::{MAX_PATH_LEN, SecretPath, SecretPathError};

/// A secret's name and metadata. Never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecretMetadata {
    /// The secret's path. Its owner, if any, is [`SecretPath::owner`].
    pub path: SecretPath,
    /// What the secret is for, for people. Empty if never set.
    pub description: String,
    /// When the secret was created.
    pub created_at: Timestamp,
    /// The user who created it, or `None` if no user did (the operator at the CLI, or Giles).
    pub created_by: Option<UserId>,
    /// When its value or description last changed.
    pub updated_at: Timestamp,
    /// The user who last changed it, or `None` if no user did.
    pub updated_by: Option<UserId>,
}

/// A secret provider operation failed. No message quotes a value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// There is no secret at the path.
    #[error("no secret {0}")]
    NotFound(SecretPath),
    /// The stored secret can't be read back: its value doesn't decrypt or authenticate, or its
    /// stored form is malformed.
    #[error("secret {path} is damaged: {reason}")]
    Damaged {
        /// The secret's path, as stored.
        path: String,
        /// What's wrong.
        reason: String,
    },
    /// The provider's backend failed or can't be reached. Says nothing about whether the secret
    /// exists.
    #[error("the secret store is unavailable: {0}")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Holds secrets by path.
///
/// Values go in through [`put`](Self::put) and come out only through [`get`](Self::get), which is
/// for the core to inject a value into a component's connection, environment, or configuration.
/// Every other method deals in names and [`SecretMetadata`]. Implementations don't check who is
/// asking: the core does.
#[async_trait]
pub trait SecretProvider: fmt::Debug + Send + Sync {
    /// The value at `path`, if there is a secret there.
    async fn get(&self, path: &SecretPath) -> Result<Option<Secret>, SecretError>;

    /// The metadata of the secret at `path`, if there is one.
    async fn metadata(&self, path: &SecretPath) -> Result<Option<SecretMetadata>, SecretError>;

    /// The secrets below `under` (paths starting with `under/`), or every secret if `under` is
    /// `None`, ordered by path.
    async fn list(&self, under: Option<&SecretPath>) -> Result<Vec<SecretMetadata>, SecretError>;

    /// Creates the secret at `path` with `value` and an empty description, or replaces its value,
    /// keeping its description. `by` is the user making the change, `None` for none.
    async fn put(
        &self,
        path: &SecretPath,
        value: &Secret,
        by: Option<&UserId>,
    ) -> Result<SecretMetadata, SecretError>;

    /// Sets the description of the secret at `path`, leaving its value alone.
    ///
    /// # Errors
    ///
    /// [`SecretError::NotFound`] if there is no secret at `path`.
    async fn describe(
        &self,
        path: &SecretPath,
        description: &str,
        by: Option<&UserId>,
    ) -> Result<SecretMetadata, SecretError>;

    /// Deletes the secret at `path`. `false` if there was none.
    async fn delete(&self, path: &SecretPath) -> Result<bool, SecretError>;
}

/// The local secret store couldn't be opened at startup. Messages name the key file and say what
/// to do; none quotes the file's contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The key file couldn't be inspected, read, or created.
    #[error("cannot {action} the secret store's key file {}: {source}", .path.display())]
    Io {
        /// The key file.
        path: PathBuf,
        /// What Giles was doing: `inspect`, `read`, `create`, or `write`.
        action: &'static str,
        /// Why.
        source: io::Error,
    },
    /// The key file isn't a regular file.
    #[error("the secret store's key file {} is not a regular file", .path.display())]
    NotAFile {
        /// The key file.
        path: PathBuf,
    },
    /// Group or others can access the key file.
    #[error(
        "group or others can access the secret store's key file {} (mode {mode:04o}); run \
         `chmod 600 {}`",
        .path.display(),
        .path.display()
    )]
    Permissions {
        /// The key file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The key file doesn't hold a key.
    #[error(
        "the secret store's key file {} must hold 64 hex digits, such as `openssl rand -hex 32` \
         prints",
        .path.display()
    )]
    Format {
        /// The key file.
        path: PathBuf,
    },
    /// The key file is missing, and secrets sealed with its key are stored.
    #[error(
        "the secret store's key file {} is missing, and giles.db holds {stored} secret(s) sealed \
         with its key; restore the file from where you keep it",
        .path.display()
    )]
    Missing {
        /// The key file.
        path: PathBuf,
        /// How many secrets are stored.
        stored: u64,
    },
    /// The key file's key doesn't unlock the stored data key, and secrets sealed with it are
    /// stored.
    #[error(
        "the secret store's key file {} doesn't unlock the secrets in giles.db ({stored} stored): \
         {reason}; put back the key file they were stored with",
        .path.display()
    )]
    WrongKey {
        /// The key file.
        path: PathBuf,
        /// How many secrets are stored.
        stored: u64,
        /// Why the data key didn't unwrap.
        reason: String,
    },
    /// The database couldn't be read or written.
    #[error("cannot open the secret store in giles.db: {0}")]
    Store(#[from] giles_store::Error),
}
