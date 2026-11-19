//! [`LocalSecrets`]: the built-in secret provider, sealing values into `giles.db`.

use std::sync::Arc;

use async_trait::async_trait;
use doozers_store::{SecretRecord, Store, WrappedKey};
use doozers_types::UserId;
use tracing::warn;

use super::cipher::{Key, OpenError, random_key};
use super::key_file::{self, KeyFile};
use super::{KeyError, SecretError, SecretMetadata, SecretPath, SecretProvider};
use crate::config::Secret;
use crate::sessions::Clock;

/// The associated data the data key is sealed with. Secret paths can't contain `:`, so a wrapped
/// data key never opens as a secret's value, nor a value as the data key.
const DATA_KEY_AAD: &[u8] = b"giles:secret-store:data-key";

/// The local secret store: one row per secret in `giles.db`, its value sealed with AES-256-GCM
/// under the store's data key, with the secret's path as associated data so a value moved to
/// another row doesn't open. The data key is stored wrapped (sealed) by the key in a [`KeyFile`].
#[derive(Clone)]
pub struct LocalSecrets {
    store: Store,
    key: Arc<Key>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for LocalSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSecrets").finish_non_exhaustive()
    }
}

impl LocalSecrets {
    /// Opens the store in `store`, unlocking it with the key in `key_file`.
    ///
    /// The first time, it makes a random data key, creating the key file if it's missing and at
    /// the default location ([`KeyError::NotCreated`] elsewhere), and stores the data key wrapped. Later, it unwraps the stored data key. If the key file is
    /// missing or doesn't unwrap the data key while no secret is stored, nothing can be lost, so
    /// it makes a new data key (and key file) with a warning. Once a secret is stored, it never
    /// does.
    ///
    /// # Errors
    ///
    /// [`KeyError`]: the key file is unreadable or malformed, or it is missing or wrong while
    /// secrets are stored, or the database failed.
    pub async fn open(
        store: Store,
        key_file: &KeyFile,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, KeyError> {
        let wrapped = store.secret_data_key().await?;
        let stored = store.secret_count().await?;
        let path = key_file.path();
        let kek = match key_file.read()? {
            Some(kek) => kek,
            None if wrapped.is_some() && stored > 0 => {
                return Err(KeyError::Missing {
                    path: path.to_owned(),
                    stored,
                    configured: !key_file.may_create(),
                });
            }
            None if !key_file.may_create() => {
                return Err(KeyError::NotCreated {
                    path: path.to_owned(),
                });
            }
            None => {
                if wrapped.is_some() {
                    warn!(
                        key_file = %path.display(),
                        "the secret store's key file is missing; no secret is stored, so Giles \
                         makes a new key"
                    );
                }
                key_file.create()?
            }
        };
        let kek = Key::new(&kek);
        if let Some(wrapped) = wrapped {
            match unwrap(&kek, &wrapped) {
                Ok(key) => {
                    return Ok(Self {
                        store,
                        key: Arc::new(key),
                        clock,
                    });
                }
                Err(reason) if stored > 0 => {
                    return Err(KeyError::WrongKey {
                        path: path.to_owned(),
                        stored,
                        reason,
                    });
                }
                Err(reason) => warn!(
                    key_file = %path.display(),
                    reason,
                    "the secret store's key file doesn't unlock its data key; no secret is \
                     stored, so Giles makes a new data key"
                ),
            }
        }
        let data_key = random_key();
        store
            .secret_data_key_set(&WrappedKey {
                source: key_file::SOURCE.to_owned(),
                value: kek.seal(DATA_KEY_AAD, data_key.as_ref()),
                created_at: clock.now(),
            })
            .await?;
        Ok(Self {
            store,
            key: Arc::new(Key::new(&data_key)),
            clock,
        })
    }
}

/// The data key in `wrapped`, opened with `kek`.
fn unwrap(kek: &Key, wrapped: &WrappedKey) -> Result<Key, String> {
    if wrapped.source != key_file::SOURCE {
        return Err(format!(
            "its data key was wrapped by a {:?} key source, not a key file",
            wrapped.source
        ));
    }
    let bytes = kek
        .open(DATA_KEY_AAD, &wrapped.value)
        .map_err(|e| format!("its data key {e}"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "its data key has the wrong length".to_owned())?;
    Ok(Key::new(&zeroize::Zeroizing::new(bytes)))
}

fn unavailable(e: doozers_store::Error) -> SecretError {
    SecretError::Unavailable(Box::new(e))
}

fn metadata(record: SecretRecord) -> Result<SecretMetadata, SecretError> {
    let path = SecretPath::new(record.path.as_str()).map_err(|e| SecretError::Damaged {
        path: record.path.clone(),
        reason: e.to_string(),
    })?;
    Ok(SecretMetadata {
        path,
        description: record.description,
        created_at: record.created_at,
        created_by: record.created_by,
        updated_at: record.updated_at,
        updated_by: record.updated_by,
    })
}

#[async_trait]
impl SecretProvider for LocalSecrets {
    async fn get(&self, path: &SecretPath) -> Result<Option<Secret>, SecretError> {
        let Some((_, sealed)) = self
            .store
            .secret(path.as_str())
            .await
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        let damaged = |reason: String| SecretError::Damaged {
            path: path.to_string(),
            reason,
        };
        let mut plain = self
            .key
            .open(path.as_str().as_bytes(), &sealed)
            .map_err(|e: OpenError| damaged(format!("its value {e}")))?;
        let value = String::from_utf8(std::mem::take(&mut *plain))
            .map_err(|_| damaged("its value is not UTF-8".to_owned()))?;
        Ok(Some(Secret::new(value)))
    }

    async fn metadata(&self, path: &SecretPath) -> Result<Option<SecretMetadata>, SecretError> {
        self.store
            .secret_record(path.as_str())
            .await
            .map_err(unavailable)?
            .map(metadata)
            .transpose()
    }

    async fn list(&self, under: Option<&SecretPath>) -> Result<Vec<SecretMetadata>, SecretError> {
        self.store
            .secret_records(under.map(SecretPath::as_str))
            .await
            .map_err(unavailable)?
            .into_iter()
            .map(metadata)
            .collect()
    }

    async fn put(
        &self,
        path: &SecretPath,
        value: &Secret,
        by: Option<&UserId>,
    ) -> Result<SecretMetadata, SecretError> {
        let sealed = self
            .key
            .seal(path.as_str().as_bytes(), value.expose().as_bytes());
        let record = self
            .store
            .secret_put(path.as_str(), sealed, by, self.clock.now())
            .await
            .map_err(unavailable)?;
        metadata(record)
    }

    async fn describe(
        &self,
        path: &SecretPath,
        description: &str,
        by: Option<&UserId>,
    ) -> Result<SecretMetadata, SecretError> {
        let record = self
            .store
            .secret_describe(path.as_str(), description, by, self.clock.now())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| SecretError::NotFound(path.clone()))?;
        metadata(record)
    }

    async fn delete(&self, path: &SecretPath) -> Result<bool, SecretError> {
        self.store
            .secret_delete(path.as_str())
            .await
            .map_err(unavailable)
    }
}

#[cfg(test)]
mod tests;
