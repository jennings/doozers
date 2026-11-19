//! `secrets` and `secret_key`: the rows of the local secret store (`doozers_core::secrets`).
//!
//! The store keeps what the core gives it and checks nothing about it: validating paths and
//! sealing and opening values are the core's business. A value only ever passes through here
//! sealed ([`SealedValue`]), so nothing in this crate sees a secret.
//!
//! Paths are compared byte for byte. The core admits only lowercase paths, so no two rows can
//! differ by case alone.

use doozers_types::{Timestamp, UserId};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::time::to_millis;
use crate::{Error, Result, Store, get_time, parse_id, query_all};

/// A value as sealed by an AEAD cipher: what the core stores in place of a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedValue {
    /// The cipher that sealed it, e.g. `aes-256-gcm`.
    pub algorithm: String,
    /// The nonce it was sealed with.
    pub nonce: Vec<u8>,
    /// The ciphertext followed by its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// A stored secret's name and metadata, without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    /// The secret's path.
    pub path: String,
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

/// The data key of the secret store, sealed by a key-encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    /// The kind of key source whose key sealed it, e.g. `key-file`.
    pub source: String,
    /// The sealed data key.
    pub value: SealedValue,
    /// When the data key was made.
    pub created_at: Timestamp,
}

const RECORD_COLUMNS: &str = "path, description, created_at, created_by, updated_at, updated_by";

fn user(row: &Row<'_>, idx: usize) -> Result<Option<UserId>> {
    row.get::<_, Option<String>>(idx)?
        .map(|id| parse_id(id, UserId::new))
        .transpose()
}

fn record_from_row(row: &Row<'_>) -> Result<SecretRecord> {
    Ok(SecretRecord {
        path: row.get(0)?,
        description: row.get(1)?,
        created_at: get_time(row, 2)?,
        created_by: user(row, 3)?,
        updated_at: get_time(row, 4)?,
        updated_by: user(row, 5)?,
    })
}

fn find_record(conn: &Connection, path: &str) -> Result<Option<SecretRecord>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {RECORD_COLUMNS} FROM secrets WHERE path = ?1"
    ))?;
    stmt.query_row([path], |row| Ok(record_from_row(row)))
        .optional()?
        .transpose()
}

fn require_record(conn: &Connection, path: &str) -> Result<SecretRecord> {
    find_record(conn, path)?.ok_or_else(|| Error::not_found(format!("secret {path}")))
}

fn by(user: Option<&UserId>) -> Option<String> {
    user.map(|u| u.as_str().to_owned())
}

impl Store {
    /// The secret at `path` and its sealed value, if there is one.
    pub async fn secret(&self, path: &str) -> Result<Option<(SecretRecord, SealedValue)>> {
        let path = path.to_owned();
        self.read(move |conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {RECORD_COLUMNS}, algorithm, nonce, ciphertext FROM secrets WHERE path = ?1"
            ))?;
            stmt.query_row([path], |row| {
                Ok(record_from_row(row).and_then(|record| {
                    Ok((
                        record,
                        SealedValue {
                            algorithm: row.get(6)?,
                            nonce: row.get(7)?,
                            ciphertext: row.get(8)?,
                        },
                    ))
                }))
            })
            .optional()?
            .transpose()
        })
        .await
    }

    /// The name and metadata of the secret at `path`, if there is one.
    pub async fn secret_record(&self, path: &str) -> Result<Option<SecretRecord>> {
        let path = path.to_owned();
        self.read(move |conn| find_record(conn, &path)).await
    }

    /// The secrets below `under` (paths starting with `under/`), or every secret if `under` is
    /// `None`, ordered by path. A secret at `under` itself isn't below it.
    pub async fn secret_records(&self, under: Option<&str>) -> Result<Vec<SecretRecord>> {
        // Paths below `p` sort from `p/` up to, not including, `p0` (`0` follows `/` in ASCII).
        let range = under.map(|p| (format!("{p}/"), format!("{p}0")));
        self.read(move |conn| match range {
            Some((from, to)) => {
                let mut stmt = conn.prepare_cached(&format!(
                    "SELECT {RECORD_COLUMNS} FROM secrets WHERE path >= ?1 AND path < ?2
                     ORDER BY path"
                ))?;
                query_all(&mut stmt, [from, to], record_from_row)
            }
            None => {
                let mut stmt = conn.prepare_cached(&format!(
                    "SELECT {RECORD_COLUMNS} FROM secrets ORDER BY path"
                ))?;
                query_all(&mut stmt, [], record_from_row)
            }
        })
        .await
    }

    /// Stores `value` at `path`: creates the secret, with an empty description, if there is
    /// none, or replaces its value and keeps its description and creation. Either way the
    /// secret's update is `now` by `user`. Returns its record.
    pub async fn secret_put(
        &self,
        path: &str,
        value: SealedValue,
        user: Option<&UserId>,
        now: Timestamp,
    ) -> Result<SecretRecord> {
        let (path, user, now) = (path.to_owned(), by(user), to_millis(now));
        self.write(move |conn| {
            conn.prepare_cached(
                "INSERT INTO secrets (path, algorithm, nonce, ciphertext,
                     created_at, created_by, updated_at, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, ?6)
                 ON CONFLICT (path) DO UPDATE SET
                     algorithm = excluded.algorithm,
                     nonce = excluded.nonce,
                     ciphertext = excluded.ciphertext,
                     updated_at = excluded.updated_at,
                     updated_by = excluded.updated_by",
            )?
            .execute(params![
                path,
                value.algorithm,
                value.nonce,
                value.ciphertext,
                now,
                user
            ])?;
            require_record(conn, &path)
        })
        .await
    }

    /// Sets the description of the secret at `path`, its update to `now` by `user`, and returns
    /// its record. `None` if there is no such secret; nothing changes then.
    pub async fn secret_describe(
        &self,
        path: &str,
        description: &str,
        user: Option<&UserId>,
        now: Timestamp,
    ) -> Result<Option<SecretRecord>> {
        let (path, description) = (path.to_owned(), description.to_owned());
        let (user, now) = (by(user), to_millis(now));
        self.write(move |conn| {
            let changed = conn
                .prepare_cached(
                    "UPDATE secrets SET description = ?2, updated_at = ?3, updated_by = ?4
                     WHERE path = ?1",
                )?
                .execute(params![path, description, now, user])?;
            if changed == 0 {
                return Ok(None);
            }
            require_record(conn, &path).map(Some)
        })
        .await
    }

    /// Deletes the secret at `path`. Returns `false` if there is none.
    pub async fn secret_delete(&self, path: &str) -> Result<bool> {
        let path = path.to_owned();
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("DELETE FROM secrets WHERE path = ?1")?
                .execute([path])?
                == 1)
        })
        .await
    }

    /// The secret store's wrapped data key, if one was stored.
    pub async fn secret_data_key(&self) -> Result<Option<WrappedKey>> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT source, algorithm, nonce, wrapped, created_at FROM secret_key",
            )?;
            stmt.query_row([], |row| {
                Ok((|| {
                    Ok(WrappedKey {
                        source: row.get(0)?,
                        value: SealedValue {
                            algorithm: row.get(1)?,
                            nonce: row.get(2)?,
                            ciphertext: row.get(3)?,
                        },
                        created_at: get_time(row, 4)?,
                    })
                })())
            })
            .optional()?
            .transpose()
        })
        .await
    }

    /// How many secrets are stored.
    pub async fn secret_count(&self) -> Result<u64> {
        self.read(|conn| {
            let count: i64 = conn
                .prepare_cached("SELECT count(*) FROM secrets")?
                .query_row([], |row| row.get(0))?;
            u64::try_from(count).map_err(|_| Error::corrupt("negative secret count"))
        })
        .await
    }

    /// Stores the secret store's wrapped data key, replacing any stored before. Every secret is
    /// sealed with the data key, so it may only change while no secret is stored; the check and
    /// the write are one transaction.
    ///
    /// # Errors
    ///
    /// [`Error::Conflict`] if a secret is stored. Nothing changes.
    pub async fn secret_data_key_set(&self, key: &WrappedKey) -> Result<()> {
        let key = key.clone();
        self.write(move |conn| {
            let stored: i64 = conn
                .prepare_cached("SELECT count(*) FROM secrets")?
                .query_row([], |row| row.get(0))?;
            if stored > 0 {
                return Err(Error::conflict(
                    "the secret store's data key can't change while secrets are stored",
                ));
            }
            conn.prepare_cached(
                "INSERT OR REPLACE INTO secret_key (id, source, algorithm, nonce, wrapped, created_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![
                key.source,
                key.value.algorithm,
                key.value.nonce,
                key.value.ciphertext,
                to_millis(key.created_at)
            ])?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::migrate::{MIGRATIONS, migrate};
    use crate::sessions::tests::{at, store};

    fn sealed(byte: u8) -> SealedValue {
        SealedValue {
            algorithm: "aes-256-gcm".into(),
            nonce: vec![byte; 12],
            ciphertext: vec![byte; 20],
        }
    }

    fn alice() -> UserId {
        UserId::new("alice").unwrap()
    }

    async fn paths(store: &Store, under: Option<&str>) -> Vec<String> {
        store
            .secret_records(under)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.path)
            .collect()
    }

    #[tokio::test]
    async fn put_creates_then_replaces_the_value_keeping_description_and_creation() {
        let (_dir, store) = store().await;
        let created = store
            .secret_put("providers/anthropic", sealed(1), None, at(0))
            .await
            .unwrap();
        assert_eq!(created.description, "");
        assert_eq!((created.created_at, created.updated_at), (at(0), at(0)));
        assert_eq!((created.created_by, created.updated_by), (None, None));

        store
            .secret_describe("providers/anthropic", "API key", None, at(1))
            .await
            .unwrap()
            .unwrap();
        let replaced = store
            .secret_put("providers/anthropic", sealed(2), Some(&alice()), at(2))
            .await
            .unwrap();
        assert_eq!(replaced.description, "API key");
        assert_eq!(
            (replaced.created_at, replaced.created_by.clone()),
            (at(0), None)
        );
        assert_eq!(
            (replaced.updated_at, replaced.updated_by.clone()),
            (at(2), Some(alice()))
        );

        let (record, value) = store.secret("providers/anthropic").await.unwrap().unwrap();
        assert_eq!(record, replaced);
        assert_eq!(value, sealed(2));
    }

    #[tokio::test]
    async fn describe_and_delete_report_a_missing_secret() {
        let (_dir, store) = store().await;
        assert!(store.secret("x").await.unwrap().is_none());
        assert!(store.secret_record("x").await.unwrap().is_none());
        assert!(
            store
                .secret_describe("x", "d", None, at(0))
                .await
                .unwrap()
                .is_none()
        );
        assert!(!store.secret_delete("x").await.unwrap());

        store.secret_put("x", sealed(1), None, at(0)).await.unwrap();
        let described = store
            .secret_describe("x", "d", Some(&alice()), at(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (described.description.as_str(), described.updated_by),
            ("d", Some(alice()))
        );
        assert!(store.secret_delete("x").await.unwrap());
        assert!(store.secret_record("x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn records_below_a_path_exclude_the_path_itself_and_its_lookalikes() {
        let (_dir, store) = store().await;
        for path in [
            "ssh",
            "ssh/prod",
            "ssh/prod/db",
            "ssh-old/a",
            "ssh.d/x",
            "ssh0",
            "a",
        ] {
            store
                .secret_put(path, sealed(0), None, at(0))
                .await
                .unwrap();
        }
        assert_eq!(
            paths(&store, Some("ssh")).await,
            ["ssh/prod", "ssh/prod/db"]
        );
        assert_eq!(paths(&store, Some("ssh/prod")).await, ["ssh/prod/db"]);
        assert!(paths(&store, Some("nothing")).await.is_empty());
        assert_eq!(
            paths(&store, None).await,
            [
                "a",
                "ssh",
                "ssh-old/a",
                "ssh.d/x",
                "ssh/prod",
                "ssh/prod/db",
                "ssh0"
            ]
        );
    }

    #[tokio::test]
    async fn the_data_key_changes_only_while_no_secret_is_stored() {
        let (_dir, store) = store().await;
        assert!(store.secret_data_key().await.unwrap().is_none());
        let first = WrappedKey {
            source: "key-file".into(),
            value: sealed(7),
            created_at: at(0),
        };
        store.secret_data_key_set(&first).await.unwrap();
        let second = WrappedKey {
            value: sealed(8),
            created_at: at(1),
            ..first.clone()
        };
        store.secret_data_key_set(&second).await.unwrap();
        assert_eq!(store.secret_data_key().await.unwrap(), Some(second.clone()));

        store.secret_put("a", sealed(1), None, at(2)).await.unwrap();
        assert_eq!(store.secret_count().await.unwrap(), 1);
        let err = store.secret_data_key_set(&first).await.unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "{err:?}");
        assert_eq!(store.secret_data_key().await.unwrap(), Some(second));
    }

    #[tokio::test]
    async fn an_existing_database_gains_the_tables_and_keeps_its_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("giles.db");
        let before = MIGRATIONS
            .iter()
            .position(|m| m.name == "0007_secrets")
            .unwrap();
        {
            let mut conn = Connection::open(&path).unwrap();
            migrate(&mut conn, &MIGRATIONS[..before], None).unwrap();
            conn.execute(
                "INSERT INTO toolsets (name, spec, created_at, updated_at)
                 VALUES ('files', '{}', 0, 0)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).await.unwrap();
        assert_eq!(store.toolsets().await.unwrap().len(), 1);
        assert!(store.secret_records(None).await.unwrap().is_empty());
        assert!(store.secret_data_key().await.unwrap().is_none());
    }
}
