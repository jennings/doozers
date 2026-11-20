//! `ssh_keys`: the metadata of the SSH keys users keep in Doozers.
//!
//! A row describes one key: its owner, label, public half, and fingerprint. The private key is not
//! here: the core keeps it in the secret store at `users/<user>/ssh-keys/<id>`, and builds that
//! path from the row's id. Ids are never reused, so a new key never meets an old key's secret.
//!
//! The store checks no key material. The core parses and fingerprints keys and hands the results
//! to [`Store::ssh_key_insert`]; the store enforces what the schema can: one row per (user,
//! fingerprint), while several users may hold the same key.

use doozers_types::{Timestamp, UserId};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::time::to_millis;
use crate::{Error, Result, Store, get_opt_time, get_time, parse_id, query_all, row_id};

row_id!(
    /// An `ssh_keys` row id. Never reused.
    SshKeyId
);

/// A stored SSH key's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyRecord {
    /// The row id.
    pub id: SshKeyId,
    /// The user who owns the key.
    pub user: UserId,
    /// The user's name for the key.
    pub label: String,
    /// The SSH name of the public key's algorithm, such as `ssh-ed25519`.
    pub algorithm: String,
    /// The public key as `<algorithm> <base64>`, without a comment.
    pub public_key: String,
    /// The `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// When the key was added.
    pub created_at: Timestamp,
    /// When the key last signed, if it ever has.
    pub last_used_at: Option<Timestamp>,
}

/// What [`Store::ssh_key_insert`] stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSshKey {
    /// The user who owns the key.
    pub user: UserId,
    /// The user's name for the key.
    pub label: String,
    /// The SSH name of the public key's algorithm.
    pub algorithm: String,
    /// The public key as `<algorithm> <base64>`, without a comment.
    pub public_key: String,
    /// The `SHA256:...` fingerprint.
    pub fingerprint: String,
}

const COLUMNS: &str =
    "id, user_id, label, algorithm, public_key, fingerprint, created_at, last_used_at";

fn from_row(row: &Row<'_>) -> Result<SshKeyRecord> {
    Ok(SshKeyRecord {
        id: row.get(0)?,
        user: parse_id(row.get(1)?, UserId::new)?,
        label: row.get(2)?,
        algorithm: row.get(3)?,
        public_key: row.get(4)?,
        fingerprint: row.get(5)?,
        created_at: get_time(row, 6)?,
        last_used_at: get_opt_time(row, 7)?,
    })
}

fn find(conn: &Connection, id: SshKeyId) -> Result<Option<SshKeyRecord>> {
    let mut stmt = conn.prepare_cached(&format!("SELECT {COLUMNS} FROM ssh_keys WHERE id = ?1"))?;
    stmt.query_row([id], |row| Ok(from_row(row)))
        .optional()?
        .transpose()
}

impl Store {
    /// Adds a key with `created_at` set to `now` and returns it.
    ///
    /// # Errors
    ///
    /// [`Error::SshKeyExists`], naming the label of the existing key, if the user already has a
    /// key with this fingerprint. Nothing changes.
    pub async fn ssh_key_insert(&self, new: NewSshKey, now: Timestamp) -> Result<SshKeyRecord> {
        self.write(move |conn| {
            let existing: Option<String> = conn
                .prepare_cached("SELECT label FROM ssh_keys WHERE user_id = ?1 AND fingerprint = ?2")?
                .query_row(params![new.user.as_str(), new.fingerprint], |row| row.get(0))
                .optional()?;
            if let Some(label) = existing {
                return Err(Error::SshKeyExists { label });
            }
            conn.prepare_cached(
                "INSERT INTO ssh_keys (user_id, label, algorithm, public_key, fingerprint, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![
                new.user.as_str(),
                new.label,
                new.algorithm,
                new.public_key,
                new.fingerprint,
                to_millis(now)
            ])?;
            let id = SshKeyId::new(conn.last_insert_rowid());
            find(conn, id)?.ok_or_else(|| Error::corrupt("the SSH key just inserted is missing"))
        })
        .await
    }

    /// The key `id`, if there is one, whoever owns it.
    pub async fn ssh_key(&self, id: SshKeyId) -> Result<Option<SshKeyRecord>> {
        self.read(move |conn| find(conn, id)).await
    }

    /// `user`'s keys, oldest first: the order the web page lists them in, which doesn't move
    /// when a key is used.
    pub async fn ssh_keys(&self, user: &UserId) -> Result<Vec<SshKeyRecord>> {
        let user = user.clone();
        self.read(move |conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM ssh_keys WHERE user_id = ?1 ORDER BY created_at, id"
            ))?;
            query_all(&mut stmt, [user.as_str()], from_row)
        })
        .await
    }

    /// `user`'s keys in the order an agent offers them: most recently used first, keys never
    /// used last, and among those the newest first.
    pub async fn ssh_keys_by_recent_use(&self, user: &UserId) -> Result<Vec<SshKeyRecord>> {
        let user = user.clone();
        self.read(move |conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM ssh_keys WHERE user_id = ?1
                 ORDER BY last_used_at IS NULL, last_used_at DESC, created_at DESC, id DESC"
            ))?;
            query_all(&mut stmt, [user.as_str()], from_row)
        })
        .await
    }

    /// Every user's keys, ordered by user, then oldest first.
    pub async fn ssh_keys_all(&self) -> Result<Vec<SshKeyRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM ssh_keys ORDER BY user_id, created_at, id"
            ))?;
            query_all(&mut stmt, [], from_row)
        })
        .await
    }

    /// Gives key `id` a new label. `false` if there is no such key.
    pub async fn ssh_key_rename(&self, id: SshKeyId, label: &str) -> Result<bool> {
        let label = label.to_owned();
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("UPDATE ssh_keys SET label = ?2 WHERE id = ?1")?
                .execute(params![id, label])?
                == 1)
        })
        .await
    }

    /// Deletes key `id`. `false` if there was none.
    pub async fn ssh_key_delete(&self, id: SshKeyId) -> Result<bool> {
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("DELETE FROM ssh_keys WHERE id = ?1")?
                .execute([id])?
                == 1)
        })
        .await
    }

    /// Sets key `id`'s `last_used_at` to `now`. `false` if there is no such key.
    pub async fn ssh_key_touch_used(&self, id: SshKeyId, now: Timestamp) -> Result<bool> {
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("UPDATE ssh_keys SET last_used_at = ?2 WHERE id = ?1")?
                .execute(params![id, to_millis(now)])?
                == 1)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCHEMA_VERSION;
    use crate::migrate::{MIGRATIONS, migrate};
    use crate::sessions::tests::{at, store};

    fn user(name: &str) -> UserId {
        UserId::new(name).unwrap()
    }

    fn new_key(owner: &str, label: &str, fingerprint: &str) -> NewSshKey {
        NewSshKey {
            user: user(owner),
            label: label.to_owned(),
            algorithm: "ssh-ed25519".to_owned(),
            public_key: format!("ssh-ed25519 AAAA{fingerprint}"),
            fingerprint: fingerprint.to_owned(),
        }
    }

    async fn labels(store: &Store, owner: &str) -> Vec<String> {
        store
            .ssh_keys(&user(owner))
            .await
            .unwrap()
            .into_iter()
            .map(|key| key.label)
            .collect()
    }

    #[tokio::test]
    async fn insert_stores_the_key_unused() {
        let (_dir, store) = store().await;
        let key = store
            .ssh_key_insert(new_key("owner", "laptop", "SHA256:a"), at(5))
            .await
            .unwrap();
        assert_eq!(key.user, user("owner"));
        assert_eq!(key.label, "laptop");
        assert_eq!(key.algorithm, "ssh-ed25519");
        assert_eq!(key.public_key, "ssh-ed25519 AAAASHA256:a");
        assert_eq!(key.fingerprint, "SHA256:a");
        assert_eq!(key.created_at, at(5));
        assert_eq!(key.last_used_at, None);
        assert_eq!(store.ssh_key(key.id).await.unwrap(), Some(key.clone()));
        assert_eq!(store.ssh_keys(&user("owner")).await.unwrap(), [key]);
        assert_eq!(store.ssh_key(SshKeyId::new(99)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_user_cant_hold_a_fingerprint_twice() {
        let (_dir, store) = store().await;
        store
            .ssh_key_insert(new_key("owner", "first", "SHA256:a"), at(0))
            .await
            .unwrap();
        let err = store
            .ssh_key_insert(new_key("owner", "second", "SHA256:a"), at(1))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::SshKeyExists { label } if label == "first"),
            "{err:?}"
        );
        assert_eq!(labels(&store, "owner").await, ["first"]);
    }

    #[tokio::test]
    async fn two_users_can_hold_the_same_key() {
        let (_dir, store) = store().await;
        let a = store
            .ssh_key_insert(new_key("owner", "mine", "SHA256:a"), at(0))
            .await
            .unwrap();
        let b = store
            .ssh_key_insert(new_key("alice", "hers", "SHA256:a"), at(1))
            .await
            .unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(labels(&store, "owner").await, ["mine"]);
        assert_eq!(labels(&store, "alice").await, ["hers"]);
        let all = store.ssh_keys_all().await.unwrap();
        assert_eq!(all, [b, a], "ordered by user: alice, then owner");
    }

    #[tokio::test]
    async fn the_schema_enforces_the_unique_fingerprint() {
        let (_dir, store) = store().await;
        store
            .ssh_key_insert(new_key("owner", "first", "SHA256:a"), at(0))
            .await
            .unwrap();
        let err = store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO ssh_keys (user_id, label, algorithm, public_key, fingerprint, created_at)
                     VALUES ('owner', 'x', 'ssh-ed25519', 'k', 'SHA256:a', 0)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Database(_)), "{err}");
    }

    #[tokio::test]
    async fn lists_are_oldest_first_and_by_recent_use_for_agents() {
        let (_dir, store) = store().await;
        let a = store
            .ssh_key_insert(new_key("owner", "a", "SHA256:a"), at(0))
            .await
            .unwrap();
        let b = store
            .ssh_key_insert(new_key("owner", "b", "SHA256:b"), at(1))
            .await
            .unwrap();
        let c = store
            .ssh_key_insert(new_key("owner", "c", "SHA256:c"), at(2))
            .await
            .unwrap();
        store
            .ssh_key_insert(new_key("alice", "other", "SHA256:z"), at(3))
            .await
            .unwrap();
        let ids = |keys: Vec<SshKeyRecord>| keys.into_iter().map(|k| k.id).collect::<Vec<_>>();

        assert_eq!(
            ids(store.ssh_keys(&user("owner")).await.unwrap()),
            [a.id, b.id, c.id]
        );
        // Never used: newest first.
        assert_eq!(
            ids(store.ssh_keys_by_recent_use(&user("owner")).await.unwrap()),
            [c.id, b.id, a.id]
        );

        // Used keys come first, the most recently used first; the others keep newest first.
        store.ssh_key_touch_used(a.id, at(10)).await.unwrap();
        store.ssh_key_touch_used(b.id, at(20)).await.unwrap();
        assert_eq!(
            ids(store.ssh_keys_by_recent_use(&user("owner")).await.unwrap()),
            [b.id, a.id, c.id]
        );
        store.ssh_key_touch_used(a.id, at(30)).await.unwrap();
        assert_eq!(
            ids(store.ssh_keys_by_recent_use(&user("owner")).await.unwrap()),
            [a.id, b.id, c.id]
        );
        // The page's order doesn't move.
        assert_eq!(
            ids(store.ssh_keys(&user("owner")).await.unwrap()),
            [a.id, b.id, c.id]
        );
    }

    #[tokio::test]
    async fn rename_changes_only_the_label() {
        let (_dir, store) = store().await;
        let key = store
            .ssh_key_insert(new_key("owner", "old", "SHA256:a"), at(0))
            .await
            .unwrap();
        assert!(store.ssh_key_rename(key.id, "new").await.unwrap());
        let renamed = store.ssh_key(key.id).await.unwrap().unwrap();
        assert_eq!(
            renamed,
            SshKeyRecord {
                label: "new".to_owned(),
                ..key
            }
        );
        assert!(!store.ssh_key_rename(SshKeyId::new(99), "x").await.unwrap());
    }

    #[tokio::test]
    async fn delete_removes_the_row_and_never_reuses_its_id() {
        let (_dir, store) = store().await;
        let first = store
            .ssh_key_insert(new_key("owner", "a", "SHA256:a"), at(0))
            .await
            .unwrap();
        assert!(store.ssh_key_delete(first.id).await.unwrap());
        assert!(!store.ssh_key_delete(first.id).await.unwrap());
        assert!(store.ssh_keys(&user("owner")).await.unwrap().is_empty());
        // The fingerprint is free again, under a new id.
        let second = store
            .ssh_key_insert(new_key("owner", "a", "SHA256:a"), at(1))
            .await
            .unwrap();
        assert!(second.id > first.id);
    }

    #[tokio::test]
    async fn touch_sets_last_used() {
        let (_dir, store) = store().await;
        let key = store
            .ssh_key_insert(new_key("owner", "a", "SHA256:a"), at(0))
            .await
            .unwrap();
        assert!(store.ssh_key_touch_used(key.id, at(7)).await.unwrap());
        let used = store.ssh_key(key.id).await.unwrap().unwrap();
        assert_eq!(used.last_used_at, Some(at(7)));
        assert_eq!(used.created_at, at(0));
        assert!(
            !store
                .ssh_key_touch_used(SshKeyId::new(99), at(8))
                .await
                .unwrap()
        );
    }

    fn table_exists(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'ssh_keys'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    #[tokio::test]
    async fn an_existing_database_gains_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doozers.db");
        let before = MIGRATIONS
            .iter()
            .position(|m| m.name == "0012_ssh_keys")
            .unwrap();
        {
            let mut conn = Connection::open(&path).unwrap();
            migrate(&mut conn, &MIGRATIONS[..before], None).unwrap();
            assert!(!table_exists(&conn));
        }
        let store = Store::open(&path).await.unwrap();
        let (exists, version) = store
            .read(|conn| {
                Ok((
                    table_exists(conn),
                    conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
                ))
            })
            .await
            .unwrap();
        assert!(exists);
        assert_eq!(version, SCHEMA_VERSION);
        assert!(store.ssh_keys_all().await.unwrap().is_empty());
    }
}
