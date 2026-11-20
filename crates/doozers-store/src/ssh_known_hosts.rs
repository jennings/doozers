//! `ssh_known_hosts`: the SSH host keys workspaces trust, one set per environment instance.
//!
//! A row is one key of one host: the environment instance, the host and port, the key's type,
//! base64 blob, and fingerprint, and where it came from: either the first connection that
//! recorded it (workspace, agent, and user) or the admin who pinned it. A host may have several
//! keys, one per type. The core normalizes hosts, parses and fingerprints keys, and decides what a
//! lookup means (`doozers_core::ssh::known_hosts`); the store enforces what the schema can, one
//! row per (environment, host, port, key), and makes the two ways in atomic: recording a key on
//! first use only when the host has none ([`Store::known_host_record_first_use`]), and pinning one
//! unless that exact key is already there ([`Store::known_host_pin`]).
//!
//! Rows move with an environment instance's rename ([`crate::RenamedRows::known_hosts`]).

use doozers_types::{Timestamp, UserId};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::time::to_millis;
use crate::{Error, Result, Store, get_opt_time, get_time, parse_id, query_all, row_id};

row_id!(
    /// An `ssh_known_hosts` row id. Never reused.
    KnownHostId
);

/// One stored host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostRecord {
    /// The row id.
    pub id: KnownHostId,
    /// The environment instance whose workspaces trust the key.
    pub environment: String,
    /// The lowercased host name or address, without brackets or port.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The SSH name of the key's algorithm, such as `ssh-ed25519`.
    pub key_type: String,
    /// The base64 of the key's wire blob, as in a `known_hosts` line.
    pub public_key: String,
    /// The `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// When the key was recorded or pinned.
    pub first_seen_at: Timestamp,
    /// The workspace whose first connection recorded the key. `None` for a pinned key.
    pub first_workspace: Option<String>,
    /// The agent of that workspace's conversation, if it had one. `None` for a pinned key.
    pub first_agent: Option<String>,
    /// The user whose keys that workspace had, if it had a key user. `None` for a pinned key.
    pub first_user: Option<String>,
    /// The admin who pinned the key. `None` for a key recorded on first use.
    pub added_by: Option<UserId>,
    /// When a connection was last checked against the key, if one has been.
    pub last_used_at: Option<Timestamp>,
}

/// What [`Store::known_host_record_first_use`] and [`Store::known_host_pin`] store. The row's
/// `first_seen_at` is the `now` the call is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKnownHost {
    /// The environment instance.
    pub environment: String,
    /// The lowercased host, without brackets or port.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The SSH name of the key's algorithm.
    pub key_type: String,
    /// The base64 of the key's wire blob.
    pub public_key: String,
    /// The `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// The workspace whose connection recorded the key; `None` when pinned.
    pub first_workspace: Option<String>,
    /// The agent of that workspace's conversation, if any; `None` when pinned.
    pub first_agent: Option<String>,
    /// The user whose keys that workspace had, if any; `None` when pinned.
    pub first_user: Option<String>,
    /// The admin who pins the key; `None` when recorded on first use.
    pub added_by: Option<UserId>,
}

const COLUMNS: &str = "id, environment, host, port, key_type, public_key, fingerprint, \
                       first_seen_at, first_workspace, first_agent, first_user, added_by, \
                       last_used_at";

fn from_row(row: &Row<'_>) -> Result<KnownHostRecord> {
    let port: i64 = row.get(3)?;
    Ok(KnownHostRecord {
        id: row.get(0)?,
        environment: row.get(1)?,
        host: row.get(2)?,
        port: u16::try_from(port).map_err(|_| Error::corrupt("a known host's port is invalid"))?,
        key_type: row.get(4)?,
        public_key: row.get(5)?,
        fingerprint: row.get(6)?,
        first_seen_at: get_time(row, 7)?,
        first_workspace: row.get(8)?,
        first_agent: row.get(9)?,
        first_user: row.get(10)?,
        added_by: row
            .get::<_, Option<String>>(11)?
            .map(|name| parse_id(name, UserId::new))
            .transpose()?,
        last_used_at: get_opt_time(row, 12)?,
    })
}

fn find(conn: &Connection, id: KnownHostId) -> Result<Option<KnownHostRecord>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM ssh_known_hosts WHERE id = ?1"
    ))?;
    stmt.query_row([id], |row| Ok(from_row(row)))
        .optional()?
        .transpose()
}

fn insert(conn: &Connection, new: &NewKnownHost, now: Timestamp) -> Result<KnownHostRecord> {
    conn.prepare_cached(
        "INSERT INTO ssh_known_hosts (environment, host, port, key_type, public_key, fingerprint,
                                      first_seen_at, first_workspace, first_agent, first_user,
                                      added_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?
    .execute(params![
        new.environment,
        new.host,
        new.port,
        new.key_type,
        new.public_key,
        new.fingerprint,
        to_millis(now),
        new.first_workspace,
        new.first_agent,
        new.first_user,
        new.added_by.as_ref().map(UserId::as_str),
    ])?;
    let id = KnownHostId::new(conn.last_insert_rowid());
    find(conn, id)?.ok_or_else(|| Error::corrupt("the known host just inserted is missing"))
}

impl Store {
    /// Records `new` on a first connection, only if the environment has no key for the host and
    /// port yet. `None`, and nothing changes, if it has one: the key offered is then a match or a
    /// mismatch for the core to judge, never new trust.
    pub async fn known_host_record_first_use(
        &self,
        new: NewKnownHost,
        now: Timestamp,
    ) -> Result<Option<KnownHostRecord>> {
        self.write(move |conn| {
            let known: i64 = conn
                .prepare_cached(
                    "SELECT count(*) FROM ssh_known_hosts
                     WHERE environment = ?1 AND host = ?2 AND port = ?3",
                )?
                .query_row(params![new.environment, new.host, new.port], |row| {
                    row.get(0)
                })?;
            if known > 0 {
                return Ok(None);
            }
            insert(conn, &new, now).map(Some)
        })
        .await
    }

    /// Adds `new` whether or not the host has other keys. `None`, and nothing changes, if this
    /// exact key is already stored for the host and port.
    pub async fn known_host_pin(
        &self,
        new: NewKnownHost,
        now: Timestamp,
    ) -> Result<Option<KnownHostRecord>> {
        self.write(move |conn| {
            let known: i64 = conn
                .prepare_cached(
                    "SELECT count(*) FROM ssh_known_hosts
                     WHERE environment = ?1 AND host = ?2 AND port = ?3 AND public_key = ?4",
                )?
                .query_row(
                    params![new.environment, new.host, new.port, new.public_key],
                    |row| row.get(0),
                )?;
            if known > 0 {
                return Ok(None);
            }
            insert(conn, &new, now).map(Some)
        })
        .await
    }

    /// The keys stored for `host` and `port` of `environment`, oldest first.
    pub async fn known_hosts_for(
        &self,
        environment: &str,
        host: &str,
        port: u16,
    ) -> Result<Vec<KnownHostRecord>> {
        let (environment, host) = (environment.to_owned(), host.to_owned());
        self.read(move |conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM ssh_known_hosts
                 WHERE environment = ?1 AND host = ?2 AND port = ?3 ORDER BY id"
            ))?;
            query_all(&mut stmt, params![environment, host, port], from_row)
        })
        .await
    }

    /// Every stored key, by environment, host, port, then oldest first: the order of the admin
    /// page.
    pub async fn known_hosts_all(&self) -> Result<Vec<KnownHostRecord>> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM ssh_known_hosts ORDER BY environment, host, port, id"
            ))?;
            query_all(&mut stmt, [], from_row)
        })
        .await
    }

    /// The row `id`, if there is one.
    pub async fn known_host(&self, id: KnownHostId) -> Result<Option<KnownHostRecord>> {
        self.read(move |conn| find(conn, id)).await
    }

    /// Sets row `id`'s `last_used_at` to `now`. `false` if there is no such row.
    pub async fn known_host_touch_used(&self, id: KnownHostId, now: Timestamp) -> Result<bool> {
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("UPDATE ssh_known_hosts SET last_used_at = ?2 WHERE id = ?1")?
                .execute(params![id, to_millis(now)])?
                == 1)
        })
        .await
    }

    /// Deletes row `id`. `false` if there was none.
    pub async fn known_host_delete(&self, id: KnownHostId) -> Result<bool> {
        self.write(move |conn| {
            Ok(conn
                .prepare_cached("DELETE FROM ssh_known_hosts WHERE id = ?1")?
                .execute([id])?
                == 1)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use doozers_types::Kind;

    use super::*;
    use crate::migrate::{MIGRATIONS, migrate};
    use crate::sessions::tests::{at, store};
    use crate::{InstanceRows, RenamedRows, SCHEMA_VERSION};

    fn new_host(environment: &str, host: &str, port: u16, key: &str) -> NewKnownHost {
        NewKnownHost {
            environment: environment.to_owned(),
            host: host.to_owned(),
            port,
            key_type: "ssh-ed25519".to_owned(),
            public_key: format!("AAAA{key}"),
            fingerprint: format!("SHA256:{key}"),
            first_workspace: Some("ws1".to_owned()),
            first_agent: Some("jeeves".to_owned()),
            first_user: Some("owner".to_owned()),
            added_by: None,
        }
    }

    fn pinned(environment: &str, host: &str, port: u16, key: &str) -> NewKnownHost {
        NewKnownHost {
            first_workspace: None,
            first_agent: None,
            first_user: None,
            added_by: Some(UserId::new("owner").unwrap()),
            ..new_host(environment, host, port, key)
        }
    }

    #[tokio::test]
    async fn first_use_stores_the_key_with_where_it_came_from() {
        let (_dir, store) = store().await;
        let record = store
            .known_host_record_first_use(new_host("docker", "github.com", 22, "a"), at(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.environment, "docker");
        assert_eq!(record.host, "github.com");
        assert_eq!(record.port, 22);
        assert_eq!(record.key_type, "ssh-ed25519");
        assert_eq!(record.public_key, "AAAAa");
        assert_eq!(record.fingerprint, "SHA256:a");
        assert_eq!(record.first_seen_at, at(5));
        assert_eq!(record.first_workspace.as_deref(), Some("ws1"));
        assert_eq!(record.first_agent.as_deref(), Some("jeeves"));
        assert_eq!(record.first_user.as_deref(), Some("owner"));
        assert_eq!(record.added_by, None);
        assert_eq!(record.last_used_at, None);
        assert_eq!(
            store
                .known_hosts_for("docker", "github.com", 22)
                .await
                .unwrap(),
            std::slice::from_ref(&record)
        );
        assert_eq!(store.known_host(record.id).await.unwrap(), Some(record));
        assert_eq!(store.known_host(KnownHostId::new(99)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn first_use_records_nothing_once_the_host_has_a_key() {
        let (_dir, store) = store().await;
        store
            .known_host_record_first_use(new_host("docker", "github.com", 22, "a"), at(0))
            .await
            .unwrap()
            .unwrap();
        // The same key, and a different one: neither is new trust.
        for key in ["a", "b"] {
            assert_eq!(
                store
                    .known_host_record_first_use(new_host("docker", "github.com", 22, key), at(1))
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            store
                .known_hosts_for("docker", "github.com", 22)
                .await
                .unwrap()
                .len(),
            1
        );
        // Another port, another host, and another environment are unknown.
        for (environment, host, port) in [
            ("docker", "github.com", 2222),
            ("docker", "gitlab.com", 22),
            ("sandbox", "github.com", 22),
        ] {
            assert!(
                store
                    .known_host_record_first_use(new_host(environment, host, port, "a"), at(2))
                    .await
                    .unwrap()
                    .is_some(),
                "{environment} {host}:{port}"
            );
        }
        assert_eq!(store.known_hosts_all().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn a_pin_adds_a_key_unless_that_key_is_already_there() {
        let (_dir, store) = store().await;
        let first = store
            .known_host_pin(pinned("docker", "git.example", 22, "a"), at(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.first_workspace, None);
        assert_eq!(first.first_agent, None);
        assert_eq!(first.first_user, None);
        assert_eq!(first.added_by.as_ref().map(UserId::as_str), Some("owner"));
        // Another key for the host is added; the same key is not.
        assert!(
            store
                .known_host_pin(pinned("docker", "git.example", 22, "b"), at(2))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .known_host_pin(pinned("docker", "git.example", 22, "a"), at(3))
                .await
                .unwrap(),
            None
        );
        let stored = store
            .known_hosts_for("docker", "git.example", 22)
            .await
            .unwrap();
        let keys: Vec<_> = stored.iter().map(|r| r.public_key.as_str()).collect();
        assert_eq!(keys, ["AAAAa", "AAAAb"]);
    }

    #[tokio::test]
    async fn the_schema_enforces_the_unique_key() {
        let (_dir, store) = store().await;
        store
            .known_host_pin(pinned("docker", "git.example", 22, "a"), at(0))
            .await
            .unwrap();
        let err = store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO ssh_known_hosts
                       (environment, host, port, key_type, public_key, fingerprint, first_seen_at)
                     VALUES ('docker', 'git.example', 22, 'ssh-ed25519', 'AAAAa', 'SHA256:a', 0)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Database(_)), "{err}");
    }

    #[tokio::test]
    async fn touch_sets_last_used_and_changes_nothing_else() {
        let (_dir, store) = store().await;
        let record = store
            .known_host_record_first_use(new_host("docker", "github.com", 22, "a"), at(1))
            .await
            .unwrap()
            .unwrap();
        assert!(store.known_host_touch_used(record.id, at(7)).await.unwrap());
        let touched = store.known_host(record.id).await.unwrap().unwrap();
        assert_eq!(
            touched,
            KnownHostRecord {
                last_used_at: Some(at(7)),
                ..record
            }
        );
        assert!(
            !store
                .known_host_touch_used(KnownHostId::new(99), at(8))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn delete_removes_the_row_so_the_host_is_unknown_again() {
        let (_dir, store) = store().await;
        let first = store
            .known_host_record_first_use(new_host("docker", "github.com", 22, "a"), at(0))
            .await
            .unwrap()
            .unwrap();
        assert!(store.known_host_delete(first.id).await.unwrap());
        assert!(!store.known_host_delete(first.id).await.unwrap());
        assert!(store.known_hosts_all().await.unwrap().is_empty());
        // The next connection records a key again, under a new id.
        let second = store
            .known_host_record_first_use(new_host("docker", "github.com", 22, "b"), at(1))
            .await
            .unwrap()
            .unwrap();
        assert!(second.id > first.id);
    }

    #[tokio::test]
    async fn the_list_is_ordered_by_environment_host_port_then_age() {
        let (_dir, store) = store().await;
        for (environment, host, port, key) in [
            ("sandbox", "a.example", 22, "1"),
            ("docker", "b.example", 22, "2"),
            ("docker", "a.example", 2222, "3"),
            ("docker", "a.example", 22, "4"),
            ("docker", "a.example", 22, "5"),
        ] {
            store
                .known_host_pin(pinned(environment, host, port, key), at(0))
                .await
                .unwrap();
        }
        let order: Vec<_> = store
            .known_hosts_all()
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.public_key)
            .collect();
        assert_eq!(order, ["AAAA4", "AAAA5", "AAAA3", "AAAA2", "AAAA1"]);
    }

    #[tokio::test]
    async fn renaming_an_environment_moves_its_known_hosts() {
        let (_dir, store) = store().await;
        store
            .known_host_pin(pinned("docker", "github.com", 22, "a"), at(0))
            .await
            .unwrap();
        store
            .known_host_pin(pinned("docker", "gitlab.com", 22, "b"), at(0))
            .await
            .unwrap();
        store
            .known_host_pin(pinned("other", "github.com", 22, "c"), at(0))
            .await
            .unwrap();

        let moved = store
            .rename_instance(Kind::Environment, "docker", "sandbox", |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(
            moved,
            RenamedRows {
                known_hosts: 2,
                ..Default::default()
            }
        );
        assert!(
            store
                .known_hosts_for("docker", "github.com", 22)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .known_hosts_for("sandbox", "github.com", 22)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .known_hosts_for("other", "github.com", 22)
                .await
                .unwrap()
                .len(),
            1
        );
        let rows = store.instance_rows(Kind::Environment).await.unwrap();
        assert_eq!(
            rows["sandbox"],
            InstanceRows {
                known_hosts: 2,
                ..Default::default()
            }
        );
    }

    #[tokio::test]
    async fn an_environment_rename_doesnt_merge_into_a_name_that_has_known_hosts() {
        let (_dir, store) = store().await;
        store
            .known_host_pin(pinned("docker", "github.com", 22, "a"), at(0))
            .await
            .unwrap();
        store
            .known_host_pin(pinned("sandbox", "github.com", 22, "b"), at(0))
            .await
            .unwrap();
        let err = store
            .rename_instance(Kind::Environment, "docker", "sandbox", |_| Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Conflict(_)), "{err}");
        assert_eq!(store.known_hosts_all().await.unwrap().len(), 2);
    }

    fn table_exists(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'ssh_known_hosts'",
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
            .position(|m| m.name == "0014_ssh_known_hosts")
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
        assert!(store.known_hosts_all().await.unwrap().is_empty());
    }
}
