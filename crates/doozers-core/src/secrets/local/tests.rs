use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use doozers_types::Timestamp;

use super::*;
use crate::paths::DataRoot;

#[derive(Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_second(1_800_000_000).unwrap()
    }
}

struct Home {
    dir: tempfile::TempDir,
    root: DataRoot,
    store: Store,
}

impl Home {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = DataRoot::new(dir.path(), Path::new("/tmp")).unwrap();
        let store = Store::open(dir.path().join("doozers.db")).await.unwrap();
        Self { dir, root, store }
    }

    fn key_file(&self) -> KeyFile {
        KeyFile::new(&self.root, &self.root.secret_key_file())
    }

    async fn open(&self) -> Result<LocalSecrets, KeyError> {
        LocalSecrets::open(self.store.clone(), &self.key_file(), Arc::new(FixedClock)).await
    }

    fn key_text(&self) -> String {
        fs::read_to_string(self.key_file().path()).unwrap()
    }

    fn write_key(&self, text: &str) {
        fs::write(self.key_file().path(), text).unwrap();
    }
}

fn path(p: &str) -> SecretPath {
    SecretPath::new(p).unwrap()
}

#[tokio::test]
async fn the_first_open_creates_a_private_key_file_and_a_data_key() {
    let home = Home::new().await;
    home.open().await.unwrap();
    let meta = fs::metadata(home.key_file().path()).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    let wrapped = home.store.secret_data_key().await.unwrap().unwrap();
    assert_eq!(wrapped.source, "key-file");
    assert_eq!(wrapped.value.algorithm, "aes-256-gcm");
    assert_eq!(home.dir.path().join("secret.key"), home.key_file().path());
}

#[tokio::test]
async fn values_round_trip_and_are_stored_sealed() {
    let home = Home::new().await;
    let secrets = home.open().await.unwrap();
    let alice = UserId::new("alice").unwrap();
    let created = secrets
        .put(
            &path("providers/anthropic"),
            &Secret::new("sk-ant-xyz"),
            Some(&alice),
        )
        .await
        .unwrap();
    assert_eq!(created.path, path("providers/anthropic"));
    assert_eq!(created.created_by, Some(alice));
    assert_eq!(
        secrets
            .get(&path("providers/anthropic"))
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "sk-ant-xyz"
    );
    assert!(
        secrets
            .get(&path("providers/openai"))
            .await
            .unwrap()
            .is_none()
    );

    let (_, sealed) = home
        .store
        .secret("providers/anthropic")
        .await
        .unwrap()
        .unwrap();
    assert!(!sealed.ciphertext.windows(10).any(|w| w == b"sk-ant-xyz"));

    secrets
        .put(
            &path("providers/anthropic"),
            &Secret::new("sk-ant-new"),
            None,
        )
        .await
        .unwrap();
    let reopened = home.open().await.unwrap();
    assert_eq!(
        reopened
            .get(&path("providers/anthropic"))
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "sk-ant-new"
    );
}

#[tokio::test]
async fn metadata_list_describe_and_delete_never_need_the_value() {
    let home = Home::new().await;
    let secrets = home.open().await.unwrap();
    for p in ["ssh/prod", "ssh/test", "users/alice/github", "anthropic"] {
        secrets
            .put(&path(p), &Secret::new("v"), None)
            .await
            .unwrap();
    }
    let described = secrets
        .describe(&path("ssh/prod"), "prod deploy key", None)
        .await
        .unwrap();
    assert_eq!(described.description, "prod deploy key");
    assert_eq!(
        secrets.metadata(&path("ssh/prod")).await.unwrap(),
        Some(described)
    );
    let listed: Vec<_> = secrets
        .list(Some(&path("ssh")))
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.path.to_string())
        .collect();
    assert_eq!(listed, ["ssh/prod", "ssh/test"]);
    assert_eq!(secrets.list(None).await.unwrap().len(), 4);

    let err = secrets
        .describe(&path("ssh/none"), "x", None)
        .await
        .unwrap_err();
    assert!(matches!(err, SecretError::NotFound(p) if p == path("ssh/none")));
    assert!(secrets.delete(&path("ssh/prod")).await.unwrap());
    assert!(!secrets.delete(&path("ssh/prod")).await.unwrap());
    assert!(secrets.metadata(&path("ssh/prod")).await.unwrap().is_none());
}

#[tokio::test]
async fn a_value_moved_to_another_path_does_not_open() {
    let home = Home::new().await;
    let secrets = home.open().await.unwrap();
    secrets
        .put(&path("ssh/prod"), &Secret::new("prod key"), None)
        .await
        .unwrap();
    let (_, sealed) = home.store.secret("ssh/prod").await.unwrap().unwrap();
    home.store
        .secret_put("ssh/test", sealed, None, FixedClock.now())
        .await
        .unwrap();
    let err = secrets.get(&path("ssh/test")).await.unwrap_err();
    assert!(
        matches!(&err, SecretError::Damaged { path, .. } if path == "ssh/test"),
        "{err:?}"
    );
    assert!(!err.to_string().contains("prod key"), "{err}");
}

#[tokio::test]
async fn with_secrets_stored_a_missing_or_wrong_key_file_refuses_and_changes_nothing() {
    let home = Home::new().await;
    let secrets = home.open().await.unwrap();
    secrets
        .put(&path("a"), &Secret::new("value"), None)
        .await
        .unwrap();
    let key = home.key_text();
    let wrapped = home.store.secret_data_key().await.unwrap();

    fs::remove_file(home.key_file().path()).unwrap();
    let err = home.open().await.unwrap_err();
    assert!(
        matches!(err, KeyError::Missing { stored: 1, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("secret.key"), "{err}");
    assert!(!home.key_file().path().exists(), "no new key file");

    home.write_key(&"ab".repeat(32));
    fs::set_permissions(
        home.key_file().path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let err = home.open().await.unwrap_err();
    assert!(
        matches!(err, KeyError::WrongKey { stored: 1, .. }),
        "{err:?}"
    );
    assert_eq!(home.store.secret_data_key().await.unwrap(), wrapped);

    home.write_key(&key);
    let secrets = home.open().await.unwrap();
    assert_eq!(
        secrets.get(&path("a")).await.unwrap().unwrap().expose(),
        "value"
    );
}

#[tokio::test]
async fn a_configured_key_file_is_used_but_never_created() {
    let home = Home::new().await;
    let configured = home.dir.path().join("elsewhere.key");
    let key_file = KeyFile::new(&home.root, &configured);
    let open = || LocalSecrets::open(home.store.clone(), &key_file, Arc::new(FixedClock));
    let err = open().await.unwrap_err();
    assert!(matches!(err, KeyError::NotCreated { .. }), "{err:?}");
    assert!(err.to_string().contains("core.secret_key_file"), "{err}");
    assert!(!configured.exists());
    assert!(home.store.secret_data_key().await.unwrap().is_none());

    fs::write(&configured, "ef".repeat(32)).unwrap();
    fs::set_permissions(
        &configured,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let secrets = open().await.unwrap();
    secrets
        .put(&path("a"), &Secret::new("value"), None)
        .await
        .unwrap();
    assert!(!home.key_file().path().exists(), "no default key file");
    assert_eq!(
        open()
            .await
            .unwrap()
            .get(&path("a"))
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "value"
    );
}

#[tokio::test]
async fn with_no_secret_stored_a_lost_or_replaced_key_file_gets_a_new_data_key() {
    let home = Home::new().await;
    home.open().await.unwrap();
    let first = home.store.secret_data_key().await.unwrap().unwrap();

    // A restore on another machine: the database came back, the key file didn't.
    fs::remove_file(home.key_file().path()).unwrap();
    let secrets = home.open().await.unwrap();
    assert!(home.key_file().path().exists());
    let second = home.store.secret_data_key().await.unwrap().unwrap();
    assert_ne!(first.value, second.value);
    secrets
        .put(&path("a"), &Secret::new("value"), None)
        .await
        .unwrap();

    // The key file was replaced while the store was empty.
    secrets.delete(&path("a")).await.unwrap();
    home.write_key(&"cd".repeat(32));
    home.open().await.unwrap();
    assert_ne!(home.store.secret_data_key().await.unwrap().unwrap(), second);
}
