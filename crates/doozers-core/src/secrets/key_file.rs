//! [`KeyFile`]: the key source of the local secret store, a file holding a 256-bit key as hex.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::KeyError;
use super::cipher::{KEY_LEN, KeyBytes, random_key};
use crate::paths::DataRoot;

/// The `source` recorded with a data key wrapped by a key file's key.
pub(super) const SOURCE: &str = "key-file";

/// The file the local secret store's key-encryption key is read from: 64 hex digits (256 bits),
/// surrounding whitespace ignored, such as `openssl rand -hex 32` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    path: PathBuf,
    /// Whether it's the default, `<root>/secret.key`, which Doozers may create.
    default: bool,
    /// Whether it's in the data root, where group and others must have no access to it. Outside,
    /// whatever mounts it (systemd, an orchestrator) owns its mode.
    in_root: bool,
}

impl KeyFile {
    /// The key file at `path` (`core.secret_key_file`) for the data root `root`. Doozers creates
    /// it, mode 0600, when it's missing and no secret is stored, but only at the default location,
    /// `<root>/secret.key`.
    pub fn new(root: &DataRoot, path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            default: path == root.secret_key_file(),
            in_root: path.starts_with(root.root()),
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether Doozers may create the file: it's at the default location.
    pub(super) fn may_create(&self) -> bool {
        self.default
    }

    /// The key, or `None` if the file doesn't exist. The file must be a regular file. In the data
    /// root, neither group nor others may have access to it.
    pub(super) fn read(&self) -> Result<Option<KeyBytes>, KeyError> {
        let meta = match fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io("inspect", source)),
        };
        if !meta.is_file() {
            return Err(KeyError::NotAFile {
                path: self.path.clone(),
            });
        }
        let mode = meta.mode() & 0o777;
        if self.in_root && mode & 0o077 != 0 {
            return Err(KeyError::Permissions {
                path: self.path.clone(),
                mode,
            });
        }
        let text = Zeroizing::new(fs::read(&self.path).map_err(|e| self.io("read", e))?);
        parse(&text).map(Some).ok_or_else(|| KeyError::Format {
            path: self.path.clone(),
        })
    }

    /// Creates the file, mode 0600, with a fresh random key, and returns the key. Fails if the
    /// file exists.
    pub(super) fn create(&self) -> Result<KeyBytes, KeyError> {
        let key = random_key();
        let mut text = Zeroizing::new(String::with_capacity(2 * KEY_LEN + 1));
        for byte in key.iter() {
            let _ = write!(text, "{byte:02x}");
        }
        text.push('\n');
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| self.io("create", e))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| self.io("write", e))?;
        Ok(key)
    }

    fn io(&self, action: &'static str, source: io::Error) -> KeyError {
        KeyError::Io {
            path: self.path.clone(),
            action,
            source,
        }
    }
}

/// The key in `text`: exactly 64 hex digits once surrounding whitespace is trimmed.
fn parse(text: &[u8]) -> Option<KeyBytes> {
    let hex = text.trim_ascii();
    if hex.len() != 2 * KEY_LEN {
        return None;
    }
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    let (pairs, _) = hex.as_chunks::<2>();
    for (byte, &[high, low]) in key.iter_mut().zip(pairs) {
        let digit = |c: u8| char::from(c).to_digit(16);
        *byte = u8::try_from(digit(high)? * 16 + digit(low)?).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn key_file(dir: &Path) -> KeyFile {
        let root = DataRoot::new(dir, Path::new("/tmp")).unwrap();
        KeyFile::new(&root, &root.secret_key_file())
    }

    #[test]
    fn a_created_key_reads_back_from_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = key_file(dir.path());
        assert!(file.read().unwrap().is_none());
        let key = file.create().unwrap();
        assert_eq!(file.read().unwrap().unwrap(), key);
        let meta = fs::metadata(file.path()).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        let text = fs::read_to_string(file.path()).unwrap();
        assert_eq!(text.len(), 65, "{text:?}");
        assert!(matches!(file.create(), Err(KeyError::Io { .. })));
    }

    #[test]
    fn outside_the_data_root_the_mode_is_left_to_whatever_mounts_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = DataRoot::new(dir.path().join("root"), Path::new("/tmp")).unwrap();
        let mounted = dir.path().join("run-secrets-doozers");
        fs::write(&mounted, "00".repeat(32)).unwrap();
        fs::set_permissions(&mounted, fs::Permissions::from_mode(0o444)).unwrap();
        let file = KeyFile::new(&root, &mounted);
        assert!(!file.may_create());
        assert!(file.read().unwrap().is_some());

        let inside = root.root().join("keys/secret.key");
        fs::create_dir_all(inside.parent().unwrap()).unwrap();
        fs::write(&inside, "00".repeat(32)).unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(matches!(
            KeyFile::new(&root, &inside).read(),
            Err(KeyError::Permissions { .. })
        ));
        assert!(KeyFile::new(&root, &root.secret_key_file()).may_create());
    }

    #[test]
    fn parses_64_hex_digits_in_either_case_with_whitespace_around() {
        let lower = "00ff".repeat(16);
        let key = parse(format!("  {lower}\n").as_bytes()).unwrap();
        assert_eq!(key[..2], [0x00, 0xff]);
        assert_eq!(parse(lower.to_uppercase().as_bytes()).unwrap(), key);
        for bad in [
            String::new(),
            "00".repeat(31),
            "00".repeat(33),
            format!("{}zz", "00".repeat(31)),
            format!("{} {}", "00".repeat(16), "00".repeat(16)),
            format!("+{}", "0".repeat(63)),
        ] {
            assert!(parse(bad.as_bytes()).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_readable_bad_or_odd_file_is_refused_without_quoting_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = key_file(dir.path());
        fs::write(file.path(), "not-a-key-but-a-secret").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        let err = file.read().unwrap_err();
        assert!(matches!(err, KeyError::Format { .. }), "{err:?}");
        assert!(!err.to_string().contains("not-a-key"), "{err}");

        fs::write(file.path(), "00".repeat(32)).unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o640)).unwrap();
        let err = file.read().unwrap_err();
        assert!(err.to_string().contains("chmod 600"), "{err}");

        let dir_file = key_file(&dir.path().join("sub"));
        fs::create_dir_all(dir_file.path()).unwrap();
        assert!(matches!(dir_file.read(), Err(KeyError::NotAFile { .. })));
    }
}
