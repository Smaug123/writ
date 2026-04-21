//! Filesystem-backed secret store.
//!
//! Secrets are stored as individual files under a base directory with mode
//! 0600, and the base directory itself must have mode 0700 (no group or
//! world access). Writes are atomic via tempfile + rename.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{SecretError, SecretKey, SecretStore};

#[derive(Debug)]
pub struct FileSecretStore {
    base: PathBuf,
}

impl FileSecretStore {
    /// Open an existing store at `base`. The directory must already exist
    /// and have mode 0700 (no access for anyone but the owner).
    pub fn open(base: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let base = base.into();
        let mode = fs::metadata(&base)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SecretError::UnsafePermissions {
                path: base.display().to_string(),
                mode,
                expected: 0o700,
            });
        }
        Ok(Self { base })
    }

    /// Open `base` if it exists; otherwise create it with mode 0700 and
    /// open it. Either way, the resulting directory's mode is verified
    /// to be at most 0700.
    pub fn create_or_open(base: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let base = base.into();
        if !Path::new(&base).exists() {
            fs::create_dir_all(&base)?;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
        }
        Self::open(base)
    }

    fn path_for(&self, key: &SecretKey) -> PathBuf {
        self.base.join(key.as_str())
    }

    fn tmp_path_for(&self, key: &SecretKey) -> PathBuf {
        self.base.join(format!("{}.tmp", key.as_str()))
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        match fs::read_to_string(self.path_for(key)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        let dest = self.path_for(key);
        let tmp = self.tmp_path_for(key);
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(value.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &dest)?;
        Ok(())
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        match fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key(s: &str) -> SecretKey {
        SecretKey::new(s).unwrap()
    }

    fn store() -> (TempDir, FileSecretStore) {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn put_then_get_returns_value() {
        let (_tmp, s) = store();
        s.put(&key("a"), "hello").unwrap();
        assert_eq!(s.get(&key("a")).unwrap().as_deref(), Some("hello"));
    }

    #[test]
    fn get_missing_key_returns_none() {
        let (_tmp, s) = store();
        assert!(s.get(&key("missing")).unwrap().is_none());
    }

    #[test]
    fn put_overwrites_existing_value() {
        let (_tmp, s) = store();
        s.put(&key("a"), "first").unwrap();
        s.put(&key("a"), "second").unwrap();
        assert_eq!(s.get(&key("a")).unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn delete_removes_value() {
        let (_tmp, s) = store();
        s.put(&key("a"), "v").unwrap();
        s.delete(&key("a")).unwrap();
        assert!(s.get(&key("a")).unwrap().is_none());
    }

    #[test]
    fn delete_missing_is_noop() {
        let (_tmp, s) = store();
        s.delete(&key("never-existed")).unwrap();
    }

    #[test]
    fn put_writes_file_with_mode_0600() {
        let (tmp, s) = store();
        s.put(&key("a"), "v").unwrap();
        let mode = fs::metadata(tmp.path().join("a"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "got mode {mode:o}");
    }

    #[test]
    fn open_rejects_directory_with_group_access() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let err = FileSecretStore::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, SecretError::UnsafePermissions { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn open_rejects_directory_with_world_access() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o705)).unwrap();
        let err = FileSecretStore::open(dir.path()).unwrap_err();
        assert!(matches!(err, SecretError::UnsafePermissions { .. }));
    }

    #[test]
    fn create_or_open_creates_directory_with_mode_0700() {
        let parent = TempDir::new().unwrap();
        let sub = parent.path().join("secrets");
        let _ = FileSecretStore::create_or_open(&sub).unwrap();
        let mode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
