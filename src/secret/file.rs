//! Filesystem-backed secret store.
//!
//! Secrets are stored as individual files under a base directory with mode
//! 0600. The base directory itself must be a directory with no group or
//! world access bits set — equivalent to the permission predicate SSH
//! applies to `~/.ssh`. `create_or_open` creates new directories with
//! exact mode 0700; `open` only enforces the "no group/world access"
//! side, so a pre-existing directory the owner has further restricted
//! (e.g. 0500 for read-only operation) is also accepted. Writes are
//! atomic via tempfile + rename.

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
    /// Open an existing store at `base`. `base` must already exist, be a
    /// directory, and carry no group or world permission bits (i.e.
    /// `mode & 0o077 == 0`). Owner bits aren't further constrained:
    /// whether the caller has enough access to perform subsequent reads
    /// or writes is their problem, not a security condition this method
    /// enforces.
    pub fn open(base: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let base = base.into();
        let meta = fs::metadata(&base)?;
        if !meta.is_dir() {
            return Err(SecretError::NotADirectory {
                path: base.display().to_string(),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
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
        // A leading '.' guarantees no collision with any real key, since
        // `SecretKey::new` rejects names starting with '.'. A random suffix
        // gives concurrent writers to distinct keys — or the same key —
        // distinct temp paths, so neither clobbers the other mid-write.
        let tmp = self.base.join(format!(".tmp.{}", uuid::Uuid::new_v4()));
        {
            let mut f = fs::OpenOptions::new()
                .create_new(true)
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

    /// Regression: an earlier version used `{key}.tmp` as the mid-write
    /// filename, so writing key "foo" would clobber the already-stored
    /// "foo.tmp" key. Temp paths are now UUID-suffixed and `.`-prefixed,
    /// which cannot collide with any valid `SecretKey`.
    #[test]
    fn put_does_not_clobber_key_ending_in_dot_tmp() {
        let (_tmp, s) = store();
        s.put(&key("foo.tmp"), "survive").unwrap();
        s.put(&key("foo"), "ok").unwrap();
        assert_eq!(s.get(&key("foo.tmp")).unwrap().as_deref(), Some("survive"));
        assert_eq!(s.get(&key("foo")).unwrap().as_deref(), Some("ok"));
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

    /// Regression: `open` previously only checked the mode bits and not
    /// `is_dir`, so a permission-safe *file* at the base path would have
    /// been happily accepted as a store root.
    #[test]
    fn open_rejects_file_that_is_not_a_directory() {
        let parent = TempDir::new().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("not-a-dir");
        {
            let mut f = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(b"hello").unwrap();
        }
        let err = FileSecretStore::open(&path).unwrap_err();
        assert!(
            matches!(err, SecretError::NotADirectory { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// Pins the "tighter than 0700 is fine" side of the documented
    /// contract: 0500 is a permission-safe read-only mode the owner may
    /// reasonably choose, and `open` must accept it. 0600 would also be
    /// permission-safe by the group/world rule, but has no search bit and
    /// so leaves TempDir unable to clean up its own scratch path — we use
    /// 0500 to keep the test self-contained.
    #[test]
    fn open_accepts_directory_tighter_than_0700() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let _ = FileSecretStore::open(dir.path()).expect("0500 dir should be accepted");
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
