//! Owner-only directories and files: the one place the mode-`0700`/`0600`
//! recipe lives.
//!
//! Every helper here requests the private mode **in the creating syscall**
//! (`mkdir(2)` / `open(2)` with `O_CREAT|O_EXCL`), then sets it again
//! afterwards. Both halves matter:
//!
//! - The kernel ANDs the requested mode with the inverse of the process
//!   umask, so the *created* mode is never looser than requested. Creating at
//!   the default mode and tightening afterwards would open a window in which
//!   another local user could `openat` into the directory (or read the file)
//!   and keep the descriptor across the later `chmod`, because POSIX checks
//!   permissions at open time, not at use time.
//! - Under a restrictive umask the created mode can be *tighter* than
//!   requested (`0o600` on a directory the daemon then cannot write into, or
//!   `0o000` on a file git must reopen by path), so the follow-up
//!   `set_permissions` widens it back to exactly what was asked for. That step
//!   is about the daemon's own access, not about anyone else's.
//!
//! The helpers are synchronous. Callers on an async runtime wrap them in
//! `spawn_blocking` if the latency matters to them.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// `mkdir(path, 0700)`, failing with [`io::ErrorKind::AlreadyExists`] if
/// anything is already there, then chmod to exactly `0700`.
///
/// For a directory the caller must own *exclusively*: a concurrent duplicate
/// should be refused, not silently joined onto the same path. If the chmod
/// fails after the `mkdir` succeeded the directory is removed again, so a
/// retry can mint it afresh rather than colliding with a half-made one.
pub fn create_dir_0700(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(DIR_MODE).create(path)?;
    if let Err(err) = fs::set_permissions(path, Permissions::from_mode(DIR_MODE)) {
        let _ = fs::remove_dir(path);
        return Err(err);
    }
    Ok(())
}

/// `mkdir -p` with mode `0700` requested for every component it creates, then
/// chmod the leaf to exactly `0700`. Only the leaf is pinned: an existing
/// parent belongs to whoever made it.
pub fn create_dir_all_0700(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(path)?;
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE))
}

/// [`create_dir_0700`], or, if `path` already exists, chmod it to exactly
/// `0700` so a looser pre-existing directory cannot expose what is put in it.
///
/// For a *shared* directory any caller may lazily materialise: the first
/// caller creates it, later ones tighten it.
pub fn ensure_dir_0700(path: &Path) -> io::Result<()> {
    match create_dir_0700(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            fs::set_permissions(path, Permissions::from_mode(DIR_MODE))
        }
        Err(err) => Err(err),
    }
}

/// `open(path, O_WRONLY|O_CREAT|O_EXCL, 0600)`, then chmod to exactly `0600`.
/// Fails with [`io::ErrorKind::AlreadyExists`] if anything is already there.
/// For callers that write the file themselves.
pub fn create_new_0600(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(FILE_MODE))?;
    Ok(file)
}

/// [`create_new_0600`], write `contents`, and `fsync` before returning, so
/// the bytes are durable by the time the caller goes on to name the file to
/// something else.
pub fn write_new_0600(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut file = create_new_0600(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Create or truncate `path` at mode `0600`, chmod it to exactly `0600`
/// (an existing inode keeps its old mode otherwise), and write `contents`.
/// For a file that is legitimately rewritten, such as a token re-issued on a
/// retried launch. Not fsynced.
pub fn write_0600(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.set_permissions(Permissions::from_mode(FILE_MODE))?;
    file.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    proptest! {
        /// Whatever a directory's mode was before, every directory helper
        /// leaves it at exactly 0700; the exclusive one refuses to touch an
        /// existing directory at all.
        #[test]
        fn directory_helpers_leave_exactly_0700(prior in 0u32..=0o777) {
            let tmp = tempfile::tempdir().unwrap();

            let fresh = tmp.path().join("fresh");
            create_dir_0700(&fresh).unwrap();
            prop_assert_eq!(mode_of(&fresh), 0o700);
            prop_assert_eq!(
                create_dir_0700(&fresh).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );

            let nested = tmp.path().join("a").join("b").join("c");
            create_dir_all_0700(&nested).unwrap();
            prop_assert_eq!(mode_of(&nested), 0o700);
            prop_assert!(create_dir_all_0700(&nested).is_ok(), "create_dir_all is idempotent");

            let existing = tmp.path().join("existing");
            fs::create_dir(&existing).unwrap();
            fs::set_permissions(&existing, Permissions::from_mode(prior)).unwrap();
            ensure_dir_0700(&existing).unwrap();
            prop_assert_eq!(mode_of(&existing), 0o700);
            let absent = tmp.path().join("absent");
            ensure_dir_0700(&absent).unwrap();
            prop_assert_eq!(mode_of(&absent), 0o700);
        }

        /// The file helpers round-trip arbitrary bytes at exactly 0600;
        /// `write_new_0600` refuses an existing file, `write_0600` replaces
        /// its contents and tightens its mode.
        #[test]
        fn file_helpers_leave_exactly_0600(
            first in proptest::collection::vec(any::<u8>(), 0..512),
            second in proptest::collection::vec(any::<u8>(), 0..512),
            prior in 0u32..=0o777,
        ) {
            let tmp = tempfile::tempdir().unwrap();

            let fresh = tmp.path().join("fresh");
            write_new_0600(&fresh, &first).unwrap();
            prop_assert_eq!(mode_of(&fresh), 0o600);
            prop_assert_eq!(fs::read(&fresh).unwrap(), first.clone());
            prop_assert_eq!(
                write_new_0600(&fresh, &second).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            prop_assert_eq!(fs::read(&fresh).unwrap(), first.clone(), "a refused write changes nothing");

            let handle = tmp.path().join("handle");
            drop(create_new_0600(&handle).unwrap());
            prop_assert_eq!(mode_of(&handle), 0o600);

            let rewritten = tmp.path().join("rewritten");
            fs::write(&rewritten, &first).unwrap();
            fs::set_permissions(&rewritten, Permissions::from_mode(prior | 0o600)).unwrap();
            write_0600(&rewritten, &second).unwrap();
            prop_assert_eq!(mode_of(&rewritten), 0o600);
            prop_assert_eq!(fs::read(&rewritten).unwrap(), second.clone());
        }
    }

    /// A chmod failure after the `mkdir` unwinds the directory, so the next
    /// attempt is not refused as a duplicate. Forced by creating the leaf
    /// inside a parent the caller cannot write to after the fact is not
    /// possible for the owner, so this pins the shape with the one failure a
    /// test can provoke: the leaf is a file, not a directory, and the chmod
    /// step is never reached.
    #[test]
    fn create_dir_refuses_a_file_at_the_path() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            create_dir_0700(&file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(file.is_file(), "the file is left alone");
    }
}
