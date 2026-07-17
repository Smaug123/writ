//! Audit-directory dedication check and legacy audit-DB migration.
//!
//! The broker VM read-write-mounts the audit directory; this module verifies
//! it holds nothing but the audit DB and its sidecars, and detects a legacy
//! audit DB that predates the dedicated-directory layout.

use std::path::{Path, PathBuf};

/// The audit DB directory the broker VM read-write-mounts holds something other
/// than the audit database and its SQLite sidecars, so the mount would expose
/// that file to the guest. This enforces the dedicated-directory invariant
/// *directly* (an allowlist over the directory's real contents), rather than
/// trying to enumerate every sensitive path that must not be inside it: any host
/// file the operator places under the mount — a config file, an executable writd
/// runs (`container`/`pf_helper`/`sudo`/`spawn_command`), a socket or bearer
/// file, the secret store, per-session broker material — would otherwise be
/// replaceable through the read-write mount and then re-read or executed by the
/// host. See `docs/design/apple-container-agent-vm.md`.
///
/// This is authoritative only when run at the moment the broker VM mount is
/// created (every lazily-written file already exists); the daemon also runs it
/// at startup as best-effort early feedback.
#[derive(Debug, thiserror::Error)]
pub enum AuditDirNotDedicated {
    /// A non-audit entry was found in the mounted directory.
    #[error(
        "the audit DB directory {audit_dir:?} is mounted read-write into the broker VM but also \
         contains {foreign:?}, which is not the audit database or a SQLite sidecar of it; give the \
         audit DB a directory dedicated to it (e.g. $XDG_DATA_HOME/writ/audit/audit.db) so the \
         broker VM cannot reach any other host file"
    )]
    Foreign {
        /// The directory the broker VM mounts read-write.
        audit_dir: PathBuf,
        /// The offending non-audit entry within it.
        foreign: PathBuf,
    },
    /// The directory could not be read to verify it — fail closed.
    #[error("cannot read the audit DB directory {audit_dir:?} to verify it is dedicated: {source}")]
    Io {
        /// The directory the read failed on.
        audit_dir: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The audit DB path is not a plain regular file (it is a symlink or a hard
    /// link), so opening it could redirect writes outside the mounted directory.
    #[error(
        "the audit database path {path:?} is a symlink or hard link, not a plain regular file; \
         refusing to open it, since it could redirect the audit log outside the mounted directory \
         (a compromised broker VM with the directory mounted read-write could plant such a link)"
    )]
    NotRegularFile {
        /// The offending audit DB path.
        path: PathBuf,
    },
}

/// Whether directory entry `name` is the audit database `basename` or one of its
/// SQLite sidecar files. Exact matches only (`<basename>`, `<basename>-wal`,
/// `<basename>-shm`, `<basename>-journal`): an arbitrary `<basename>-…` suffix is
/// *not* accepted, so a host file sharing the prefix (e.g. a `spawn_command`
/// named `audit.db-helper`) is still treated as foreign.
///
/// This is a *name* test, so it cannot distinguish a real sidecar from a
/// host-control file the operator deliberately placed at the exact sidecar path
/// (e.g. configuring the `container` executable at `<audit>/audit.db-wal`). That
/// residual is out of scope: it requires an adversarial *operator* configuration
/// — the operator already owns the host — not a compromised guest, which is the
/// boundary this guard defends. Provenance-checking every entry, or re-adding an
/// (unbounded) blocklist of every host path, is not worth that non-threat.
fn is_audit_artifact(name: &std::ffi::OsStr, basename: &std::ffi::OsStr) -> bool {
    const SIDECAR_SUFFIXES: [&[u8]; 3] = [b"-wal", b"-shm", b"-journal"];
    let name = name.as_encoded_bytes();
    let base = basename.as_encoded_bytes();
    if name == base {
        return true;
    }
    SIDECAR_SUFFIXES.iter().any(|suffix| {
        name.len() == base.len() + suffix.len()
            && &name[..base.len()] == base
            && &name[base.len()..] == *suffix
    })
}

/// Whether `meta` (a regular file's) has exactly one hard link, i.e. no alias
/// under another name/directory. A SQLite database and its sidecars are singly
/// linked; a multiply-linked file in the audit directory would expose (and let
/// the guest overwrite) the same inode elsewhere on the host.
#[cfg(unix)]
fn has_single_link(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() == 1
}

/// Non-Unix hosts have no hard-link count to check; writ's broker VM is Unix-only.
#[cfg(not(unix))]
fn has_single_link(_meta: &std::fs::Metadata) -> bool {
    true
}

/// The filesystem identity (device, inode) of `meta`, used to recognise a
/// directory entry regardless of the (possibly case-differing) name it was
/// opened under. `None` off Unix, where writ's broker VM does not run and the
/// name-based fallback suffices on the case-sensitive filesystems in use.
#[cfg(unix)]
fn file_identity(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_identity(_meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Enforce that the audit DB's directory — the one the broker VM mounts
/// read-write — contains only the audit database and its SQLite sidecars, so
/// nothing else host-owned is reachable read-write inside the broker VM.
///
/// The *scanned* directory is the real form of what the broker actually mounts:
/// [`crate::agent_vm_daemon`]'s `resolve_broker_audit_paths` mounts
/// `absolute(audit_db).parent()`, so this canonicalises **that parent** (not the
/// DB — the DB's own final symlink could resolve into a different directory than
/// the one mounted). Case-insensitive collisions collapse to filesystem identity
/// once the directory exists.
///
/// An allowed entry must be a **regular file** (a directory, symlink, or other
/// object using a sidecar name is rejected), **singly linked** (no hard-link
/// alias to an external inode), and either **the audit DB itself** — matched by
/// filesystem identity, so a case-aliased config name like `AUDIT.DB` opening the
/// on-disk `audit.db` still matches — or a `-{wal,shm,journal}` sidecar of the DB.
/// Sidecar names are checked against both the configured basename and the DB
/// entry's on-disk basename: SQLite names a sidecar after the path it was opened
/// with, but on a case-insensitive filesystem an existing sidecar keeps its
/// original spelling; both refer to the same file there and coincide on a
/// case-sensitive filesystem, so accepting either widens nothing.
///
/// A not-yet-created directory is not a violation (nothing is mounted yet); a
/// directory that cannot be read fails closed (`Io`). Callers gate this on
/// `broker_placement == Vm` and open the audit DB first; it is authoritative at
/// broker-VM mount time, when every lazily-written file already exists.
/// Preflight, run **before** `AuditLog::open` under vm placement: if the audit
/// DB path already exists it must be a plain regular file with a single hard
/// link — not a symlink or multiply-linked file. `AuditLog::open` follows
/// symlinks, so a link planted at the path (e.g. by a compromised broker VM that
/// outlived a prior daemon and still holds the audit directory mounted
/// read-write) would otherwise let the host initialise or migrate an unintended
/// target before the post-open dedicated-directory scan could reject it. A
/// not-yet-created path is fine (`open` creates a regular file there); an
/// unreadable path fails closed.
pub fn ensure_audit_db_entry_is_regular_file(audit_db: &Path) -> Result<(), AuditDirNotDedicated> {
    let abs = std::path::absolute(audit_db).unwrap_or_else(|_| audit_db.to_path_buf());
    // `symlink_metadata` does not follow the final symlink, so a symlink at the
    // path reports as such rather than as its target.
    let metadata = match std::fs::symlink_metadata(&abs) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AuditDirNotDedicated::Io {
                audit_dir: abs.parent().unwrap_or(&abs).to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() || !has_single_link(&metadata) {
        return Err(AuditDirNotDedicated::NotRegularFile { path: abs });
    }
    Ok(())
}

pub fn ensure_audit_dir_is_dedicated(audit_db: &Path) -> Result<(), AuditDirNotDedicated> {
    let abs = std::path::absolute(audit_db).unwrap_or_else(|_| audit_db.to_path_buf());
    let Some(parent) = abs.parent() else {
        return Ok(());
    };
    // The real directory the broker plan mounts (virtiofs resolves the parent).
    let mount_dir = match parent.canonicalize() {
        Ok(dir) => dir,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AuditDirNotDedicated::Io {
                audit_dir: parent.to_path_buf(),
                source,
            });
        }
    };
    // The configured DB basename and the DB's filesystem identity (to recognise
    // its own entry regardless of the case-aliased name it was opened under).
    let configured_basename = abs.file_name().map(|n| n.to_os_string());
    let db_identity = std::fs::metadata(&abs).ok().and_then(|m| file_identity(&m));

    // Collect the entries (rejecting any non-regular-file eagerly, skipping any
    // deleted mid-scan) so the DB's own on-disk entry name can be located by
    // identity before names are validated.
    let read = match std::fs::read_dir(&mount_dir) {
        Ok(read) => read,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AuditDirNotDedicated::Io {
                audit_dir: mount_dir,
                source,
            });
        }
    };
    let mut files = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(entry) => entry,
            // A concurrent audit writer can delete a transient sidecar mid-scan;
            // an entry that vanished is not exposed, so treat it as transient.
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(AuditDirNotDedicated::Io {
                    audit_dir: mount_dir.clone(),
                    source,
                });
            }
        };
        let io = |source| AuditDirNotDedicated::Io {
            audit_dir: mount_dir.clone(),
            source,
        };
        // `file_type` does not follow symlinks, so a symlink is not `is_file`.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io(source)),
        };
        if !file_type.is_file() {
            return Err(AuditDirNotDedicated::Foreign {
                audit_dir: mount_dir.clone(),
                foreign: entry.path(),
            });
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io(source)),
        };
        files.push((entry, metadata));
    }

    // The DB's on-disk entry name, matched by filesystem identity. Sidecars are
    // accepted relative to *both* this and the configured basename: SQLite names
    // a sidecar after the path it was opened with, but on a case-insensitive
    // filesystem an existing sidecar keeps its original spelling (e.g. `audit.db`
    // renamed in config to `AUDIT.DB` leaves `audit.db-wal` on disk). Both refer
    // to the same file there, and coincide on a case-sensitive filesystem, so
    // accepting either widens nothing.
    let dirent_basename = db_identity.and_then(|id| {
        files
            .iter()
            .find(|(_, meta)| file_identity(meta) == Some(id))
            .map(|(entry, _)| entry.file_name())
    });

    for (entry, metadata) in &files {
        let name = entry.file_name();
        let is_db = db_identity.is_some_and(|id| file_identity(metadata) == Some(id));
        let is_named_artifact = configured_basename
            .as_deref()
            .is_some_and(|base| is_audit_artifact(&name, base))
            || dirent_basename
                .as_deref()
                .is_some_and(|base| is_audit_artifact(&name, base));
        // A hard link named like a sidecar (or the DB) would alias an inode
        // elsewhere on the host that the guest could read or overwrite through
        // the read-write mount, so require a single link too.
        if (is_db || is_named_artifact) && has_single_link(metadata) {
            continue;
        }
        return Err(AuditDirNotDedicated::Foreign {
            audit_dir: mount_dir.clone(),
            foreign: entry.path(),
        });
    }
    Ok(())
}

/// The pre-2026-07 default audit DB location, before it moved into a dedicated
/// `audit/` directory (see [`super::default_audit_db_path`]). Retained only so the
/// daemon can detect an un-migrated legacy database and refuse to boot rather
/// than silently fork audit history; it is not a supported configuration target.
pub fn legacy_default_audit_db_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join("writ/audit.db")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
        PathBuf::from(home).join(".local/share/writ/audit.db")
    }
}

/// An install that relied on the *default* audit DB path, upgraded across the
/// move into a dedicated `audit/` directory, still has its system-of-record at
/// the legacy path. Booting would open a fresh empty DB at the new default and
/// silently fork audit history (reconciliation and the UI would lose every
/// prior session and grant), so the daemon refuses instead.
///
/// The recovery command (see the `Display` impl) moves the database **with
/// its SQLite sidecars** (the `-wal`/`-shm`/`-journal` files, each moved only if
/// present) and creates the new directory first — moving `audit.db` alone would
/// orphan a hot rollback journal or WAL and lose rows / skip crash recovery on
/// the next open, and a broad `audit.db*` glob would sweep in unrelated files
/// like `audit.db.backup` (which the dedicated-directory check would then
/// reject). It must run with `writd` stopped so nothing is mid-write.
///
/// The recovery `mv` assumes the legacy database is a regular file. If instead
/// the legacy *default* path is itself a symlink (an unusual operator setup that
/// [`path_entry_present`] still detects, so history is not silently forked),
/// moving the link changes what a relative target resolves to — such an operator
/// should use the advertised `audit_db` override pointing at the resolved
/// database rather than the `mv`.
#[derive(Debug)]
pub struct LegacyAuditDbNotMigrated {
    /// The legacy default location that still holds the audit history.
    pub legacy: PathBuf,
    /// The new default location the daemon would otherwise create empty.
    pub new: PathBuf,
    /// The new default's parent directory — created by the recovery command
    /// before the move, since `create_dir_all` only runs on the success path.
    pub new_parent: PathBuf,
}

impl std::error::Error for LegacyAuditDbNotMigrated {}

/// Wrap `s` in single quotes for safe POSIX-shell interpolation, escaping any
/// embedded single quote via the `'\''` idiom. Used so the recovery command
/// stays valid even for paths containing shell metacharacters or quotes.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl std::fmt::Display for LegacyAuditDbNotMigrated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (legacy, new) = (self.legacy.display(), self.new.display());
        // Shell-quoted forms for the copy-pasteable recovery command.
        let ql = shell_single_quote(&self.legacy.to_string_lossy());
        let qp = shell_single_quote(&self.new_parent.to_string_lossy());
        write!(
            f,
            "found a legacy audit database at {legacy}, but the default audit DB path has moved to \
             {new} (a dedicated directory the broker VM can mount read-write without exposing \
             anything else). Refusing to start with an empty audit log. To keep the existing \
             history, first stop writd AND any running broker VMs — a detached broker holds this \
             database open and its directory mounted, so moving it while live risks divergent or \
             lost writes — then move the database with its SQLite sidecars into the new directory \
             (sidecars first, the database last, so an interrupted move is re-detected rather than \
             opening a database without its recovery journal):\
             \n  (set -e; mkdir -p {qp}; for s in -wal -shm -journal ''; do [ -e {ql}\"$s\" ] && \
             mv {ql}\"$s\" {qp}/; done)\n\
             Alternatively, if the legacy directory holds nothing but the database, set `audit_db` \
             to {legacy} to keep using it in place."
        )
    }
}

/// Whether the daemon must refuse to boot to avoid silently forking audit
/// history after the default audit DB path moved. True only when the effective
/// path came from the *default* (neither `--audit-db` nor config selected it),
/// the new default DB does not yet exist, and a legacy database is present.
/// Pure: filesystem existence is passed in by the caller.
pub fn legacy_audit_db_needs_migration(
    used_default: bool,
    new_default_exists: bool,
    legacy_exists: bool,
) -> bool {
    used_default && !new_default_exists && legacy_exists
}

/// Whether `path` currently exists as a directory entry — a regular file, a
/// directory, or a symlink (even a **dangling** one). Unlike [`Path::try_exists`]
/// (which follows symlinks and reports a dangling link as absent), this uses
/// `symlink_metadata`, so a symlinked legacy database whose target is
/// temporarily unavailable is still detected as migration state rather than
/// mistaken for "already migrated". Non-`NotFound` IO errors propagate so the
/// caller can fail closed.
pub fn path_entry_present(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{default_audit_db_path, default_secret_store_path};
    use proptest::prelude::*;

    #[test]
    fn audit_dir_with_only_db_and_sidecars_is_dedicated() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::write(dir.join("audit.db-wal"), b"").unwrap();
        std::fs::write(dir.join("audit.db-shm"), b"").unwrap();
        std::fs::write(dir.join("audit.db-journal"), b"").unwrap();
        ensure_audit_dir_is_dedicated(&db).expect("the DB and its sidecars only is dedicated");
    }

    #[test]
    fn audit_dir_with_a_foreign_file_is_rejected() {
        // A host-control file (e.g. the config) sharing the mounted directory.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::write(dir.join("config.json"), b"{}").unwrap();
        match ensure_audit_dir_is_dedicated(&db).expect_err("a foreign file must be rejected") {
            AuditDirNotDedicated::Foreign { foreign, .. } => {
                assert!(foreign.ends_with("config.json"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn audit_dir_with_a_foreign_subdir_is_rejected() {
        // e.g. a secret store or executable directory dropped into the mount.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        ensure_audit_dir_is_dedicated(&db).expect_err("a foreign subdirectory must be rejected");
    }

    #[test]
    fn case_aliased_db_name_is_accepted() {
        // Regression (P2): configuring the DB under a different-cased name than
        // the on-disk entry (valid on case-insensitive filesystems) must not
        // false-reject a dedicated directory. The DB is matched by filesystem
        // identity, not by the caller's spelling. A no-op on case-sensitive
        // filesystems, where `AUDIT.DB` is simply a different, absent file.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.db"), b"").unwrap();
        let aliased = dir.join("AUDIT.DB");
        if !aliased.exists() {
            return; // case-sensitive filesystem: nothing to test.
        }
        ensure_audit_dir_is_dedicated(&aliased)
            .expect("a case-aliased DB name in a dedicated directory must be accepted");
    }

    #[test]
    fn case_aliased_sidecar_is_accepted() {
        // Regression (P2): SQLite names sidecars after the path it was opened
        // with, so a DB configured as `AUDIT.DB` yields `AUDIT.DB-journal`. That
        // must be accepted even though the DB entry is on-disk `audit.db`. A
        // no-op on case-sensitive filesystems.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.db"), b"").unwrap();
        let aliased_db = dir.join("AUDIT.DB");
        if !aliased_db.exists() {
            return; // case-sensitive filesystem: nothing to test.
        }
        std::fs::write(dir.join("AUDIT.DB-journal"), b"").unwrap();
        ensure_audit_dir_is_dedicated(&aliased_db)
            .expect("a sidecar named after the configured (aliased) DB path must be accepted");
    }

    #[test]
    fn persistent_sidecar_keeps_original_casing_after_config_alias() {
        // Regression (P2): a DB created as `audit.db` (leaving `audit.db-wal`),
        // then reconfigured as `AUDIT.DB`, keeps the on-disk `audit.db-wal`
        // spelling; SQLite opens it through the aliased path. It must be accepted
        // against the DB entry's own basename. No-op on case-sensitive systems.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.db"), b"").unwrap();
        std::fs::write(dir.join("audit.db-wal"), b"").unwrap();
        let aliased_db = dir.join("AUDIT.DB");
        if !aliased_db.exists() {
            return; // case-sensitive filesystem: nothing to test.
        }
        ensure_audit_dir_is_dedicated(&aliased_db)
            .expect("a persistent lowercase sidecar must be accepted under an aliased config");
    }

    #[test]
    fn regular_audit_db_entry_passes_preflight() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("audit.db");
        std::fs::write(&db, b"").unwrap();
        ensure_audit_db_entry_is_regular_file(&db).expect("a plain regular DB file is fine");
    }

    #[test]
    fn absent_audit_db_entry_passes_preflight() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_audit_db_entry_is_regular_file(&tmp.path().join("audit.db"))
            .expect("a not-yet-created DB is created as a regular file by open");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_audit_db_entry_is_rejected_by_preflight() {
        // A symlink planted at the DB path (e.g. by a compromised broker VM) must
        // be rejected before `AuditLog::open` follows it to an unintended target.
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere.db");
        std::fs::write(&target, b"").unwrap();
        let link = tmp.path().join("audit.db");
        symlink(&target, &link).unwrap();
        match ensure_audit_db_entry_is_regular_file(&link)
            .expect_err("a symlinked DB path must be rejected")
        {
            AuditDirNotDedicated::NotRegularFile { path } => assert!(path.ends_with("audit.db")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_audit_db_entry_is_rejected_by_preflight() {
        let tmp = tempfile::tempdir().unwrap();
        let external = tmp.path().join("external");
        std::fs::write(&external, b"").unwrap();
        let db = tmp.path().join("audit.db");
        std::fs::hard_link(&external, &db).unwrap();
        ensure_audit_db_entry_is_regular_file(&db)
            .expect_err("a hard-linked DB path must be rejected");
    }

    #[test]
    fn audit_dir_not_yet_created_is_not_a_violation() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("audit").join("audit.db"); // dir absent
        ensure_audit_dir_is_dedicated(&db).expect("a not-yet-created audit dir is not a violation");
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("a b"), "'a b'");
        // An embedded single quote closes, escapes, and reopens.
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }

    #[cfg(unix)]
    #[test]
    fn path_entry_present_detects_a_dangling_symlink() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        assert!(!path_entry_present(&missing).unwrap());
        let dangling = tmp.path().join("dangling");
        symlink(tmp.path().join("no-such-target"), &dangling).unwrap();
        // `try_exists` would follow the link and report absent; we must detect it.
        assert!(!dangling.try_exists().unwrap());
        assert!(path_entry_present(&dangling).unwrap());
    }

    #[test]
    fn legacy_audit_db_migration_truth_table() {
        // Refuse only when the default was used, the new DB is absent, and a
        // legacy DB is present.
        assert!(legacy_audit_db_needs_migration(true, false, true));
        assert!(!legacy_audit_db_needs_migration(false, false, true)); // explicit path chosen
        assert!(!legacy_audit_db_needs_migration(true, true, true)); // already on the new path
        assert!(!legacy_audit_db_needs_migration(true, false, false)); // fresh install
    }

    #[test]
    fn legacy_default_audit_db_path_differs_from_new_default() {
        // The legacy detector must point at the old sibling location, not the new
        // dedicated dir, or it could never fire; the new default is that legacy
        // dir's `audit/` subdirectory.
        assert_ne!(legacy_default_audit_db_path(), default_audit_db_path());
        assert_eq!(
            default_audit_db_path().parent().unwrap().parent().unwrap(),
            legacy_default_audit_db_path().parent().unwrap(),
        );
    }

    #[test]
    fn default_secret_store_is_not_inside_the_default_audit_dir() {
        // Regression (P1): the broker VM read-write-mounts the audit DB's
        // directory, so the default secret store must not live inside it. Fails
        // on the pre-fix default (audit.db a sibling of secrets/ under writ/).
        let audit_dir = default_audit_db_path().parent().unwrap().to_path_buf();
        assert!(
            !default_secret_store_path().starts_with(&audit_dir),
            "default secret store {:?} must not be inside the default audit dir {audit_dir:?}",
            default_secret_store_path(),
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_dir_with_a_symlink_entry_is_rejected() {
        // A symlink inside the mount is guest-retargetable whatever it points at.
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        symlink(tmp.path().join("elsewhere"), dir.join("link")).unwrap();
        ensure_audit_dir_is_dedicated(&db).expect_err("a symlink entry must be rejected");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_db_whose_mount_exposes_siblings_is_rejected() {
        // `resolve_broker_audit_paths` mounts the DB's *lexical* parent. If the
        // DB is a symlink into a subdir, the mount still exposes that parent and
        // its siblings; the symlink entry (not a regular file) is rejected.
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared");
        let real = shared.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("audit.db"), b"").unwrap();
        std::fs::create_dir_all(shared.join("secrets")).unwrap();
        let db_link = shared.join("audit.db");
        symlink(real.join("audit.db"), &db_link).unwrap();
        ensure_audit_dir_is_dedicated(&db_link)
            .expect_err("a symlinked DB whose mount exposes sibling dirs must be rejected");
    }

    #[test]
    fn directory_named_like_a_sidecar_is_rejected() {
        // A non-file object using a sidecar name (e.g. a secret store at
        // `<audit>/audit.db-wal/…`) must not be accepted on the name alone.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(dir.join("audit.db-wal")).unwrap(); // a directory
        std::fs::write(dir.join("audit.db"), b"").unwrap();
        ensure_audit_dir_is_dedicated(&dir.join("audit.db"))
            .expect_err("a directory named like a sidecar must be rejected");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_sidecar_is_rejected() {
        // A sidecar-named entry that is a hard link aliases an inode elsewhere;
        // the guest could overwrite that external file through the mount.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        let external = tmp.path().join("external-secret");
        std::fs::write(&external, b"secret").unwrap();
        std::fs::hard_link(&external, dir.join("audit.db-wal")).unwrap();
        ensure_audit_dir_is_dedicated(&db)
            .expect_err("a hard-linked sidecar aliasing an external inode must be rejected");
    }

    #[test]
    fn audit_dir_with_prefix_sharing_file_is_rejected() {
        // A file that merely shares the DB prefix (e.g. a spawn_command named
        // `audit.db-helper`) is not a sidecar and must be rejected.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audit");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::write(dir.join("audit.db-helper"), b"").unwrap();
        ensure_audit_dir_is_dedicated(&db)
            .expect_err("a prefix-sharing non-sidecar file must be rejected");
    }

    proptest! {
        /// A directory containing the DB plus arbitrary extra entries is
        /// dedicated iff every extra entry is a recognised SQLite sidecar.
        #[test]
        fn dedicated_iff_only_db_and_sidecars(
            extras in proptest::collection::vec("[a-z][a-z0-9.-]{0,10}", 0..5),
        ) {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("audit");
            std::fs::create_dir_all(&dir).unwrap();
            let db = dir.join("audit.db");
            std::fs::write(&db, b"").unwrap();
            const ALLOWED: [&str; 4] =
                ["audit.db", "audit.db-wal", "audit.db-shm", "audit.db-journal"];
            let mut any_foreign = false;
            for name in &extras {
                if name == "audit.db" {
                    continue; // the DB itself, already present
                }
                std::fs::write(dir.join(name), b"").unwrap();
                if !ALLOWED.contains(&name.as_str()) {
                    any_foreign = true;
                }
            }
            prop_assert_eq!(ensure_audit_dir_is_dedicated(&db).is_err(), any_foreign);
        }
    }
}
