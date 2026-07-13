//! On-disk staging area for VM-initiated git pushes.
//!
//! When a guest VM calls the push endpoint, the broker does *not* contact
//! GitHub. Instead it persists the bundle and accompanying metadata to a
//! host-local directory tree, where a human can inspect and promote the
//! change before it touches the remote. This module is the persistence
//! layer for that staging area.
//!
//! Layout under `<root>`:
//! ```text
//! <root>/staged/<request_id>/entry.json   # VmGitPushStagedReceipt
//! <root>/staged/<request_id>/bundle       # git bundle bytes
//! <root>/tmp/<scratch>/                   # in-flight staging dirs
//! ```
//!
//! Atomicity: each `stage()` writes to a scratch directory inside `tmp/`,
//! fsyncs the files, then renames the scratch directory to its final name
//! under `staged/`. If the final name is already occupied with byte-
//! identical contents the call succeeds idempotently; if the contents
//! differ a `Conflict` error is returned. `RequestId` is a UUID issued by
//! the broker, so genuine collisions across distinct requests are
//! astronomical — the idempotency path exists for retried requests.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::core::{RequestId, UnixMillis};
use crate::vm_git::{VmGitPushMetadata, VmGitPushStagedReceipt};

const STAGED_DIR: &str = "staged";
const TMP_DIR: &str = "tmp";
const ENTRY_FILE: &str = "entry.json";
const BUNDLE_FILE: &str = "bundle";

/// A staged push as stored on disk: the receipt that was returned to the
/// guest plus the git bundle bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEntry {
    receipt: VmGitPushStagedReceipt,
    bundle: Vec<u8>,
}

impl StagedEntry {
    pub fn receipt(&self) -> &VmGitPushStagedReceipt {
        &self.receipt
    }

    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    pub fn into_parts(self) -> (VmGitPushStagedReceipt, Vec<u8>) {
        (self.receipt, self.bundle)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    /// A staged entry for this `request_id` already exists with different
    /// bytes. The caller is replaying a request id with a different
    /// payload, which the broker treats as a correctness violation rather
    /// than silently overwriting.
    #[error("staged entry for request {request_id} already exists with different contents")]
    Conflict { request_id: RequestId },
    /// No staged entry exists for this `request_id`.
    #[error("no staged entry for request {request_id}")]
    NotFound { request_id: RequestId },
    /// A staged entry exists but its on-disk shape is unreadable.
    #[error("staged entry for request {request_id} is corrupt: {message}")]
    Corrupt {
        request_id: RequestId,
        message: String,
    },
    /// A staged entry directory was found whose name is not a valid
    /// request id. Indicates external tampering or a partially-cleaned
    /// scratch directory; surfaced rather than silently skipped.
    #[error("staged directory entry {name:?} is not a valid request id: {message}")]
    UnrecognisedStagedDir { name: String, message: String },
    #[error("staging IO error: {0}")]
    Io(#[from] io::Error),
}

/// Host-local persistence for VM-staged pushes. Cheap to clone (only owns
/// a `PathBuf`); intended to be wrapped in an `Arc` and shared across
/// request handlers.
#[derive(Clone, Debug)]
pub struct GitPushStagingStore {
    root: PathBuf,
}

impl GitPushStagingStore {
    /// Open or initialise a staging store rooted at `root`. Creates the
    /// `staged/` and `tmp/` subdirectories with 0o700 permissions if they
    /// do not already exist.
    pub fn open(root: PathBuf) -> io::Result<Self> {
        create_private_dir(&root)?;
        create_private_dir(&root.join(STAGED_DIR))?;
        create_private_dir(&root.join(TMP_DIR))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist a new staged push. Returns the receipt that should be
    /// handed back to the guest. Calling twice with the same
    /// `request_id` and byte-identical `metadata` / `bundle` is
    /// idempotent; calling twice with the same `request_id` but
    /// different content returns `StagingError::Conflict`.
    ///
    /// `staged_at` is taken from the caller rather than read from the
    /// clock so the staging store can be exercised deterministically
    /// from tests; production code passes `UnixMillis::now()`.
    pub fn stage(
        &self,
        request_id: RequestId,
        staged_at: UnixMillis,
        metadata: VmGitPushMetadata,
        bundle: Vec<u8>,
    ) -> Result<VmGitPushStagedReceipt, StagingError> {
        let receipt = VmGitPushStagedReceipt::new(
            metadata.repo().clone(),
            metadata.branch().clone(),
            metadata.expected_remote_head().cloned(),
            metadata.new_head().clone(),
            request_id,
            staged_at,
        );
        let entry_bytes = serde_json::to_vec(&receipt)
            .expect("VmGitPushStagedReceipt serialises without IO; struct fields are infallible");

        // No fast-path existence check: that would only catch the
        // non-racy case and would still leave a TOCTOU gap before the
        // rename. The rename itself is the single source of truth — its
        // failure mode tells us whether we lost an idempotent race.
        let final_dir = self.staged_path(request_id);
        let scratch = self.scratch_path();
        create_private_dir(&scratch)?;
        let outcome = self.populate_and_commit(&scratch, &final_dir, &entry_bytes, &bundle);
        match outcome {
            Ok(()) => Ok(receipt),
            Err(StagingError::Io(err)) if is_rename_target_occupied(&err) => {
                // Either the final dir was already populated when stage()
                // started, or a concurrent stage() for the same
                // request_id beat us to the rename. Either way, the
                // contents on disk are the canonical truth; reconcile
                // against them.
                let _ = fs::remove_dir_all(&scratch);
                self.reconcile_existing(request_id, &entry_bytes, &bundle)
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&scratch);
                Err(err)
            }
        }
    }

    /// Summarise every staged push currently on disk. Order is
    /// unspecified; callers should sort by `staged_at` if presentation
    /// order matters.
    pub fn list(&self) -> Result<Vec<VmGitPushStagedReceipt>, StagingError> {
        let dir = self.root.join(STAGED_DIR);
        let read = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut entries = Vec::new();
        for child in read {
            let child = child?;
            let file_type = child.file_type()?;
            if !file_type.is_dir() {
                continue;
            }
            let request_id = parse_request_id_from_dirname(&child.file_name())?;
            let receipt = self.load_receipt(request_id)?;
            entries.push(receipt);
        }
        Ok(entries)
    }

    /// Enumerate the staging tree entry-by-entry for boot recovery: one
    /// result per `staged/` child directory, so a single malformed
    /// sibling cannot hide every healthy carrier the way [`Self::list`]'s
    /// fail-fast does. A returned `Ok(receipt)` is a *complete* carrier —
    /// its `entry.json` parses, its directory name matches the recorded
    /// request id, and its `bundle` file is present — so a recovery
    /// caller may safely mark it resolvable. Malformed entries (bad or
    /// missing `entry.json`, missing `bundle`, non-request-id directory
    /// name) surface as `Err` and must be skipped, never recovered:
    /// recording a `staged` outcome for a torn carrier would point the
    /// operator at a push that can never be promoted.
    ///
    /// Only a failure to *open* `staged/` itself (a genuinely broken
    /// staging root) fails the whole call; a missing `staged/` yields an
    /// empty list. The bundle presence check is a metadata probe, not a
    /// read, so this stays cheap even for large carriers.
    pub fn list_entries_for_recovery(
        &self,
    ) -> Result<Vec<Result<VmGitPushStagedReceipt, StagingError>>, StagingError> {
        let dir = self.root.join(STAGED_DIR);
        let read = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err.into()),
        };
        let mut entries = Vec::new();
        for child in read {
            // A per-child readdir error (or a `file_type` that fails —
            // e.g. an `lstat` racing a concurrent `delete`) must stay
            // local: reporting it in-band keeps every healthy sibling
            // already discovered, which is the whole point of this API
            // over `list`. Only the `read_dir` open above fails the call.
            let child = match child {
                Ok(child) => child,
                Err(err) => {
                    entries.push(Err(StagingError::Io(err)));
                    continue;
                }
            };
            match child.file_type() {
                // Staged carriers are always directories; skip anything
                // else silently, matching `list`.
                Ok(file_type) if !file_type.is_dir() => continue,
                Ok(_) => entries.push(self.probe_recoverable_entry(&child.file_name())),
                Err(err) => entries.push(Err(StagingError::Io(err))),
            }
        }
        Ok(entries)
    }

    /// Probe one `staged/` child for [`Self::list_entries_for_recovery`]:
    /// parse its directory name, load its receipt, and confirm the bundle
    /// is a readable regular file.
    fn probe_recoverable_entry(
        &self,
        name: &OsStr,
    ) -> Result<VmGitPushStagedReceipt, StagingError> {
        let request_id = parse_request_id_from_dirname(name)?;
        let receipt = self.load_receipt(request_id)?;
        self.verify_bundle_readable(request_id)?;
        Ok(receipt)
    }

    /// Confirm the carrier's `bundle` is a *readable regular file*, not
    /// merely present. A recovered `staged` outcome must point at a
    /// carrier the approve/reject paths can actually `load()` (which
    /// `fs::read`s the bundle); a bare `try_exists()` would accept a
    /// directory, FIFO, or mode-denied path and let recovery record
    /// `staged` for a push that can never be resolved. `is_file()` rules
    /// out non-regular shapes; opening (without reading) rules out an
    /// unreadable regular file. Missing bundle → `Corrupt`; other open
    /// failures → `Io` (the recovery sweep skips both without recording
    /// an outcome).
    fn verify_bundle_readable(&self, request_id: RequestId) -> Result<(), StagingError> {
        let path = self.staged_path(request_id).join(BUNDLE_FILE);
        match fs::metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                return Err(StagingError::Corrupt {
                    request_id,
                    message: "bundle is not a regular file".to_string(),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(StagingError::Corrupt {
                    request_id,
                    message: "bundle file missing".to_string(),
                });
            }
            Err(err) => return Err(StagingError::Io(err)),
        }
        // Confirmed regular above, so opening cannot block on a FIFO.
        // We open but do not read: this is a cheap readability probe,
        // not a load of a potentially large bundle.
        match fs::File::open(&path) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(StagingError::Corrupt {
                request_id,
                message: "bundle file missing".to_string(),
            }),
            Err(err) => Err(StagingError::Io(err)),
        }
    }

    /// Re-establish the durability of a carrier's directory entry before
    /// a caller records an audit decision that assumes the carrier
    /// survives a power loss. `stage()` fsyncs the parent `staged/` after
    /// its `rename`, but if *that* final fsync failed the rename can be
    /// visible yet not durable; the boot recovery sweep calls this before
    /// writing the `staged` outcome so the "carrier durable ⇒ outcome
    /// recorded" ordering holds on the recovery path too. Idempotent.
    pub fn ensure_carrier_durable(&self, request_id: RequestId) -> Result<(), StagingError> {
        fsync_dir(&self.staged_path(request_id))?;
        fsync_dir(&self.root.join(STAGED_DIR))?;
        Ok(())
    }

    /// Remove the on-disk staging directory for `request_id`. Idempotent:
    /// calling twice, or calling against an id that was never staged,
    /// returns `Ok(())`. Used by the broker after recording a terminal
    /// operator decision (reject or, later, promote) so the staging tree
    /// reflects the resolution recorded in the audit log.
    pub fn delete(&self, request_id: RequestId) -> Result<(), StagingError> {
        let dir = self.staged_path(request_id);
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(StagingError::Io(err)),
        }
        // Durably commit the unlink so a crash here doesn't resurrect a
        // staged push whose terminal resolution is already in the audit
        // log. Matches the fsync on populate_and_commit's rename path.
        fsync_dir(&self.root.join(STAGED_DIR))?;
        Ok(())
    }

    /// Load one staged push by `request_id`, including its bundle bytes.
    pub fn load(&self, request_id: RequestId) -> Result<StagedEntry, StagingError> {
        let dir = self.staged_path(request_id);
        if !dir.exists() {
            return Err(StagingError::NotFound { request_id });
        }
        let receipt = self.load_receipt(request_id)?;
        let bundle = fs::read(dir.join(BUNDLE_FILE)).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                StagingError::Corrupt {
                    request_id,
                    message: "bundle file missing".to_string(),
                }
            } else {
                StagingError::Io(err)
            }
        })?;
        Ok(StagedEntry { receipt, bundle })
    }

    /// Look up one staged push's receipt by `request_id` without reading
    /// the bundle bytes. Returns `Ok(None)` only when the staging
    /// directory is definitively absent (the natural state for an id
    /// that was approved/rejected and had its directory removed),
    /// `Ok(Some)` on hit, and `Err` on a genuine corruption / IO problem
    /// — including filesystem-level probe errors such as
    /// `PermissionDenied` or `NotADirectory`. Surfacing those is
    /// deliberate: a session-filtered caller relies on `Ok(None)`
    /// meaning "really not there", not "we couldn't tell".
    ///
    /// This is the "ID-driven" counterpart to [`Self::list`]: a caller
    /// that already knows which request ids it cares about (e.g. from an
    /// audit-side join) can avoid scanning the whole staging directory
    /// and is therefore not exposed to malformed sibling entries that
    /// happen to share the staging root.
    pub fn try_load_receipt(
        &self,
        request_id: RequestId,
    ) -> Result<Option<VmGitPushStagedReceipt>, StagingError> {
        // `try_exists` distinguishes "confirmed absent" (Ok(false)) from
        // "couldn't tell" (Err) — unlike `exists`, which folds every
        // metadata error into `false`. We only want to skip the load on
        // a real `NotFound`; permission / not-a-directory / other IO
        // errors must surface so the operator sees the broken staging
        // tree rather than an empty success.
        match self.staged_path(request_id).try_exists() {
            Ok(true) => self.load_receipt(request_id).map(Some),
            Ok(false) => Ok(None),
            Err(err) => Err(StagingError::Io(err)),
        }
    }

    fn staged_path(&self, request_id: RequestId) -> PathBuf {
        self.root.join(STAGED_DIR).join(request_id.to_string())
    }

    fn scratch_path(&self) -> PathBuf {
        self.root
            .join(TMP_DIR)
            .join(uuid::Uuid::new_v4().to_string())
    }

    fn load_receipt(&self, request_id: RequestId) -> Result<VmGitPushStagedReceipt, StagingError> {
        let path = self.staged_path(request_id).join(ENTRY_FILE);
        let raw = fs::read(&path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                StagingError::Corrupt {
                    request_id,
                    message: "entry.json missing".to_string(),
                }
            } else {
                StagingError::Io(err)
            }
        })?;
        let receipt: VmGitPushStagedReceipt =
            serde_json::from_slice(&raw).map_err(|err| StagingError::Corrupt {
                request_id,
                message: format!("entry.json unreadable: {err}"),
            })?;
        if receipt.push_request_id() != request_id {
            return Err(StagingError::Corrupt {
                request_id,
                message: format!(
                    "entry.json records request id {} but lives under {}",
                    receipt.push_request_id(),
                    request_id
                ),
            });
        }
        Ok(receipt)
    }

    fn reconcile_existing(
        &self,
        request_id: RequestId,
        entry_bytes: &[u8],
        bundle: &[u8],
    ) -> Result<VmGitPushStagedReceipt, StagingError> {
        let dir = self.staged_path(request_id);
        let existing_entry = fs::read(dir.join(ENTRY_FILE))?;
        let existing_bundle = fs::read(dir.join(BUNDLE_FILE))?;
        if existing_entry == entry_bytes && existing_bundle == bundle {
            self.load_receipt(request_id)
        } else {
            Err(StagingError::Conflict { request_id })
        }
    }

    fn populate_and_commit(
        &self,
        scratch: &Path,
        final_dir: &Path,
        entry_bytes: &[u8],
        bundle: &[u8],
    ) -> Result<(), StagingError> {
        write_private_file(&scratch.join(ENTRY_FILE), entry_bytes)?;
        write_private_file(&scratch.join(BUNDLE_FILE), bundle)?;
        fsync_dir(scratch)?;
        fs::rename(scratch, final_dir)?;
        fsync_dir(&self.root.join(STAGED_DIR))?;
        Ok(())
    }
}

/// Discriminate the rename error that means "the target path is already
/// populated, reconcile against it" from a true IO failure.
///
/// On Linux and macOS, `rename(scratch_dir, populated_dir)` returns
/// `ENOTEMPTY` (mapped to `ErrorKind::DirectoryNotEmpty`). The
/// `AlreadyExists` arm is kept defensively for edge cases such as a
/// final path occupied by a non-directory file.
fn is_rename_target_occupied(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::AlreadyExists
    )
}

fn parse_request_id_from_dirname(name: &OsStr) -> Result<RequestId, StagingError> {
    let as_str = name
        .to_str()
        .ok_or_else(|| StagingError::UnrecognisedStagedDir {
            name: name.to_string_lossy().into_owned(),
            message: "directory name is not UTF-8".to_string(),
        })?;
    as_str
        .parse::<RequestId>()
        .map_err(|err| StagingError::UnrecognisedStagedDir {
            name: as_str.to_string(),
            message: err.to_string(),
        })
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false).mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err),
        }
    }
}

fn write_private_file(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn fsync_dir(path: &Path) -> io::Result<()> {
    let dir = fs::File::open(path)?;
    // On platforms where directory fsync is a no-op (e.g. some Windows
    // filesystems) this still records the intent; on Unix it durably
    // commits the rename so a crash after this point still surfaces the
    // entry in `staged/`.
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_git::{GitBranchName, GitCloneRepo, GitObjectId};
    use proptest::prelude::*;
    use std::str::FromStr as _;
    use tempfile::TempDir;

    fn sample_object_id(nibble: char) -> GitObjectId {
        std::iter::repeat_n(nibble, 40)
            .collect::<String>()
            .parse()
            .unwrap()
    }

    fn sample_repo() -> GitCloneRepo {
        "owner/repo".parse().unwrap()
    }

    fn sample_branch() -> GitBranchName {
        GitBranchName::from_str("feature/x").unwrap()
    }

    fn sample_metadata() -> VmGitPushMetadata {
        VmGitPushMetadata::new(
            sample_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        )
    }

    fn open_store() -> (GitPushStagingStore, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = GitPushStagingStore::open(tmp.path().join("staging")).unwrap();
        (store, tmp)
    }

    #[test]
    fn open_is_idempotent_and_creates_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("staging");
        let _ = GitPushStagingStore::open(root.clone()).unwrap();
        let _ = GitPushStagingStore::open(root.clone()).unwrap();
        assert!(root.join("staged").is_dir());
        assert!(root.join("tmp").is_dir());
    }

    #[test]
    fn stage_then_load_returns_same_entry() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let metadata = sample_metadata();
        let bundle = b"PACK bundle bytes".to_vec();
        let staged_at = UnixMillis::from_millis(1_700_000_000_123);

        let receipt = store
            .stage(request_id, staged_at, metadata.clone(), bundle.clone())
            .unwrap();
        assert_eq!(receipt.push_request_id(), request_id);
        assert_eq!(receipt.staged_at(), staged_at);
        assert_eq!(receipt.repo(), metadata.repo());
        assert_eq!(receipt.branch(), metadata.branch());
        assert_eq!(
            receipt.expected_remote_head(),
            metadata.expected_remote_head(),
        );
        assert_eq!(receipt.new_head(), metadata.new_head());

        let loaded = store.load(request_id).unwrap();
        assert_eq!(loaded.bundle(), bundle.as_slice());
        assert_eq!(loaded.receipt(), &receipt);
    }

    #[test]
    fn stage_twice_with_same_payload_is_idempotent() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "22222222-2222-2222-2222-222222222222".parse().unwrap();
        let metadata = sample_metadata();
        let bundle = b"identical bundle".to_vec();
        let staged_at = UnixMillis::from_millis(42);

        let first = store
            .stage(request_id, staged_at, metadata.clone(), bundle.clone())
            .unwrap();
        let second = store
            .stage(request_id, staged_at, metadata.clone(), bundle.clone())
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn stage_twice_with_different_metadata_errors_conflict() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        let metadata_a = sample_metadata();
        let metadata_b = VmGitPushMetadata::new(
            sample_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('c'), // different new_head
        );
        let bundle = b"bundle".to_vec();
        let staged_at = UnixMillis::from_millis(7);

        store
            .stage(request_id, staged_at, metadata_a, bundle.clone())
            .unwrap();
        let err = store
            .stage(request_id, staged_at, metadata_b, bundle)
            .unwrap_err();
        assert!(matches!(err, StagingError::Conflict { request_id: id } if id == request_id));
    }

    #[test]
    fn stage_twice_with_different_bundle_errors_conflict() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "44444444-4444-4444-4444-444444444444".parse().unwrap();
        let metadata = sample_metadata();
        let staged_at = UnixMillis::from_millis(9);

        store
            .stage(
                request_id,
                staged_at,
                metadata.clone(),
                b"bundle-one".to_vec(),
            )
            .unwrap();
        let err = store
            .stage(request_id, staged_at, metadata, b"bundle-two".to_vec())
            .unwrap_err();
        assert!(matches!(err, StagingError::Conflict { request_id: id } if id == request_id));
    }

    #[test]
    fn stage_twice_with_different_staged_at_errors_conflict() {
        // The staging snapshot is the (metadata, bundle, staged_at) triple
        // as serialised on disk. A retry that drifts wall-clock should be
        // surfaced rather than silently overwriting.
        let (store, _tmp) = open_store();
        let request_id: RequestId = "55555555-5555-5555-5555-555555555555".parse().unwrap();
        let metadata = sample_metadata();
        let bundle = b"bundle".to_vec();

        store
            .stage(
                request_id,
                UnixMillis::from_millis(1),
                metadata.clone(),
                bundle.clone(),
            )
            .unwrap();
        let err = store
            .stage(request_id, UnixMillis::from_millis(2), metadata, bundle)
            .unwrap_err();
        assert!(matches!(err, StagingError::Conflict { request_id: id } if id == request_id));
    }

    #[test]
    fn load_unknown_request_returns_not_found() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "66666666-6666-6666-6666-666666666666".parse().unwrap();
        let err = store.load(request_id).unwrap_err();
        assert!(matches!(err, StagingError::NotFound { request_id: id } if id == request_id));
    }

    #[test]
    fn list_returns_all_staged_entries() {
        let (store, _tmp) = open_store();
        let ids: [RequestId; 3] = [
            "10000000-0000-0000-0000-000000000001".parse().unwrap(),
            "10000000-0000-0000-0000-000000000002".parse().unwrap(),
            "10000000-0000-0000-0000-000000000003".parse().unwrap(),
        ];
        for (i, id) in ids.iter().enumerate() {
            store
                .stage(
                    *id,
                    UnixMillis::from_millis(i as i64),
                    sample_metadata(),
                    format!("bundle-{i}").into_bytes(),
                )
                .unwrap();
        }
        let mut listed: Vec<RequestId> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.push_request_id())
            .collect();
        listed.sort();
        let mut expected = ids.to_vec();
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn list_empty_store_returns_empty_vec() {
        let (store, _tmp) = open_store();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn list_rejects_unrecognised_directory() {
        let (store, _tmp) = open_store();
        let bogus = store.root().join("staged").join("not-a-uuid");
        fs::create_dir(&bogus).unwrap();
        let err = store.list().unwrap_err();
        assert!(matches!(err, StagingError::UnrecognisedStagedDir { .. }));
    }

    #[test]
    fn load_corrupt_entry_returns_corrupt() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "77777777-7777-7777-7777-777777777777".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(0),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        let entry = store
            .root()
            .join("staged")
            .join(request_id.to_string())
            .join("entry.json");
        fs::write(&entry, b"{not json").unwrap();
        let err = store.load(request_id).unwrap_err();
        assert!(matches!(err, StagingError::Corrupt { request_id: id, .. } if id == request_id));
    }

    #[test]
    fn load_missing_bundle_returns_corrupt() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "88888888-8888-8888-8888-888888888888".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(0),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        let bundle = store
            .root()
            .join("staged")
            .join(request_id.to_string())
            .join("bundle");
        fs::remove_file(&bundle).unwrap();
        let err = store.load(request_id).unwrap_err();
        assert!(matches!(err, StagingError::Corrupt { request_id: id, .. } if id == request_id));
    }

    #[test]
    fn try_load_receipt_returns_none_when_dir_absent() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".parse().unwrap();
        let receipt = store.try_load_receipt(request_id).unwrap();
        assert!(receipt.is_none());
    }

    #[test]
    fn try_load_receipt_returns_some_for_present_entry() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(0),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        let receipt = store.try_load_receipt(request_id).unwrap().unwrap();
        assert_eq!(receipt.push_request_id(), request_id);
    }

    /// Replacing `staged/` with a regular file makes any
    /// `staged/<request-id>` probe fail with `NotADirectory` rather
    /// than `NotFound`. The pre-fix `Path::exists()` would have folded
    /// that into `false` and made the filtered listing silently drop
    /// audit-named pushes. With `try_exists` we surface the IO error.
    #[test]
    fn try_load_receipt_surfaces_io_error_when_staged_dir_is_broken() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "cccccccc-cccc-cccc-cccc-cccccccccccc".parse().unwrap();
        let staged = store.root().join("staged");
        fs::remove_dir_all(&staged).unwrap();
        fs::write(&staged, b"").unwrap();
        let err = store.try_load_receipt(request_id).unwrap_err();
        assert!(matches!(err, StagingError::Io(_)), "got: {err:?}");
    }

    #[test]
    fn branch_creation_roundtrips_with_null_expected_head() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        let metadata =
            VmGitPushMetadata::new(sample_repo(), sample_branch(), None, sample_object_id('d'));
        let receipt = store
            .stage(
                request_id,
                UnixMillis::from_millis(123),
                metadata,
                b"bundle".to_vec(),
            )
            .unwrap();
        assert!(receipt.expected_remote_head().is_none());
        let loaded = store.load(request_id).unwrap();
        assert!(loaded.receipt().expected_remote_head().is_none());
    }

    /// Regression test for the rename-error discrimination logic. On
    /// Unix-like systems renaming a populated scratch directory onto a
    /// populated target returns `ENOTEMPTY` (`ErrorKind::DirectoryNotEmpty`),
    /// not `AlreadyExists`. A previous version of `stage()` matched only
    /// the latter and surfaced the rename error to callers instead of
    /// reconciling, breaking idempotent replay.
    #[test]
    fn stage_reconciles_when_final_dir_is_already_populated() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "bbbbbbbb-0000-0000-0000-000000000000".parse().unwrap();
        let staged_at = UnixMillis::from_millis(2024);
        let metadata = sample_metadata();
        let bundle = b"identical bundle bytes".to_vec();

        let expected_receipt = VmGitPushStagedReceipt::new(
            metadata.repo().clone(),
            metadata.branch().clone(),
            metadata.expected_remote_head().cloned(),
            metadata.new_head().clone(),
            request_id,
            staged_at,
        );
        let entry_bytes = serde_json::to_vec(&expected_receipt).unwrap();
        let final_dir = store.root().join(STAGED_DIR).join(request_id.to_string());
        create_private_dir(&final_dir).unwrap();
        write_private_file(&final_dir.join(ENTRY_FILE), &entry_bytes).unwrap();
        write_private_file(&final_dir.join(BUNDLE_FILE), &bundle).unwrap();

        let receipt = store
            .stage(request_id, staged_at, metadata, bundle)
            .unwrap();
        assert_eq!(receipt, expected_receipt);
    }

    #[cfg(unix)]
    #[test]
    fn staged_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let (store, _tmp) = open_store();
        let request_id: RequestId = "aaaaaaaa-0000-0000-0000-000000000000".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(0),
                sample_metadata(),
                b"secret".to_vec(),
            )
            .unwrap();
        let dir = store.root().join("staged").join(request_id.to_string());
        for file in [ENTRY_FILE, BUNDLE_FILE] {
            let mode = fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{file} mode was {mode:o}");
        }
    }

    #[test]
    fn delete_removes_staged_entry_and_load_then_returns_not_found() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "cccccccc-0000-0000-0000-000000000000".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"to be deleted".to_vec(),
            )
            .unwrap();
        let dir = store.root().join("staged").join(request_id.to_string());
        assert!(dir.exists(), "staged dir must exist before delete");

        store.delete(request_id).unwrap();

        assert!(!dir.exists(), "staged dir must be gone after delete");
        let err = store.load(request_id).unwrap_err();
        assert!(matches!(err, StagingError::NotFound { request_id: id } if id == request_id));
        let listed: Vec<RequestId> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|r| r.push_request_id())
            .collect();
        assert!(listed.is_empty(), "list must not show the deleted entry");
    }

    #[test]
    fn delete_is_idempotent_when_called_twice() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "dddddddd-0000-0000-0000-000000000000".parse().unwrap();
        store
            .stage(
                request_id,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"twice".to_vec(),
            )
            .unwrap();
        store.delete(request_id).unwrap();
        store.delete(request_id).unwrap();
    }

    #[test]
    fn delete_unknown_request_is_ok() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "eeeeeeee-0000-0000-0000-000000000000".parse().unwrap();
        store.delete(request_id).unwrap();
    }

    // ---- list_entries_for_recovery ------------------------------------

    #[test]
    fn list_entries_for_recovery_returns_ok_for_healthy_entries() {
        let (store, _tmp) = open_store();
        let ids: [RequestId; 2] = [
            "20000000-0000-0000-0000-000000000001".parse().unwrap(),
            "20000000-0000-0000-0000-000000000002".parse().unwrap(),
        ];
        for id in &ids {
            store
                .stage(
                    *id,
                    UnixMillis::from_millis(1),
                    sample_metadata(),
                    b"b".to_vec(),
                )
                .unwrap();
        }
        let mut got: Vec<RequestId> = store
            .list_entries_for_recovery()
            .unwrap()
            .into_iter()
            .map(|r| r.unwrap().push_request_id())
            .collect();
        got.sort();
        let mut expected = ids.to_vec();
        expected.sort();
        assert_eq!(got, expected);
    }

    #[test]
    fn list_entries_for_recovery_empty_store_is_empty() {
        let (store, _tmp) = open_store();
        assert!(store.list_entries_for_recovery().unwrap().is_empty());
    }

    /// The key property behind the corrupt-sibling fix: a torn directory
    /// (here, `entry.json` removed) is reported as a single `Err` while
    /// every healthy sibling still comes back `Ok` — unlike [`list`],
    /// which fails the whole call.
    #[test]
    fn list_entries_for_recovery_isolates_a_torn_sibling() {
        let (store, _tmp) = open_store();
        let healthy: RequestId = "30000000-0000-0000-0000-000000000001".parse().unwrap();
        let torn: RequestId = "30000000-0000-0000-0000-000000000002".parse().unwrap();
        store
            .stage(
                healthy,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        store
            .stage(
                torn,
                UnixMillis::from_millis(2),
                sample_metadata(),
                b"torn".to_vec(),
            )
            .unwrap();
        // Tear the second carrier by removing its receipt.
        fs::remove_file(store.staged_path(torn).join(ENTRY_FILE)).unwrap();

        // `list` fails outright on the torn sibling...
        assert!(store.list().is_err());

        // ...but the recovery enumeration isolates it.
        let entries = store.list_entries_for_recovery().unwrap();
        assert_eq!(entries.len(), 2);
        let mut healthy_seen = false;
        let mut torn_seen = false;
        for entry in entries {
            match entry {
                Ok(receipt) => {
                    assert_eq!(receipt.push_request_id(), healthy);
                    healthy_seen = true;
                }
                Err(StagingError::Corrupt { request_id, .. }) => {
                    assert_eq!(request_id, torn);
                    torn_seen = true;
                }
                other => panic!("unexpected entry: {other:?}"),
            }
        }
        assert!(healthy_seen && torn_seen);
    }

    #[test]
    fn list_entries_for_recovery_flags_missing_bundle() {
        let (store, _tmp) = open_store();
        let id: RequestId = "40000000-0000-0000-0000-000000000001".parse().unwrap();
        store
            .stage(
                id,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"gone".to_vec(),
            )
            .unwrap();
        fs::remove_file(store.staged_path(id).join(BUNDLE_FILE)).unwrap();

        let entries = store.list_entries_for_recovery().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries.into_iter().next().unwrap(),
            Err(StagingError::Corrupt { request_id, .. }) if request_id == id
        ));
    }

    /// A carrier whose `bundle` is a directory (or any non-regular file)
    /// must be reported `Corrupt`, not `Ok`: recovering it would record
    /// `staged` for a push whose bundle `load()` can never `fs::read`.
    #[test]
    fn list_entries_for_recovery_flags_non_regular_bundle() {
        let (store, _tmp) = open_store();
        let id: RequestId = "40000000-0000-0000-0000-00000000000f".parse().unwrap();
        store
            .stage(
                id,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"orig".to_vec(),
            )
            .unwrap();
        // Replace the bundle file with a directory.
        let bundle = store.staged_path(id).join(BUNDLE_FILE);
        fs::remove_file(&bundle).unwrap();
        fs::create_dir(&bundle).unwrap();

        let entries = store.list_entries_for_recovery().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries.into_iter().next().unwrap(),
            Err(StagingError::Corrupt { request_id, .. }) if request_id == id
        ));
    }

    #[test]
    fn ensure_carrier_durable_succeeds_for_a_staged_carrier() {
        let (store, _tmp) = open_store();
        let id: RequestId = "40000000-0000-0000-0000-0000000000aa".parse().unwrap();
        store
            .stage(
                id,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"b".to_vec(),
            )
            .unwrap();
        // Idempotent: safe to call repeatedly.
        store.ensure_carrier_durable(id).unwrap();
        store.ensure_carrier_durable(id).unwrap();
    }

    /// A stray non-directory under `staged/` is skipped silently rather
    /// than surfaced as an error or an entry — exercises the per-child
    /// `file_type` branch that must not abort the scan.
    #[test]
    fn list_entries_for_recovery_skips_stray_files() {
        let (store, _tmp) = open_store();
        let healthy: RequestId = "60000000-0000-0000-0000-000000000001".parse().unwrap();
        store
            .stage(
                healthy,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        fs::write(store.root().join(STAGED_DIR).join("stray-file"), b"junk").unwrap();

        let entries = store.list_entries_for_recovery().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the stray file must not appear as an entry"
        );
        assert_eq!(
            entries
                .into_iter()
                .next()
                .unwrap()
                .unwrap()
                .push_request_id(),
            healthy,
        );
    }

    #[test]
    fn list_entries_for_recovery_flags_unrecognised_dir() {
        let (store, _tmp) = open_store();
        let healthy: RequestId = "50000000-0000-0000-0000-000000000001".parse().unwrap();
        store
            .stage(
                healthy,
                UnixMillis::from_millis(1),
                sample_metadata(),
                b"ok".to_vec(),
            )
            .unwrap();
        fs::create_dir(store.root().join(STAGED_DIR).join("not-a-uuid")).unwrap();

        let entries = store.list_entries_for_recovery().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| matches!(
            e,
            Ok(receipt) if receipt.push_request_id() == healthy
        )));
        assert!(
            entries
                .iter()
                .any(|e| matches!(e, Err(StagingError::UnrecognisedStagedDir { .. })))
        );
    }

    // ---- proptest strategies ------------------------------------------

    fn object_id_strategy() -> impl Strategy<Value = GitObjectId> {
        "[0-9a-fA-F]{40}".prop_map(|hex| hex.parse().unwrap())
    }

    fn expected_head_strategy() -> impl Strategy<Value = Option<GitObjectId>> {
        proptest::option::of(object_id_strategy())
    }

    fn bundle_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..512)
    }

    fn request_id_strategy() -> impl Strategy<Value = RequestId> {
        any::<[u8; 16]>().prop_map(|bytes| {
            let uuid = uuid::Uuid::from_bytes(bytes);
            uuid.to_string().parse().unwrap()
        })
    }

    fn staged_at_strategy() -> impl Strategy<Value = UnixMillis> {
        any::<i64>().prop_map(UnixMillis::from_millis)
    }

    proptest! {
        #[test]
        fn stage_then_load_roundtrips(
            request_id in request_id_strategy(),
            staged_at in staged_at_strategy(),
            expected in expected_head_strategy(),
            new_head in object_id_strategy(),
            bundle in bundle_strategy(),
        ) {
            let (store, _tmp) = open_store();
            let metadata = VmGitPushMetadata::new(
                sample_repo(),
                sample_branch(),
                expected.clone(),
                new_head.clone(),
            );
            let receipt = store
                .stage(request_id, staged_at, metadata, bundle.clone())
                .unwrap();
            let loaded = store.load(request_id).unwrap();
            prop_assert_eq!(loaded.receipt(), &receipt);
            prop_assert_eq!(loaded.bundle(), bundle.as_slice());
            prop_assert_eq!(receipt.push_request_id(), request_id);
            prop_assert_eq!(receipt.staged_at(), staged_at);
            prop_assert_eq!(receipt.expected_remote_head(), expected.as_ref());
            prop_assert_eq!(receipt.new_head(), &new_head);
        }

        #[test]
        fn stage_is_idempotent_on_identical_inputs(
            request_id in request_id_strategy(),
            staged_at in staged_at_strategy(),
            expected in expected_head_strategy(),
            new_head in object_id_strategy(),
            bundle in bundle_strategy(),
        ) {
            let (store, _tmp) = open_store();
            let metadata = VmGitPushMetadata::new(
                sample_repo(),
                sample_branch(),
                expected,
                new_head,
            );
            let first = store
                .stage(request_id, staged_at, metadata.clone(), bundle.clone())
                .unwrap();
            let second = store
                .stage(request_id, staged_at, metadata, bundle)
                .unwrap();
            prop_assert_eq!(first, second);
        }

        #[test]
        fn list_reflects_every_staged_request(
            request_ids in prop::collection::hash_set(request_id_strategy(), 0..6),
        ) {
            let (store, _tmp) = open_store();
            for (i, id) in request_ids.iter().enumerate() {
                store
                    .stage(
                        *id,
                        UnixMillis::from_millis(i as i64),
                        sample_metadata(),
                        format!("bundle-{i}").into_bytes(),
                    )
                    .unwrap();
            }
            let mut listed: Vec<RequestId> = store
                .list()
                .unwrap()
                .into_iter()
                .map(|r| r.push_request_id())
                .collect();
            listed.sort();
            let mut expected: Vec<RequestId> = request_ids.into_iter().collect();
            expected.sort();
            prop_assert_eq!(listed, expected);
        }
    }
}
