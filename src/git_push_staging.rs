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
    let as_str = name.to_str().ok_or_else(|| StagingError::UnrecognisedStagedDir {
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
        let entry = store.root().join("staged").join(request_id.to_string()).join("entry.json");
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
        let bundle = store.root().join("staged").join(request_id.to_string()).join("bundle");
        fs::remove_file(&bundle).unwrap();
        let err = store.load(request_id).unwrap_err();
        assert!(matches!(err, StagingError::Corrupt { request_id: id, .. } if id == request_id));
    }

    #[test]
    fn branch_creation_roundtrips_with_null_expected_head() {
        let (store, _tmp) = open_store();
        let request_id: RequestId = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        let metadata = VmGitPushMetadata::new(
            sample_repo(),
            sample_branch(),
            None,
            sample_object_id('d'),
        );
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
