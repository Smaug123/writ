//! A `(repo, rev)`-keyed on-disk cache of bare `git clone --mirror`
//! repositories.
//!
//! The broker already clones every requested repo into a bare mirror to build
//! the guest's bundle, then discards it. Flake-input provisioning needs that
//! same checkout again — to read `flake.lock` and run `nix flake archive` — so
//! this cache retains the mirror under a key derived from the repository and
//! the resolved commit, letting a later provision step reuse it without a
//! second fetch. Keying by `(repo, rev)` lets many concurrent VMs that clone
//! the same flake at the same commit share one mirror, while a moved branch
//! gets a fresh entry (so a still-running VM's older revision stays available).
//!
//! The store is just a directory on disk: there is no shared in-memory state,
//! so concurrent broker tasks coordinate purely through atomic filesystem
//! operations — each insert stages a complete entry in a private temp
//! directory and publishes it with a single `rename`, deduping clones of the
//! same key. A crash mid-publish can only leave a discardable `.staging-*`
//! directory, which a later insert sweeps.
//!
//! Eviction ([`MirrorCache::evict_to_bounds`]) is bounded by both an entry
//! count and a total-byte budget, evicting oldest-first. It coordinates with
//! in-flight provisions through an in-memory [`MirrorPins`] registry: a
//! provision pins an entry's slug for the duration of its `git clone --local`
//! materialise, and eviction skips any pinned slug, so GC can never delete a
//! mirror out from under a running clone. The pin check and the entry's
//! atomic rename-aside happen under the same lock, so a pin taken after the
//! rename simply finds the entry gone (the provision then sees a cache miss and
//! degrades) rather than racing a half-deleted mirror.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::agent_run::sha256_hex;
use crate::core::RepoRef;

/// Name of the bare mirror directory inside each cache entry. Matches the
/// `mirror.git` the clone planner produces, so the moved-in directory keeps a
/// familiar shape for an operator inspecting the cache.
const MIRROR_DIR_NAME: &str = "mirror.git";

/// Prefix of the private temporary directory an in-flight publish stages into.
const STAGING_PREFIX: &str = ".staging-";

/// Prefix of a directory an eviction has renamed aside and is about to remove.
/// Like a `.staging-*` leftover, a `.deleting-*` directory left by a crash
/// mid-eviction is swept later; both are non-entry slots that lookups ignore.
const DELETING_PREFIX: &str = ".deleting-";

/// A `.staging-*` directory older than this is treated as a crash leftover and
/// swept. A real publish only holds its staging directory for two renames
/// (the clone already happened), so any staging directory this old cannot
/// belong to a live insert; the margin is generous to tolerate slow disks.
const STALE_STAGING_AGE: Duration = Duration::from_secs(3600);

/// A resolved Git commit hash (the output of `git rev-parse`). Parsed, not
/// validated: an interior value is always 40 (SHA-1) or 64 (SHA-256) lowercase
/// hex characters, so it is safe to embed in a cache key without further
/// sanitising.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GitCommitSha(String);

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum GitCommitShaError {
    #[error("git commit sha must be 40 or 64 lowercase hex characters, got {0:?}")]
    Invalid(String),
}

impl GitCommitSha {
    /// Parse `git rev-parse` output (or any candidate commit hash). Trims
    /// surrounding whitespace — `git` appends a newline — then requires exactly
    /// 40 or 64 lowercase hex characters. `git` always prints lowercase, so
    /// requiring it keeps the canonical form unambiguous for keying.
    pub fn parse(raw: &str) -> Result<Self, GitCommitShaError> {
        let trimmed = raw.trim();
        let len_ok = trimmed.len() == 40 || trimmed.len() == 64;
        let chars_ok = trimmed
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if len_ok && chars_ok {
            Ok(Self(trimmed.to_string()))
        } else {
            Err(GitCommitShaError::Invalid(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The filesystem-safe key for a cached mirror, derived from the case-folded
/// repository identity and the resolved commit. The slug is a SHA-256 hex
/// digest, so it can never escape the cache root via a crafted repository name
/// and two distinct `(repo, rev)` pairs never collide in practice.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MirrorCacheKey {
    slug: String,
}

impl MirrorCacheKey {
    pub fn new(repo: &RepoRef, rev: &GitCommitSha) -> Self {
        // The canonical (case-folded) repo identity matches GitHub's own
        // resolution, so `Owner/Repo` and `owner/repo` at the same commit share
        // one entry. The newline separates the fields unambiguously because a
        // canonical owner/name never contains one.
        let material = format!("{}\n{}", repo.canonicalise(), rev.as_str());
        Self {
            slug: sha256_hex(material.as_bytes()),
        }
    }

    /// The entry's directory name within the cache root.
    pub fn slug(&self) -> &str {
        &self.slug
    }
}

/// Outcome of an [`MirrorCache::insert`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MirrorCacheInsertion {
    /// The mirror was moved into the cache and now backs this key.
    Stored,
    /// An entry for this key already existed (an equivalent mirror from a
    /// concurrent or earlier clone of the same `(repo, rev)`), so the existing
    /// mirror was kept. The caller's source may or may not have been consumed
    /// (see [`MirrorCache::insert`]); clean up the work directory regardless.
    AlreadyPresent,
}

/// In-memory record of which cache entries (by slug) an in-flight provision is
/// mid-materialising, so [`MirrorCache::evict_to_bounds`] never deletes a mirror
/// out from under a running `git clone --local`. Shared (cheap `Arc` clone)
/// between the clone handler that runs eviction and the provision path that
/// pins; broker-wide, since a clone in one session may evict while another
/// session provisions the same `(repo, rev)`.
///
/// The map holds a *reference count* per slug: two VMs provisioning the same
/// commit concurrently both pin it, and the entry stays protected until the
/// last guard drops.
#[derive(Clone, Default)]
pub struct MirrorPins {
    pinned: Arc<Mutex<HashMap<String, usize>>>,
    /// Serializes whole eviction passes. Without it, two concurrent passes
    /// could each snapshot the same over-budget store and both claim victims,
    /// over-evicting. It is distinct from `pinned` so an eviction's (slow)
    /// sizing never blocks pinning — only other evictions wait.
    gc: Arc<Mutex<()>>,
}

/// Holds a pin on one slug for its lifetime; dropping it releases the pin.
pub struct MirrorPinGuard {
    pins: MirrorPins,
    slug: String,
}

impl MirrorPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin `slug` until the returned guard is dropped. Acquire this *before*
    /// [`MirrorCache::get`] and hold it across the materialise, so eviction
    /// (which checks the pin set under the same lock) cannot remove the entry
    /// while the clone reads it.
    pub fn pin(&self, slug: &str) -> MirrorPinGuard {
        *self.pinned_lock().entry(slug.to_string()).or_insert(0) += 1;
        MirrorPinGuard {
            pins: self.clone(),
            slug: slug.to_string(),
        }
    }

    fn pinned_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        // A poisoned pins lock means a thread panicked mid-update; the map is
        // still structurally valid (counts are plain integers), so recover the
        // guard rather than propagate the panic into eviction or provisioning.
        self.pinned.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn gc_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.gc.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for MirrorPinGuard {
    fn drop(&mut self) {
        let mut map = self.pins.pinned_lock();
        if let Some(count) = map.get_mut(&self.slug) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.slug);
            }
        }
    }
}

/// The size budget an eviction pass holds the mirror store under: an entry
/// count *and* a total-byte ceiling. Eviction removes oldest-first until the
/// store is at or under both (skipping pinned entries).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MirrorCacheBounds {
    max_entries: usize,
    max_bytes: u64,
}

impl MirrorCacheBounds {
    pub fn new(max_entries: usize, max_bytes: u64) -> Self {
        Self {
            max_entries,
            max_bytes,
        }
    }
}

/// What one [`MirrorCache::evict_to_bounds`] pass did.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MirrorEvictionOutcome {
    /// Entries removed to get under the bounds.
    pub evicted: usize,
    /// Total bytes the removed entries occupied.
    pub bytes_freed: u64,
    /// Entries that would have been evicted but were pinned by an in-flight
    /// provision, so they were left in place — the store may stay over budget
    /// until they are unpinned.
    pub retained_pinned: usize,
}

/// A `(repo, rev)`-keyed cache of bare mirrors rooted at a directory. Cheap to
/// clone (just a path); all on-disk state lives under the root, and the only
/// in-memory coordination — pins for eviction — is passed in explicitly via
/// [`MirrorPins`] rather than held here, so the cache stays a comparable value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorCache {
    root: PathBuf,
}

impl MirrorCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the path to the retained bare mirror for `key`, if one is cached.
    /// The caller should materialise an *independent* tree from it promptly (see
    /// [`crate::flake_materialize`]) rather than hold the path: there is no
    /// eviction today, but FK4's GC will reclaim mirrors, and a local clone is
    /// unaffected by that whereas the returned path is not.
    pub fn get(&self, key: &MirrorCacheKey) -> Option<PathBuf> {
        let mirror = self.root.join(key.slug()).join(MIRROR_DIR_NAME);
        mirror.is_dir().then_some(mirror)
    }

    /// Publish a freshly-cloned bare mirror into the cache under `key`. A
    /// *complete* entry is staged in a private temp directory and published with
    /// a single atomic `rename`, so concurrent clones of the same `(repo, rev)`
    /// resolve to one winner and a crash or lost race can only leave a
    /// discardable `.staging-*` directory — never a half-built slot that would
    /// shadow the key. Losers (and the fast-path case where a complete entry
    /// already exists) see [`MirrorCacheInsertion::AlreadyPresent`].
    ///
    /// `src_mirror` is moved, and on the race-loser path may be consumed even
    /// though the existing entry is kept — so the caller must clean up its own
    /// work directory regardless of the outcome rather than rely on
    /// `src_mirror` surviving. When `src_mirror` is on the cache root's
    /// filesystem the move is an atomic rename; when it is on a different
    /// filesystem (a separate cache volume), the stage falls back to a
    /// recursive copy. The staging-to-entry publish is always same-filesystem
    /// and atomic either way.
    pub fn insert(
        &self,
        key: &MirrorCacheKey,
        src_mirror: &Path,
    ) -> std::io::Result<MirrorCacheInsertion> {
        create_private_dir_all(&self.root)?;
        let entry = self.root.join(key.slug());
        // Fast path: a complete entry already backs this key. Keep it and leave
        // the caller's source for it to clean up.
        if entry.join(MIRROR_DIR_NAME).is_dir() {
            return Ok(MirrorCacheInsertion::AlreadyPresent);
        }
        // Stage the whole entry, then publish atomically.
        let staging = self
            .root
            .join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4().simple()));
        create_private_dir(&staging)?;
        let staged_mirror = staging.join(MIRROR_DIR_NAME);
        if let Err(err) = std::fs::rename(src_mirror, &staged_mirror) {
            // A cross-device rename (cache root and clone work dir on different
            // filesystems) fails with `CrossesDevices`; fall back to a recursive
            // copy into staging so a separate cache volume still works. Other
            // failures (missing or unreadable source) are propagated.
            if err.kind() == std::io::ErrorKind::CrossesDevices {
                if let Err(copy_err) = copy_dir_recursive(src_mirror, &staged_mirror) {
                    let _ = std::fs::remove_dir_all(&staging);
                    return Err(copy_err);
                }
            } else {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(err);
            }
        }
        // `rename` onto a missing or empty `entry` succeeds (publishing, or
        // healing a leftover empty slot from an earlier crash); onto a populated
        // `entry` it fails, so a concurrent winner is preserved.
        match std::fs::rename(&staging, &entry) {
            Ok(()) => {
                self.sweep_stale(SystemTime::now());
                Ok(MirrorCacheInsertion::Stored)
            }
            Err(err) => {
                let _ = std::fs::remove_dir_all(&staging);
                if entry.join(MIRROR_DIR_NAME).is_dir() {
                    Ok(MirrorCacheInsertion::AlreadyPresent)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Evict oldest-first until the store is at or under `bounds`, skipping any
    /// entry pinned by an in-flight provision. The whole pass runs under the
    /// `pins` GC lock, so concurrent passes serialize rather than each acting on
    /// the same stale over-budget snapshot and over-evicting. Each victim is
    /// claimed under the `pins` map lock — renamed aside to a `.deleting-*` slot
    /// atomically with the pin check — and removed afterwards, so the map lock is
    /// held only for fast metadata operations and a pin taken after the claim
    /// finds the entry gone (its provision then sees a cache miss and degrades)
    /// rather than racing a half-deleted mirror. If every over-budget candidate
    /// is pinned the store stays over budget until they unpin; the
    /// [`MirrorEvictionOutcome`] reports that so the caller can log it.
    /// Best-effort: a stale-leftover sweep runs first, and unreadable or racing
    /// entries are skipped.
    pub fn evict_to_bounds(
        &self,
        pins: &MirrorPins,
        bounds: MirrorCacheBounds,
    ) -> MirrorEvictionOutcome {
        // Serialize whole passes: snapshot, claim, and remove all happen under
        // this lock so a second concurrent pass sees the first's effect rather
        // than a stale snapshot. The (slow) sizing below is under this GC lock,
        // not the pins map lock, so it never blocks pinning.
        let _gc = pins.gc_lock();
        self.sweep_stale(SystemTime::now());

        let mut entries = self.scan_entries();
        let mut total_entries = entries.len();
        let mut total_bytes: u64 = entries.iter().map(|entry| entry.bytes).sum();
        if total_entries <= bounds.max_entries && total_bytes <= bounds.max_bytes {
            return MirrorEvictionOutcome::default();
        }
        // Oldest first: the entry directory's mtime is its publish time.
        entries.sort_by_key(|entry| entry.modified);

        let mut outcome = MirrorEvictionOutcome::default();
        let mut claimed: Vec<(PathBuf, u64)> = Vec::new();
        {
            let pinned = pins.pinned_lock();
            for entry in &entries {
                if total_entries <= bounds.max_entries && total_bytes <= bounds.max_bytes {
                    break;
                }
                if pinned.contains_key(&entry.slug) {
                    outcome.retained_pinned += 1;
                    continue;
                }
                let deleting = self.root.join(format!(
                    "{DELETING_PREFIX}{}",
                    uuid::Uuid::new_v4().simple()
                ));
                if std::fs::rename(&entry.path, &deleting).is_ok() {
                    claimed.push((deleting, entry.bytes));
                    total_entries -= 1;
                    total_bytes = total_bytes.saturating_sub(entry.bytes);
                }
            }
        }

        // Remove the claimed entries with the pins lock released — the rename
        // already made them invisible to lookups, so the (slow) recursive
        // delete must not block concurrent pins.
        for (path, bytes) in claimed {
            if std::fs::remove_dir_all(&path).is_ok() {
                outcome.evicted += 1;
                outcome.bytes_freed = outcome.bytes_freed.saturating_add(bytes);
            }
        }
        outcome
    }

    /// Snapshot the published entries (slug dirs holding a `mirror.git`), with
    /// each one's publish time and on-disk size. Non-entry slots
    /// (`.staging-*`, `.deleting-*`, and empty leftovers) are skipped. No lock
    /// is held: sizing walks files and must not block pinning.
    fn scan_entries(&self) -> Vec<MirrorEntryInfo> {
        let mut out = Vec::new();
        let Ok(read_dir) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for entry in read_dir.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(STAGING_PREFIX) || name.starts_with(DELETING_PREFIX) {
                continue;
            }
            let path = entry.path();
            if !path.join(MIRROR_DIR_NAME).is_dir() {
                continue;
            }
            let modified = std::fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            out.push(MirrorEntryInfo {
                slug: name.into_owned(),
                bytes: dir_size(&path),
                modified,
                path,
            });
        }
        out
    }

    /// Remove `.staging-*` / `.deleting-*` directories older than
    /// [`STALE_STAGING_AGE`] relative to `now`, leaving younger ones (which may
    /// belong to a live insert or eviction) alone. Without this, a crash after
    /// the source moved into staging but before publish — or after an eviction
    /// renamed an entry aside but before it removed it — would leave a full
    /// mirror that nothing ever reclaims. The reference time is injected so the
    /// sweep is deterministic in tests. Best-effort: unreadable or racing
    /// entries are skipped.
    fn sweep_stale(&self, now: SystemTime) {
        let Ok(read_dir) = std::fs::read_dir(&self.root) else {
            return;
        };
        for entry in read_dir.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with(STAGING_PREFIX) || name.starts_with(DELETING_PREFIX)) {
                continue;
            }
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                continue;
            }
            let aged_out = std::fs::metadata(entry.path())
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|mtime| now.duration_since(mtime).ok())
                .is_some_and(|age| age >= STALE_STAGING_AGE);
            if aged_out {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// One published cache entry, captured for an eviction pass.
struct MirrorEntryInfo {
    slug: String,
    path: PathBuf,
    modified: SystemTime,
    bytes: u64,
}

/// Total size of the regular files under `path` (recursively). Best-effort:
/// unreadable entries contribute zero rather than aborting the walk, so a racing
/// removal can only under-count, never panic.
fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    let Ok(read_dir) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            total = total.saturating_add(dir_size(&entry.path()));
        } else if let Ok(metadata) = entry.metadata() {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

/// Create a directory (and any missing parents) restricted to the owner. The
/// cache holds bare clones of possibly-private repositories, so other local
/// users must not be able to traverse into it; the explicit `set_permissions`
/// after creation defeats the process umask (which would otherwise commonly
/// leave a world-traversable 0755 directory).
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Create a single new private directory, failing if it already exists.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Recursively copy a directory tree — the cross-device fallback for staging a
/// mirror whose work dir is on a different filesystem from the cache. A bare git
/// mirror contains only regular files and directories, so symlinks are not
/// handled. `dest` is created; the source is left in place for its owner to
/// clean up. `fs::copy` preserves file modes; the published entry's privacy
/// comes from its 0700 root, not from the inner directory modes.
fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn repo(owner: &str, name: &str) -> RepoRef {
        RepoRef {
            owner: owner.to_string(),
            name: name.to_string(),
        }
    }

    fn sha(hex: &str) -> GitCommitSha {
        GitCommitSha::parse(hex).unwrap()
    }

    fn forty(seed: u8) -> String {
        format!("{seed:02x}").repeat(20)
    }

    /// Create a stand-in bare mirror (a directory carrying one marker file) for
    /// the cache to move; the cache treats it as an opaque directory, so a real
    /// git repo is unnecessary here.
    fn make_mirror(parent: &Path, marker: &str) -> PathBuf {
        let dir = parent.join(format!("src-{marker}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("HEAD"), marker.as_bytes()).unwrap();
        dir
    }

    /// The on-disk path where a stored mirror lives. The cache exposes no read
    /// API yet (the safe, eviction-pinned read lands with its consumer), so the
    /// tests assert cache state directly against the layout.
    fn stored_mirror(cache: &MirrorCache, key: &MirrorCacheKey) -> PathBuf {
        cache.root().join(key.slug()).join(MIRROR_DIR_NAME)
    }

    #[test]
    fn parse_accepts_sha1_and_sha256_and_trims_newline() {
        assert_eq!(sha(&"a".repeat(40)).as_str(), &"a".repeat(40));
        assert_eq!(sha(&"0".repeat(64)).as_str(), &"0".repeat(64));
        // `git rev-parse` appends a newline.
        assert_eq!(
            GitCommitSha::parse("0123456789abcdef0123456789abcdef01234567\n")
                .unwrap()
                .as_str(),
            "0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn parse_rejects_wrong_length_uppercase_and_non_hex() {
        for bad in [
            "a".repeat(39),
            "a".repeat(41),
            "A".repeat(40), // uppercase is not git's canonical output
            "g".repeat(40), // non-hex
            String::new(),
        ] {
            assert_eq!(
                GitCommitSha::parse(&bad),
                Err(GitCommitShaError::Invalid(bad.clone())),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn key_is_stable_case_folded_and_rev_sensitive() {
        let rev = sha(&forty(1));
        let base = MirrorCacheKey::new(&repo("Owner", "Repo"), &rev);
        // Same (repo, rev) => same slug.
        assert_eq!(base, MirrorCacheKey::new(&repo("Owner", "Repo"), &rev));
        // GitHub-equivalent casing => same slug.
        assert_eq!(base, MirrorCacheKey::new(&repo("owner", "repo"), &rev));
        // A different commit => a different slug.
        assert_ne!(
            base,
            MirrorCacheKey::new(&repo("Owner", "Repo"), &sha(&forty(2)))
        );
        // A different repo => a different slug.
        assert_ne!(base, MirrorCacheKey::new(&repo("Owner", "Other"), &rev));
        // The slug is a SHA-256 hex digest, so it is filesystem-safe.
        assert_eq!(base.slug().len(), 64);
        assert!(base.slug().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn insert_moves_the_mirror_into_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        let src = make_mirror(tmp.path(), "content");

        assert_eq!(
            cache.insert(&key, &src).unwrap(),
            MirrorCacheInsertion::Stored
        );
        // The source was moved, not copied.
        assert!(!src.exists());
        assert_eq!(
            std::fs::read(stored_mirror(&cache, &key).join("HEAD")).unwrap(),
            b"content"
        );
    }

    #[test]
    fn get_returns_a_present_mirror_and_misses_otherwise() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        assert!(cache.get(&key).is_none());

        cache
            .insert(&key, &make_mirror(tmp.path(), "content"))
            .unwrap();
        assert_eq!(cache.get(&key), Some(stored_mirror(&cache, &key)));
        // A different key still misses.
        assert!(
            cache
                .get(&MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(2))))
                .is_none()
        );
    }

    #[test]
    fn second_insert_for_same_key_dedups_and_keeps_the_original() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));

        let first = make_mirror(tmp.path(), "first");
        assert_eq!(
            cache.insert(&key, &first).unwrap(),
            MirrorCacheInsertion::Stored
        );
        let second = make_mirror(tmp.path(), "second");
        assert_eq!(
            cache.insert(&key, &second).unwrap(),
            MirrorCacheInsertion::AlreadyPresent
        );

        // The original is preserved; the losing source is left for its caller.
        assert_eq!(
            std::fs::read(stored_mirror(&cache, &key).join("HEAD")).unwrap(),
            b"first"
        );
        assert!(second.exists(), "the deduped source must be left untouched");
    }

    #[test]
    fn insert_with_missing_source_errors_and_leaves_no_poisoned_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        let missing = tmp.path().join("does-not-exist");

        assert!(cache.insert(&key, &missing).is_err());
        // No slot is left behind, so a later real insert still wins.
        assert!(!stored_mirror(&cache, &key).exists());
        let real = make_mirror(tmp.path(), "real");
        assert_eq!(
            cache.insert(&key, &real).unwrap(),
            MirrorCacheInsertion::Stored
        );
        assert!(stored_mirror(&cache, &key).exists());
    }

    #[cfg(unix)]
    #[test]
    fn insert_creates_owner_only_directories() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        let src = make_mirror(tmp.path(), "private");
        cache.insert(&key, &src).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // The mirror holds possibly-private repo objects, so the cache root and
        // each entry must be owner-only regardless of the process umask.
        assert_eq!(mode(cache.root()), 0o700);
        assert_eq!(mode(&cache.root().join(key.slug())), 0o700);
    }

    #[test]
    fn insert_heals_an_orphaned_empty_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        // Simulate a crash that left an empty slug directory with no mirror: a
        // poisoned slot that must not block this key from ever caching again.
        std::fs::create_dir_all(cache.root().join(key.slug())).unwrap();
        assert!(!stored_mirror(&cache, &key).exists());

        let src = make_mirror(tmp.path(), "healed");
        assert_eq!(
            cache.insert(&key, &src).unwrap(),
            MirrorCacheInsertion::Stored
        );
        assert_eq!(
            std::fs::read(stored_mirror(&cache, &key).join("HEAD")).unwrap(),
            b"healed"
        );
    }

    #[test]
    fn copy_dir_recursive_copies_a_nested_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("objects/pack")).unwrap();
        std::fs::write(src.join("HEAD"), b"ref: refs/heads/main").unwrap();
        std::fs::write(src.join("objects/pack/p.idx"), b"idx").unwrap();
        let dest = tmp.path().join("dest");

        copy_dir_recursive(&src, &dest).unwrap();

        assert_eq!(
            std::fs::read(dest.join("HEAD")).unwrap(),
            b"ref: refs/heads/main"
        );
        assert_eq!(
            std::fs::read(dest.join("objects/pack/p.idx")).unwrap(),
            b"idx"
        );
        // The cross-device fallback leaves the source in place for its owner.
        assert!(src.join("HEAD").exists());
    }

    #[test]
    fn insert_sweeps_only_aged_out_staging_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        // A real published entry plus a leftover staging dir holding a mirror
        // (as a crash mid-publish would leave behind).
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        cache
            .insert(&key, &make_mirror(tmp.path(), "live"))
            .unwrap();
        let staging = cache.root().join(format!("{STAGING_PREFIX}orphan"));
        std::fs::create_dir_all(staging.join(MIRROR_DIR_NAME)).unwrap();

        // A fresh staging dir might belong to a live insert, so it is kept.
        cache.sweep_stale(SystemTime::now());
        assert!(staging.exists(), "a fresh staging dir must not be swept");

        // Far enough ahead that it has aged out: now it is swept, while the
        // real entry is left untouched.
        cache.sweep_stale(SystemTime::now() + STALE_STAGING_AGE + Duration::from_secs(1));
        assert!(!staging.exists(), "an aged-out staging dir must be swept");
        assert!(
            stored_mirror(&cache, &key).exists(),
            "the real entry must survive a sweep"
        );
    }

    /// Stamp an entry directory's mtime so eviction's oldest-first ordering is
    /// deterministic: a larger `secs_ago` is older. Opening a directory
    /// read-only and `set_modified` (futimens on the fd) is allowed on Unix.
    fn age_entry(cache: &MirrorCache, key: &MirrorCacheKey, secs_ago: u64) {
        let dir = cache.root().join(key.slug());
        let when = SystemTime::now() - Duration::from_secs(secs_ago);
        std::fs::File::options()
            .read(true)
            .open(&dir)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    /// Insert a mirror whose payload is `bytes` long, so a byte-budget eviction
    /// has a known size to work with, and return its key.
    fn insert_sized(cache: &MirrorCache, parent: &Path, seed: u8, bytes: usize) -> MirrorCacheKey {
        let key = MirrorCacheKey::new(&repo("o", "n"), &sha(&forty(seed)));
        let src = parent.join(format!("src-{seed}"));
        std::fs::create_dir_all(src.join(MIRROR_DIR_NAME)).unwrap();
        std::fs::write(src.join(MIRROR_DIR_NAME).join("pack"), vec![b'x'; bytes]).unwrap();
        cache.insert(&key, &src).unwrap();
        key
    }

    #[test]
    fn evict_is_a_noop_within_bounds() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        let a = insert_sized(&cache, tmp.path(), 1, 16);
        let b = insert_sized(&cache, tmp.path(), 2, 16);

        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(8, u64::MAX));

        assert_eq!(outcome, MirrorEvictionOutcome::default());
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&b).is_some());
    }

    #[test]
    fn evict_removes_oldest_first_to_entry_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        let keys: Vec<_> = (0..4u8)
            .map(|i| insert_sized(&cache, tmp.path(), i, 16))
            .collect();
        // Oldest (index 0) .. newest (index 3).
        for (i, key) in keys.iter().enumerate() {
            age_entry(&cache, key, 100 - (i as u64) * 10);
        }

        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(2, u64::MAX));

        assert_eq!(outcome.evicted, 2);
        assert_eq!(outcome.retained_pinned, 0);
        assert!(cache.get(&keys[0]).is_none(), "oldest evicted");
        assert!(cache.get(&keys[1]).is_none(), "second-oldest evicted");
        assert!(cache.get(&keys[2]).is_some(), "newer kept");
        assert!(cache.get(&keys[3]).is_some(), "newest kept");
    }

    #[test]
    fn evict_honours_the_byte_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        // Three ~1 KiB entries; budget for ~one and a half, so two oldest go.
        let keys: Vec<_> = (0..3u8)
            .map(|i| insert_sized(&cache, tmp.path(), i, 1024))
            .collect();
        for (i, key) in keys.iter().enumerate() {
            age_entry(&cache, key, 100 - (i as u64) * 10);
        }

        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(usize::MAX, 1536));

        assert_eq!(outcome.evicted, 2);
        assert!(outcome.bytes_freed >= 2048, "freed both payloads");
        assert!(cache.get(&keys[0]).is_none());
        assert!(cache.get(&keys[1]).is_none());
        assert!(cache.get(&keys[2]).is_some(), "newest kept under budget");
    }

    #[test]
    fn evict_never_removes_a_pinned_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        let old = insert_sized(&cache, tmp.path(), 1, 16);
        let new = insert_sized(&cache, tmp.path(), 2, 16);
        age_entry(&cache, &old, 100);
        age_entry(&cache, &new, 50);

        // Pin the oldest; it is the natural first eviction victim but must be
        // kept, so the bound is met by evicting the (newer) unpinned entry.
        let guard = pins.pin(old.slug());
        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(1, u64::MAX));

        assert_eq!(outcome.retained_pinned, 1);
        assert_eq!(outcome.evicted, 1);
        assert!(cache.get(&old).is_some(), "pinned entry survives eviction");
        assert!(cache.get(&new).is_none(), "unpinned entry evicted to bound");

        // Once unpinned, a later pass can reclaim it.
        drop(guard);
        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(0, u64::MAX));
        assert_eq!(outcome.evicted, 1);
        assert!(cache.get(&old).is_none(), "evictable once unpinned");
    }

    #[test]
    fn concurrent_evictions_do_not_over_evict() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        // Six entries, distinct ages; bound to four.
        let keys: Vec<_> = (0..6u8)
            .map(|i| {
                let key = insert_sized(&cache, tmp.path(), i, 16);
                age_entry(&cache, &key, 100 - (i as u64) * 5);
                key
            })
            .collect();

        // Two passes race. The GC lock serializes them, so the second sees the
        // first's effect and stops at the bound instead of acting on a stale
        // over-budget snapshot and removing extra entries.
        let (c1, p1) = (cache.clone(), pins.clone());
        let (c2, p2) = (cache.clone(), pins.clone());
        let bounds = MirrorCacheBounds::new(4, u64::MAX);
        let h1 = std::thread::spawn(move || c1.evict_to_bounds(&p1, bounds));
        let h2 = std::thread::spawn(move || c2.evict_to_bounds(&p2, bounds));
        h1.join().unwrap();
        h2.join().unwrap();

        let remaining = keys.iter().filter(|k| cache.get(k).is_some()).count();
        assert_eq!(remaining, 4, "exactly the bound remains; no over-eviction");
    }

    #[test]
    fn pins_refcount_until_the_last_guard_drops() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let pins = MirrorPins::new();
        let key = insert_sized(&cache, tmp.path(), 1, 16);

        let g1 = pins.pin(key.slug());
        let g2 = pins.pin(key.slug());
        drop(g1);
        // One guard still held: eviction must still skip it.
        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(0, u64::MAX));
        assert_eq!(outcome.retained_pinned, 1);
        assert_eq!(outcome.evicted, 0);
        assert!(cache.get(&key).is_some());

        drop(g2);
        let outcome = cache.evict_to_bounds(&pins, MirrorCacheBounds::new(0, u64::MAX));
        assert_eq!(outcome.evicted, 1);
        assert!(cache.get(&key).is_none());
    }
}
