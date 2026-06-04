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
//! directory and publishes it with a single `rename`. The cache is the
//! imperative shell; [`plan_eviction`] is the pure core that decides what the
//! bound sheds.
//!
//! Retaining mirrors is all this stage does. The read/lease side that hands a
//! *pinned* mirror to the provisioner — and so must be safe against concurrent
//! eviction (a bare `get` returning a path the bound could delete out from
//! under the caller is not) — lands with that consumer in a later stage.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::agent_run::sha256_hex;
use crate::core::RepoRef;

/// Name of the bare mirror directory inside each cache entry. Matches the
/// `mirror.git` the clone planner produces, so the moved-in directory keeps a
/// familiar shape for an operator inspecting the cache.
const MIRROR_DIR_NAME: &str = "mirror.git";

/// A zero-byte sentinel whose mtime records when an entry was last inserted or
/// looked up. The directory's own mtime is not portable enough to rely on for
/// LRU ordering, so the cache stamps this file explicitly.
const LAST_USED_FILE: &str = ".last_used";

/// Prefix of the private temporary directory an in-flight publish stages into.
const STAGING_PREFIX: &str = ".staging-";

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

/// One cache entry as seen by the eviction planner: its directory name and when
/// it was last used. Kept separate from the on-disk representation so the
/// planner is a pure function over plain data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorCacheEntry {
    pub slug: String,
    pub last_used: SystemTime,
}

/// Choose which entries to evict so that at most `max_entries` remain, oldest
/// `last_used` first. Pure and total: ties are broken by slug so the result is
/// deterministic, and nothing is evicted while the cache is at or under the
/// bound.
pub fn plan_eviction(entries: &[MirrorCacheEntry], max_entries: NonZeroUsize) -> Vec<String> {
    let max = max_entries.get();
    if entries.len() <= max {
        return Vec::new();
    }
    let mut ordered: Vec<&MirrorCacheEntry> = entries.iter().collect();
    // Oldest first; slug breaks last_used ties for a deterministic victim set.
    ordered.sort_by(|a, b| {
        a.last_used
            .cmp(&b.last_used)
            .then_with(|| a.slug.cmp(&b.slug))
    });
    let evict_count = entries.len() - max;
    ordered
        .into_iter()
        .take(evict_count)
        .map(|entry| entry.slug.clone())
        .collect()
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

/// A `(repo, rev)`-keyed cache of bare mirrors rooted at a directory. Cheap to
/// clone (a path plus a bound); all state lives on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorCache {
    root: PathBuf,
    max_entries: NonZeroUsize,
}

impl MirrorCache {
    pub fn new(root: impl Into<PathBuf>, max_entries: NonZeroUsize) -> Self {
        Self {
            root: root.into(),
            max_entries,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Publish a freshly-cloned bare mirror into the cache under `key`. A
    /// *complete* entry is staged in a private temp directory and published with
    /// a single atomic `rename`, so concurrent clones of the same `(repo, rev)`
    /// resolve to one winner and a crash or lost race can only leave a
    /// discardable `.staging-*` directory — never a half-built slot that would
    /// shadow the key while `get` returns `None`. Losers (and the fast-path
    /// case where a complete entry already exists) see
    /// [`MirrorCacheInsertion::AlreadyPresent`]. After a successful store the
    /// bound is enforced best-effort.
    ///
    /// `src_mirror` is moved, and on the race-loser path may be consumed even
    /// though the existing entry is kept — so the caller must clean up its own
    /// work directory regardless of the outcome rather than rely on
    /// `src_mirror` surviving. Requires `src_mirror` to be on the same
    /// filesystem as the cache root so both moves are atomic renames (the
    /// default puts both under the broker work root).
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
            let _ = self.touch(&entry);
            return Ok(MirrorCacheInsertion::AlreadyPresent);
        }
        // Stage the whole entry, then publish atomically.
        let staging = self
            .root
            .join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4().simple()));
        create_private_dir(&staging)?;
        if let Err(err) = std::fs::rename(src_mirror, staging.join(MIRROR_DIR_NAME)) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(err);
        }
        // `rename` onto a missing or empty `entry` succeeds (publishing, or
        // healing a leftover empty slot from an earlier crash); onto a populated
        // `entry` it fails, so a concurrent winner is preserved.
        match std::fs::rename(&staging, &entry) {
            Ok(()) => {
                // Stamp last-used as of publication, not staging creation: a
                // slow insert must not hand `enforce_bound` a stale timestamp
                // that makes the just-published entry look like the oldest and
                // get evicted out from under this `Stored` return.
                let _ = self.touch(&entry);
                self.enforce_bound();
                Ok(MirrorCacheInsertion::Stored)
            }
            Err(err) => {
                let _ = std::fs::remove_dir_all(&staging);
                if entry.join(MIRROR_DIR_NAME).is_dir() {
                    let _ = self.touch(&entry);
                    Ok(MirrorCacheInsertion::AlreadyPresent)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Stamp the entry's last-used sentinel with the current time by recreating
    /// it (an `O_CREAT|O_TRUNC` open updates the mtime).
    fn touch(&self, entry: &Path) -> std::io::Result<()> {
        std::fs::File::create(entry.join(LAST_USED_FILE)).map(drop)
    }

    /// Evict the oldest entries until the cache is within its bound. Best-effort
    /// and race-tolerant: a victim another task already removed is ignored, and
    /// because eviction targets the oldest entries a just-inserted mirror is
    /// never the victim. The bound may be transiently exceeded by the number of
    /// in-flight concurrent inserts before it settles.
    fn enforce_bound(&self) {
        // Sweep crash leftovers first: a `.staging-*` directory holds a full
        // mirror but is invisible to `scan`/the bound, so without this repeated
        // interrupted inserts could grow the cache without limit.
        self.sweep_stale_staging(SystemTime::now());
        let Ok(entries) = self.scan() else {
            return;
        };
        for slug in plan_eviction(&entries, self.max_entries) {
            let _ = std::fs::remove_dir_all(self.root.join(slug));
        }
    }

    /// Remove `.staging-*` directories older than [`STALE_STAGING_AGE`] relative
    /// to `now`, leaving younger ones (which may belong to a live insert)
    /// alone. The reference time is injected so the sweep is deterministic in
    /// tests. Best-effort: unreadable or racing entries are skipped.
    fn sweep_stale_staging(&self, now: SystemTime) {
        let Ok(read_dir) = std::fs::read_dir(&self.root) else {
            return;
        };
        for entry in read_dir.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(STAGING_PREFIX) {
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

    /// List the current cache entries (immediate subdirectories) with their
    /// last-used times.
    fn scan(&self) -> std::io::Result<Vec<MirrorCacheEntry>> {
        let mut entries = Vec::new();
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(read_dir) => read_dir,
            // No root yet => nothing cached.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
            Err(err) => return Err(err),
        };
        for entry in read_dir {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let slug = entry.file_name().to_string_lossy().into_owned();
            // Skip in-flight `.staging-*` publishes (and any other dotfile): a
            // real entry slug is a 64-char hex digest and never starts with `.`.
            if slug.starts_with('.') {
                continue;
            }
            let last_used = self.last_used_of(&entry.path());
            entries.push(MirrorCacheEntry { slug, last_used });
        }
        Ok(entries)
    }

    /// Read an entry's last-used time, falling back to the directory's own mtime
    /// and finally the epoch (so a sentinel-less entry sorts as oldest and is
    /// shed first rather than lingering forever).
    fn last_used_of(&self, entry: &Path) -> SystemTime {
        std::fs::metadata(entry.join(LAST_USED_FILE))
            .and_then(|metadata| metadata.modified())
            .or_else(|_| std::fs::metadata(entry).and_then(|metadata| metadata.modified()))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use proptest::prelude::*;

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

    /// The on-disk path where a stored mirror lives. FK3b ships no read API
    /// (the safe, eviction-pinned read lands with its consumer), so the tests
    /// assert cache state directly against the layout.
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
        assert_ne!(base, MirrorCacheKey::new(&repo("Owner", "Repo"), &sha(&forty(2))));
        // A different repo => a different slug.
        assert_ne!(base, MirrorCacheKey::new(&repo("Owner", "Other"), &rev));
        // The slug is a SHA-256 hex digest, so it is filesystem-safe.
        assert_eq!(base.slug().len(), 64);
        assert!(base.slug().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn insert_moves_the_mirror_into_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
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
    fn second_insert_for_same_key_dedups_and_keeps_the_original() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
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
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
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
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
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
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
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
    fn insert_enforces_the_entry_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let max = NonZeroUsize::new(3).unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"), max);

        // Insert well past the bound with distinct keys.
        for seed in 0u8..8 {
            let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(seed)));
            let src = make_mirror(tmp.path(), &format!("m{seed}"));
            cache.insert(&key, &src).unwrap();
        }

        let count = std::fs::read_dir(cache.root())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_type().unwrap().is_dir())
            .count();
        assert_eq!(count, max.get(), "the bound must cap retained entries");
    }

    #[test]
    fn sweep_removes_only_aged_out_staging_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"), NonZeroUsize::new(4).unwrap());
        // A real published entry plus a leftover staging dir holding a mirror
        // (as a crash mid-publish would leave behind).
        let key = MirrorCacheKey::new(&repo("o", "r"), &sha(&forty(1)));
        cache.insert(&key, &make_mirror(tmp.path(), "live")).unwrap();
        let staging = cache.root().join(format!("{STAGING_PREFIX}orphan"));
        std::fs::create_dir_all(staging.join(MIRROR_DIR_NAME)).unwrap();

        // A fresh staging dir might belong to a live insert, so it is kept.
        cache.sweep_stale_staging(SystemTime::now());
        assert!(staging.exists(), "a fresh staging dir must not be swept");

        // Far enough ahead that it has aged out: now it is swept, while the
        // real entry is left untouched.
        cache.sweep_stale_staging(SystemTime::now() + STALE_STAGING_AGE + Duration::from_secs(1));
        assert!(!staging.exists(), "an aged-out staging dir must be swept");
        assert!(
            stored_mirror(&cache, &key).exists(),
            "the real entry must survive a sweep"
        );
    }

    #[test]
    fn under_bound_evicts_nothing() {
        let entries = vec![
            MirrorCacheEntry {
                slug: "a".into(),
                last_used: SystemTime::UNIX_EPOCH,
            },
            MirrorCacheEntry {
                slug: "b".into(),
                last_used: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            },
        ];
        assert!(plan_eviction(&entries, NonZeroUsize::new(2).unwrap()).is_empty());
        assert!(plan_eviction(&entries, NonZeroUsize::new(5).unwrap()).is_empty());
    }

    #[test]
    fn eviction_sheds_the_oldest_first() {
        let entries = vec![
            MirrorCacheEntry {
                slug: "newest".into(),
                last_used: SystemTime::UNIX_EPOCH + Duration::from_secs(30),
            },
            MirrorCacheEntry {
                slug: "oldest".into(),
                last_used: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            },
            MirrorCacheEntry {
                slug: "middle".into(),
                last_used: SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            },
        ];
        assert_eq!(
            plan_eviction(&entries, NonZeroUsize::new(1).unwrap()),
            vec!["oldest".to_string(), "middle".to_string()]
        );
    }

    proptest! {
        /// The planner always lands the cache within its bound, evicts exactly
        /// the overflow, and never sheds a newer entry while keeping an older
        /// one (the LRU invariant, ties broken deterministically by slug).
        #[test]
        fn eviction_is_bounded_and_oldest_first(
            raw in proptest::collection::vec((0u64..1000, "[a-z0-9]{1,10}"), 0..40),
            max in 1usize..15,
        ) {
            // Distinct slugs model distinct cache directories.
            let mut seen = HashSet::new();
            let entries: Vec<MirrorCacheEntry> = raw
                .into_iter()
                .filter(|(_, slug)| seen.insert(slug.clone()))
                .map(|(secs, slug)| MirrorCacheEntry {
                    slug,
                    last_used: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
                })
                .collect();
            let max_nz = NonZeroUsize::new(max).unwrap();

            let evicted = plan_eviction(&entries, max_nz);
            let survivors = entries.len() - evicted.len();

            prop_assert_eq!(evicted.len(), entries.len().saturating_sub(max));
            prop_assert!(survivors <= max);
            if entries.len() <= max {
                prop_assert!(evicted.is_empty());
            }

            // No evicted entry is newer than any survivor, under the same total
            // order the planner uses (last_used, then slug).
            let evicted_set: HashSet<&String> = evicted.iter().collect();
            let order = |e: &MirrorCacheEntry| (e.last_used, e.slug.clone());
            let newest_evicted = entries
                .iter()
                .filter(|e| evicted_set.contains(&e.slug))
                .map(order)
                .max();
            let oldest_survivor = entries
                .iter()
                .filter(|e| !evicted_set.contains(&e.slug))
                .map(order)
                .min();
            if let (Some(evicted_max), Some(survivor_min)) = (newest_evicted, oldest_survivor) {
                prop_assert!(
                    evicted_max <= survivor_min,
                    "evicted {evicted_max:?} should not be newer than survivor {survivor_min:?}"
                );
            }
        }
    }
}
