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
//! This stage only *retains* mirrors; it deliberately does not evict. Deleting
//! an entry safely means knowing which mirrors are pinned by an in-flight
//! provision — the same coordination the eviction-safe read side needs — so a
//! bound that races in-flight inserts and readers here would be unsound.
//! Bounding and the pinned read both land with the provisioner (this cache's
//! consumer) and the GC stage, where that coordination exists.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::agent_run::sha256_hex;
use crate::core::RepoRef;

/// Name of the bare mirror directory inside each cache entry. Matches the
/// `mirror.git` the clone planner produces, so the moved-in directory keeps a
/// familiar shape for an operator inspecting the cache.
const MIRROR_DIR_NAME: &str = "mirror.git";

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
/// clone (just a path); all state lives on disk.
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
                self.sweep_stale_staging(SystemTime::now());
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

    /// Remove `.staging-*` directories older than [`STALE_STAGING_AGE`] relative
    /// to `now`, leaving younger ones (which may belong to a live insert)
    /// alone. Without this, a crash after the source moved into staging but
    /// before publish would leave a full mirror that nothing ever reclaims. The
    /// reference time is injected so the sweep is deterministic in tests.
    /// Best-effort: unreadable or racing entries are skipped.
    fn sweep_stale_staging(&self, now: SystemTime) {
        let Ok(read_dir) = std::fs::read_dir(&self.root) else {
            return;
        };
        for entry in read_dir.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(STAGING_PREFIX)
            {
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
}
