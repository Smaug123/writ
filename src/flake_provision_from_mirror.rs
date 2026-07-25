//! Orchestrate flake-input provisioning from a retained bare mirror: look the
//! mirror up in the cache by `(repo, rev)`, materialise the flake at that
//! commit into a throwaway local clone, and admit it for the host provisioning
//! primitive to run.
//!
//! This is the host core the `/v1/nix/flake/provision` endpoint wraps; it owns
//! no HTTP, capability, or config-parsing concerns — the broker supplies the
//! tool paths, directories, and bounds. It writes no audit rows either: the
//! two-phase split it exposes ([`admit_flake_provision_from_cached_mirror`],
//! then [`AdmittedMirrorFlakeProvision::run`]) is precisely so the *shell* can
//! record the attempt between them, under the `broker_effect` guard.

use std::path::PathBuf;
use std::time::Duration;

use crate::core::RepoRef;
use crate::flake_lock::FlakeProvisionBounds;
use crate::flake_materialize::{MaterializeError, MaterializedFlake, materialize_flake_tree};
use crate::flake_provision::{
    AdmittedFlakeProvision, FlakeProvisionError, PerformedFlakeProvision, admit_flake_provision,
};
use crate::vm_git_mirror_cache::{GitCommitSha, MirrorCache, MirrorCacheKey, MirrorPins};

/// The host paths, directories, and bounds the broker supplies once for
/// provisioning flake inputs from a cached mirror.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorFlakeProvisionConfig {
    git_program: PathBuf,
    nix_program: PathBuf,
    /// Where materialised throwaway clones are created (owner-only).
    materialize_scratch_root: PathBuf,
    /// The shared content-addressed flake-input cache to provision into — the
    /// same directory the nix-cache endpoint serves local-first (FK3a).
    cache_dir: PathBuf,
    bounds: FlakeProvisionBounds,
    /// Timeout for the git materialisation step (the `nix` step is bounded by
    /// `bounds`).
    git_timeout: Duration,
}

impl MirrorFlakeProvisionConfig {
    pub fn new(
        git_program: impl Into<PathBuf>,
        nix_program: impl Into<PathBuf>,
        materialize_scratch_root: impl Into<PathBuf>,
        cache_dir: impl Into<PathBuf>,
        bounds: FlakeProvisionBounds,
        git_timeout: Duration,
    ) -> Self {
        Self {
            git_program: git_program.into(),
            nix_program: nix_program.into(),
            materialize_scratch_root: materialize_scratch_root.into(),
            cache_dir: cache_dir.into(),
            bounds,
            git_timeout,
        }
    }
}

/// The result of pre-flighting a provision-from-mirror.
#[derive(Debug)]
pub enum MirrorFlakeProvisionAdmission {
    /// The flake was materialised and its committed lock admitted: the run may
    /// now be recorded and performed.
    Admitted(AdmittedMirrorFlakeProvision),
    /// No mirror is retained for this `(repo, rev)` — a cache miss. Nothing was
    /// fetched and nothing is worth auditing; the caller decides how to surface
    /// it (e.g. the guest proceeds without the optimisation).
    MirrorNotCached,
}

/// An admitted provisioning run plus the materialised checkout it reads. The
/// checkout is a throwaway local clone whose guard must outlive the run, so it
/// is held here and dropped when [`run`](Self::run) returns.
#[derive(Debug)]
pub struct AdmittedMirrorFlakeProvision {
    /// Held for its `Drop`: removes the materialised checkout.
    _tree: MaterializedFlake,
    admitted: AdmittedFlakeProvision,
}

impl AdmittedMirrorFlakeProvision {
    /// What the run will do, for the caller's audit request row.
    pub fn admitted(&self) -> &AdmittedFlakeProvision {
        &self.admitted
    }

    /// Run `nix flake archive` against the materialised checkout, then remove
    /// it. Every exit is a truthful [`PerformedFlakeProvision`] for the caller
    /// to record.
    pub async fn run(self) -> PerformedFlakeProvision {
        self.admitted.run().await
        // `self._tree` drops here, removing the materialised checkout.
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MirrorFlakeProvisionError {
    #[error(transparent)]
    Materialize(#[from] MaterializeError),
    #[error(transparent)]
    Provision(#[from] FlakeProvisionError),
}

/// Pre-flight provisioning the locked flake inputs of `repo` at `rev`, reusing
/// the bare mirror retained for `(repo, rev)`. Returns
/// [`MirrorFlakeProvisionAdmission::MirrorNotCached`] when no mirror is
/// retained; otherwise materialises the flake into a throwaway clone and admits
/// its committed lock. Nothing here is auditable: a cache miss fetched nothing,
/// a materialise failure reached no network, and a refused lock is a property of
/// the repository. The audited egress starts only in
/// [`AdmittedMirrorFlakeProvision::run`], which the caller records around.
///
/// `pins` guards against the clone handler's opportunistic eviction: the
/// entry's slug is pinned across the cache lookup and the `git clone --local`
/// materialise, so GC cannot remove the mirror mid-clone. The pin is released
/// once the tree is materialised — it is then independent of the mirror — so the
/// longer `nix flake archive` step does not keep the entry from being reclaimed.
pub async fn admit_flake_provision_from_cached_mirror(
    config: &MirrorFlakeProvisionConfig,
    cache: &MirrorCache,
    pins: &MirrorPins,
    repo: &RepoRef,
    rev: &GitCommitSha,
) -> Result<MirrorFlakeProvisionAdmission, MirrorFlakeProvisionError> {
    let key = MirrorCacheKey::new(repo, rev);
    let tree = {
        // Hold the pin only across lookup + materialise. A pin taken here makes
        // a concurrent eviction skip this slug; if eviction already claimed it,
        // the lookup misses and we report a cache miss rather than racing.
        let _pin = pins.pin(key.slug());
        let Some(mirror) = cache.get(&key) else {
            return Ok(MirrorFlakeProvisionAdmission::MirrorNotCached);
        };
        materialize_flake_tree(
            &config.git_program,
            &mirror,
            rev,
            &config.materialize_scratch_root,
            config.git_timeout,
        )
        .await?
    };
    let admitted = admit_flake_provision(
        &config.nix_program,
        tree.path(),
        &config.cache_dir,
        config.bounds,
    )
    .await?;
    Ok(MirrorFlakeProvisionAdmission::Admitted(
        AdmittedMirrorFlakeProvision {
            _tree: tree,
            admitted,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::flake_fixtures::{fake_nix_archiving, no_input_flake_mirror, tool_on_path};

    fn bounds() -> FlakeProvisionBounds {
        FlakeProvisionBounds::new(64, 1 << 30, Duration::from_secs(120)).unwrap()
    }

    fn config(
        git_program: PathBuf,
        nix_program: PathBuf,
        tmp: &Path,
    ) -> MirrorFlakeProvisionConfig {
        MirrorFlakeProvisionConfig::new(
            git_program,
            nix_program,
            tmp.join("materialize"),
            tmp.join("flake-input-cache"),
            bounds(),
            Duration::from_secs(120),
        )
    }

    fn repo() -> RepoRef {
        RepoRef {
            owner: "o".into(),
            name: "n".into(),
        }
    }

    #[tokio::test]
    async fn returns_not_cached_when_no_mirror_is_retained() {
        // No mirror is ever inserted, so the cache miss short-circuits before
        // any git/nix work — this path needs neither tool.
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let cfg = config(PathBuf::from("git"), PathBuf::from("nix"), tmp.path());
        let rev = GitCommitSha::parse(&"a".repeat(40)).unwrap();

        let admission = admit_flake_provision_from_cached_mirror(
            &cfg,
            &cache,
            &MirrorPins::new(),
            &repo(),
            &rev,
        )
        .await
        .unwrap();

        assert!(matches!(
            admission,
            MirrorFlakeProvisionAdmission::MirrorNotCached
        ));
    }

    /// The admission describes what the run will do — the fields the caller's
    /// audit request row is built from — before any `nix` runs.
    #[tokio::test]
    async fn admission_describes_the_run_it_has_not_yet_performed() {
        let Some(git_program) = tool_on_path("git") else {
            eprintln!("skipping: git must be on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let (mirror_src, rev) = no_input_flake_mirror(&git_program, tmp.path());
        let cache = MirrorCache::new(tmp.path().join("cache"));
        cache
            .insert(&MirrorCacheKey::new(&repo(), &rev), &mirror_src)
            .unwrap();
        let cfg = config(git_program, fake_nix_archiving(tmp.path()), tmp.path());

        let admission = admit_flake_provision_from_cached_mirror(
            &cfg,
            &cache,
            &MirrorPins::new(),
            &repo(),
            &rev,
        )
        .await
        .unwrap();

        let MirrorFlakeProvisionAdmission::Admitted(admitted) = admission else {
            panic!("the mirror was just cached");
        };
        let plan = admitted.admitted();
        assert_eq!(plan.input_count(), 0, "the fixture lock declares no inputs");
        assert_eq!(plan.cache_dir(), tmp.path().join("flake-input-cache"));
        assert!(
            plan.flake_dir().starts_with(tmp.path().join("materialize")),
            "the run reads the materialised checkout, got {}",
            plan.flake_dir().display()
        );
        // The materialised checkout exists while the admission is held, and is
        // removed when the run finishes with it.
        let flake_dir = plan.flake_dir().to_path_buf();
        assert!(flake_dir.is_dir());
        let performed = admitted.run().await;
        assert!(performed.into_result().is_ok());
        assert!(
            !flake_dir.exists(),
            "the throwaway checkout must be cleaned up"
        );
    }

    #[tokio::test]
    async fn provisions_the_inputs_of_a_cached_no_input_flake() {
        let (Some(git_program), Some(nix_program)) = (tool_on_path("git"), tool_on_path("nix"))
        else {
            eprintln!("skipping: git and nix must both be on PATH");
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let (mirror_src, rev) = no_input_flake_mirror(&git_program, tmp.path());

        // Retain the bare mirror under its (repo, rev) key, as a clone would.
        let cache = MirrorCache::new(tmp.path().join("cache"));
        cache
            .insert(&MirrorCacheKey::new(&repo(), &rev), &mirror_src)
            .unwrap();

        let cfg = config(git_program, nix_program, tmp.path());

        let admission = admit_flake_provision_from_cached_mirror(
            &cfg,
            &cache,
            &MirrorPins::new(),
            &repo(),
            &rev,
        )
        .await
        .unwrap();

        let MirrorFlakeProvisionAdmission::Admitted(admitted) = admission else {
            panic!("the mirror was just cached");
        };
        let report = admitted
            .run()
            .await
            .into_result()
            .expect("provisioning a cached no-input flake should succeed");
        assert_eq!(report.input_count(), 0);
        assert!(
            report.archived_path_count() >= 1,
            "the flake's own source path should be archived, got {}",
            report.archived_path_count()
        );
    }
}
