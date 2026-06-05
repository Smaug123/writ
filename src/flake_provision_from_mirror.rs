//! Orchestrate flake-input provisioning from a retained bare mirror: look the
//! mirror up in the cache by `(repo, rev)`, materialise the flake at that
//! commit into a throwaway local clone, and run the host provisioning primitive
//! against it.
//!
//! This is the host core the `/v1/nix/flake/provision` endpoint wraps; it owns
//! no HTTP, capability, or config-parsing concerns — the broker supplies the
//! tool paths, directories, and bounds, plus the open audit session.

use std::path::PathBuf;
use std::time::Duration;

use crate::audit::AuditLog;
use crate::core::{RepoRef, SessionId};
use crate::flake_lock::FlakeProvisionBounds;
use crate::flake_materialize::{MaterializeError, materialize_flake_tree};
use crate::flake_provision::{FlakeProvisionError, FlakeProvisionReport, provision_flake_inputs};
use crate::vm_git_mirror_cache::{GitCommitSha, MirrorCache, MirrorCacheKey};

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

/// The result of a provision-from-mirror attempt.
#[derive(Debug)]
pub enum MirrorFlakeProvisionOutcome {
    /// The flake's locked inputs were provisioned into the cache.
    Provisioned(FlakeProvisionReport),
    /// No mirror is retained for this `(repo, rev)` — a cache miss. The caller
    /// decides how to surface it (e.g. the guest proceeds without the
    /// optimisation, or reports that provisioning was unavailable).
    MirrorNotCached,
}

#[derive(Debug, thiserror::Error)]
pub enum MirrorFlakeProvisionError {
    #[error(transparent)]
    Materialize(#[from] MaterializeError),
    #[error(transparent)]
    Provision(#[from] FlakeProvisionError),
}

/// Provision the locked flake inputs of `repo` at `rev`, reusing the bare
/// mirror retained for `(repo, rev)`. Returns
/// [`MirrorFlakeProvisionOutcome::MirrorNotCached`] when no mirror is retained;
/// otherwise materialises the flake into a throwaway clone and runs the host
/// provisioning primitive against it. The materialised clone is always cleaned
/// up before returning (its guard is dropped here), whatever the outcome.
pub async fn provision_flake_from_cached_mirror(
    config: &MirrorFlakeProvisionConfig,
    cache: &MirrorCache,
    repo: &RepoRef,
    rev: &GitCommitSha,
    audit: &AuditLog,
    session_id: SessionId,
) -> Result<MirrorFlakeProvisionOutcome, MirrorFlakeProvisionError> {
    let key = MirrorCacheKey::new(repo, rev);
    let Some(mirror) = cache.get(&key) else {
        return Ok(MirrorFlakeProvisionOutcome::MirrorNotCached);
    };
    let flake = materialize_flake_tree(
        &config.git_program,
        &mirror,
        rev,
        &config.materialize_scratch_root,
        config.git_timeout,
    )
    .await?;
    let report = provision_flake_inputs(
        &config.nix_program,
        flake.path(),
        &config.cache_dir,
        config.bounds,
        audit,
        session_id,
    )
    .await?;
    Ok(MirrorFlakeProvisionOutcome::Provisioned(report))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Stdio;

    use super::*;
    use crate::core::{SessionRecord, UnixMillis};

    fn tool_on_path(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    }

    fn git(program: &Path, args: &[&str], cwd: &Path) {
        let status = std::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn git_stdout(program: &Path, args: &[&str], cwd: &Path) -> String {
        let out = std::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Build a bare mirror of a repo whose committed flake declares no inputs —
    /// the only network-free provisioning fixture, since the classifier rejects
    /// local `path`/`file://` inputs. Returns `(bare_mirror_dir, rev)`.
    fn no_input_flake_mirror(git_program: &Path, root: &Path) -> (PathBuf, GitCommitSha) {
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(git_program, &["init", "-q", "-b", "main"], &repo);
        std::fs::write(
            repo.join("flake.nix"),
            "{\n  description = \"fixture\";\n  outputs = { self }: { ok = true; };\n}\n",
        )
        .unwrap();
        std::fs::write(
            repo.join("flake.lock"),
            r#"{"nodes":{"root":{}},"root":"root","version":7}"#,
        )
        .unwrap();
        git(git_program, &["add", "."], &repo);
        git(git_program, &["commit", "-qm", "flake"], &repo);
        let rev = GitCommitSha::parse(&git_stdout(git_program, &["rev-parse", "HEAD"], &repo))
            .expect("rev-parse must yield a commit hash");
        let mirror = root.join("mirror.git");
        git(
            git_program,
            &[
                "clone",
                "-q",
                "--mirror",
                repo.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
            root,
        );
        (mirror, rev)
    }

    fn open_session(audit: &AuditLog) -> SessionId {
        let session_id = SessionId::new();
        audit
            .open_session(&SessionRecord {
                session_id,
                label: Some("fk3c-test".into()),
                agent_kind: None,
                agent_model: None,
                opened_at: UnixMillis::from_millis(1_700_000_000),
                closed_at: None,
            })
            .unwrap();
        session_id
    }

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

    #[tokio::test]
    async fn returns_not_cached_when_no_mirror_is_retained() {
        // No mirror is ever inserted, so the cache miss short-circuits before
        // any git/nix work — this path needs neither tool.
        let tmp = tempfile::tempdir().unwrap();
        let cache = MirrorCache::new(tmp.path().join("cache"));
        let cfg = config(PathBuf::from("git"), PathBuf::from("nix"), tmp.path());
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = open_session(&audit);
        let repo = RepoRef {
            owner: "o".into(),
            name: "n".into(),
        };
        let rev = GitCommitSha::parse(&"a".repeat(40)).unwrap();

        let outcome =
            provision_flake_from_cached_mirror(&cfg, &cache, &repo, &rev, &audit, session_id)
                .await
                .unwrap();

        assert!(matches!(
            outcome,
            MirrorFlakeProvisionOutcome::MirrorNotCached
        ));
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
        let repo = RepoRef {
            owner: "o".into(),
            name: "n".into(),
        };

        // Retain the bare mirror under its (repo, rev) key, as a clone would.
        let cache = MirrorCache::new(tmp.path().join("cache"));
        cache
            .insert(&MirrorCacheKey::new(&repo, &rev), &mirror_src)
            .unwrap();

        let cfg = config(git_program, nix_program, tmp.path());
        let audit = AuditLog::open_in_memory().unwrap();
        let session_id = open_session(&audit);

        let outcome =
            provision_flake_from_cached_mirror(&cfg, &cache, &repo, &rev, &audit, session_id)
                .await
                .unwrap();

        let report = match outcome {
            MirrorFlakeProvisionOutcome::Provisioned(report) => report,
            MirrorFlakeProvisionOutcome::MirrorNotCached => panic!("the mirror was just cached"),
        };
        assert_eq!(report.input_count(), 0);
        assert!(
            report.archived_path_count() >= 1,
            "the flake's own source path should be archived, got {}",
            report.archived_path_count()
        );
        // The provision was audited against the session.
        let entries = audit
            .list_flake_provision_requests_for_session(session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_id, report.request_id());
    }
}
