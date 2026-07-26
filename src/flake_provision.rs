//! Host edge for flake-input provisioning (the imperative shell over the
//! [`crate::flake_lock`] functional core).
//!
//! Given a checked-out flake and a target binary cache, this runs `nix flake
//! archive` on the host to copy the repo's committed, locked inputs into the
//! cache the no-egress guest later substitutes from. The core decides
//! *whether* a lock may be provisioned (it is the trust gate — see
//! `flake_lock`); this module *does* the provisioning and audits it.
//!
//! Shape: pre-flight is pure-ish and fails closed *before* any audit row or
//! egress (read the lock, parse it, build the [`FlakeProvisionPlan`] — a
//! malformed/unpinned/non-public/local/SSRF lock is refused here). Only once
//! the plan is admissible does the audited run begin: a
//! `flake_provision_request` row is written, then `nix` is run under the
//! shared `process_supervisor` (timeout + process-group SIGKILL), the
//! resulting cache is measured and bounds-checked fail-closed, and a
//! `flake_provision_outcome` row is appended. nix archives into a *staging*
//! cache, never the guest-visible `cache_dir`; only a verified, within-budget
//! archive is merged into `cache_dir`. The cache is the broker's *shared*
//! content-addressed binary cache, so the merge is an additive, idempotent
//! union — it preserves other repos' entries, publishes NAR payloads before
//! the narinfos that reference them, and never removes anything. So a crash,
//! timeout, over-budget archive, or audit-write failure can never leave
//! *untrusted* or *inconsistent* content there: an interrupted merge leaves
//! only the verified, self-certifying entries it managed to publish (never a
//! narinfo without its NAR), which is exactly what a content-addressed cache
//! tolerates and what keeps the merge safe under concurrent provisioners.
//!
//! The host fetch runs *credential-free*: the environment is cleared to only
//! the non-credential plumbing nix needs (PATH, daemon socket, CA certs), with
//! a fresh `HOME`, so the host's user-level `nix.conf` / `~/.netrc` / git
//! credentials cannot reach the fetch. This is what makes the classifier's "a
//! private repo fails at fetch" assumption hold — without it, an untrusted lock
//! naming a private `github:` input could make the broker cache private source
//! for the guest using the operator's tokens.
//!
//! Three residuals are out of v1 scope, documented rather than papered over;
//! the plan defers the stronger host-fetch isolation (a disposable egress-VM
//! provisioner) that would close the first two:
//!
//!   1. A system-level `/etc/nix/nix.conf` `access-tokens` on a host where the
//!      broker is *not* a trusted nix user cannot be overridden by the client.
//!   2. nix runs against the host's default store/daemon, so a private input
//!      whose fixed-output source is *already realised* in that store can be
//!      archived without a fetch — bypassing the "fails at fetch" assumption. A
//!      fresh per-run store would close this.
//!   3. The static classifier rejects *literal* internal/loopback hosts, but an
//!      allowed *domain* can DNS-resolve to an internal address; nix runs on the
//!      host with no egress filter, so it would connect before any hash check.
//!      Fetch-time public-IP enforcement (a network sandbox/proxy) is needed.
//!
//! Until the egress-VM provisioner lands, run the broker as a non-trusted nix
//! user, without system credentials, on a host whose outbound network it is
//! acceptable for the broker to reach.

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::process::Command;

use crate::audit::FlakeProvisionResult;
use crate::core::RequestId;
use crate::flake_lock::{
    FlakeLock, FlakeLockError, FlakeProvisionBounds, FlakeProvisionPlan, FlakeProvisionPlanError,
};
use crate::process_supervisor::{self, StderrMode, StdoutMode, SupervisedOutcome};

const FLAKE_LOCK_FILE: &str = "flake.lock";

/// What a successful provisioning landed in the cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeProvisionReport {
    request_id: RequestId,
    input_count: usize,
    archived_path_count: u64,
    archived_bytes: u64,
}

impl FlakeProvisionReport {
    /// The audit `request_id` for this provisioning, so a caller can correlate
    /// the returned report with the `flake_provision_*` audit rows.
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Inputs the committed lock declared (from the functional core).
    pub fn input_count(&self) -> usize {
        self.input_count
    }

    /// Store paths the archive landed in the cache.
    pub fn archived_path_count(&self) -> u64 {
        self.archived_path_count
    }

    /// Total on-disk size of the cache after the archive.
    pub fn archived_bytes(&self) -> u64 {
        self.archived_bytes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlakeProvisionError {
    #[error("could not read flake lock {path}: {source}")]
    ReadLock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    ParseLock(FlakeLockError),
    #[error(transparent)]
    Plan(FlakeProvisionPlanError),
    #[error("could not resolve nix program: {0}")]
    ResolveNix(String),
    #[error("could not create provisioning scratch: {source}")]
    Scratch { source: std::io::Error },
    #[error("could not publish provisioning cache to {path}: {source}")]
    PublishCache {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("nix flake archive could not be run: {0}")]
    Supervise(String),
    #[error("nix flake archive timed out after {timeout:?}")]
    TimedOut { timeout: Duration },
    #[error("nix flake archive failed with {status}")]
    NixFailed { status: ExitStatus },
    #[error("could not scan provisioning cache {path}: {source}")]
    ScanCache {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "archived {archived_bytes} bytes exceeds the configured maximum {max_total_bytes}; \
         the over-budget cache is not provisioned (fail-closed)"
    )]
    OverBudget {
        archived_bytes: u64,
        max_total_bytes: u64,
    },
}

/// A provisioning run that passed pre-flight: the committed lock was read,
/// parsed, and planned (so the classifier has already refused anything local,
/// private, credential-requiring, or unpinned), and `nix` resolved. Holding one
/// is the proof that the run is *admissible* — which is exactly the point at
/// which the attempted host egress becomes worth auditing.
///
/// It carries everything the audit request row describes
/// ([`request_id`](Self::request_id), [`flake_dir`](Self::flake_dir),
/// [`cache_dir`](Self::cache_dir), [`input_count`](Self::input_count)), so the
/// shell can record the attempt *before* [`run`](Self::run) performs it. This
/// module writes no audit rows itself: it returns descriptions of what happened
/// and the caller records them (today, the `broker_effect` driver, whose guard
/// makes the pair structural).
#[derive(Debug)]
pub struct AdmittedFlakeProvision {
    request_id: RequestId,
    /// The resolved, canonicalised `nix` binary.
    program: PathBuf,
    plan: FlakeProvisionPlan,
}

impl AdmittedFlakeProvision {
    /// The id correlating the audit rows with the returned report.
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub fn flake_dir(&self) -> &Path {
        self.plan.flake_dir()
    }

    pub fn cache_dir(&self) -> &Path {
        self.plan.cache_dir()
    }

    /// Inputs the committed lock declared (from the functional core).
    pub fn input_count(&self) -> usize {
        self.plan.input_count()
    }
}

/// The observed result of an admitted run. Every exit is describable as a
/// truthful audit outcome — success carries the archive metrics, and every
/// failure carries the message it is recorded under — so, unlike git-push
/// staging, this effect never needs to abandon its audit guard.
#[derive(Debug)]
pub enum PerformedFlakeProvision {
    Provisioned(FlakeProvisionReport),
    Failed {
        /// The message recorded in the audit outcome row. It is *not* the
        /// error's `Display`: the row deliberately records what the run
        /// observed (`nix flake archive exited with …`) rather than the
        /// caller-facing wording.
        message: String,
        error: FlakeProvisionError,
    },
}

impl PerformedFlakeProvision {
    /// The audit outcome row this run truthfully records.
    pub fn audit_result(&self) -> FlakeProvisionResult<'_> {
        match self {
            Self::Provisioned(report) => FlakeProvisionResult::Success {
                archived_path_count: report.archived_path_count,
                archived_bytes: report.archived_bytes,
            },
            Self::Failed { message, .. } => FlakeProvisionResult::Failure { error: message },
        }
    }

    /// Collapse to the ordinary result, discarding the audit wording.
    pub fn into_result(self) -> Result<FlakeProvisionReport, FlakeProvisionError> {
        match self {
            Self::Provisioned(report) => Ok(report),
            Self::Failed { error, .. } => Err(error),
        }
    }

    fn failed(message: String, error: FlakeProvisionError) -> Self {
        Self::Failed { message, error }
    }
}

/// Pre-flight the committed, locked flake checked out at `flake_dir` against
/// the binary cache at `cache_dir`, admitting it for a `nix flake archive` run.
///
/// Pre-flight (read lock → parse → plan → resolve `nix`) fails closed before any
/// egress *and before the caller has anything to audit*. A refused lock is
/// returned as [`FlakeProvisionError::ParseLock`] / [`FlakeProvisionError::Plan`]
/// — no fetch was attempted, so there is no attempt to record, and the caller
/// decides how to surface a non-provisionable repo. Only the returned
/// [`AdmittedFlakeProvision`] can be [`run`](AdmittedFlakeProvision::run), so the
/// audited egress cannot start without the description the request row needs.
pub async fn admit_flake_provision(
    nix_program: &Path,
    flake_dir: &Path,
    cache_dir: &Path,
    bounds: FlakeProvisionBounds,
) -> Result<AdmittedFlakeProvision, FlakeProvisionError> {
    let lock_path = flake_dir.join(FLAKE_LOCK_FILE);
    let lock_bytes =
        tokio::fs::read(&lock_path)
            .await
            .map_err(|source| FlakeProvisionError::ReadLock {
                path: lock_path.clone(),
                source,
            })?;
    let lock = FlakeLock::parse(&lock_bytes).map_err(FlakeProvisionError::ParseLock)?;
    let plan = FlakeProvisionPlan::new(
        nix_program.to_path_buf(),
        flake_dir.to_path_buf(),
        cache_dir.to_path_buf(),
        bounds,
        &lock,
    )
    .map_err(FlakeProvisionError::Plan)?;

    // Still pre-fetch: a missing `nix` is a host misconfiguration, not an
    // attempted egress, so it is refused here rather than recorded as a failure.
    let program = process_supervisor::resolve_program(plan.nix_program(), "nix_program")
        .await
        .map_err(|err| FlakeProvisionError::ResolveNix(err.to_string()))?;

    Ok(AdmittedFlakeProvision {
        request_id: RequestId::new(),
        program,
        plan,
    })
}

impl AdmittedFlakeProvision {
    /// Run `nix flake archive` for this admitted plan and publish the verified
    /// archive into the shared cache. Every exit — including a panic-free host
    /// fault — is reported as a [`PerformedFlakeProvision`] the caller records;
    /// this never writes an audit row itself.
    pub async fn run(self) -> PerformedFlakeProvision {
        let AdmittedFlakeProvision {
            request_id,
            program,
            plan,
        } = self;
        let bounds = plan.bounds();
        let cache_dir = plan.cache_dir().to_path_buf();

        // Per-run scratch named by the unpredictable request id: a fresh HOME
        // (so the host's user-level nix.conf / ~/.netrc / git credentials cannot
        // reach the fetch) and a same-filesystem staging cache. nix archives
        // into staging — never straight into the guest-visible cache_dir — so a
        // crash, timeout, over-budget, or audit failure cannot expose
        // partial/untrusted content; staging is published into cache_dir only
        // after the run is verified.
        let home_dir = match create_home_dir(request_id) {
            Ok(home_dir) => home_dir,
            Err(source) => {
                return PerformedFlakeProvision::failed(
                    format!("could not create provisioning scratch: {source}"),
                    FlakeProvisionError::Scratch { source },
                );
            }
        };
        let staging = match create_staging(&cache_dir, request_id) {
            Ok(staging) => staging,
            Err(source) => {
                cleanup_home_dir(&home_dir);
                return PerformedFlakeProvision::failed(
                    format!("could not create provisioning staging: {source}"),
                    FlakeProvisionError::Scratch { source },
                );
            }
        };
        // Remove the staging cache on *every* exit path below — including a
        // panic — so a failed run never leaks the (possibly disk-filling)
        // unpublished archive. On success the merge has already copied the
        // entries out before this drops.
        let _staging_cleanup = StagingCleanup(staging.clone());

        let mut command = Command::new(program);
        apply_nix_env(&mut command, &home_dir);
        command.args(nix_isolation_args());
        command.args(plan.nix_archive_args(&staging));
        command.stdin(Stdio::null());
        // Run from `/` so that for a `git+https` input, the `git` nix invokes
        // does not discover a repo-local `.git/config` (an `url.*.insteadOf` /
        // `credential.helper`) by walking up from the broker's cwd — the
        // `GIT_CONFIG_*` env only blocks system/global config, not repo-local.
        command.current_dir("/");
        // The supervisor sets stdout, stderr, and the process group, bounds the
        // wall-clock, and SIGKILLs the group on exit or timeout. nix's stderr is
        // discarded (`StderrMode::Discard`): a hostile flake can spew unbounded
        // diagnostics during evaluation, so we never retain them. Failures
        // report the exit status; an operator can re-run for detail.
        let outcome = process_supervisor::run_supervised(
            &mut command,
            bounds.timeout(),
            StdoutMode::Discard,
            StderrMode::Discard,
        )
        .await;

        cleanup_home_dir(&home_dir);

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => {
                // Spawn/wait/kill failure: report the attempt as a failure.
                return PerformedFlakeProvision::failed(
                    format!("nix flake archive could not be run: {err}"),
                    FlakeProvisionError::Supervise(err.to_string()),
                );
            }
        };

        match outcome {
            SupervisedOutcome::StdoutCapExceeded { cap } => {
                // Unreachable under StdoutMode::Discard (stdout is never
                // captured, so the cap is never evaluated), but fail closed
                // rather than panic if the supervisor contract ever changes
                // underneath us.
                let message =
                    format!("nix flake archive stdout exceeded the {cap}-byte capture cap");
                PerformedFlakeProvision::failed(
                    message.clone(),
                    FlakeProvisionError::Supervise(message),
                )
            }
            SupervisedOutcome::TimedOut => PerformedFlakeProvision::failed(
                format!("nix flake archive timed out after {:?}", bounds.timeout()),
                FlakeProvisionError::TimedOut {
                    timeout: bounds.timeout(),
                },
            ),
            SupervisedOutcome::Exited { status, .. } if !status.success() => {
                PerformedFlakeProvision::failed(
                    format!("nix flake archive exited with {status}"),
                    FlakeProvisionError::NixFailed { status },
                )
            }
            SupervisedOutcome::Exited { .. } => {
                let scan_dir = staging.clone();
                let scan = tokio::task::spawn_blocking(move || scan_cache(&scan_dir))
                    .await
                    .expect("cache scan task panicked");
                let (archived_path_count, archived_bytes) = match scan {
                    Ok(metrics) => metrics,
                    Err(source) => {
                        return PerformedFlakeProvision::failed(
                            format!("could not scan provisioning cache: {source}"),
                            FlakeProvisionError::ScanCache {
                                path: staging,
                                source,
                            },
                        );
                    }
                };

                if archived_bytes > bounds.max_total_bytes() {
                    return PerformedFlakeProvision::failed(
                        format!(
                            "archived {archived_bytes} bytes exceeds the configured maximum {}",
                            bounds.max_total_bytes()
                        ),
                        FlakeProvisionError::OverBudget {
                            archived_bytes,
                            max_total_bytes: bounds.max_total_bytes(),
                        },
                    );
                }

                // Merge the verified, within-budget archive into the shared
                // content-addressed cache *before* returning the success the
                // caller records, so the append-only audit log never claims
                // success for a cache that a failed publish left unexposed. The
                // merge adds this flake's entries without dropping other repos';
                // every merged entry is verified, so exposing it before the
                // (immediately-following) success row is durable is not a trust
                // regression.
                if let Err(source) = merge_into_cache(&staging, &cache_dir, request_id) {
                    return PerformedFlakeProvision::failed(
                        format!("could not publish provisioning cache: {source}"),
                        FlakeProvisionError::PublishCache {
                            path: cache_dir,
                            source,
                        },
                    );
                }
                PerformedFlakeProvision::Provisioned(FlakeProvisionReport {
                    request_id,
                    input_count: plan.input_count(),
                    archived_path_count,
                    archived_bytes,
                })
            }
        }
    }
}

/// `nix` global flags that isolate the run from credentials the committed lock
/// did not name, and from the untrusted flake's own config:
///
///   * `access-tokens ""` / `netrc-file /dev/null` disable credential sources
///     the *client* can override (on a multi-user daemon these are restricted
///     settings whose override is ignored — the cleared env + fresh HOME do the
///     work there; on a single-user / trusted-user host they take effect, so
///     they are defence in depth); and
///   * `accept-flake-config false` refuses to honour the untrusted repo's
///     `flake.nix` `nixConfig` (e.g. an `extra-substituters` pointing at an
///     internal URL), which would otherwise drive host egress outside the lock
///     entries the classifier vetted — even on a host with
///     `accept-flake-config = true` in its `nix.conf`.
///
/// They must precede the `flake archive` subcommand, hence prepended.
fn nix_isolation_args() -> [&'static str; 9] {
    [
        "--option",
        "access-tokens",
        "",
        "--option",
        "netrc-file",
        "/dev/null",
        "--option",
        "accept-flake-config",
        "false",
    ]
}

/// Run `nix` credential-free: clear the inherited environment and pass through
/// only the non-credential plumbing it needs, with a fresh `HOME` so the host's
/// user-level `nix.conf` / `~/.netrc` / git credential helpers do not apply to
/// the fetch. (A system-level `/etc/nix/nix.conf` `access-tokens` on a host
/// where the broker is not a trusted nix user is the one residual the client
/// cannot override — documented in the module header.)
fn apply_nix_env(command: &mut Command, home_dir: &Path) {
    command.env_clear();
    for key in [
        "PATH",
        "NIX_REMOTE",
        "NIX_SSL_CERT_FILE",
        "SSL_CERT_FILE",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // A per-run `HOME` instead of `/dev/null`: nix needs a writable home, so this
    // cannot use the full `CLEAN_GIT_CONFIG_ENV` recipe. It gets the whole config
    // *denial* set from the shared constant, so a variable added there is not
    // silently missing here.
    command.env("HOME", home_dir);
    writ_core::git_env::apply_git_config_denials_async(command);
    command.env("GIT_TERMINAL_PROMPT", "0");
}

/// Create the per-run fresh `HOME` directory (named by the unpredictable
/// request id under the temp dir) that isolates nix from the host's user-level
/// config/credentials.
fn create_home_dir(request_id: RequestId) -> std::io::Result<PathBuf> {
    let home_dir = std::env::temp_dir().join(format!(
        "writ-flake-provision-{}-home",
        request_id.as_uuid()
    ));
    std::fs::create_dir(&home_dir)?;
    Ok(home_dir)
}

fn cleanup_home_dir(home_dir: &Path) {
    let _ = std::fs::remove_dir_all(home_dir);
}

/// Create the per-run staging cache as a same-filesystem sibling of `cache_dir`
/// (so the merge's per-entry renames stay on one filesystem), named by the
/// unpredictable request id. nix archives here, never into `cache_dir` directly.
fn create_staging(cache_dir: &Path, request_id: RequestId) -> std::io::Result<PathBuf> {
    let parent = cache_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache directory has no parent",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let staging = parent.join(format!(".writ-flake-stage-{}", request_id.as_uuid()));
    std::fs::create_dir(&staging)?;
    Ok(staging)
}

/// Merge the verified staging cache into the shared, content-addressed
/// `cache_dir`, adding each entry without removing or corrupting existing ones.
///
/// `cache_dir` is the broker's shared binary cache (the plan's default), so a
/// later provisioning of a *different* repo must not drop this repo's narinfos
/// and vice-versa — hence a union, not a replace. The merge is purely additive
/// and idempotent, which keeps it correct for a live, shared, possibly
/// concurrently-written cache:
///   * NAR payloads are published before the `*.narinfo` files that reference
///     them, so a narinfo is never visible (to a guest, or after a crash/
///     partial run) advertising a NAR that is not yet present;
///   * an entry already present is content-addressed and byte-identical, so it
///     is left untouched — never truncated under a reader;
///   * a new entry is written to a temp sibling and atomically renamed into
///     place (the temp is removed on either copy or rename error), so a reader
///     never sees a partial file and a failed copy cannot corrupt the cache; and
///   * nothing is ever *removed*. A run that fails partway leaves only the
///     valid, self-certifying entries it managed to publish — these are correct
///     regardless of which run produced them, and another concurrent provision
///     may already have reused them, so rolling them back would be both
///     unnecessary (they are not corrupt) and unsafe (it could delete an entry
///     a concurrent run is relying on).
fn merge_into_cache(
    staging: &Path,
    cache_dir: &Path,
    request_id: RequestId,
) -> std::io::Result<()> {
    std::fs::create_dir_all(cache_dir)?;

    // Collect every file (creating directories as we go), then publish them
    // NAR-payloads-first so a narinfo can never reference a missing NAR.
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![staging.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let source = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let relative = source
                    .strip_prefix(staging)
                    .expect("entry is under the staging root");
                std::fs::create_dir_all(cache_dir.join(relative))?;
                stack.push(source);
            } else if file_type.is_file() {
                files.push(source);
            }
            // A nix file cache has no symlinks; anything else is skipped.
        }
    }
    let is_narinfo = |path: &Path| path.extension().is_some_and(|ext| ext == "narinfo");
    files.sort_by_key(|path| is_narinfo(path));

    for source in files {
        let relative = source
            .strip_prefix(staging)
            .expect("entry is under the staging root");
        let destination = cache_dir.join(relative);
        if destination.try_exists()? {
            continue;
        }
        let parent = destination
            .parent()
            .expect("a cache entry under cache_dir has a parent");
        std::fs::create_dir_all(parent)?;
        let file_name = destination
            .file_name()
            .expect("a cache entry has a file name")
            .to_string_lossy();
        let temp = parent.join(format!(".writ-tmp-{}-{file_name}", request_id.as_uuid()));
        if let Err(err) = std::fs::copy(&source, &temp) {
            let _ = std::fs::remove_file(&temp);
            return Err(err);
        }
        if let Err(err) = std::fs::rename(&temp, &destination) {
            let _ = std::fs::remove_file(&temp);
            return Err(err);
        }
    }
    Ok(())
}

/// Best-effort removal of an unpublished staging cache after a failed run.
fn clean_staging(staging: &Path) {
    match std::fs::remove_dir_all(staging) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(
            staging = %staging.display(),
            error = %err,
            "could not remove provisioning staging cache after a failed run",
        ),
    }
}

/// Drop guard that removes the staging cache on *every* function exit — normal
/// return, early `?`, or panic — so a failed run never leaks the unpublished
/// (possibly disk-filling) archive. On success the merge has already copied the
/// entries out before this drops.
struct StagingCleanup(PathBuf);

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        clean_staging(&self.0);
    }
}

/// Recursively sum the regular-file bytes under `dir` and count `*.narinfo`
/// files (= store paths archived into the cache).
fn scan_cache(dir: &Path) -> std::io::Result<(u64, u64)> {
    let mut narinfo_count = 0u64;
    let mut total_bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                total_bytes = total_bytes.saturating_add(entry.metadata()?.len());
                if entry.path().extension().is_some_and(|ext| ext == "narinfo") {
                    narinfo_count += 1;
                }
            }
        }
    }
    Ok((narinfo_count, total_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flake_fixtures::fake_nix_failing;

    /// The audit outcome a performed run describes, as the DAO would see it.
    /// Every run must describe exactly one, and it must agree with the ordinary
    /// result — that agreement is what lets the shell record the pair without
    /// re-deriving anything.
    fn audit_outcome(performed: &PerformedFlakeProvision) -> (bool, String) {
        match performed.audit_result() {
            FlakeProvisionResult::Success { .. } => (true, String::new()),
            FlakeProvisionResult::Failure { error } => (false, error.to_string()),
        }
    }

    fn bounds(max_total_bytes: u64) -> FlakeProvisionBounds {
        FlakeProvisionBounds::new(64, max_total_bytes, Duration::from_secs(120)).unwrap()
    }

    #[test]
    fn isolation_args_disable_tokens_netrc_and_flake_config_before_subcommand() {
        // Pins the isolation global flags and that they precede `flake archive`
        // (nix global options must come before the subcommand).
        assert_eq!(
            nix_isolation_args(),
            [
                "--option",
                "access-tokens",
                "",
                "--option",
                "netrc-file",
                "/dev/null",
                "--option",
                "accept-flake-config",
                "false"
            ]
        );
    }

    /// Locate `nix` on PATH. Returns `None` (test skips) when nix is absent, so
    /// the suite still runs on machines without nix; CI has nix.
    fn nix_program() -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join("nix"))
            .find(|candidate| candidate.is_file())
    }

    /// A no-input flake: the only network-free fixture, since the classifier
    /// (correctly) rejects local `path`/`file://` inputs. `nix flake archive`
    /// still copies the flake's own source path into the cache.
    fn write_no_input_flake(dir: &Path) {
        std::fs::write(
            dir.join("flake.nix"),
            "{\n  description = \"fk1b fixture\";\n  outputs = { self }: { ok = true; };\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("flake.lock"),
            r#"{"nodes":{"root":{}},"root":"root","version":7}"#,
        )
        .unwrap();
    }

    /// Admitting and running is one step in the tests that only care about the
    /// run: the split exists for the *caller* to record the attempt between the
    /// two halves.
    async fn admit_and_run(
        nix: &Path,
        flake_dir: &Path,
        cache_dir: &Path,
        bounds: FlakeProvisionBounds,
    ) -> Result<PerformedFlakeProvision, FlakeProvisionError> {
        Ok(admit_flake_provision(nix, flake_dir, cache_dir, bounds)
            .await?
            .run()
            .await)
    }

    #[tokio::test]
    async fn provisions_a_no_input_flake_and_describes_a_success_outcome() {
        let Some(nix) = nix_program() else {
            eprintln!("skipping: nix not found on PATH");
            return;
        };
        let flake = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        write_no_input_flake(flake.path());

        let performed = admit_and_run(&nix, flake.path(), cache.path(), bounds(1 << 30))
            .await
            .expect("a no-input flake is admissible");

        let (is_success, _) = audit_outcome(&performed);
        assert!(is_success, "got: {performed:?}");
        let report = performed
            .into_result()
            .expect("provisioning a no-input flake should succeed");
        assert_eq!(report.input_count(), 0);
        assert!(
            report.archived_path_count() >= 1,
            "the flake's own source path should be archived, got {}",
            report.archived_path_count()
        );
        assert!(report.archived_bytes() > 0);

        // The cache really holds narinfos.
        let (narinfos, _) = scan_cache(cache.path()).unwrap();
        assert_eq!(narinfos, report.archived_path_count());
    }

    #[tokio::test]
    async fn over_budget_archive_fails_closed_and_describes_a_failure_outcome() {
        let Some(nix) = nix_program() else {
            eprintln!("skipping: nix not found on PATH");
            return;
        };
        let flake = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        write_no_input_flake(flake.path());

        // A 1-byte cap is exceeded by any real archive.
        let performed = admit_and_run(&nix, flake.path(), cache.path(), bounds(1))
            .await
            .expect("the lock is admissible; the budget is what fails");

        let (is_success, error) = audit_outcome(&performed);
        assert!(!is_success, "a 1-byte budget must fail closed");
        assert!(
            error.contains("exceeds the configured maximum"),
            "got: {error}"
        );

        // The over-budget archive must be removed, not left substitutable.
        let remaining = if cache.path().exists() {
            scan_cache(cache.path())
                .map(|(narinfos, _)| narinfos)
                .unwrap_or(0)
        } else {
            0
        };
        assert_eq!(remaining, 0, "over-budget cache must be cleaned");

        assert!(
            matches!(
                performed.into_result(),
                Err(FlakeProvisionError::OverBudget { .. })
            ),
            "the caller-facing error must agree with the audit outcome"
        );
    }

    /// A run that fails still describes a truthful outcome, so the caller always
    /// has a row to complete its audit pair with — no nix needed to prove it.
    #[tokio::test]
    async fn a_failed_run_describes_the_failure_it_is_recorded_under() {
        let flake = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        write_no_input_flake(flake.path());
        let nix = fake_nix_failing(flake.path(), 3);

        let performed = admit_and_run(&nix, flake.path(), cache.path(), bounds(1 << 30))
            .await
            .expect("a no-input flake is admissible");

        let (is_success, error) = audit_outcome(&performed);
        assert!(!is_success);
        assert!(
            error.contains("nix flake archive exited with"),
            "got: {error}"
        );
        assert!(matches!(
            performed.into_result(),
            Err(FlakeProvisionError::NixFailed { .. })
        ));
    }

    #[tokio::test]
    async fn reprovisioning_merges_into_a_shared_cache_preserving_other_entries() {
        let Some(nix) = nix_program() else {
            eprintln!("skipping: nix not found on PATH");
            return;
        };
        let flake = tempfile::tempdir().unwrap();
        // A cache *subdir* of the tempdir, so the staging sibling lands in this
        // test's private tempdir rather than the shared system temp.
        let cache = tempfile::tempdir().unwrap();
        let cache_dir = cache.path().join("cache");
        write_no_input_flake(flake.path());

        admit_and_run(&nix, flake.path(), &cache_dir, bounds(1 << 30))
            .await
            .expect("a no-input flake is admissible")
            .into_result()
            .expect("first provisioning should succeed");

        // Seed a foreign content-addressed entry, as if another repo had been
        // provisioned into this shared cache.
        let foreign = cache_dir.join("ffffffffffffffffffffffffffffffff.narinfo");
        std::fs::write(&foreign, b"StorePath: /nix/store/x\n").unwrap();

        // Reprovision: a union merge must add this flake's entries without
        // dropping the foreign one.
        admit_and_run(&nix, flake.path(), &cache_dir, bounds(1 << 30))
            .await
            .expect("a no-input flake is admissible")
            .into_result()
            .expect("reprovisioning into a shared cache should succeed");

        assert!(
            foreign.exists(),
            "merge must preserve other repos' cache entries"
        );
        let (narinfos, _) = scan_cache(&cache_dir).unwrap();
        assert!(
            narinfos >= 2,
            "cache should hold the foreign entry plus this flake's, got {narinfos}"
        );

        // No `.writ-flake-stage-*` leftovers beside the cache.
        let leftovers = std::fs::read_dir(cache.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".writ-flake-")
            })
            .count();
        assert_eq!(leftovers, 0, "no staging dirs should be left behind");
    }

    /// A missing lock is refused at admission, so the caller never gets an
    /// `AdmittedFlakeProvision` — and therefore has nothing to record.
    #[tokio::test]
    async fn missing_lock_is_refused_before_admission() {
        // No nix needed: pre-flight refusal.
        let flake = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        // flake dir exists but has no flake.lock

        let err = admit_flake_provision(
            Path::new("nix"),
            flake.path(),
            cache.path(),
            bounds(1 << 30),
        )
        .await
        .expect_err("a missing lock must be refused");
        assert!(
            matches!(err, FlakeProvisionError::ReadLock { .. }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn non_provisionable_lock_is_refused_before_admission() {
        // An ssh input is rejected by the functional core; no admission, no nix.
        let flake = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        std::fs::write(
            flake.path().join("flake.nix"),
            "{ outputs = { self, dep }: { }; }\n",
        )
        .unwrap();
        std::fs::write(
            flake.path().join("flake.lock"),
            crate::flake_fixtures::SSH_INPUT_LOCK,
        )
        .unwrap();

        let err = admit_flake_provision(
            Path::new("nix"),
            flake.path(),
            cache.path(),
            bounds(1 << 30),
        )
        .await
        .expect_err("an ssh input must be refused");
        assert!(matches!(err, FlakeProvisionError::Plan(_)), "got: {err:?}");
    }
}
