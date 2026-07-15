//! The crash harness's world fixture and full-pipeline approve tests.
//!
//! [`ApproveWorld`] assembles the real broker around the two fakes:
//! the staged push's prerequisite lives in a [`FakeOrigin`] served
//! over dumb HTTP (the prepare fetch is a real `git fetch`), the Git
//! Data API and the token mint are a [`FakeGitHub`] whose model is the
//! oracle's ground truth, the audit DB is **file-backed** (an
//! in-memory DB cannot survive the sweep's reboots), and the staging
//! store, work root and signing key are real. Every test that needs
//! `git` skips when it is absent, matching the suite convention.
//!
//! This module carries the Stage-4 oracles: the first end-to-end
//! *successful* approve through `dispatch_message` (everything prior
//! stopped at a stubbed git), and the counting run that discovers the
//! sweep's upper bound. The single-crash sweep is Stage 5; the
//! double-crash and torn-residue stretch tests (Stage 6) reuse its
//! recovery helpers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::test_support::{InMemStore, open_session};
use super::*;
use crate::audit::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState, GitPushResolution};
use crate::core::AgentKind;
use crate::core::RepoRef;
use crate::crash_point::{CrashOutcome, CrashPlan, run_until_crash};
use crate::fake_github::FakeGitHub;
use crate::fake_origin::{FakeOrigin, ORIGIN_NAME, ORIGIN_OWNER, maybe_git};
use crate::github::{GitHubAppConfig, GitHubAppRegistryConfig, GitHubMinter};
use crate::policy::PolicyConfig;
use crate::secret::SecretKey;
use crate::signing::WritSigningKey;
use crate::vm_git::{GitBranchName, GitCloneRepo, VmGitPushMetadata};
use crate::vm_git_bundle::{GitCredentialBoundary, GitSecretEnvVar};

const RSA_TEST_PEM: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");
const SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
const INSTALLATION_ID: u64 = 999;
pub(super) const WORLD_BRANCH: &str = "main";
pub(super) const OPERATOR: &str = "alice";

/// The real broker wired to the fakes, with one staged push ready to
/// approve. Fields are the handles the sweep's oracle needs.
pub(super) struct ApproveWorld {
    pub(super) state: Arc<BrokerState<InMemStore>>,
    pub(super) github: FakeGitHub,
    pub(super) origin: FakeOrigin,
    pub(super) request_id: RequestId,
    /// The audit DB file — reopened across simulated reboots.
    pub(super) audit_path: PathBuf,
    staging_path: PathBuf,
    work_root: PathBuf,
    /// The write allowlist the broker was built with — reused verbatim
    /// when the sweep reboots so policy is identical across the crash.
    writable_repos: Vec<RepoRef>,
    /// Owns staging store, work root and audit DB alike.
    pub(super) _tmp: tempfile::TempDir,
}

impl ApproveWorld {
    /// `None` when `git` is not on `PATH` (callers skip). The staged
    /// push's target repo is on the write allowlist, so policy grants
    /// the approve-time mint — the setup every crash-recovery oracle
    /// wants. Use [`start_with_writable_repos`](Self::start_with_writable_repos)
    /// to exercise a policy that denies.
    pub(super) async fn start() -> Option<Self> {
        let repo: RepoRef = format!("{ORIGIN_OWNER}/{ORIGIN_NAME}").parse().unwrap();
        Self::start_with_writable_repos(vec![repo]).await
    }

    /// As [`start`](Self::start), but with an explicit write allowlist.
    /// The staged push always targets `ORIGIN_OWNER/ORIGIN_NAME`; pass
    /// an allowlist that omits it to build a world whose policy denies
    /// the approve.
    pub(super) async fn start_with_writable_repos(writable_repos: Vec<RepoRef>) -> Option<Self> {
        let origin = FakeOrigin::start().await?;
        let github = FakeGitHub::start(ORIGIN_OWNER, ORIGIN_NAME, INSTALLATION_ID).await;
        // GitHub's branch is at the prerequisite — exactly the state
        // the staged receipt's lease was taken against.
        github.set_ref(WORLD_BRANCH, origin.prereq().as_str());

        let tmp = tempfile::tempdir().expect("approve world tempdir");
        let audit_path = tmp.path().join("audit.sqlite3");
        let staging_path = tmp.path().join("staging");
        let work_root = tmp.path().join("promote");
        std::fs::create_dir_all(&work_root).expect("create work root");

        let state = build_state(
            &audit_path,
            &staging_path,
            &work_root,
            &github,
            &origin,
            &writable_repos,
        );

        // Stage the push whose prerequisite the origin serves and
        // whose bundle the origin built: receipt and world agree by
        // construction.
        let session_id = open_session(&state).await;
        let request_id = RequestId::new();
        let repo: GitCloneRepo = format!("{ORIGIN_OWNER}/{ORIGIN_NAME}").parse().unwrap();
        let branch: GitBranchName = WORLD_BRANCH.parse().unwrap();
        let metadata = VmGitPushMetadata::new(
            repo.clone(),
            branch.clone(),
            Some(origin.prereq().clone()),
            origin.tip().clone(),
        );
        let staging = state.staging_store.as_ref().unwrap().clone();
        let bundle = origin.bundle_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            staging
                .stage(
                    request_id,
                    UnixMillis::from_millis(1_700_000_040_000),
                    metadata,
                    bundle,
                )
                .unwrap();
        })
        .await
        .unwrap();
        state
            .audit
            .record_git_push_request(&crate::audit::GitPushRequestRecord {
                push_request_id: request_id,
                session_id,
                received_at: UnixMillis::from_millis(1_700_000_040_500),
                repo,
                branch,
                expected_remote_head: Some(origin.prereq().clone()),
                new_head: origin.tip().clone(),
                correlation_id: None,
            })
            .unwrap();
        state
            .audit
            .record_git_push_outcome(&crate::audit::GitPushOutcomeRecord {
                push_request_id: request_id,
                completed_at: UnixMillis::from_millis(1_700_000_040_500),
                result: crate::audit::GitPushOutcomeResult::Staged,
                github_status: None,
                message: "staged for operator review",
            })
            .unwrap();

        Some(Self {
            state,
            github,
            origin,
            request_id,
            audit_path,
            staging_path,
            work_root,
            writable_repos,
            _tmp: tmp,
        })
    }

    pub(super) fn approve_message(&self) -> ClientMessage {
        ClientMessage::ApproveStagedPush {
            request_id: self.request_id,
            operator: OPERATOR.into(),
        }
    }

    /// A fresh broker over the same durable stores — the "rebooted
    /// daemon" the sweep retries through. The crashed broker's state
    /// stays alive in the world (as a crashed process's kernel
    /// resources would not, but its *disk* state is what matters and
    /// that is shared by path).
    pub(super) fn rebooted_state(&self) -> Arc<BrokerState<InMemStore>> {
        build_state(
            &self.audit_path,
            &self.staging_path,
            &self.work_root,
            &self.github,
            &self.origin,
            &self.writable_repos,
        )
    }
}

fn build_state(
    audit_path: &std::path::Path,
    staging_path: &std::path::Path,
    work_root: &std::path::Path,
    github: &FakeGitHub,
    origin: &FakeOrigin,
    writable_repos: &[RepoRef],
) -> Arc<BrokerState<InMemStore>> {
    let git = maybe_git().expect("callers hold a FakeOrigin, so git exists");
    let promote_runtime = crate::git_push_promote::PromoteRuntimeConfig::new(
        git,
        origin.clone_base_url(),
        GitCredentialBoundary::new(
            PathBuf::from("/usr/local/bin/fake-askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap(),
        work_root.to_path_buf(),
        std::time::Duration::from_secs(30),
    )
    .expect("promote runtime config");

    let pk = SecretKey::new("gh-app-pk").unwrap();
    let secrets = InMemStore::default();
    secrets.put(&pk, RSA_TEST_PEM).unwrap();
    let mut apps = BTreeMap::new();
    apps.insert(
        AgentKind::Claude,
        GitHubAppConfig {
            app_id: 42,
            installation_id: INSTALLATION_ID,
            installation_owner: ORIGIN_OWNER.into(),
            private_key_secret: pk,
            api_base: github.uri(),
        },
    );

    Arc::new(BrokerState {
        audit: Arc::new(AuditLog::open(audit_path).expect("file-backed audit DB opens")),
        minter: GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap()),
        secrets,
        policy: PolicyConfig {
            writable_repos: writable_repos.to_vec(),
            default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
        },
        staging_store: Some(Arc::new(
            GitPushStagingStore::open(staging_path.to_path_buf()).expect("staging store opens"),
        )),
        notes_repo: None,
        signing_key: Some(WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap()),
        run_agent_spawn: None,
        promote_runtime: Some(Arc::new(promote_runtime)),
        mirror_pins: crate::vm_git_mirror_cache::MirrorPins::new(),
        chatgpt_oauth_authority: Default::default(),
    })
}

/// Stage-4 oracle, part 1: the whole pipeline — real staging fetch
/// over the origin's dumb HTTP, real unbundle/plan/walk, uploads and
/// publish against the fake GitHub — succeeds through the public
/// handler, and every layer agrees on the outcome: the wire reply, the
/// fake's ref (moved exactly once, to the reply's tip), and the audit
/// log (Resolved(Succeeded) whose resolution mint matches the v7
/// ledger).
#[tokio::test]
async fn approve_pipeline_succeeds_end_to_end_against_fake_github() {
    let Some(world) = ApproveWorld::start().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    let resp = dispatch_message(world.approve_message(), &world.state).await;
    let ServerMessage::StagedPushApproved {
        request_id,
        new_app_tip,
    } = resp
    else {
        panic!("expected StagedPushApproved, got {resp:?}");
    };
    assert_eq!(request_id, world.request_id);

    // The fake's ground truth agrees with the wire reply.
    assert_eq!(
        world.github.ref_of(WORLD_BRANCH).unwrap(),
        new_app_tip.as_str(),
    );
    assert_eq!(
        world.github.ref_history(WORLD_BRANCH).len(),
        2,
        "seed plus exactly one publish",
    );
    assert_eq!(world.github.patch_requests().len(), 1);

    // And so does the audit log.
    let attempts = world
        .state
        .audit
        .approve_attempts_for_push(world.request_id)
        .unwrap();
    assert_eq!(attempts.len(), 1);
    let GitPushApproveAttemptState::Resolved {
        outcome:
            GitPushApproveAttemptOutcome::Succeeded {
                new_app_tip: audited,
            },
        mint,
        ..
    } = &attempts[0].state
    else {
        panic!("expected Resolved(Succeeded), got {:?}", attempts[0].state);
    };
    assert_eq!(audited, &new_app_tip);
    let ledger = world
        .state
        .audit
        .attempt_recorded_mint(attempts[0].attempt_id)
        .unwrap()
        .expect("the approve minted, so the ledger has a row");
    assert_eq!(*mint, Some(ledger));
    let resolution = world
        .state
        .audit
        .get_git_push(world.request_id)
        .unwrap()
        .unwrap()
        .resolution
        .expect("approved push has a resolution row");
    let GitPushResolution::Approved(resolution_mint) = resolution.decision else {
        panic!("expected Approved, got {:?}", resolution.decision);
    };
    assert_eq!(resolution_mint.jti, ledger.jti);
}

/// The write allowlist (`policy.writable_repos`) must gate the
/// *approve* route, not only the live-credential route. A staged push
/// carries the exact capability the operator is being asked to
/// authorise — `VmGitPushMetadata::authorization_request()` yields
/// `Contents { Write, repo }` — and `policy::decide` denies writes to
/// a repo that is not on the allowlist. The clone path routes its
/// request through `policy::decide` and honours that; the approve path
/// built its `contents:write` scope by hand and minted directly, so an
/// operator could approve a guest-originated push to any *installed*
/// repo regardless of policy.
///
/// This asserts the invariant against the fake GitHub's ground truth:
/// approving an off-allowlist push mints no installation token, issues
/// no branch PATCH, leaves the branch where the lease was taken, and
/// does not report success.
#[tokio::test]
async fn approve_of_push_to_non_writable_repo_is_denied() {
    // The staged push targets `ORIGIN_OWNER/ORIGIN_NAME`; the allowlist
    // deliberately names a *different* repo under the same installation
    // (which the coarse installation-owner check in the minter would
    // still let a token be minted for). `policy::decide` denies writes
    // to the staged repo under this policy, and the approve path must
    // reach the same verdict.
    let other: RepoRef = format!("{ORIGIN_OWNER}/some-other-repo").parse().unwrap();
    let Some(world) = ApproveWorld::start_with_writable_repos(vec![other]).await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    let resp = dispatch_message(world.approve_message(), &world.state).await;

    // The security-critical fact: no installation token was minted for
    // the off-allowlist repo. A mint is a `POST` to
    // `/app/installations/{id}/access_tokens`, and the fake records
    // every request it serves.
    let minted = world
        .github
        .requests()
        .iter()
        .any(|r| r.method == "POST" && r.path.ends_with("/access_tokens"));
    assert!(
        !minted,
        "approve minted a token for a repo denied by writable_repos: {resp:?}",
    );

    // Corollaries at the Git Data API: no branch update was attempted,
    // and the branch still sits at the lease baseline.
    assert!(
        world.github.patch_requests().is_empty(),
        "approve issued a branch PATCH for a policy-denied repo: {resp:?}",
    );
    assert_eq!(
        world.github.ref_of(WORLD_BRANCH).unwrap(),
        world.origin.prereq().as_str(),
        "the branch moved despite the push being denied by policy: {resp:?}",
    );

    // And the operator's approve did not report success.
    assert!(
        !matches!(resp, ServerMessage::StagedPushApproved { .. }),
        "approve of a non-writable repo returned success: {resp:?}",
    );
}

/// Stage-4 oracle, part 2: a counting run over the same approve
/// discovers the sweep's upper bound. The assertion is a floor, not an
/// exact count, so adding a point is not a test-breaking event — the
/// names are printed on failure to make a shrinkage legible.
#[tokio::test]
async fn counting_run_reports_the_sweeps_upper_bound() {
    let Some(world) = ApproveWorld::start().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    let plan = CrashPlan::count();
    let resp = run_until_crash(
        &plan,
        dispatch_message(world.approve_message(), &world.state),
    )
    .await
    .expect_completed("counting mode must not crash");
    assert!(
        matches!(resp, ServerMessage::StagedPushApproved { .. }),
        "counting mode must not perturb the pipeline: {resp:?}",
    );
    assert!(
        plan.points_passed() >= 12,
        "expected at least the 13 instrumented boundaries, saw {} ({:?})",
        plan.points_passed(),
        plan.names(),
    );
}

/// One counting run over a fresh world: the sweep's upper bound `N`
/// and the point names (for labels). `None` when `git` is absent.
pub(super) async fn count_points() -> Option<(usize, Vec<&'static str>)> {
    let world = ApproveWorld::start().await?;
    let plan = CrashPlan::count();
    run_until_crash(
        &plan,
        dispatch_message(world.approve_message(), &world.state),
    )
    .await
    .expect_completed("counting run must complete");
    let n = plan.points_passed();
    let names = plan.names();
    assert_eq!(names.len(), n);
    Some((n, names))
}

/// Everything the sweep needs to know about a world after a crash and
/// reboot: the reopened audit log, reconciled, with the invariants
/// I-A (recovery totality) already asserted.
async fn reboot_and_reconcile(world: &ApproveWorld, label: &str) -> AuditLog {
    let audit = AuditLog::open(&world.audit_path).expect("rebooted audit DB opens");
    crate::boot_reconcile::reconcile_pending_approve_attempts(&audit, UnixMillis::now())
        .unwrap_or_else(|err| panic!("boot reconcile failed at {label}: {err}"));

    // I-A: recovery totality. No attempt survives reconcile as
    // `Started`, and any attempt whose mint the v7 ledger recorded
    // carries exactly that mint in whatever state it is now in.
    let attempts = audit.approve_attempts_for_push(world.request_id).unwrap();
    assert!(
        !attempts.is_empty(),
        "the crashed approve started an attempt ({label})"
    );
    for attempt in &attempts {
        assert!(
            !matches!(attempt.state, GitPushApproveAttemptState::Started),
            "I-A: Started attempt survived boot reconcile at {label}",
        );
        if let Some(ledger) = audit.attempt_recorded_mint(attempt.attempt_id).unwrap() {
            match &attempt.state {
                GitPushApproveAttemptState::Uncertain { mint } => assert_eq!(
                    *mint, ledger,
                    "I-A: Uncertain mint diverged from ledger at {label}",
                ),
                GitPushApproveAttemptState::Resolved { mint, .. } => assert_eq!(
                    *mint,
                    Some(ledger),
                    "I-A: resolved attempt lost its ledger mint at {label}",
                ),
                GitPushApproveAttemptState::Started => unreachable!("asserted above"),
            }
        }
    }
    audit
}

/// The operator playbook's first step after a reboot, as
/// [`unblock_retry`] resolves it.
enum RecoveryStep {
    /// The joint success TX had already landed; the push is terminal.
    AlreadyApproved,
    /// The crashed attempt's PATCH had landed; the operator reconciled
    /// it `Applied` — terminal.
    ReconciledApplied,
    /// No publish happened (possibly established by a `NotApplied`
    /// reconciliation of an `Uncertain` survivor); a plain retry is
    /// now unblocked.
    RetryUnblocked,
}

/// Follow the operator playbook one step: read the resolution if the
/// joint TX landed; otherwise reconcile an `Eligible` survivor with
/// the verdict the fake's *actual branch* dictates (`Applied` when the
/// crashed attempt's PATCH landed, `NotApplied` when it provably did
/// not); otherwise the push is already retryable.
fn unblock_retry(world: &ApproveWorld, audit: &AuditLog, label: &str) -> RecoveryStep {
    let entry = audit.get_git_push(world.request_id).unwrap().unwrap();
    if let Some(resolution) = entry.resolution {
        assert!(
            matches!(resolution.decision, GitPushResolution::Approved(_)),
            "a crash mid-approve must never leave a non-approved resolution at {label}",
        );
        return RecoveryStep::AlreadyApproved;
    }
    match audit
        .classify_reconciliation_target(world.request_id)
        .unwrap()
    {
        crate::audit::ReconciliationTarget::Eligible {
            attempt_id: supersedes,
        } => {
            let current = world.github.ref_of(WORLD_BRANCH).unwrap();
            if current == world.origin.prereq().as_str() {
                audit
                    .record_reconciliation_attempt_not_applied(
                        ApproveAttemptId::new(),
                        supersedes,
                        OPERATOR,
                        "fake's branch never moved",
                        UnixMillis::now(),
                    )
                    .unwrap_or_else(|err| panic!("NotApplied must land at {label}: {err}"));
                RecoveryStep::RetryUnblocked
            } else {
                audit
                    .record_reconciliation_attempt_applied(
                        ApproveAttemptId::new(),
                        supersedes,
                        &current.parse().unwrap(),
                        OPERATOR,
                        "confirmed against the fake's branch",
                        UnixMillis::now(),
                    )
                    .unwrap_or_else(|err| panic!("Applied must land at {label}: {err}"));
                RecoveryStep::ReconciledApplied
            }
        }
        crate::audit::ReconciliationTarget::NothingToReconcile
        | crate::audit::ReconciliationTarget::NoAttempts => RecoveryStep::RetryUnblocked,
        crate::audit::ReconciliationTarget::AttemptInFlight => {
            panic!("boot reconcile left an in-flight attempt at {label}")
        }
    }
}

/// Drive a rebooted world the rest of the way to an approved publish:
/// one [`unblock_retry`] step, then a crash-free retry if one is
/// needed. In particular no crash residue (staging dirs, ledger rows)
/// may block the retry.
async fn drive_to_approved(world: &ApproveWorld, audit: &AuditLog, label: &str) {
    match unblock_retry(world, audit, label) {
        RecoveryStep::AlreadyApproved | RecoveryStep::ReconciledApplied => {}
        RecoveryStep::RetryUnblocked => {
            let rebooted = world.rebooted_state();
            let resp = dispatch_message(world.approve_message(), &rebooted).await;
            assert!(
                matches!(resp, ServerMessage::StagedPushApproved { .. }),
                "retry after recovery at {label} must succeed, got {resp:?}",
            );
        }
    }
}

/// I-D, single publish: recovery ends with exactly one approved
/// resolution, exactly one succeeded attempt, exactly one PATCH and
/// exactly one ref movement — and the fake's ref sits at the succeeded
/// attempt's tip. Counted against the fake's ground truth, however
/// many crashes and retries the world went through.
fn assert_single_publish(world: &ApproveWorld, label: &str) {
    let audit = AuditLog::open(&world.audit_path).unwrap();
    let entry = audit.get_git_push(world.request_id).unwrap().unwrap();
    let resolution = entry
        .resolution
        .unwrap_or_else(|| panic!("no resolution after recovery at {label}"));
    assert!(
        matches!(resolution.decision, GitPushResolution::Approved(_)),
        "I-D: recovery must end approved at {label}",
    );
    let tips: Vec<String> = audit
        .approve_attempts_for_push(world.request_id)
        .unwrap()
        .iter()
        .filter_map(|a| match &a.state {
            GitPushApproveAttemptState::Resolved {
                outcome: GitPushApproveAttemptOutcome::Succeeded { new_app_tip },
                ..
            } => Some(new_app_tip.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        tips.len(),
        1,
        "I-D: exactly one succeeded attempt at {label}"
    );
    assert_eq!(
        world.github.patch_requests().len(),
        1,
        "I-D: exactly one PATCH at {label}"
    );
    assert_eq!(
        world.github.ref_history(WORLD_BRANCH).len(),
        2,
        "I-D: seed plus exactly one ref movement at {label}"
    );
    assert_eq!(
        world.github.ref_of(WORLD_BRANCH).unwrap(),
        tips[0],
        "I-D: the fake's ref must sit at the published tip at {label}"
    );
}

/// The single-crash sweep, retry scenario (DESIGN §6, invariants
/// I-A…I-D). One counting run discovers the upper bound `N`; each
/// `k ∈ 0..N` then gets a fresh world, a crash at point `k`, a reboot
/// with boot reconcile, and a drive to exactly one approved publish —
/// by plain retry when the crash was provably pre-PATCH, by operator
/// reconciliation when the PATCH had already reached the fake.
#[tokio::test]
async fn crash_sweep_every_index_recovers_to_one_approved_publish() {
    let Some((_, names)) = count_points().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    let mut saw_pre_patch = false;
    let mut saw_post_patch = false;
    for (k, &name) in names.iter().enumerate() {
        let label = format!("k={k} ({name})");
        let world = ApproveWorld::start()
            .await
            .expect("git existed for the counting run");
        let plan = CrashPlan::crash_at(k);
        let (index, _) = run_until_crash(
            &plan,
            dispatch_message(world.approve_message(), &world.state),
        )
        .await
        .expect_crashed("k is within the counted range");
        assert_eq!(index, k);

        let audit = reboot_and_reconcile(&world, &label).await;

        // Classify pre- vs post-PATCH from the fake's request log —
        // the ground truth, not the audit log under test.
        let patches_from_crashed_attempt = world.github.patch_requests().len();
        if patches_from_crashed_attempt == 0 {
            saw_pre_patch = true;
            // I-B: pre-PATCH truth. The branch is untouched. Whether
            // reject is *permitted* depends on the broker's weaker
            // knowledge: a crash between the Uncertain TX and the
            // PATCH leaves an Uncertain row the broker cannot
            // distinguish from a sent PATCH, so it conservatively
            // quarantines. Reject is allowed exactly when the crashed
            // attempt never reached Uncertain.
            assert_eq!(
                world.github.ref_of(WORLD_BRANCH).unwrap(),
                world.origin.prereq().as_str(),
                "I-B: branch moved without a PATCH at k={k} ({name})",
            );
            assert_eq!(world.github.ref_history(WORLD_BRANCH).len(), 1);
            let uncertain_survivor = audit
                .approve_attempts_for_push(world.request_id)
                .unwrap()
                .iter()
                .any(|a| matches!(a.state, GitPushApproveAttemptState::Uncertain { .. }));
            assert_eq!(
                audit
                    .reject_blocker_for_push(world.request_id)
                    .unwrap()
                    .is_none(),
                !uncertain_survivor,
                "I-B: reject permission must mirror the Uncertain quarantine at k={k} ({name})",
            );
        } else {
            saw_post_patch = true;
            // I-C: the fake applies a received PATCH atomically, so the
            // ref must show the movement the audit log is uncertain
            // about (or certain of, if the crash landed even later).
            assert!(
                world.github.ref_history(WORLD_BRANCH).len() >= 2,
                "I-C: a PATCH was received but the ref never moved at k={k} ({name})",
            );
        }

        // Scenario A: drive to completion (the operator playbook:
        // reconcile per the fake's ground truth, then retry if no
        // publish happened), then I-D.
        drive_to_approved(&world, &audit, &label).await;
        assert_single_publish(&world, &label);
    }

    // Meta-check: the sweep must straddle the PATCH, or the classifier
    // has silently degenerated and half the invariants never ran.
    assert!(
        saw_pre_patch && saw_post_patch,
        "sweep must observe both pre- and post-PATCH crashes \
         (pre: {saw_pre_patch}, post: {saw_post_patch})",
    );
}

/// The single-crash sweep, reject scenario. After every crash and
/// reboot the operator tries to *reject* instead: permitted (and
/// final) when the crash was provably pre-PATCH, refused while the
/// attempt is quarantined, and "already resolved" once the crash
/// landed after the joint TX or a reconciliation acknowledged the
/// applied PATCH.
#[tokio::test]
async fn crash_sweep_reject_is_permitted_exactly_when_the_patch_provably_never_fired() {
    let Some((_, names)) = count_points().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    for (k, &name) in names.iter().enumerate() {
        let world = ApproveWorld::start()
            .await
            .expect("git existed for the counting run");
        let plan = CrashPlan::crash_at(k);
        run_until_crash(
            &plan,
            dispatch_message(world.approve_message(), &world.state),
        )
        .await
        .expect_crashed("k is within the counted range");

        let audit = reboot_and_reconcile(&world, &format!("k={k} ({name})")).await;
        let already_resolved = audit
            .get_git_push(world.request_id)
            .unwrap()
            .unwrap()
            .resolution
            .is_some();
        let patched = !world.github.patch_requests().is_empty();

        let rebooted = world.rebooted_state();
        let reject = ClientMessage::RejectStagedPush {
            request_id: world.request_id,
            operator: OPERATOR.into(),
            reason: RejectionReason::try_new("sweep reject").unwrap(),
        };
        let resp = dispatch_message(reject.clone(), &rebooted).await;

        let uncertain_survivor = audit
            .approve_attempts_for_push(world.request_id)
            .unwrap()
            .iter()
            .any(|a| matches!(a.state, GitPushApproveAttemptState::Uncertain { .. }));

        if already_resolved {
            assert!(
                matches!(resp, ServerMessage::StagedPushAlreadyResolved { .. }),
                "post-TX crash: reject must see the resolution at k={k} ({name}), got {resp:?}",
            );
        } else if !patched && !uncertain_survivor {
            // I-B: the PATCH provably never fired and the broker knows
            // it, so the operator can change their mind — and the
            // branch must never move.
            assert!(
                matches!(resp, ServerMessage::StagedPushRejected { .. }),
                "pre-PATCH crash: reject must land at k={k} ({name}), got {resp:?}",
            );
            assert_eq!(
                world.github.ref_of(WORLD_BRANCH).unwrap(),
                world.origin.prereq().as_str(),
                "rejected push must leave the branch untouched at k={k} ({name})",
            );
        } else if !patched {
            // The Uncertain-but-no-PATCH window: the broker cannot
            // prove what ground truth knows, so reject is refused
            // until the operator reconciles NotApplied — after which
            // reject lands and the branch has never moved.
            assert!(
                matches!(resp, ServerMessage::Error { .. }),
                "Uncertain survivor must refuse reject at k={k} ({name}), got {resp:?}",
            );
            let crate::audit::ReconciliationTarget::Eligible {
                attempt_id: supersedes,
            } = audit
                .classify_reconciliation_target(world.request_id)
                .unwrap()
            else {
                panic!("Uncertain survivor must be reconcilable at k={k} ({name})");
            };
            audit
                .record_reconciliation_attempt_not_applied(
                    ApproveAttemptId::new(),
                    supersedes,
                    OPERATOR,
                    "fake's branch never moved",
                    UnixMillis::now(),
                )
                .unwrap();
            let resp = dispatch_message(reject, &world.rebooted_state()).await;
            assert!(
                matches!(resp, ServerMessage::StagedPushRejected { .. }),
                "post-NotApplied reject must land at k={k} ({name}), got {resp:?}",
            );
            assert_eq!(
                world.github.ref_of(WORLD_BRANCH).unwrap(),
                world.origin.prereq().as_str(),
                "rejected push must leave the branch untouched at k={k} ({name})",
            );
        } else {
            // I-C: quarantined. Reject is refused until an operator
            // reconciles; the fake shows the PATCH applied, so the
            // verdict is Applied, after which reject reports the push
            // as already (approvingly) resolved.
            assert!(
                matches!(resp, ServerMessage::Error { .. }),
                "quarantined push must refuse reject at k={k} ({name}), got {resp:?}",
            );
            let crate::audit::ReconciliationTarget::Eligible {
                attempt_id: supersedes,
            } = audit
                .classify_reconciliation_target(world.request_id)
                .unwrap()
            else {
                panic!("quarantined push must be reconcilable at k={k} ({name})");
            };
            let current = world.github.ref_of(WORLD_BRANCH).unwrap();
            audit
                .record_reconciliation_attempt_applied(
                    ApproveAttemptId::new(),
                    supersedes,
                    &current.parse().unwrap(),
                    OPERATOR,
                    "confirmed against the fake's branch",
                    UnixMillis::now(),
                )
                .unwrap();
            let resp = dispatch_message(reject, &world.rebooted_state()).await;
            assert!(
                matches!(resp, ServerMessage::StagedPushAlreadyResolved { .. }),
                "post-reconciliation reject must see the resolution at k={k} ({name}), \
                 got {resp:?}",
            );
        }
    }
}

/// Stage 6, double crash (DESIGN §7): crash at `k₁`, reboot, follow
/// the operator playbook one step; if that step is a retry, crash the
/// retry at `k₂`; reboot; finish. The invariants are state-based, not
/// trace-based, so they are unchanged — that is the point of writing
/// them that way. Sampled rather than swept: the full `N²` grid costs
/// too many subprocess-heavy runs for `cargo test`; 32 proptest cases
/// keep the property honest without the bill.
#[test]
fn double_crash_sampled_pairs_recover_to_one_approved_publish() {
    use proptest::test_runner::{Config, TestRunner};

    if maybe_git().is_none() {
        eprintln!("skipping: `git` not on PATH");
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (n, _) = rt
        .block_on(count_points())
        .expect("`git` presence checked above");

    let mut config = Config::with_cases(32);
    config.source_file = Some(file!());
    // This runner drives an async case on the shared `rt` above, so it
    // must execute in-process. `Config::with_cases` inherits `fork` /
    // `timeout` from the environment (`PROPTEST_FORK`, `PROPTEST_TIMEOUT`),
    // and both fork the case into a subprocess that re-enters the test
    // binary rather than this closure — meaningless here. Forcing them
    // off keeps the runtime test honest under any env, and sidesteps the
    // `Must supply test_name when forking enabled` panic a hand-built
    // config (no `test_name`) would otherwise hit.
    config.fork = false;
    config.timeout = 0;
    let mut runner = TestRunner::new(config);
    runner
        .run(&(0..n, 0..n), |(k1, k2)| {
            rt.block_on(double_crash_case(k1, k2));
            Ok(())
        })
        .unwrap_or_else(|err| panic!("double-crash property failed: {err}"));
}

async fn double_crash_case(k1: usize, k2: usize) {
    let label = format!("k1={k1}, k2={k2}");
    let world = ApproveWorld::start().await.expect("git is on PATH");
    let plan = CrashPlan::crash_at(k1);
    run_until_crash(
        &plan,
        dispatch_message(world.approve_message(), &world.state),
    )
    .await
    .expect_crashed("k1 is within the counted range");
    let audit = reboot_and_reconcile(&world, &label).await;

    match unblock_retry(&world, &audit, &label) {
        RecoveryStep::AlreadyApproved | RecoveryStep::ReconciledApplied => {
            // The first crash landed post-publish; there is nothing
            // left for the second crash to interrupt.
        }
        RecoveryStep::RetryUnblocked => {
            let plan = CrashPlan::crash_at(k2);
            match run_until_crash(
                &plan,
                dispatch_message(world.approve_message(), &world.rebooted_state()),
            )
            .await
            {
                CrashOutcome::Completed(resp) => {
                    // `k₂` lay past the retry's last point.
                    assert!(
                        matches!(resp, ServerMessage::StagedPushApproved { .. }),
                        "uncrashed retry must succeed at {label}, got {resp:?}",
                    );
                }
                CrashOutcome::Crashed { .. } => {
                    let audit = reboot_and_reconcile(&world, &label).await;
                    drive_to_approved(&world, &audit, &label).await;
                }
            }
        }
    }
    assert_single_publish(&world, &label);
}

/// Stage 6, torn residue (DESIGN §7): a real crash can tear the
/// staging dir's files, not just abandon them — SQLite's transactions
/// give the audit store torn-write freedom, but the filesystem has no
/// such shield. After every staging-phase crash, corrupt the residue
/// two ways (truncate the bundle; empty the directory) and the
/// recovery must not notice: attempt-keyed staging dirs mean nothing
/// ever reads a dead attempt's directory.
#[tokio::test]
async fn torn_staging_residue_never_blocks_the_retry() {
    let Some((_, names)) = count_points().await else {
        eprintln!("skipping: `git` not on PATH");
        return;
    };

    #[derive(Clone, Copy, Debug)]
    enum Tear {
        TruncateBundle,
        EmptyDir,
    }

    let staging_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.starts_with("prepare::"))
        .map(|(k, _)| k)
        .collect();
    assert!(
        staging_indices.len() >= 6,
        "the staging phase has six instrumented steps, saw {names:?}",
    );
    for &k in &staging_indices {
        for tear in [Tear::TruncateBundle, Tear::EmptyDir] {
            let label = format!("k={k} ({}), {tear:?}", names[k]);
            let world = ApproveWorld::start()
                .await
                .expect("git existed for the counting run");
            let plan = CrashPlan::crash_at(k);
            run_until_crash(
                &plan,
                dispatch_message(world.approve_message(), &world.state),
            )
            .await
            .expect_crashed("k is within the counted range");

            // The crash abandoned the attempt's staging dir; tear it.
            let approve_root = world.work_root.join("approve");
            let dirs: Vec<PathBuf> = std::fs::read_dir(&approve_root)
                .unwrap_or_else(|err| panic!("staging root must exist after {label}: {err}"))
                .map(|entry| entry.unwrap().path())
                .collect();
            assert!(
                !dirs.is_empty(),
                "a staging-phase crash leaves residue at {label}",
            );
            for dir in &dirs {
                match tear {
                    Tear::TruncateBundle => {
                        std::fs::write(dir.join("staged.bundle"), b"").unwrap();
                    }
                    Tear::EmptyDir => {
                        for entry in std::fs::read_dir(dir).unwrap() {
                            let path = entry.unwrap().path();
                            if path.is_dir() {
                                std::fs::remove_dir_all(&path).unwrap();
                            } else {
                                std::fs::remove_file(&path).unwrap();
                            }
                        }
                    }
                }
            }

            let audit = reboot_and_reconcile(&world, &label).await;
            drive_to_approved(&world, &audit, &label).await;
            assert_single_publish(&world, &label);
        }
    }
}
