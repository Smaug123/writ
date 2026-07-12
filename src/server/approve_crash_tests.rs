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
//! sweep's upper bound. The sweep itself is Stage 5.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::test_support::{InMemStore, open_session};
use super::*;
use crate::audit::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState, GitPushResolution};
use crate::core::AgentKind;
use crate::crash_point::CrashPlan;
use crate::crash_point::run_until_crash;
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
    // dead_code allows: read by the Stage-5 sweep, which reboots the
    // audit DB from `audit_path` and anchors assertions on the origin.
    #[allow(dead_code)]
    pub(super) origin: FakeOrigin,
    pub(super) request_id: RequestId,
    /// The audit DB file — reopened across simulated reboots.
    #[allow(dead_code)]
    pub(super) audit_path: PathBuf,
    /// Owns staging store, work root and audit DB alike.
    pub(super) _tmp: tempfile::TempDir,
}

impl ApproveWorld {
    /// `None` when `git` is not on `PATH` (callers skip).
    pub(super) async fn start() -> Option<Self> {
        let origin = FakeOrigin::start().await?;
        let github = FakeGitHub::start(ORIGIN_OWNER, ORIGIN_NAME, INSTALLATION_ID).await;
        // GitHub's branch is at the prerequisite — exactly the state
        // the staged receipt's lease was taken against.
        github.set_ref(WORLD_BRANCH, origin.prereq().as_str());

        let tmp = tempfile::tempdir().expect("approve world tempdir");
        let audit_path = tmp.path().join("audit.sqlite3");
        let staging_store =
            GitPushStagingStore::open(tmp.path().join("staging")).expect("staging store opens");
        let work_root = tmp.path().join("promote");
        std::fs::create_dir_all(&work_root).expect("create work root");

        let git = maybe_git().expect("FakeOrigin::start returned Some, so git exists");
        let promote_runtime = crate::git_push_promote::PromoteRuntimeConfig::new(
            git,
            origin.clone_base_url(),
            GitCredentialBoundary::new(
                PathBuf::from("/usr/local/bin/fake-askpass"),
                GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
            )
            .unwrap(),
            work_root,
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

        let state = Arc::new(BrokerState {
            audit: Arc::new(AuditLog::open(&audit_path).expect("file-backed audit DB opens")),
            minter: GitHubMinter::new_registry(GitHubAppRegistryConfig::new(apps).unwrap()),
            secrets,
            policy: PolicyConfig {
                writable_repos: Vec::new(),
                default_ttl: crate::core::TtlSeconds::new(3600).unwrap(),
            },
            staging_store: Some(Arc::new(staging_store)),
            notes_repo: None,
            signing_key: Some(WritSigningKey::from_openssh_pem(SIGNING_PEM).unwrap()),
            run_agent_spawn: None,
            promote_runtime: Some(Arc::new(promote_runtime)),
            mirror_pins: crate::vm_git_mirror_cache::MirrorPins::new(),
        });

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
            _tmp: tmp,
        })
    }

    pub(super) fn approve_message(&self) -> ClientMessage {
        ClientMessage::ApproveStagedPush {
            request_id: self.request_id,
            operator: OPERATOR.into(),
        }
    }
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
