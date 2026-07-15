//! `ApproveStagedPush` state-machine tests and `truncate_for_wire` units.

use super::test_support::*;
use super::*;
use crate::audit::{GitPushApproveAttemptOutcome, GitPushApproveAttemptState};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mint failure (no GitHub mock for the access_tokens endpoint) must
/// drive the attempt to `Resolved(PrePatchFailure)` with no mint
/// captured — mint never produced a `MintedToken`, so there is no
/// `PromoteMintAudit` to record. The handler surfaces a generic
/// Error to the caller; no resolution row is written (the schema
/// trigger insists approved/rejected resolutions are operator
/// decisions, not failure side effects), and the staging dir
/// remains so the operator can retry once the GitHub App config is
/// healed.
#[tokio::test]
async fn approve_staged_push_mint_failure_resolves_attempt_as_pre_patch_failure() {
    let server = MockServer::start().await;
    // No `/app/installations/.../access_tokens` mock: the mint
    // request falls through wiremock's default 404 handler and
    // surfaces as a mint failure inside the handler.
    let (state, _tmp) = make_state_with_approve_ready(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("mint failed"),
                "expected mint-failure error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // Attempt row reached `Resolved(PrePatchFailure)` without a
    // mint context: the mint never succeeded, so the row carries
    // `mint: None`.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert_eq!(attempts.len(), 1);
    match &attempts[0].state {
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure { detail },
            mint,
            ..
        } => {
            assert!(mint.is_none(), "mint must not be captured on pre-mint fail");
            assert!(
                detail.contains("mint failed"),
                "failure detail must name the mint step: {detail}",
            );
        }
        other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
    }

    // No resolution row: PrePatchFailure leaves the push rejectable.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());

    // Staging dir is still there so reject (or a follow-up
    // approve) can act on the same staged push.
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// A prior `Rejected` resolution row makes the push immutable: any
/// follow-up approve must short-circuit with
/// `StagedPushAlreadyResolved` before starting an attempt or
/// minting a token. The check sits on the joined audit view so a
/// rejected-then-deleted-staging-dir push (the normal reject
/// outcome) still races correctly with a concurrent approve.
#[tokio::test]
async fn approve_staged_push_with_prior_resolution_short_circuits() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_approve_ready(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;

    state
        .audit
        .record_git_push_resolution(&crate::audit::GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at: UnixMillis::from_millis(1_700_000_041_000),
            decision: crate::audit::GitPushResolution::Rejected,
            operator: "bob",
            reason: "not ready",
        })
        .unwrap();

    // Belt-and-braces: a mock with `expect(0)` on the mint endpoint
    // would panic if the handler reached the mint step. The short-
    // circuit must fire before that.
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    assert_eq!(
        resp,
        ServerMessage::StagedPushAlreadyResolved { request_id }
    );

    // No attempt row created: the short-circuit fires before
    // `start_approve_attempt`.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert!(attempts.is_empty());
}

/// Branch-creation pushes (no `expected_remote_head`) are refused
/// by the handler before any attempt or mint: the fast-forward
/// planner needs a lease anchor, and approve does not yet have a
/// safe story for creating a brand-new branch via PUT. Refusing
/// here gives the operator a clear diagnostic instead of letting
/// the request fail deeper in the pipeline.
#[tokio::test]
async fn approve_staged_push_for_branch_creation_returns_error() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_approve_ready(&server);
    let session_id = open_session(&state).await;

    // Build a staged push whose audit row has
    // `expected_remote_head = None`. Mirrors `stage_with_audit`
    // but with a hand-rolled metadata that carries no parent.
    let request_id = RequestId::new();
    let metadata = crate::vm_git::VmGitPushMetadata::new(
        sample_clone_repo(),
        sample_branch(),
        None,
        sample_object_id('b'),
    );
    let staging = state.staging_store.as_ref().unwrap().clone();
    let bundle = b"bundle".to_vec();
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
            repo: sample_clone_repo(),
            branch: sample_branch(),
            expected_remote_head: None,
            new_head: sample_object_id('b'),
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

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("branch-creation"),
                "expected branch-creation refusal, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // No attempt row: refusal happens before
    // `start_approve_attempt`.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert!(attempts.is_empty());
}

/// Drive an approve against a push whose on-disk carrier metadata
/// diverges from the audit request row (modelling a local-disk fault or
/// tamper) and assert the handler fails closed: an `Error` naming the
/// carrier/audit divergence, no attempt row started, no credential
/// minted, no resolution written, and the carrier left intact for
/// operator triage.
async fn assert_carrier_audit_drift_refused(
    carrier: crate::vm_git::VmGitPushMetadata,
    audited: crate::vm_git::VmGitPushMetadata,
) {
    let server = MockServer::start().await;
    // `expect(0)` on the mint endpoint: reaching the mint step is a test
    // failure — the divergence must be caught before any credential is
    // minted.
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let (state, _tmp) = make_state_with_approve_ready(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_carrier_diverging_from_audit(
        &state,
        session_id,
        carrier,
        audited,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("does not match the audit record"),
                "expected carrier/audit divergence refusal, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // No attempt row: the refusal fires before `start_approve_attempt`,
    // so no credential is minted and the push stays rejectable.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert!(
        attempts.is_empty(),
        "divergence must be caught before an attempt is started",
    );

    // No resolution row and the carrier is intact: the operator can
    // investigate the drift and reject (or repair) the push.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// A carrier that names a different repo than the audit row must be
/// refused: minting `contents:write` and pushing against the carrier
/// repo would redirect the real write while the audit retains the
/// original repo.
#[tokio::test]
async fn approve_refuses_when_carrier_repo_diverges_from_audit() {
    assert_carrier_audit_drift_refused(
        crate::vm_git::VmGitPushMetadata::new(
            "owner/other".parse().unwrap(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
    )
    .await;
}

/// A carrier that names a different branch than the audit row must be
/// refused: the PATCH moves the carrier branch, so a tampered branch
/// redirects the write to a ref the operator never reviewed.
#[tokio::test]
async fn approve_refuses_when_carrier_branch_diverges_from_audit() {
    assert_carrier_audit_drift_refused(
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            "feature/y".parse().unwrap(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
    )
    .await;
}

/// A carrier that names a different tip than the audit row must be
/// refused: the PATCH sets the branch to the carrier `new_head`, so a
/// tampered tip advances the branch to a commit the operator never
/// reviewed.
#[tokio::test]
async fn approve_refuses_when_carrier_new_head_diverges_from_audit() {
    assert_carrier_audit_drift_refused(
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('c'),
        ),
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
    )
    .await;
}

/// A carrier that names a different lease anchor than the audit row must
/// be refused: `expected_remote_head` is the fast-forward lease the
/// PATCH is guarded on, so a tampered anchor can smuggle a push past a
/// lease the operator's review assumed.
#[tokio::test]
async fn approve_refuses_when_carrier_expected_remote_head_diverges_from_audit() {
    assert_carrier_audit_drift_refused(
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('c')),
            sample_object_id('b'),
        ),
        crate::vm_git::VmGitPushMetadata::new(
            sample_clone_repo(),
            sample_branch(),
            Some(sample_object_id('a')),
            sample_object_id('b'),
        ),
    )
    .await;
}

/// An approve failure that fires before `update_ref` (e.g. the
/// `git init --bare` in `prepare_staging_repo` because the configured
/// `git_program` is bogus) must drive the attempt from `Started`
/// straight to `Resolved(PrePatchFailure)` — never through `Uncertain`,
/// which is reserved for the PATCH round-trip. The mint context is
/// captured on the resolved row even so (the credential *was* burned),
/// and reject becomes legal again because the trigger admits reject
/// when every attempt is `PrePatchFailure`.
#[tokio::test]
async fn approve_staged_push_run_approve_failure_resolves_as_pre_patch_failure() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_approve_ready(&server);
    // `make_state_with_approve_ready` wires git_program to
    // `/nonexistent/bin/git`, so `prepare_staging_repo`'s
    // `git init --bare` fails — exactly the pre-PATCH failure
    // mode this test wants to exercise.
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;

    let expiry = expiry_str_from_now(3600);
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_test_token",
            "expires_at": expiry,
            "permissions": {"contents": "write", "metadata": "read"},
            "repository_selection": "selected",
            "repositories": [{"full_name": "owner/repo"}],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("staging preparation failed")
                    || message.contains("approve pipeline failed"),
                "expected pre-PATCH pipeline failure, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // Attempt row reached `Resolved(PrePatchFailure)` carrying the mint
    // context. It got there from `Started`:
    // `complete_attempt_pre_patch_failure_capturing_mint` is the only
    // DAO method that writes mint columns on a resolve, and it refuses
    // any state other than `Started` — so this row is also proof that
    // the pipeline never entered `Uncertain`.
    let attempts = state.audit.approve_attempts_for_push(request_id).unwrap();
    assert_eq!(attempts.len(), 1);
    match &attempts[0].state {
        GitPushApproveAttemptState::Resolved {
            outcome: GitPushApproveAttemptOutcome::PrePatchFailure { detail },
            mint,
            ..
        } => {
            assert!(
                mint.is_some(),
                "the burned credential must be recorded on the resolved row",
            );
            assert!(
                detail.contains("run_approve failed"),
                "failure detail must name the pipeline step: {detail}",
            );
            // The v7 mint ledger was written *before* the prepare phase
            // started, and it agrees with the resolved row — this is the
            // durable record that would have survived had the broker
            // crashed instead of failing cleanly.
            let recorded = state
                .audit
                .attempt_recorded_mint(attempts[0].attempt_id)
                .unwrap();
            assert_eq!(
                recorded, *mint,
                "mint ledger must agree with the resolved row's mint",
            );
        }
        other => panic!("expected Resolved(PrePatchFailure), got {other:?}"),
    }

    // PrePatchFailure leaves the push rejectable: no resolution
    // row, staging dir still on disk.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// Crash residue must not brick retries. A broker that dies
/// mid-prepare leaves the per-attempt staging repo on disk (its
/// cleanup never ran); boot reconcile resolves the *audit* row but is
/// deliberately filesystem-blind. A fresh approve for the same push
/// must therefore never collide with the residue — staging dirs are
/// keyed by attempt id, which is minted fresh per approve — so the
/// retry proceeds to the real pipeline instead of failing
/// `StagingDirExists` forever.
#[tokio::test]
async fn approve_retry_is_not_blocked_by_crash_leftover_staging_dir() {
    let server = MockServer::start().await;
    let (state, tmp) = make_state_with_approve_ready(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;

    // Simulate a prior attempt that died mid-prepare: its staging dir
    // is still on disk. (Keyed by the *push request id* it would
    // collide with every retry; keyed by attempt id it never can. The
    // request-id path is the pre-fix layout — a retry must tolerate
    // residue at either.)
    let residue = tmp
        .path()
        .join("promote")
        .join("approve")
        .join(request_id.to_string());
    std::fs::create_dir_all(&residue).unwrap();

    let expiry = expiry_str_from_now(3600);
    Mock::given(method("POST"))
        .and(path("/app/installations/999/access_tokens"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_test_token",
            "expires_at": expiry,
            "permissions": {"contents": "write", "metadata": "read"},
            "repository_selection": "selected",
            "repositories": [{"full_name": "owner/repo"}],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;

    // The bogus `git_program` makes the pipeline fail at `git init`,
    // which is fine — what must NOT happen is a refusal because the
    // residue directory already exists.
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                !message.contains("already exists"),
                "crash residue must not block the retry: {message}",
            );
        }
        other => panic!("expected Error from the bogus git binary, got {other:?}"),
    }
}

#[test]
fn truncate_for_wire_passes_short_input_through() {
    let s = "hello".to_string();
    assert_eq!(truncate_for_wire(s.clone(), 16), s);
}

#[test]
fn truncate_for_wire_passes_exact_cap_through() {
    // At exactly `cap` bytes there is nothing to truncate; the
    // sentinel marker must not be appended.
    let s = "x".repeat(8);
    assert_eq!(truncate_for_wire(s.clone(), 8), s);
}

#[test]
fn truncate_for_wire_caps_oversize_input_and_appends_marker() {
    let s = "x".repeat(10);
    let out = truncate_for_wire(s, 4);
    assert_eq!(out, "xxxx... [truncated]");
}

#[test]
fn truncate_for_wire_respects_utf8_boundary_when_cap_lands_mid_codepoint() {
    // "é" is a two-byte UTF-8 sequence (0xC3 0xA9). With cap=1 the
    // naive split would land between the two bytes; the helper must
    // back up to the previous char boundary so the result is valid
    // UTF-8.
    let s = "é".to_string();
    let out = truncate_for_wire(s.clone(), 1);
    // s is 2 bytes so cap=1 triggers truncation; the prefix before
    // the marker must be empty (the only char boundary at-or-below
    // 1 is 0).
    assert_eq!(out, "... [truncated]");
}

/// Operator validation runs before the configured-state checks so a
/// caller can never use a malformed operator field to probe the
/// broker's internal config shape. An empty operator is rejected
/// with the same message the reject path uses.
#[tokio::test]
async fn approve_staged_push_with_empty_operator_returns_error() {
    let server = MockServer::start().await;
    // Use the plain (un-staging) state to prove the validation
    // short-circuits before the staging check fires.
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id: RequestId::new(),
            operator: String::new(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("operator identity must not be empty"),
                "expected empty-operator error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// Same shape as the empty-operator test: oversize operators (over
/// `MAX_OPERATOR_BYTES`) are rejected before any disk IO so a
/// caller can't pad the audit log via the operator field. The cap
/// is shared with the reject path.
#[tokio::test]
async fn approve_staged_push_with_oversize_operator_returns_error() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let oversize = "x".repeat(MAX_OPERATOR_BYTES + 1);
    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id: RequestId::new(),
            operator: oversize,
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("exceeding the"),
                "expected oversize-operator error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// If `staging_store` is unset the broker can never have produced
/// a staged push receipt for this `request_id` in the first place,
/// so the right surface is "not configured" rather than
/// `UnknownStagedPush`. Same shape as the reject path's
/// `staging_not_configured` response.
#[tokio::test]
async fn approve_staged_push_without_staging_store_returns_not_configured() {
    let server = MockServer::start().await;
    let state = make_state(&server, vec![], "o");
    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("git push staging is not configured"),
                "expected staging-not-configured error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// `staging_store` is wired but `promote_runtime` is not: the load
/// step would technically be runnable, but kicking it off without
/// `promote_runtime` would just succeed and then dead-end at the
/// mint slice. Returning a "not configured" error here gives the
/// operator a precise diagnosis instead.
#[tokio::test]
async fn approve_staged_push_without_promote_runtime_returns_not_configured() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_staging(&server);
    let session_id = open_session(&state).await;
    let request_id = stage_with_staged_outcome(
        &state,
        session_id,
        b"bundle".to_vec(),
        UnixMillis::from_millis(1_700_000_040_000),
        UnixMillis::from_millis(1_700_000_040_500),
    )
    .await;
    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id,
            operator: "alice".into(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("promote_runtime is unset"),
                "expected promote_runtime-not-configured error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
    // The configured-state check must not have written an audit
    // row or removed the staging dir.
    let audit_entry = state.audit.get_git_push(request_id).unwrap().unwrap();
    assert!(audit_entry.resolution.is_none());
    assert!(
        state
            .staging_store
            .as_ref()
            .unwrap()
            .load(request_id)
            .is_ok()
    );
}

/// `staging_store` and `promote_runtime` are both wired but
/// `signing_key` is not. Without the signing key, the eventual
/// `run_approve` call would have no app-identity to sign the
/// replayed commits with — same diagnosis pattern as
/// `promote_runtime`.
#[tokio::test]
async fn approve_staged_push_without_signing_key_returns_not_configured() {
    use crate::git_push_promote::PromoteRuntimeConfig;
    use crate::vm_git_bundle::{GitCloneBaseUrl, GitCredentialBoundary, GitSecretEnvVar};
    let server = MockServer::start().await;
    let (mut state, tmp) = make_state_with_staging(&server);
    let runtime = PromoteRuntimeConfig::new(
        PathBuf::from("/nonexistent/bin/git"),
        GitCloneBaseUrl::github(),
        GitCredentialBoundary::new(
            PathBuf::from("/nonexistent/bin/askpass"),
            GitSecretEnvVar::new("WRIT_GIT_TOKEN").unwrap(),
        )
        .unwrap(),
        tmp.path().join("promote"),
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    let inner = Arc::get_mut(&mut state).expect("fresh Arc has no other handles");
    inner.promote_runtime = Some(Arc::new(runtime));
    // signing_key intentionally left None.

    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id: RequestId::new(),
            operator: "alice".into(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("signing_key is unset"),
                "expected signing_key-not-configured error, got: {message}",
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

/// A request_id with no corresponding staging dir on disk must
/// surface as `UnknownStagedPush`, not a generic Error — the
/// reject path uses the same convention. This lets the CLI render
/// "no such staged push" cleanly instead of leaking IO error text.
#[tokio::test]
async fn approve_staged_push_with_unknown_request_returns_unknown_staged_push() {
    let server = MockServer::start().await;
    let (state, _tmp) = make_state_with_approve_ready(&server);
    let unknown = RequestId::new();
    let resp = dispatch_message(
        ClientMessage::ApproveStagedPush {
            request_id: unknown,
            operator: "alice".into(),
        },
        &state,
    )
    .await;
    match resp {
        ServerMessage::UnknownStagedPush { request_id } => {
            assert_eq!(request_id, unknown);
        }
        other => panic!("expected UnknownStagedPush, got {other:?}"),
    }
}
