//! Staged-push approval subsystem: the `list`, `show`, `reject`,
//! `approve`, and `reconcile` handlers for the git-push staging flow,
//! plus their helpers.
//!
//! These handlers are dispatched from [`super::dispatch_message_with_agent_vm`];
//! socket transport and the agent-run path stay in the parent [`super`]
//! module. Tests drive them through `dispatch_message` rather than calling
//! in directly. Extracted from `server.rs` to keep the dispatcher readable;
//! behaviour is unchanged.

use super::*;

pub(super) async fn list_staged_pushes<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    session_id: Option<SessionId>,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    let receipts = match session_id {
        // No filter: scan the whole staging directory. Sync work hops
        // off the async runtime so a directory-walk on a slow
        // filesystem doesn't block other connections.
        None => match tokio::task::spawn_blocking(move || staging_store.list()).await {
            Ok(Ok(receipts)) => receipts,
            Ok(Err(err)) => {
                return ServerMessage::Error {
                    message: err.to_string(),
                };
            }
            Err(err) => {
                return ServerMessage::Error {
                    message: format!("staging list task failed: {err}"),
                };
            }
        },
        // Session filter: drive the lookup off the audit log, which is
        // the source of truth for which request ids belong to a given
        // session. Loading by id (rather than scanning every staging
        // dir and then filtering) keeps the filtered path's blast
        // radius scoped to the entries the audit log actually names:
        // an unrelated malformed sibling directory (e.g. left by
        // external tampering) won't surface as an error from a
        // session-filtered call it has nothing to do with.
        //
        // Audit rows whose staging directory is gone (the natural state
        // for a previously approved/rejected push) are silently skipped:
        // the request id is part of the session's history but the
        // staged entry is no longer waiting for review. A staging entry
        // that is *present but corrupt* for an audit-named id is still
        // a real broker invariant violation and surfaces as Error — the
        // audit log promised this entry; if it doesn't parse, the
        // operator should see that, not get an empty list.
        Some(session_id) => {
            let audit = Arc::clone(&state.audit);
            let request_ids: Vec<RequestId> = match tokio::task::spawn_blocking(move || {
                audit.list_git_pushes_for_session(session_id)
            })
            .await
            {
                Ok(Ok(rows)) => rows.into_iter().map(|row| row.push_request_id).collect(),
                Ok(Err(err)) => {
                    return ServerMessage::Error {
                        message: err.to_string(),
                    };
                }
                Err(err) => {
                    return ServerMessage::Error {
                        message: format!("audit list task failed: {err}"),
                    };
                }
            };

            // Per-id staging reads on one blocking task (rather than
            // spawn_blocking per id) keeps the task-spawn overhead
            // bounded on sessions with many pushes.
            let load = tokio::task::spawn_blocking(move || {
                let mut receipts = Vec::with_capacity(request_ids.len());
                for id in request_ids {
                    if let Some(receipt) = staging_store.try_load_receipt(id)? {
                        receipts.push(receipt);
                    }
                }
                Ok::<_, StagingError>(receipts)
            })
            .await;
            match load {
                Ok(Ok(receipts)) => receipts,
                Ok(Err(err)) => {
                    return ServerMessage::Error {
                        message: err.to_string(),
                    };
                }
                Err(err) => {
                    return ServerMessage::Error {
                        message: format!("staging load task failed: {err}"),
                    };
                }
            }
        }
    };

    let pushes = receipts
        .iter()
        .map(StagedPushSummary::from_receipt)
        .collect();
    ServerMessage::StagedPushes { pushes }
}

pub(super) async fn show_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };
    let entry = match load_staged_entry(&staging_store, request_id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };

    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    let audit_entry = match audit_lookup {
        Ok(Ok(Some(entry))) => entry,
        Ok(Ok(None)) => {
            // Staged on disk but no audit row — broker invariant violation.
            // Surface explicitly rather than fabricating a `received_at`.
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has no audit record; \
                     promotion cannot proceed until the broker state is repaired",
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            };
        }
    };

    let (receipt, bundle) = entry.into_parts();
    let bundle_bytes = bundle.len() as u64;
    let summary = StagedPushSummary::from_receipt(&receipt);
    let audit = StagedPushAuditView {
        session_id: audit_entry.session_id,
        received_at: audit_entry.received_at,
        result: audit_entry.result,
    };
    ServerMessage::StagedPush {
        push: StagedPushDetail {
            summary,
            bundle_bytes,
            audit,
        },
    }
}

/// Cap on the operator string the broker will accept. The audit row's
/// `operator` column is unbounded text, so the broker enforces a sane
/// upper bound at the wire boundary to keep a malformed CLI from
/// bloating the audit DB. The local socket is the trust boundary; the
/// operator field is informational only.
pub(crate) const MAX_OPERATOR_BYTES: usize = 256;

/// Reject an empty or oversize operator identity before any IO, so a
/// caller cannot probe broker state via a malformed identity field.
/// Shared verbatim by reject/approve/reconcile; the limit and the
/// wording live in one place. Returns `Some(error_response)` when the
/// operator is invalid, `None` when it passes.
fn validate_operator(operator: &str) -> Option<ServerMessage> {
    if operator.is_empty() {
        return Some(ServerMessage::Error {
            message: "operator identity must not be empty".into(),
        });
    }
    if operator.len() > MAX_OPERATOR_BYTES {
        return Some(ServerMessage::Error {
            message: format!(
                "operator identity is {} bytes, exceeding the {MAX_OPERATOR_BYTES}-byte limit",
                operator.len(),
            ),
        });
    }
    None
}

/// Load a staging entry off the blocking pool, mapping the absence of a
/// staging directory to a clean `UnknownStagedPush`. Every staged-push
/// handler probes staging through here so they agree on what "the
/// staging is gone" means: a missing dir is `UnknownStagedPush`, a
/// failed `spawn_blocking` join is a generic `Error`. Callers that only
/// need an existence check discard the returned [`StagedEntry`].
async fn load_staged_entry(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) -> Result<StagedEntry, ServerMessage> {
    let staging_store = Arc::clone(staging_store);
    match tokio::task::spawn_blocking(move || staging_store.load(request_id)).await {
        Ok(Ok(entry)) => Ok(entry),
        Ok(Err(StagingError::NotFound { request_id })) => {
            Err(ServerMessage::UnknownStagedPush { request_id })
        }
        Ok(Err(err)) => Err(ServerMessage::Error {
            message: err.to_string(),
        }),
        Err(err) => Err(ServerMessage::Error {
            message: format!("staging load task failed: {err}"),
        }),
    }
}

pub(super) async fn reject_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
    reason: RejectionReason,
) -> ServerMessage {
    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    if let Some(resp) = validate_operator(&operator) {
        return resp;
    }

    // Verify the staging directory exists before touching the audit
    // log. Matching `show_staged_push`'s ordering lets the two endpoints
    // agree on what "the staging is gone" means and gives the operator
    // a clean `UnknownStagedPush` instead of a trigger-violation error
    // when the dir was already deleted by a prior reject.
    if let Err(resp) = load_staged_entry(&staging_store, request_id).await {
        return resp;
    }

    // Consult the approve-attempt state machine before attempting the
    // INSERT. The `git_push_resolution_refuses_active_approve` trigger
    // is the load-bearing correctness piece (it refuses contradictory
    // commits at the SQL boundary), but its raw `RAISE(ABORT, ...)`
    // text is opaque to the operator. Calling `reject_blocker_for_push`
    // first lets the handler surface a typed diagnostic that names the
    // attempt and points at the operator action. The trigger-mapping
    // below covers the SELECT-vs-INSERT race where a fresh `Started`
    // row lands in the gap.
    match preflight_reject_blocker(state, request_id).await {
        Ok(None) => {}
        Ok(Some(blocker)) => {
            return reject_blocker_response(&staging_store, request_id, blocker).await;
        }
        Err(message) => return ServerMessage::Error { message },
    }

    let decided_at = UnixMillis::now();
    let reason_owned = reason.as_str().to_string();
    let operator_owned = operator.clone();
    let audit = Arc::clone(&state.audit);
    let resolution_result = tokio::task::spawn_blocking(move || {
        audit.record_git_push_resolution(&GitPushResolutionRecord {
            push_request_id: request_id,
            decided_at,
            decision: GitPushResolution::Rejected,
            operator: &operator_owned,
            reason: &reason_owned,
        })
    })
    .await;
    match resolution_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The PK on `git_push_resolution.push_request_id` surfaces
            // as a SQLite "UNIQUE constraint" error when a previous
            // decision is already recorded. The trigger that requires a
            // `staged` outcome row surfaces with the literal message
            // pinned in the migration. Other SQL errors are broker
            // invariant violations.
            if is_unique_constraint_violation(&err) {
                // A prior `Rejected` decision means the staging dir
                // should already be gone. If we still saw it on disk
                // above, the previous reject's cleanup failed mid-way:
                // retry the delete here so the operator has a recovery
                // path instead of the dir staying stuck in
                // `promote list`. `Approved` is left alone because Stage
                // D's promotion flow owns that directory's lifecycle.
                retry_cleanup_for_rejected(state, &staging_store, request_id).await;
                return ServerMessage::StagedPushAlreadyResolved { request_id };
            }
            if is_active_approve_refusal(&err) {
                // The defence-in-depth path: an attempt row landed
                // between our preflight blocker check and this INSERT,
                // and the trigger refused the commit. Re-query so the
                // operator gets the same typed diagnostic the preflight
                // path would have produced.
                match preflight_reject_blocker(state, request_id).await {
                    Ok(Some(blocker)) => {
                        return reject_blocker_response(&staging_store, request_id, blocker).await;
                    }
                    // The blocker disappeared between the trigger
                    // firing and the re-query (e.g. the racing approve
                    // resolved to PrePatchFailure). This is a stale
                    // refusal — the row is now insertable. Rather than
                    // retry here and risk an infinite-loop interaction
                    // with whatever wrote the row, surface a concrete
                    // diagnostic so the operator retries explicitly.
                    Ok(None) => {
                        return ServerMessage::Error {
                            message: format!(
                                "staged push {request_id} reject was refused by an in-flight \
                                 approve attempt that has since resolved; retry the reject"
                            ),
                        };
                    }
                    Err(message) => return ServerMessage::Error { message },
                }
            }
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_resolution",
                request_id = %request_id,
                error = %err,
                "audit write failed: staged push reject not recorded",
            );
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit write task failed: {err}"),
            };
        }
    }

    // Audit row committed. Delete the staging dir last so that if the
    // delete fails, the next call sees both the audit row and the dir
    // and returns `StagedPushAlreadyResolved` rather than silently
    // reporting success without removing the on-disk artifact.
    let delete_result = {
        let staging_store = Arc::clone(&staging_store);
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
    };
    match delete_result {
        Ok(Ok(())) => ServerMessage::StagedPushRejected { request_id },
        Ok(Err(err)) => ServerMessage::Error {
            message: format!(
                "staged push {request_id} was recorded as rejected but the staging \
                 directory could not be removed: {err}"
            ),
        },
        Err(err) => ServerMessage::Error {
            message: format!("staging delete task failed: {err}"),
        },
    }
}

/// TTL for the GitHub installation token minted by an approve decision.
///
/// GitHub returns ~1h installation tokens regardless of what we request
/// and the minter rejects responses where `expires_at` exceeds
/// `issued_at + ttl + TTL_SKEW_TOLERANCE_SECONDS`. Setting the ceiling
/// any lower than [`GITHUB_INSTALLATION_TOKEN_MAX_SECONDS`] makes every
/// real mint fail with `TtlExceeded`. The minter's TTL is an
/// *accept-back* bound on the GitHub-returned expiry, not a request the
/// server honours — pinning it at the GitHub-imposed maximum is the
/// only correct setting. The credential's actual lifetime is bounded by
/// the duration of this single approve invocation; the broker drops
/// the token (and the only reference to it) once the pipeline
/// completes.
const APPROVE_MINT_TTL_SECONDS: i64 = GITHUB_INSTALLATION_TOKEN_MAX_SECONDS;

/// Handler for [`ClientMessage::ApproveStagedPush`].
///
/// Drives the approve-attempt state machine defined in
/// `docs/design/approve_state_machine.md`. Each invocation creates one
/// `git_push_approve_attempt` row; the row transitions
/// `Started → Uncertain → Resolved` (or `Started → Resolved` on a
/// pre-mint failure) with the schema's forward-only trigger enforcing
/// the order. The state machine — not a filesystem marker, not an
/// in-memory mutex — is the load-bearing piece that gates reject and
/// the only durable state approve mutates outside of GitHub.
///
/// Flow:
///
///   1. Validate `operator` (non-empty, bounded) before any IO so a
///      caller cannot probe broker state via a malformed identity field.
///   2. Check the three configured-state slots (`staging_store`,
///      `promote_runtime`, `signing_key`) so a not-configured broker
///      returns a precise diagnosis rather than dead-ending later.
///   3. Load the staging entry atomically (receipt + bundle bytes); a
///      missing entry surfaces as `UnknownStagedPush`.
///   4. Read the joined audit view via [`AuditLog::get_git_push`]:
///        * **Early short-circuit** on a prior resolution row — no
///          attempt is started and no credential is wasted.
///        * Refuse if no `Staged` outcome row exists (the staging dir
///          and the audit log have drifted apart — operator must
///          investigate).
///        * Refuse a branch-creation push (no `expected_remote_head`):
///          the walker needs a lease anchor a fresh branch does not
///          have. Documented gap; failing closed is the right shape.
///   5. Look up the originating session for `agent_kind`. The session
///      is by definition closed by now; `get_session` reads it just the
///      same.
///   6. `start_approve_attempt`: insert `Started` row. The DAO refuses
///      if any attempt is `Started`/`Uncertain` or
///      `Resolved(PostPatchFailure)` — those are the
///      reject-blocking states and would also block a fresh approve.
///   7. Mint a one-shot installation token. On failure: transition the
///      attempt to `Resolved(PrePatchFailure)` (no mint to capture).
///   8. `record_attempt_mint`: persist the burned credential's identity
///      in the append-only mint ledger *before* anything uses it, so a
///      crash anywhere in the prepare phase cannot lose which credential
///      was issued. On failure: `Resolved(PrePatchFailure)` capturing
///      the mint on the resolved row directly.
///   9. Run [`prepare_approve`] against the staging entry — staging
///      fetch, unbundle, plan, and every object upload — with the
///      attempt row still `Started`. None of that can move the branch,
///      so a crash here is auto-recovered by boot reconcile (which
///      copies the ledger mint onto the row it resolves). On a returned
///      error: `Resolved(PrePatchFailure)` capturing the mint — every
///      [`RunApproveError`] is pre-PATCH by construction.
///  10. `mark_attempt_uncertain`: capture the mint context inline on
///      the attempt row. **This is the TX that commits the broker to
///      "the PATCH may exist on GitHub"** — reject is refused from this
///      point until the attempt resolves. It yields the
///      [`crate::audit::UncertainAttempt`] witness, the only key that
///      opens [`crate::git_push_approve::PreparedApprove::commit`].
///  11. `PreparedApprove::commit` re-verifies the lease one last time
///      and issues the single branch-moving `PATCH`. Its error type
///      splits by proof: the `FinalLease*` variants fire before the
///      `PATCH` is sent (branch provably untouched →
///      `Resolved(PrePatchFailure)`, push stays retryable), and
///      `CommitError::UpdateRef` proves a `PATCH` reached GitHub
///      without a confirmed response →
///      `complete_attempt_post_patch_failure` (quarantines the push).
///  12. On success: `complete_attempt_succeeded` atomically transitions
///      the attempt to `Resolved(Succeeded)` *and* writes the
///      `git_push_resolution(decision='approved')` row in a single
///      SQLite transaction (the resolution-INSERT trigger sees the
///      attempt already at `succeeded` and lets the row through).
///  13. Staging-dir delete is best-effort after the joint TX; failures
///      are logged. A stale dir surfaces in `promote list` for manual
///      cleanup.
///
/// The token's `api_base` is plumbed straight through from
/// [`crate::github::MintedToken::into_promote_pieces`] — using a
/// different base would mint against one GitHub instance and call the
/// Git Data REST API against another, which the consume-and-pair shape
/// rules out at compile time.
pub(super) async fn approve_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
) -> ServerMessage {
    if let Some(resp) = validate_operator(&operator) {
        return resp;
    }

    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };
    let Some(promote_runtime) = state.promote_runtime.clone() else {
        return approve_staged_push_not_configured("promote_runtime");
    };
    let Some(signing_key) = state.signing_key.clone() else {
        return approve_staged_push_not_configured("signing_key");
    };

    let entry = match load_staged_entry(&staging_store, request_id).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };

    let agent_kind = match check_approvable_push(state, request_id, entry.receipt()).await {
        Ok(agent_kind) => agent_kind,
        Err(resp) => return resp,
    };

    let attempt_id = match start_approve_attempt_row(state, request_id, &operator).await {
        Ok(attempt_id) => attempt_id,
        Err(resp) => return resp,
    };
    crate::crash_point::point("approve::attempt_started").await;

    let new_app_tip = match execute_started_attempt(
        state,
        attempt_id,
        request_id,
        &operator,
        agent_kind,
        entry,
        &promote_runtime,
        &signing_key,
    )
    .await
    {
        Ok(new_app_tip) => new_app_tip,
        Err(resp) => return resp,
    };

    delete_staging_after_approve(&staging_store, request_id).await;

    ServerMessage::StagedPushApproved {
        request_id,
        new_app_tip,
    }
}

/// Compare the on-disk staged carrier's metadata against the audited
/// request row, returning a human-readable description of every field
/// that has drifted (or `None` when they agree). The two are written
/// from a single `VmGitPushMetadata` at staging time, so any divergence
/// is local corruption or tampering; each drifted field is named with
/// both sides so an operator can see exactly how the carrier was altered.
fn carrier_audit_divergence(
    receipt: &crate::vm_git::VmGitPushStagedReceipt,
    audit_entry: &crate::audit::GitPushAuditEntry,
) -> Option<String> {
    let mut drift: Vec<String> = Vec::new();
    if receipt.repo() != &audit_entry.repo {
        drift.push(format!(
            "repo: carrier {}, audit {}",
            receipt.repo(),
            audit_entry.repo
        ));
    }
    if receipt.branch() != &audit_entry.branch {
        drift.push(format!(
            "branch: carrier {}, audit {}",
            receipt.branch(),
            audit_entry.branch
        ));
    }
    if receipt.expected_remote_head() != audit_entry.expected_remote_head.as_ref() {
        drift.push(format!(
            "expected_remote_head: carrier {:?}, audit {:?}",
            receipt.expected_remote_head().map(ToString::to_string),
            audit_entry
                .expected_remote_head
                .as_ref()
                .map(ToString::to_string),
        ));
    }
    if receipt.new_head() != &audit_entry.new_head {
        drift.push(format!(
            "new_head: carrier {}, audit {}",
            receipt.new_head(),
            audit_entry.new_head
        ));
    }
    if drift.is_empty() {
        None
    } else {
        Some(drift.join("; "))
    }
}

/// Read the joined audit view and confirm the push is approvable,
/// returning the originating session's `agent_kind` (the GitHub App to
/// mint against). Refuses — without starting an attempt — on a prior
/// resolution, a missing `Staged` outcome row, a staged carrier whose
/// metadata has drifted from the audit row, or a branch-creation push
/// (no `expected_remote_head`, which the walker's lease anchor requires).
///
/// `receipt` is the metadata read back from the on-disk carrier; the
/// consistency check below proves it agrees with the audit row before
/// the mint and PATCH downstream trust it as the write target.
async fn check_approvable_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    receipt: &crate::vm_git::VmGitPushStagedReceipt,
) -> Result<Option<crate::core::AgentKind>, ServerMessage> {
    // Joined audit view: the source of truth for the prior-resolution
    // short-circuit (so a duplicate approve never starts an attempt or
    // wastes a mint), the outcome-row precondition, and the session-id
    // we need to select the GitHub App.
    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    let audit_entry = match audit_lookup {
        Ok(Ok(Some(entry))) => entry,
        Ok(Ok(None)) => {
            return Err(ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has a staging directory but no audit row; \
                     broker audit log and staging store have drifted apart"
                ),
            });
        }
        Ok(Err(err)) => {
            return Err(ServerMessage::Error {
                message: format!("audit lookup failed: {err}"),
            });
        }
        Err(err) => {
            return Err(ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            });
        }
    };

    if audit_entry.resolution.is_some() {
        return Err(ServerMessage::StagedPushAlreadyResolved { request_id });
    }

    if audit_entry.result != Some(GitPushOutcomeResult::Staged) {
        return Err(ServerMessage::Error {
            message: format!(
                "staged push {request_id} has no `staged` outcome row \
                 (audit result: {:?}); refusing to approve a push that is not staged",
                audit_entry.result,
            ),
        });
    }

    // Defence in depth: the staged carrier and the audit request row are
    // two persisted copies of one `VmGitPushMetadata`, written together
    // when the push was accepted (see `vm_http::git_push`), so under
    // normal operation they agree on repo, branch, lease anchor, and tip.
    // The mint scope and the branch-moving PATCH downstream are driven
    // entirely from the *carrier*; the audit log records the *intent*
    // an operator reviews. A local-disk fault or tamper that drifts the
    // carrier from the audit row would redirect the real write while the
    // audit retains the original intent — so refuse before minting. The
    // audit log is the source of truth; a diverged carrier is corruption,
    // and correctness beats availability here. Refusing (rather than
    // preferring one side) keeps the carrier intact for operator triage.
    if let Some(divergence) = carrier_audit_divergence(receipt, &audit_entry) {
        return Err(ServerMessage::Error {
            message: format!(
                "staged push {request_id} carrier metadata does not match the audit record \
                 ({divergence}); refusing to approve a push whose on-disk carrier has drifted \
                 from the audited intent"
            ),
        });
    }

    if audit_entry.expected_remote_head.is_none() {
        return Err(ServerMessage::Error {
            message: format!(
                "staged push {request_id} is a branch-creation push \
                 (no expected_remote_head); approve does not yet support branch creation"
            ),
        });
    }

    let session_id = audit_entry.session_id;
    let session_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_session(session_id)).await
    };
    let session = match session_lookup {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            return Err(ServerMessage::Error {
                message: format!(
                    "staged push {request_id} references session {session_id} \
                     but that session is not in the audit log"
                ),
            });
        }
        Ok(Err(err)) => {
            return Err(ServerMessage::Error {
                message: format!("session lookup failed: {err}"),
            });
        }
        Err(err) => {
            return Err(ServerMessage::Error {
                message: format!("session lookup task failed: {err}"),
            });
        }
    };

    Ok(session.agent_kind)
}

/// Insert the durable `Started` attempt row that gates concurrent
/// approve/reject. A `Started` row written here survives a crash: the
/// DAO refuses to start a second non-`pre_patch_failure` attempt and the
/// `git_push_resolution_refuses_active_approve` trigger treats `started`
/// as in-flight, so a wedged `Started` row is recovered by boot reconcile
/// (which drives stale `Started` attempts — and `Uncertain` ones past
/// their mint `expires_at` — to `Resolved(PrePatchFailure)`) rather than
/// by manual DB repair.
async fn start_approve_attempt_row<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: &str,
) -> Result<ApproveAttemptId, ServerMessage> {
    let attempt_id = ApproveAttemptId::new();
    let started_at = UnixMillis::now();
    let start_result = {
        let audit = Arc::clone(&state.audit);
        let operator = operator.to_string();
        tokio::task::spawn_blocking(move || {
            audit.start_approve_attempt(attempt_id, request_id, &operator, started_at)
        })
        .await
    };
    match start_result {
        Ok(Ok(())) => Ok(attempt_id),
        Ok(Err(err)) => {
            // `start_approve_attempt` refuses in three shapes: a prior
            // resolution row exists (the short-circuit in
            // `check_approvable_push` normally catches this, but a race
            // between two concurrent approves can land both past that
            // check before either has inserted), a non-`pre_patch_failure`
            // attempt is active for the same push, or the staged-outcome
            // precondition has gone away under us. All are surfaced as a
            // generic error: the operator (or a future reviewer) reads the
            // audit row to disambiguate.
            Err(ServerMessage::Error {
                message: format!("approve attempt could not be started: {err}"),
            })
        }
        Err(err) => Err(ServerMessage::Error {
            message: format!("approve attempt start task failed: {err}"),
        }),
    }
}

/// Drive a freshly-`Started` attempt to a terminal state and return the
/// new app tip on success. Mints a one-shot installation token, runs the
/// approve pipeline up to the publish, marks the attempt `Uncertain`
/// (the commit point past which the broker can no longer prove GitHub
/// did not move), issues the `PATCH`, and commits the joint
/// success/resolution TX. Every failure path first resolves the attempt
/// through the appropriate `resolve_*_failure` DAO (so the row never stays
/// `Started`/`Uncertain` on a returned error) and then yields the wire
/// `Error` for the caller to return; this is the one place the
/// `attempt_id`/`mint_audit` threading lives.
///
/// The `Uncertain` window is deliberately as narrow as the GitHub API
/// permits — one `PATCH` round-trip. Everything before it (staging
/// fetch, unbundle, plan, object uploads) leaves the branch untouched
/// and so runs under `Started`, which boot reconcile resolves without
/// an operator. Only a crash that could have moved the branch earns a
/// manual reconciliation.
// `result_large_err`: `ServerMessage` is the wire reply type; this transient
// local Result early-returns it unchanged, so boxing would only add indirection
// at every construction site. `too_many_arguments`: the flat shape matches the
// `prepare_approve` / run_agent precedent in this crate.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
async fn execute_started_attempt<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    operator: &str,
    agent_kind: Option<crate::core::AgentKind>,
    entry: StagedEntry,
    promote_runtime: &PromoteRuntimeConfig,
    signing_key: &WritSigningKey,
) -> Result<crate::vm_git::GitObjectId, ServerMessage> {
    // The staged push targets one repo and needs `contents:write` to
    // publish it. Route that as a `CapabilityRequest` through the same
    // policy engine every other mint uses, rather than hand-building the
    // scope: this is what subjects approvals to the `writable_repos`
    // allowlist. `decide` grants `contents:write` + `metadata:read` for a
    // `Contents { Write }` request — exactly the promote scope. Only the
    // TTL is overridden, to the GitHub installation-token ceiling: see
    // [`APPROVE_MINT_TTL_SECONDS`] — it is an accept-back bound on the
    // expiry GitHub returns, not a lifetime the server grants, and the
    // minter's permissions-echo check still refuses any scope drift.
    let promote_request = CapabilityRequest::GitHub(GitHubRequest::Contents {
        access: GitHubAccess::Write,
        repo: entry.receipt().repo().as_repo_ref().clone(),
    });
    let authorization = match policy::decide(&promote_request, &state.policy) {
        Decision::Grant(authorization) => authorization.with_ttl(
            TtlSeconds::new(APPROVE_MINT_TTL_SECONDS)
                .expect("APPROVE_MINT_TTL_SECONDS is in TtlSeconds range"),
        ),
        Decision::Deny { reason } => {
            // A policy denial is a pre-patch failure: nothing has touched
            // GitHub yet, so the attempt resolves cleanly and the operator
            // is told the approve was refused by policy.
            let detail = format!("policy denied approve-time mint: {reason}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
            return Err(ServerMessage::Error {
                message: format!("approve refused: {reason}"),
            });
        }
    };

    let mint_result = state
        .minter
        .mint_for_agent(&state.secrets, agent_kind, authorization)
        .await;
    let minted = match mint_result {
        Ok(m) => m,
        Err(err) => {
            let detail = format!("mint failed: {}", err.agent_message());
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
            return Err(ServerMessage::Error {
                message: format!("approve-time mint failed: {}", err.agent_message()),
            });
        }
    };

    let (api_base, raw_token, mint_audit) = minted.into_promote_pieces();
    crate::crash_point::point("approve::minted").await;

    // Persist the burned credential's identity *before* anything else
    // uses it. The prepare phase below is long, network-bound, and runs
    // with the attempt row still `Started` (mint columns NULL by the
    // schema CHECK); without this ledger row a broker crash mid-prepare
    // would lose which credential was issued — and used, for the object
    // uploads — against GitHub. Boot reconcile copies the ledger mint
    // onto the row it resolves. If the ledger write itself fails, the
    // broker refuses to proceed: a credential it cannot durably account
    // for must not touch GitHub (correctness over availability).
    let mint_record_result = {
        let audit = Arc::clone(&state.audit);
        let recorded_at = UnixMillis::now();
        tokio::task::spawn_blocking(move || {
            audit.record_attempt_mint(attempt_id, mint_audit, recorded_at)
        })
        .await
    };
    match mint_record_result {
        Ok(Ok(())) => {
            crate::crash_point::point("approve::mint_recorded").await;
        }
        Ok(Err(err)) => {
            // The ledger INSERT was refused, so the row is still
            // `Started` with no mint anywhere: capture it on the
            // resolved row directly.
            let detail = format!("record_attempt_mint failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve-time mint could not be recorded: {err}"),
            });
        }
        Err(err) => {
            let detail = format!("record_attempt_mint task failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve-time mint recording task failed: {err}"),
            });
        }
    }

    let token = match GitSecretValue::new(raw_token) {
        Ok(t) => t,
        Err(err) => {
            let detail = format!("mint produced unusable token: {err}");
            // Mint succeeded by the time we have a `MintedToken`, so
            // capture the mint context on the attempt row even though
            // the token cannot be used. The audit log can still answer
            // "what mint was issued for this attempt." (The ledger row
            // above already records the same mint; the schema trigger
            // checks the two agree.)
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve-time mint produced an unusable token: {err}"),
            });
        }
    };

    let receipt = entry.receipt();
    let repo = receipt.repo().clone();
    let branch = receipt.branch().clone();
    // `check_approvable_push` proved the carrier agrees with the audit
    // row (`carrier_audit_divergence`) and then refused the audit row's
    // branch-creation case (`expected_remote_head.is_none()`), so the
    // carrier's `expected_remote_head` is necessarily `Some` here.
    let expected_remote_head = receipt
        .expected_remote_head()
        .cloned()
        .expect("expected_remote_head presence was checked by check_approvable_push");
    let bundle_tip = receipt.new_head().clone();
    let (_, bundle_bytes) = entry.into_parts();

    // Phase 1 — everything that provably cannot move the branch on
    // GitHub: fetch, unbundle, plan, and the walker's object uploads.
    // The attempt row stays `Started` throughout, which is the state
    // boot reconcile can resolve on its own, so a crash anywhere in
    // here costs a retry rather than a manual reconciliation.
    let prepare_result = prepare_approve(
        promote_runtime,
        &state.git_data_http,
        &api_base,
        &token,
        &repo,
        &branch,
        &expected_remote_head,
        &bundle_tip,
        &bundle_bytes,
        signing_key,
        // Trailers are an open follow-up: the design pins a per-approve
        // trailer set (operator id, original commit sha) but the policy
        // hasn't been ratified yet, so the slice ships with no trailers
        // and the bundle's commits are replayed verbatim. The empty
        // slice is identical in shape to what the prepare_approve unit
        // tests pass.
        &[],
        attempt_id,
    )
    .await;

    let prepared = match prepare_result {
        Ok(prepared) => {
            crate::crash_point::point("approve::prepared").await;
            prepared
        }
        Err(err) => {
            // Every `RunApproveError` is pre-PATCH by construction —
            // the type cannot express a PATCH failure, which is why the
            // classification is no longer a match on variants. The
            // attempt is still `Started`, so the mint context is
            // captured on the resolved row (the ledger row written
            // above holds the same mint; the schema trigger checks the
            // two agree).
            //
            // `err` can wrap `GitDataError::ApiError { body, .. }`
            // whose `body` is unbounded GitHub/GHES bytes; cap both
            // the audit `detail` and the wire `message` at
            // `MAX_WIRE_ERROR_BYTES` so a hostile or misbehaving
            // server can't bloat the audit DB column or blow up the
            // `ServerMessage::Error` envelope.
            let detail =
                truncate_for_wire(format!("run_approve failed: {err}"), MAX_WIRE_ERROR_BYTES);
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            let message = match &err {
                RunApproveError::Prepare(_) => format!("staging preparation failed: {err}"),
                _ => format!("approve pipeline failed: {err}"),
            };
            return Err(ServerMessage::Error {
                message: truncate_for_wire(message, MAX_WIRE_ERROR_BYTES),
            });
        }
    };

    // Phase 2 — commit to "the PATCH may exist on GitHub". From here
    // until `Resolved` lands the attempt is `Uncertain`, and the
    // `git_push_resolution_refuses_active_approve` trigger blocks any
    // concurrent reject (it already did while `Started`, so narrowing
    // this window does not open a reject race). The `UncertainAttempt`
    // this yields is the only key that opens `PreparedApprove::commit`,
    // so the record cannot fall on the wrong side of the PATCH.
    let uncertain_result = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.mark_attempt_uncertain(attempt_id, mint_audit))
            .await
    };
    let authority = match uncertain_result {
        Ok(Ok(authority)) => {
            crate::crash_point::point("approve::uncertain_recorded").await;
            authority
        }
        Ok(Err(err)) => {
            // The attempt row is still `Started` (the UPDATE was
            // refused) so a `pre_patch_failure` capturing the mint is
            // the correct shape: no PATCH was issued, but the mint was.
            let detail = format!("mark_attempt_uncertain failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve attempt could not enter Uncertain: {err}"),
            });
        }
        Err(err) => {
            let detail = format!("mark_attempt_uncertain task failed: {err}");
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, Some(mint_audit))
                .await;
            return Err(ServerMessage::Error {
                message: format!("approve attempt Uncertain task failed: {err}"),
            });
        }
    };

    // Phase 3 — the last-second lease recheck and the PATCH. The error
    // type splits by proof: the `FinalLease*` variants fire before any
    // PATCH is sent (the branch is provably untouched, so the attempt
    // resolves `Uncertain → Resolved(PrePatchFailure)` and the push
    // stays retryable / rejectable), while `UpdateRef` *is* the proof
    // that a ref update reached GitHub and did not confirm, so it
    // resolves as `PostPatchFailure`. Matching on the variant is the
    // whole classification — there is no cause-string inspection to
    // get wrong.
    let outcome = match prepared.commit(&authority).await {
        Ok(outcome) => {
            crate::crash_point::point("approve::patched").await;
            outcome
        }
        Err(err @ (CommitError::FinalLeaseLookup(_) | CommitError::FinalLeaseMoved { .. })) => {
            // `FinalLeaseLookup` can wrap unbounded GitHub/GHES body
            // bytes, same as the prepare-phase errors; cap both copies.
            let detail =
                truncate_for_wire(format!("run_approve failed: {err}"), MAX_WIRE_ERROR_BYTES);
            resolve_pre_patch_failure(state, attempt_id, request_id, &detail, None).await;
            return Err(ServerMessage::Error {
                message: truncate_for_wire(
                    format!(
                        "approve pipeline refused to publish: the branch could not be \
                         re-verified at expected_remote_head immediately before update_ref; \
                         staged push {request_id} remains retryable: {err}"
                    ),
                    MAX_WIRE_ERROR_BYTES,
                ),
            });
        }
        Err(err @ CommitError::UpdateRef(_)) => {
            let detail =
                truncate_for_wire(format!("run_approve failed: {err}"), MAX_WIRE_ERROR_BYTES);
            resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
            return Err(ServerMessage::Error {
                message: truncate_for_wire(
                    format!(
                        "approve pipeline issued update_ref against GitHub but the response \
                         could not be confirmed; staged push {request_id} is quarantined and \
                         must be reconciled manually: {err}"
                    ),
                    MAX_WIRE_ERROR_BYTES,
                ),
            });
        }
    };

    // Joint TX: attempt → Resolved(Succeeded) *and* the
    // `git_push_resolution(decision='approved')` row land in one
    // SQLite transaction. The resolution-INSERT trigger sees the
    // attempt at `succeeded` (the UPDATE runs first) and admits the
    // row; an in-flight reject would have been refused at its own
    // INSERT by the same trigger.
    let new_app_tip = outcome.new_app_tip().clone();
    let completed_at = UnixMillis::now();
    let reason = format!("approved by {operator}");
    let success_result = {
        let audit = Arc::clone(&state.audit);
        let new_app_tip = new_app_tip.clone();
        let operator = operator.to_string();
        let reason = reason.clone();
        tokio::task::spawn_blocking(move || {
            audit.complete_attempt_succeeded(
                attempt_id,
                &new_app_tip,
                &operator,
                &reason,
                completed_at,
            )
        })
        .await
    };
    match success_result {
        Ok(Ok(())) => {
            crate::crash_point::point("approve::resolved").await;
        }
        Ok(Err(err)) => {
            // The branch on GitHub now points at `new_app_tip` but the
            // audit log could not commit the joint TX. The attempt is
            // still `Uncertain`. Try to record `PostPatchFailure` so
            // reject is refused going forward; if that also fails the
            // attempt stays `Uncertain` and boot reconcile surfaces it.
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_succeeded",
                request_id = %request_id,
                attempt_id = %attempt_id,
                jti = %mint_audit.jti,
                error = %err,
                "audit write failed: approve succeeded on GitHub but joint TX did not commit; \
                 falling back to PostPatchFailure",
            );
            let detail = format!("complete_attempt_succeeded failed: {err}");
            resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
            return Err(ServerMessage::Error {
                message: format!(
                    "branch was advanced on GitHub (new_app_tip = {new_app_tip}) but the audit \
                     resolution row could not be committed: {err}"
                ),
            });
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_succeeded",
                request_id = %request_id,
                attempt_id = %attempt_id,
                jti = %mint_audit.jti,
                error = %err,
                "audit write task failed: approve succeeded on GitHub but joint TX did not commit; \
                 falling back to PostPatchFailure",
            );
            let detail = format!("complete_attempt_succeeded task failed: {err}");
            resolve_post_patch_failure(state, attempt_id, request_id, &detail).await;
            return Err(ServerMessage::Error {
                message: format!("approve resolution task failed: {err}"),
            });
        }
    }

    Ok(new_app_tip)
}

/// Best-effort staging-dir delete after the approve resolution row is
/// committed. A stale dir surfaces in `promote list` for manual cleanup
/// and cannot cause a contradictory reject because the resolution row is
/// already in place, so failures are logged, not surfaced.
async fn delete_staging_after_approve(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) {
    let delete_result = {
        let staging_store = Arc::clone(staging_store);
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
    };
    match delete_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(
                request_id = %request_id,
                error = %err,
                "approved staged push: staging dir delete failed; \
                 audit row is committed, dir will appear in `promote list`",
            );
        }
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                error = %err,
                "approved staged push: staging dir delete task failed; \
                 leaving for boot-time reconciliation",
            );
        }
    }
}

/// Drive an attempt to `Resolved(PrePatchFailure)`. Chooses between the
/// mint-capturing and non-capturing DAO variants based on whether the
/// caller has a mint to record: the column-immutability trigger refuses
/// to write a mint different from one that's already there, so we must
/// not pass `Some(mint)` to the capturing variant when the attempt is
/// already `Uncertain` (it carries the mint inline already).
async fn resolve_pre_patch_failure<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    detail: &str,
    mint_to_capture: Option<PromoteMintAudit>,
) {
    let completed_at = UnixMillis::now();
    let audit = Arc::clone(&state.audit);
    let detail_owned = detail.to_string();
    let result = tokio::task::spawn_blocking(move || match mint_to_capture {
        Some(mint) => audit.complete_attempt_pre_patch_failure_capturing_mint(
            attempt_id,
            mint,
            &detail_owned,
            completed_at,
        ),
        None => audit.complete_attempt_pre_patch_failure(attempt_id, &detail_owned, completed_at),
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_pre_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write failed: approve attempt could not be resolved as PrePatchFailure; \
                 attempt remains Started/Uncertain — boot reconcile will surface it",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_pre_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write task failed: approve attempt could not be resolved as PrePatchFailure; \
                 attempt remains Started/Uncertain — boot reconcile will surface it",
            );
        }
    }
}

/// Drive an `Uncertain` attempt to `Resolved(PostPatchFailure)`. Used
/// by the two paths that prove the PATCH was sent: a
/// `CommitError::UpdateRef` from `PreparedApprove::commit` (non-2xx /
/// transport drop on the PATCH itself) and the post-success
/// joint-TX-failed path (the PATCH succeeded but the audit log could
/// not commit it).
async fn resolve_post_patch_failure<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    attempt_id: ApproveAttemptId,
    request_id: RequestId,
    detail: &str,
) {
    let completed_at = UnixMillis::now();
    let audit = Arc::clone(&state.audit);
    let detail_owned = detail.to_string();
    let result = tokio::task::spawn_blocking(move || {
        audit.complete_attempt_post_patch_failure(attempt_id, &detail_owned, completed_at)
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_post_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write failed: approve attempt could not be resolved as PostPatchFailure; \
                 attempt remains Uncertain — boot reconcile will surface it",
            );
        }
        Err(err) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_post_patch_failure",
                request_id = %request_id,
                attempt_id = %attempt_id,
                error = %err,
                "audit write task failed: approve attempt could not be resolved as PostPatchFailure; \
                 attempt remains Uncertain — boot reconcile will surface it",
            );
        }
    }
}

fn approve_staged_push_not_configured(component: &str) -> ServerMessage {
    ServerMessage::Error {
        message: format!(
            "ApproveStagedPush dispatch is not configured: {component} is unset; \
             writd needs staging_store + promote_runtime + signing_key to serve ApproveStagedPush"
        ),
    }
}

/// Handler for [`ClientMessage::ReconcileStagedPush`].
///
/// Drives a manual reconciliation of a quarantined approve attempt by
/// inserting a born-terminal `git_push_approve_attempt` row whose
/// `supersedes_attempt_id` points back at the predecessor. The
/// predecessor is the oldest non-superseded attempt in either
/// `Uncertain` (boot-observed only) or `Resolved(PostPatchFailure)` —
/// the two states that wedge a staged push between reject and approve
/// after the broker observes (or may have observed) the PATCH go out.
///
/// Flow:
///   1. Wire-side validation of `operator` and the outcome's free-form
///      text (`reason` on `Applied`, `detail` on `NotApplied`): non-empty
///      and bounded so a malformed CLI cannot bloat the audit DB. The
///      DAO repeats the non-empty check as defence-in-depth; the upper
///      bound is enforced at the wire only.
///   2. Require `staging_store` configured. Reconciliation requires a
///      staging dir to act against (operators inspect it to decide
///      Applied vs NotApplied); a daemon without staging cannot honour
///      the request.
///   3. Load the staging entry. Missing dir surfaces as
///      `UnknownStagedPush` — symmetrical with reject/approve.
///   4. Joined audit view: a prior resolution row short-circuits to
///      `StagedPushAlreadyResolved`. This guards against the operator
///      racing themselves (e.g. running `promote reconcile` against a
///      push that just landed a duplicate approve).
///   5. Classify the push via [`AuditLog::classify_reconciliation_target`]:
///        * `Eligible { attempt_id }` → fall through to the DAO write.
///        * Anything else → `StagedPushNotReconcilable` with a typed
///          reason naming the classification.
///   6. Mint a fresh `ApproveAttemptId` for the reconciliation row and
///      branch on `outcome`:
///        * `Applied` → joint TX writes the reconciliation attempt row
///          *and* the `git_push_resolution(decision='approved')` row,
///          carrying the predecessor's captured mint context verbatim.
///        * `NotApplied` → born-terminal `Resolved(PrePatchFailure)`
///          reconciliation row. No resolution row is written; the push
///          is once again rejectable.
///   7. On `Applied` success: best-effort `staging_store.delete`. On
///      `NotApplied`: leave the staging dir on disk so the operator can
///      drive a follow-up reject/retry.
///   8. Map any `AuditError::Invariant` returned by the DAO into
///      `StagedPushNotReconcilable` — the predecessor's eligibility
///      slipped between classify and the write (concurrent
///      reconciliation, race with a state change). Other errors land
///      as `ServerMessage::Error` and are logged at
///      [`AUDIT_WRITE_FAILURE_TARGET`].
pub(super) async fn reconcile_staged_push<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
    operator: String,
    outcome: ReconcileOutcome,
) -> ServerMessage {
    if let Some(resp) = validate_operator(&operator) {
        return resp;
    }

    // The free-form outcome text gets recorded verbatim on the audit
    // row (`reason` on the resolution row for Applied, `failure_detail`
    // on the reconciliation attempt for NotApplied). Cap at the same
    // 4 KiB upper bound the `RejectionReason` parser enforces so the
    // audit DB cannot be bloated by a malformed CLI.
    let outcome_text = match &outcome {
        ReconcileOutcome::Applied { reason, .. } => ("reason", reason.as_str()),
        ReconcileOutcome::NotApplied { detail } => ("detail", detail.as_str()),
    };
    if outcome_text.1.is_empty() {
        return ServerMessage::Error {
            message: format!(
                "reconciliation {label} must not be empty",
                label = outcome_text.0,
            ),
        };
    }
    if outcome_text.1.len() > crate::protocol::MAX_REJECTION_REASON_BYTES {
        return ServerMessage::Error {
            message: format!(
                "reconciliation {label} is {len} bytes, exceeding the {cap}-byte limit",
                label = outcome_text.0,
                len = outcome_text.1.len(),
                cap = crate::protocol::MAX_REJECTION_REASON_BYTES,
            ),
        };
    }

    let Some(staging_store) = state.staging_store.clone() else {
        return staging_not_configured();
    };

    // Probe staging before any audit work. Missing-dir is the same
    // surface as reject/approve; if the operator passes a stale request
    // id we want to say so explicitly rather than write an audit row
    // referencing a push the broker can no longer see.
    if let Err(resp) = load_staged_entry(&staging_store, request_id).await {
        return resp;
    }

    // Short-circuit on a prior resolution row before classifying. A
    // resolved push has nothing to reconcile (the operator decision
    // is already in place), and saying so explicitly avoids spending
    // a classify SELECT on a no-op.
    let audit_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await
    };
    match audit_lookup {
        Ok(Ok(Some(entry))) => {
            if entry.resolution.is_some() {
                return ServerMessage::StagedPushAlreadyResolved { request_id };
            }
        }
        Ok(Ok(None)) => {
            return ServerMessage::Error {
                message: format!(
                    "staged push {request_id} has a staging directory but no audit row; \
                     broker audit log and staging store have drifted apart"
                ),
            };
        }
        Ok(Err(err)) => {
            return ServerMessage::Error {
                message: format!("audit lookup failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("audit lookup task failed: {err}"),
            };
        }
    }

    // Classify the push. The variants surface to the operator as four
    // distinct "nothing to reconcile" reasons so the CLI can guide the
    // next action (wait for boot reconcile vs. there was never an
    // attempt vs. every blocker is already cleared).
    let target_lookup = {
        let audit = Arc::clone(&state.audit);
        tokio::task::spawn_blocking(move || audit.classify_reconciliation_target(request_id)).await
    };
    let predecessor = match target_lookup {
        Ok(Ok(ReconciliationTarget::Eligible { attempt_id })) => attempt_id,
        Ok(Ok(ReconciliationTarget::NoAttempts)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "no approve attempt has been recorded against staged push {request_id}; \
                     nothing to reconcile"
                ),
            };
        }
        Ok(Ok(ReconciliationTarget::AttemptInFlight)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} has an in-flight approve attempt; \
                     reconciliation must wait for the live attempt to resolve \
                     (or for boot reconcile to drive a daemon-survivor row)"
                ),
            };
        }
        Ok(Ok(ReconciliationTarget::NothingToReconcile)) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} has no quarantined approve attempt to clear; \
                     every attempt is already cleanly terminated"
                ),
            };
        }
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "classify_reconciliation_target",
                request_id = %request_id,
                error = %err,
                "audit read failed: reconciliation classification errored",
            );
            return ServerMessage::Error {
                message: format!("reconciliation classification failed: {err}"),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("reconciliation classification task failed: {err}"),
            };
        }
    };

    let attempt_id = ApproveAttemptId::new();
    let completed_at = UnixMillis::now();
    let is_applied = matches!(outcome, ReconcileOutcome::Applied { .. });
    let write_result = match outcome {
        ReconcileOutcome::Applied {
            new_app_tip,
            reason,
        } => {
            let audit = Arc::clone(&state.audit);
            let operator = operator.clone();
            tokio::task::spawn_blocking(move || {
                audit.record_reconciliation_attempt_applied(
                    attempt_id,
                    predecessor,
                    &new_app_tip,
                    &operator,
                    &reason,
                    completed_at,
                )
            })
            .await
        }
        ReconcileOutcome::NotApplied { detail } => {
            let audit = Arc::clone(&state.audit);
            let operator = operator.clone();
            tokio::task::spawn_blocking(move || {
                audit.record_reconciliation_attempt_not_applied(
                    attempt_id,
                    predecessor,
                    &operator,
                    &detail,
                    completed_at,
                )
            })
            .await
        }
    };

    // The DAO refuses on Invariant shapes that all reduce to "the
    // predecessor isn't actually clearable any more" — most likely a
    // concurrent reconciliation landed first. Surface the typed
    // `NotReconcilable` so the operator re-runs `promote list` and
    // picks the next blocker.
    match write_result {
        Ok(Ok(())) => {}
        Ok(Err(AuditError::Invariant(detail))) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} reconciliation refused by audit invariant: \
                     {detail}; re-run promote list and retry"
                ),
            };
        }
        Ok(Err(AuditError::LabeledInvariant { label, message })) => {
            return ServerMessage::StagedPushNotReconcilable {
                request_id,
                reason: format!(
                    "staged push {request_id} reconciliation refused by audit invariant \
                     ({label}): {message}; re-run promote list and retry"
                ),
            };
        }
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "git_push_approve_attempt_reconciliation",
                request_id = %request_id,
                attempt_id = %attempt_id,
                predecessor = %predecessor,
                error = %err,
                "audit write failed: reconciliation attempt not recorded",
            );
            return ServerMessage::Error {
                message: err.to_string(),
            };
        }
        Err(err) => {
            return ServerMessage::Error {
                message: format!("reconciliation audit write task failed: {err}"),
            };
        }
    }

    // Applied: the joint TX committed the resolution row. The push is
    // now terminally approved, so the staging dir is finished — try to
    // delete it the same way `approve_staged_push` does. NotApplied
    // leaves the staging dir alone so a follow-up reject sees it on
    // disk.
    if is_applied {
        let delete_result = {
            let staging_store = Arc::clone(&staging_store);
            tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await
        };
        match delete_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    "reconciled (applied) staged push: staging dir delete failed; \
                     audit row is committed, dir will appear in `promote list`",
                );
            }
            Err(err) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    "reconciled (applied) staged push: staging dir delete task failed; \
                     leaving for boot-time reconciliation",
                );
            }
        }
    }

    ServerMessage::StagedPushReconciled { request_id }
}

/// Maximum byte length of an error string echoed back on the wire in a
/// [`ServerMessage::Error`] or written into the
/// `git_push_approve_attempt.failure_detail` audit column. The approve
/// pipeline can wrap a [`crate::github_git_db::GitDataError::ApiError`]
/// whose `body` is the raw bytes a GitHub Enterprise instance (or a
/// proxy in front of it) returns; that body is otherwise unbounded and
/// would expand both the broker's per-error wire footprint *and* the
/// audit DB without limit. 4 KiB is large enough to preserve the
/// diagnostic shape (status line, JSON error object, the first few
/// stack-trace-ish lines) while keeping a worst-case error envelope
/// comfortably under the broker's per-message processing budget.
const MAX_WIRE_ERROR_BYTES: usize = 4 * 1024;

/// Truncate `s` to at most `cap` bytes, with a sentinel marker so the
/// reader can tell the message is a prefix. The marker is appended
/// after the cap (the returned string is `cap + marker.len()` bytes
/// long when truncation happens), because the goal is to bound the
/// *body* the broker reflects from GitHub, not to bound the total
/// envelope to the byte. Splits on a `char` boundary so the result is
/// valid UTF-8 even when the cap lands inside a multi-byte sequence.
pub(super) fn truncate_for_wire(s: String, cap: usize) -> String {
    if s.len() <= cap {
        return s;
    }
    let mut boundary = cap;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut out = s;
    out.truncate(boundary);
    out.push_str("... [truncated]");
    out
}

/// Best-effort retry of the staging-dir delete on a duplicate-resolution
/// path: a prior `Rejected` row commits the decision, but if its
/// follow-up `delete` failed (transient filesystem error, perm flip,
/// crash) the dir lingers and the operator has no way to clear it.
/// Try again here and swallow any error — the caller still returns
/// `StagedPushAlreadyResolved`, and if the dir remains it will surface
/// in the next `promote list` for the operator to act on.
async fn retry_cleanup_for_rejected<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
) {
    let audit = Arc::clone(&state.audit);
    let lookup = tokio::task::spawn_blocking(move || audit.get_git_push(request_id)).await;
    let prior_decision = match lookup {
        Ok(Ok(Some(entry))) => entry.resolution.map(|r| r.decision),
        _ => None,
    };
    if !matches!(prior_decision, Some(GitPushResolution::Rejected)) {
        return;
    }
    retry_staging_delete(staging_store, request_id, "duplicate-reject").await;
}

/// Best-effort staging-dir delete used by the duplicate-resolution
/// recovery paths. Logs a `warn` if the delete itself errors;
/// task-join failures are surfaced the same way. Centralised here so
/// the duplicate-reject and the
/// `RejectBlocker::AlreadyApproved` branches share the same
/// observable behaviour — both are "a prior resolution committed, the
/// staging dir may have leaked, retry the cleanup."
async fn retry_staging_delete(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
    context: &'static str,
) {
    let staging_store = Arc::clone(staging_store);
    let delete_outcome =
        tokio::task::spawn_blocking(move || staging_store.delete(request_id)).await;
    match delete_outcome {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(
                request_id = %request_id,
                context,
                error = %err,
                "staging cleanup retry failed; staging dir may still be present",
            );
        }
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                context,
                error = %err,
                "staging cleanup retry task failed; staging dir may still be present",
            );
        }
    }
}

/// Recognise the "row already exists" failure shape for the
/// `git_push_resolution` PK insert. Rusqlite surfaces both
/// `SQLITE_CONSTRAINT_PRIMARYKEY` (1555) and `SQLITE_CONSTRAINT_UNIQUE`
/// (2067) via `ConstraintViolation`; the message text disambiguates.
pub(super) fn is_unique_constraint_violation(err: &crate::audit::AuditError) -> bool {
    let crate::audit::AuditError::Sqlite(sql_err) = err else {
        return false;
    };
    let rusqlite::Error::SqliteFailure(code, _) = sql_err else {
        return false;
    };
    if !matches!(code.code, rusqlite::ErrorCode::ConstraintViolation) {
        return false;
    }
    let message = sql_err.to_string().to_lowercase();
    message.contains("unique") || message.contains("primary key")
}

/// Detect the `git_push_resolution_refuses_active_approve` trigger
/// firing. The trigger is the schema-level defence-in-depth for the
/// approve-attempt state machine: any attempted `INSERT` into
/// `git_push_resolution` while a same-push attempt is `Started`,
/// `Uncertain`, or `Resolved(PostPatchFailure)` is refused with the
/// literal message below. The reject handler calls
/// [`AuditLog::reject_blocker_for_push`] *first* to give the operator a
/// typed diagnostic, but the SELECT-vs-INSERT window admits a racing
/// approve that lands a fresh `Started` row in between; matching the
/// trigger's text lets the handler translate that race back into the
/// same typed surface instead of leaking the raw SQL refusal.
///
/// The matched literal is mirrored from
/// `crates/writ-audit/src/migrations/0005_approve_attempt_state_machine.sql`.
pub(super) fn is_active_approve_refusal(err: &crate::audit::AuditError) -> bool {
    const TRIGGER_MESSAGE: &str =
        "git push resolution refused: approve attempt is in-flight or quarantined";
    let crate::audit::AuditError::Sqlite(sql_err) = err else {
        return false;
    };
    let rusqlite::Error::SqliteFailure(code, _) = sql_err else {
        return false;
    };
    if !matches!(code.code, rusqlite::ErrorCode::ConstraintViolation) {
        return false;
    }
    sql_err.to_string().contains(TRIGGER_MESSAGE)
}

/// Query [`AuditLog::reject_blocker_for_push`] from the broker's tokio
/// runtime, returning the typed `Option<RejectBlocker>` plus a wire
/// error message if the spawn-blocking call itself fails. Centralising
/// this lets the handler call the same machinery twice (preflight and
/// the trigger-race recovery path) without duplicating the join /
/// error-mapping boilerplate.
async fn preflight_reject_blocker<S: SecretStore + Send + Sync + 'static>(
    state: &Arc<BrokerState<S>>,
    request_id: RequestId,
) -> Result<Option<RejectBlocker>, String> {
    let audit = Arc::clone(&state.audit);
    match tokio::task::spawn_blocking(move || audit.reject_blocker_for_push(request_id)).await {
        Ok(Ok(blocker)) => Ok(blocker),
        Ok(Err(err)) => {
            tracing::error!(
                target: AUDIT_WRITE_FAILURE_TARGET,
                kind = "reject_blocker_for_push",
                request_id = %request_id,
                error = %err,
                "audit read failed: reject blocker query errored",
            );
            Err(err.to_string())
        }
        Err(err) => Err(format!("audit read task failed: {err}")),
    }
}

/// Map a non-`None` [`RejectBlocker`] into the reject handler's
/// response. `AlreadyApproved` reuses the existing
/// `StagedPushAlreadyResolved` surface — when the joint TX in
/// `complete_attempt_succeeded` commits, the resolution row is present
/// alongside the attempt row, so the operator-facing behaviour matches
/// a duplicate-reject hit. The other variants surface as `Error` with
/// a diagnostic that names the attempt and points the operator at the
/// next action.
async fn reject_blocker_response(
    staging_store: &Arc<GitPushStagingStore>,
    request_id: RequestId,
    blocker: RejectBlocker,
) -> ServerMessage {
    match blocker {
        RejectBlocker::AttemptInFlight { attempt_id } => ServerMessage::Error {
            message: format!(
                "staged push {request_id} cannot be rejected: approve attempt {attempt_id} \
                 is in flight; retry once it resolves or wait for boot reconcile to drive \
                 the attempt to a terminal state"
            ),
        },
        RejectBlocker::AlreadyApproved { .. } => {
            // The approve handler best-effort deletes the staging dir
            // post-joint-TX (`approve_staged_push` line ~1449); if that
            // delete failed the dir is still on disk and the operator's
            // late reject is the second chance to remove it. The
            // existing `retry_cleanup_for_rejected` path only fires for
            // a prior `Rejected` decision, so the shared
            // `retry_staging_delete` helper covers the
            // duplicate-approve branch with the same observable
            // behaviour.
            retry_staging_delete(staging_store, request_id, "duplicate-approve").await;
            ServerMessage::StagedPushAlreadyResolved { request_id }
        }
        RejectBlocker::PostPatchUncertain { attempt_id } => ServerMessage::Error {
            message: format!(
                "staged push {request_id} cannot be rejected: approve attempt {attempt_id} \
                 may have advanced the branch on GitHub; inspect the remote ref and \
                 reconcile manually before retrying"
            ),
        },
    }
}

fn staging_not_configured() -> ServerMessage {
    ServerMessage::Error {
        message: "git push staging is not configured; \
                  the broker config needs an agent_vm.vm_http section"
            .into(),
    }
}
