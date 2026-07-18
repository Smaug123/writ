//! The git-push audit DAO: the `AuditLog` methods that read and write the
//! git-push request/outcome/resolution/approve-attempt rows.
//!
//! This is one inherent `impl AuditLog` block, split out of `git_push.rs` to
//! keep that module's record types, row-mapping helpers, and the DAO methods
//! legible separately. The `AuditLog` struct itself lives in the crate root;
//! the record types, row structs, and `*_from_row` helpers stay in the parent
//! `git_push` module and are reached via `super`. Behaviour is unchanged.

use super::*;

impl AuditLog {
    /// Persist a parsed VM Git push request before any credential mint,
    /// remote fetch, or external push is attempted.
    pub fn record_git_push_request(&self, r: &GitPushRequestRecord) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let session_closed_at: Option<Option<i64>> = tx
                .query_row(
                    "SELECT closed_at FROM session WHERE session_id = ?1",
                    params![r.session_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match session_closed_at {
                None => return Err(AuditError::Invariant("session does not exist")),
                Some(Some(_)) => return Err(AuditError::Invariant("session is closed")),
                Some(None) => {}
            }

            tx.execute(
                "INSERT INTO git_push_request (
                     push_request_id,
                     session_id,
                     received_at,
                     repo,
                     branch,
                     expected_remote_head,
                     new_head,
                     correlation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    r.repo.to_string(),
                    r.branch.as_str(),
                    r.expected_remote_head.as_ref().map(GitObjectId::as_str),
                    r.new_head.as_str(),
                    r.correlation_id.as_ref().map(CorrelationId::as_str),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the terminal broker-visible result for a VM Git push request.
    /// This is permitted after session close because the request was accepted
    /// while the session was open. After the v5 schema, the only results
    /// the schema admits are `denied`, `validation_failed`, and `staged`;
    /// the post-promote terminal states are recorded against
    /// `git_push_approve_attempt` instead.
    pub fn record_git_push_outcome(&self, r: &GitPushOutcomeRecord<'_>) -> Result<(), AuditError> {
        if r.message.is_empty() {
            return Err(AuditError::Invariant(
                "git push outcome message must not be empty",
            ));
        }
        if let Some(status) = r.github_status
            && !(100..=599).contains(&status)
        {
            return Err(AuditError::Invariant(
                "git push outcome GitHub status must be 100..599",
            ));
        }

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_outcome (
                     push_request_id,
                     completed_at,
                     result,
                     github_status,
                     message
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.completed_at.as_millis(),
                    r.result.as_str(),
                    r.github_status.map(i64::from),
                    r.message,
                ],
            )?;
            Ok(())
        })
    }

    /// Persist an operator decision on a staged push. The v13 schema's
    /// `BEFORE INSERT` trigger requires `git_push_outcome.result = 'staged'`
    /// for this request id, and the table's primary key prevents a
    /// second decision being recorded — both constraints surface as
    /// `AuditError::Sqlite`. The caller is responsible for empty-string
    /// rejection so callers see a clean `Invariant` message instead of
    /// a raw SQL CHECK violation.
    pub fn record_git_push_resolution(
        &self,
        r: &GitPushResolutionRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.operator.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution operator must not be empty",
            ));
        }
        if r.reason.is_empty() {
            return Err(AuditError::Invariant(
                "git push resolution reason must not be empty",
            ));
        }

        let (mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at) = match r.decision {
            GitPushResolution::Rejected => (None, None, None, None),
            GitPushResolution::Approved(audit) => {
                let github_app_id = i64::try_from(audit.github_app_id).map_err(|_| {
                    AuditError::Invariant(
                        "git push resolution mint github_app_id exceeds SQLite integer",
                    )
                })?;
                (
                    Some(audit.jti.as_uuid().to_string()),
                    Some(github_app_id),
                    Some(audit.issued_at.as_millis()),
                    Some(audit.expires_at.as_millis()),
                )
            }
        };

        self.with_conn_mut(|c| {
            c.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id,
                     decided_at,
                     decision,
                     operator,
                     reason,
                     mint_jti,
                     mint_github_app_id,
                     mint_issued_at,
                     mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.push_request_id.as_uuid().to_string(),
                    r.decided_at.as_millis(),
                    r.decision.kind_str(),
                    r.operator,
                    r.reason,
                    mint_jti,
                    mint_github_app_id,
                    mint_issued_at,
                    mint_expires_at,
                ],
            )?;
            Ok(())
        })
    }

    /// Fetch the joined audit view for one VM Git push by request id, or
    /// `None` if no request row has been recorded. Promote tooling uses
    /// this to attach session and outcome context to a staged push that
    /// the operator looked up by id.
    pub fn get_git_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_REQUEST_SQL)?;
            let row = stmt
                .query_row(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )
                .optional()?;
            row.transpose()
        })
    }

    pub fn list_git_pushes_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<GitPushAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(GIT_PUSH_AUDIT_ENTRY_BY_SESSION_SQL)?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    git_push_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// Insert a fresh `Started` approve attempt against a staged push.
    /// Required preconditions: the request row exists and has a
    /// `Staged` outcome row (the v3 trigger
    /// `git_push_resolution_requires_staged` reaches the same shape from
    /// the resolution side; this DAO mirrors that for attempts so an
    /// attempt cannot land for a push the audit log never observed
    /// staged).
    pub fn start_approve_attempt(
        &self,
        attempt_id: ApproveAttemptId,
        push_request_id: RequestId,
        operator: &str,
        started_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt operator must not be empty",
            ));
        }
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let staged: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_outcome
                     WHERE push_request_id = ?1 AND result = 'staged'",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if staged.is_none() {
                return Err(AuditError::Invariant(
                    "approve attempt requires staged outcome",
                ));
            }
            // A resolution row (approved *or* rejected) already exists
            // for this push. Permitting a new attempt would let the
            // approve path advance GitHub against a push the audit log
            // has already declared terminal: the `complete_attempt_*`
            // joint TX would later fail the resolution PK INSERT, but
            // by then `update_ref` may already have run. Refuse here.
            let resolution: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_resolution
                     WHERE push_request_id = ?1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if resolution.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt refused: push already has a resolution",
                ));
            }
            // Another attempt is still running (`started`/`uncertain`)
            // or a prior attempt is quarantined as `post_patch_failure`.
            // A second attempt would race the first's PATCH (in-flight)
            // or contradict the quarantine (post-patch failure leaves
            // GitHub's state uncertain until manual reconciliation).
            // Only a clean slate, or a history of `pre_patch_failure`
            // resolutions, is retryable.
            //
            // The NOT EXISTS clause excludes attempts that have been
            // cleared by a v6 reconciliation row (a successful manual
            // reconciliation supersedes its predecessor's quarantine).
            // Without this filter, an operator who reconciled a
            // `PostPatchFailure` to "did not apply" could never retry
            // the push — the predecessor would forever block fresh
            // starts.
            let blocker: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_approve_attempt a
                      WHERE a.push_request_id = ?1
                        AND (a.state IN ('started', 'uncertain')
                          OR (a.state = 'resolved' AND a.outcome = 'post_patch_failure'))
                        AND NOT EXISTS (
                            SELECT 1 FROM git_push_approve_attempt b
                            WHERE b.supersedes_attempt_id = a.attempt_id
                        )
                      LIMIT 1",
                    params![push_request_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if blocker.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt refused: prior attempt is in-flight or quarantined",
                ));
            }

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, ?3, ?4, 'started',
                           NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL)",
                params![
                    attempt_id.as_uuid().to_string(),
                    push_request_id.as_uuid().to_string(),
                    operator,
                    started_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Record the mint an approve attempt just burned in the
    /// append-only `git_push_approve_attempt_mint` ledger. Called
    /// immediately after the installation token is issued, *before*
    /// the prepare phase (staging fetch, unbundle, plan, object
    /// uploads) starts: that phase is long, network-bound, and runs
    /// with the attempt row still `Started` (mint columns NULL), so
    /// without this row a crash mid-prepare would permanently lose the
    /// identity of a credential that was really issued — and used, for
    /// the uploads — against GitHub. Boot reconcile reads the ledger
    /// back via [`AuditLog::attempt_recorded_mint`] and copies the
    /// mint onto the row it resolves.
    ///
    /// Refused unless the attempt exists and is still `Started` (the
    /// schema trigger enforces the same shape): once the attempt is
    /// `Uncertain` or `Resolved` the mint is carried inline on the
    /// attempt row and a late ledger write could only rewrite history.
    /// At most one ledger row per attempt (it is a primary key): an
    /// attempt mints at most once.
    pub fn record_attempt_mint(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
        recorded_at: UnixMillis,
    ) -> Result<(), AuditError> {
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "started" {
                return Err(AuditError::Invariant(
                    "approve attempt mint ledger requires 'started' state",
                ));
            }
            let already: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM git_push_approve_attempt_mint WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if already.is_some() {
                return Err(AuditError::Invariant(
                    "approve attempt already has a mint ledger row",
                ));
            }
            tx.execute(
                "INSERT INTO git_push_approve_attempt_mint (
                     attempt_id, mint_jti, mint_github_app_id,
                     mint_issued_at, mint_expires_at, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    attempt_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                    recorded_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Read back the mint recorded against an attempt by
    /// [`AuditLog::record_attempt_mint`], if any. Boot reconcile uses
    /// this to resolve a crashed `Started` attempt *with* the burned
    /// credential's identity instead of dropping it.
    pub fn attempt_recorded_mint(
        &self,
        attempt_id: ApproveAttemptId,
    ) -> Result<Option<PromoteMintAudit>, AuditError> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                       FROM git_push_approve_attempt_mint
                      WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((jti_str, app_id, issued_at, expires_at)) = row else {
                return Ok(None);
            };
            let jti = uuid::Uuid::parse_str(&jti_str)
                .map(Jti::from_uuid)
                .map_err(|_| AuditError::Invariant("attempt mint ledger: jti is not a uuid"))?;
            let github_app_id = u64::try_from(app_id).map_err(|_| {
                AuditError::Invariant("attempt mint ledger: github_app_id is negative")
            })?;
            Ok(Some(PromoteMintAudit {
                jti,
                github_app_id,
                issued_at: UnixMillis::from_millis(issued_at),
                expires_at: UnixMillis::from_millis(expires_at),
            }))
        })
    }

    /// Transition a `Started` attempt to `Uncertain`, persisting the
    /// captured mint context. Called immediately before issuing the
    /// GitHub `update_ref` PATCH: once this commit lands the broker
    /// owes the audit log a `Resolved` row, and reject must be refused
    /// in the interim.
    ///
    /// Returns the [`UncertainAttempt`] witness. The promote layer
    /// demands one to issue its PATCH, so "the durable record that a
    /// PATCH may exist precedes the PATCH" is a fact the type system
    /// checks rather than a comment someone has to keep honouring.
    pub fn mark_attempt_uncertain(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
    ) -> Result<UncertainAttempt, AuditError> {
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;
        self.with_conn_mut(|c| {
            let updated = c.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'uncertain',
                        mint_jti = ?2,
                        mint_github_app_id = ?3,
                        mint_issued_at = ?4,
                        mint_expires_at = ?5
                  WHERE attempt_id = ?1
                    AND state = 'started'",
                params![
                    attempt_id.as_uuid().to_string(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )?;
            if updated == 0 {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'started' state",
                ));
            }
            Ok(UncertainAttempt { attempt_id })
        })
    }

    /// Atomically complete an `Uncertain` attempt as `Succeeded` *and*
    /// write the matching `git_push_resolution(decision='approved')`
    /// row. This is the load-bearing transactional commit of the
    /// approve workflow: the audit log either records the full
    /// approval (attempt resolved + resolution row) or neither side
    /// commits. The resolution row's mint columns are derived from the
    /// attempt's stored mint to guarantee they agree.
    pub fn complete_attempt_succeeded(
        &self,
        attempt_id: ApproveAttemptId,
        new_app_tip: &GitObjectId,
        operator: &str,
        reason: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution operator must not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(AuditError::Invariant(
                "approve resolution reason must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            // Load the current attempt row inside the TX so the
            // resolution row is written from the same mint context that
            // the attempt records.
            let row = tx
                .query_row(
                    "SELECT state, push_request_id,
                            mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                       FROM git_push_approve_attempt
                      WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| {
                        Ok(ApproveAttemptMintRow {
                            state: row.get(0)?,
                            push_request_id: row.get(1)?,
                            mint_jti: row.get(2)?,
                            mint_app: row.get(3)?,
                            mint_iat: row.get(4)?,
                            mint_exp: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            let Some(ApproveAttemptMintRow {
                state,
                push_request_id,
                mint_jti,
                mint_app,
                mint_iat,
                mint_exp,
            }) = row
            else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "uncertain" {
                return Err(AuditError::Invariant(
                    "approve attempt is not in 'uncertain' state",
                ));
            }
            let (Some(mint_jti), Some(mint_app), Some(mint_iat), Some(mint_exp)) =
                (mint_jti, mint_app, mint_iat, mint_exp)
            else {
                return Err(AuditError::Invariant(
                    "approve attempt 'uncertain' row is missing mint context",
                ));
            };

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = 'succeeded',
                        new_app_tip = ?2,
                        completed_at = ?3
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    new_app_tip.as_str(),
                    completed_at.as_millis(),
                ],
            )?;

            tx.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id, decided_at, decision, operator, reason,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    push_request_id,
                    completed_at.as_millis(),
                    operator,
                    reason,
                    mint_jti,
                    mint_app,
                    mint_iat,
                    mint_exp,
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Complete a `Started` or `Uncertain` attempt as
    /// `PrePatchFailure`. The schema's forward-only trigger allows this
    /// transition from either non-terminal state; the DAO does the
    /// matching state check before issuing the UPDATE so an attempt
    /// that has already resolved produces a readable invariant error
    /// instead of a silent no-op.
    ///
    /// Mint handling: an `Uncertain` row keeps the mint context
    /// recorded by [`AuditLog::mark_attempt_uncertain`]; a `Started`
    /// row with a v7 mint-ledger row (see
    /// [`AuditLog::record_attempt_mint`]) has that mint copied onto
    /// the resolved row automatically, so a recorded credential's
    /// identity follows the attempt whichever resolve path runs; a
    /// `Started` row with no ledger row resolves mint-NULL. If the
    /// caller holds a mint that is *not* in the ledger (the ledger
    /// write itself failed), use
    /// [`AuditLog::complete_attempt_pre_patch_failure_capturing_mint`]
    /// instead.
    pub fn complete_attempt_pre_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "pre_patch_failure",
            &["started", "uncertain"],
            detail,
            completed_at,
        )
    }

    /// Complete a `Started` attempt as `PrePatchFailure` while
    /// capturing the mint context the caller already minted. This is
    /// the path for the "mint succeeded, prepare/plan/walker failed
    /// before TX2" case in the approve flow: GitHub was never PATCHed
    /// (so the resolution is provably retryable, hence
    /// `pre_patch_failure`), but the broker burned a real credential
    /// that the audit log must record. Refused from any state other
    /// than `Started`: an `Uncertain` row already carries its mint via
    /// [`AuditLog::mark_attempt_uncertain`], and the column-level
    /// immutability trigger would block writing a different one — use
    /// [`AuditLog::complete_attempt_pre_patch_failure`] in that case.
    pub fn complete_attempt_pre_patch_failure_capturing_mint(
        &self,
        attempt_id: ApproveAttemptId,
        mint: PromoteMintAudit,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt failure detail must not be empty",
            ));
        }
        let github_app_id = i64::try_from(mint.github_app_id).map_err(|_| {
            AuditError::Invariant("approve attempt mint github_app_id exceeds SQLite integer")
        })?;

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = current_state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if state != "started" {
                return Err(AuditError::Invariant(
                    "approve attempt: capturing-mint pre_patch_failure requires 'started' state",
                ));
            }

            tx.execute(
                "UPDATE git_push_approve_attempt
                    SET state = 'resolved',
                        outcome = 'pre_patch_failure',
                        failure_detail = ?2,
                        completed_at = ?3,
                        mint_jti = ?4,
                        mint_github_app_id = ?5,
                        mint_issued_at = ?6,
                        mint_expires_at = ?7
                  WHERE attempt_id = ?1",
                params![
                    attempt_id.as_uuid().to_string(),
                    detail,
                    completed_at.as_millis(),
                    mint.jti.as_uuid().to_string(),
                    github_app_id,
                    mint.issued_at.as_millis(),
                    mint.expires_at.as_millis(),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Complete an `Uncertain` attempt as `PostPatchFailure`. Only
    /// admitted from `uncertain` — `started` cannot reach this state
    /// because no PATCH could have been issued yet.
    pub fn complete_attempt_post_patch_failure(
        &self,
        attempt_id: ApproveAttemptId,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.complete_attempt_failure(
            attempt_id,
            "post_patch_failure",
            &["uncertain"],
            detail,
            completed_at,
        )
    }

    /// Record that boot reconcile observed an `Uncertain` attempt at
    /// daemon startup. The marker is the "this row has survived a
    /// daemon restart" claim that the reconciliation DAO requires
    /// before admitting an `Uncertain` predecessor — see comment on
    /// the `git_push_approve_attempt_boot_observed` table in
    /// migration 0004.
    ///
    /// Idempotent: a second call against the same `attempt_id` is a
    /// no-op (preserving the original `observed_at`), matching the
    /// boot reconcile contract that re-observing a still-Uncertain row
    /// across successive boots must not error.
    pub fn mark_attempt_boot_observed(
        &self,
        attempt_id: ApproveAttemptId,
        observed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            c.execute(
                "INSERT OR IGNORE INTO git_push_approve_attempt_boot_observed
                     (attempt_id, observed_at)
                 VALUES (?1, ?2)",
                params![attempt_id.as_uuid().to_string(), observed_at.as_millis()],
            )?;
            Ok(())
        })
    }

    /// Record a manual reconciliation attempt against a quarantined
    /// predecessor (state `Uncertain` or `Resolved(PostPatchFailure)`),
    /// declaring that the operator has confirmed the PATCH did land on
    /// GitHub. Writes a born-terminal `Resolved(Succeeded)` attempt row
    /// pointing back at the predecessor via `supersedes_attempt_id`,
    /// and — in the same transaction — the matching
    /// `git_push_resolution(decision='approved')` row carrying the
    /// predecessor's captured mint context. The mint is copied verbatim
    /// (rather than re-captured at reconciliation time) because the
    /// audit log's promise is "this approval used credential X"; only
    /// the predecessor knows which credential was issued to GitHub.
    ///
    /// The DAO refuses to write if the predecessor is not in an
    /// eligible state or has already been superseded; the schema
    /// triggers enforce the same invariant as defence in depth.
    pub fn record_reconciliation_attempt_applied(
        &self,
        attempt_id: ApproveAttemptId,
        supersedes: ApproveAttemptId,
        new_app_tip: &GitObjectId,
        operator: &str,
        reason: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt operator must not be empty",
            ));
        }
        if reason.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt reason must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let predecessor = load_reconciliation_predecessor(&tx, supersedes)?;
            let mint = predecessor.require_mint()?;

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                     supersedes_attempt_id
                 ) VALUES (?1, ?2, ?3, ?4, 'resolved', 'succeeded', ?4,
                           ?5, NULL,
                           ?6, ?7, ?8, ?9,
                           ?10)",
                params![
                    attempt_id.as_uuid().to_string(),
                    predecessor.push_request_id,
                    operator,
                    completed_at.as_millis(),
                    new_app_tip.as_str(),
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                    supersedes.as_uuid().to_string(),
                ],
            )?;

            tx.execute(
                "INSERT INTO git_push_resolution (
                     push_request_id, decided_at, decision, operator, reason,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                 ) VALUES (?1, ?2, 'approved', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    predecessor.push_request_id,
                    completed_at.as_millis(),
                    operator,
                    reason,
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Record a manual reconciliation attempt declaring that the
    /// operator has confirmed the PATCH did *not* land on GitHub. Writes
    /// a born-terminal `Resolved(PrePatchFailure)` attempt row that
    /// supersedes the predecessor; once this commits, the push is once
    /// again rejectable (a follow-up Reject would write the
    /// `decision='rejected'` row). The reconciliation row carries the
    /// predecessor's mint context — even though no PATCH landed, the
    /// audit log records the credential that *was* issued to GitHub —
    /// and the schema CHECK admits mint on a `pre_patch_failure` row.
    ///
    /// No `git_push_resolution` row is written here. Reconciliation as
    /// "not applied" leaves the push in the same state as if the
    /// original approve had hit a pre-PATCH failure; the operator drives
    /// the eventual reject/retry through the existing handlers.
    pub fn record_reconciliation_attempt_not_applied(
        &self,
        attempt_id: ApproveAttemptId,
        supersedes: ApproveAttemptId,
        operator: &str,
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if operator.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt operator must not be empty",
            ));
        }
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "reconciliation attempt failure detail must not be empty",
            ));
        }

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let predecessor = load_reconciliation_predecessor(&tx, supersedes)?;
            let mint = predecessor.require_mint()?;

            tx.execute(
                "INSERT INTO git_push_approve_attempt (
                     attempt_id, push_request_id, operator, started_at,
                     state, outcome, completed_at, new_app_tip, failure_detail,
                     mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at,
                     supersedes_attempt_id
                 ) VALUES (?1, ?2, ?3, ?4, 'resolved', 'pre_patch_failure', ?4,
                           NULL, ?5,
                           ?6, ?7, ?8, ?9,
                           ?10)",
                params![
                    attempt_id.as_uuid().to_string(),
                    predecessor.push_request_id,
                    operator,
                    completed_at.as_millis(),
                    detail,
                    mint.jti,
                    mint.github_app_id,
                    mint.issued_at,
                    mint.expires_at,
                    supersedes.as_uuid().to_string(),
                ],
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    fn complete_attempt_failure(
        &self,
        attempt_id: ApproveAttemptId,
        outcome: &'static str,
        allowed_states: &[&'static str],
        detail: &str,
        completed_at: UnixMillis,
    ) -> Result<(), AuditError> {
        if detail.is_empty() {
            return Err(AuditError::Invariant(
                "approve attempt failure detail must not be empty",
            ));
        }
        // SQLite CHECK forbids `failure_detail = ''` but a caller-supplied
        // string with whitespace-only content would pass; we keep the
        // strict empty-string check at the DAO boundary as a thin
        // sanity net. The `not empty` guard is intentionally tight; the
        // schema allows any non-empty string.

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM git_push_approve_attempt WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(state) = current_state else {
                return Err(AuditError::Invariant("approve attempt does not exist"));
            };
            if !allowed_states.contains(&state.as_str()) {
                return Err(AuditError::Invariant(
                    "approve attempt is not in a state that admits this failure outcome",
                ));
            }

            // A `started` attempt may carry a v7 mint-ledger row (the
            // mint is recorded before the prepare phase; the inline
            // columns stay NULL until `uncertain`). The resolve must
            // copy that mint onto the row — invariant: a recorded
            // credential's identity follows the attempt into every
            // later state. Read it inside the TX so the copy and the
            // eligibility check see one snapshot; the schema's
            // `resolve_carries_ledger_mint` trigger backs this up
            // against paths that forget. An `uncertain` attempt
            // already carries its mint inline and the UPDATE below
            // leaves those columns untouched.
            let ledger_mint = if state == "started" {
                tx.query_row(
                    "SELECT mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                       FROM git_push_approve_attempt_mint
                      WHERE attempt_id = ?1",
                    params![attempt_id.as_uuid().to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?
            } else {
                None
            };

            match ledger_mint {
                Some((jti, app_id, issued_at, expires_at)) => {
                    tx.execute(
                        "UPDATE git_push_approve_attempt
                            SET state = 'resolved',
                                outcome = ?2,
                                failure_detail = ?3,
                                completed_at = ?4,
                                mint_jti = ?5,
                                mint_github_app_id = ?6,
                                mint_issued_at = ?7,
                                mint_expires_at = ?8
                          WHERE attempt_id = ?1",
                        params![
                            attempt_id.as_uuid().to_string(),
                            outcome,
                            detail,
                            completed_at.as_millis(),
                            jti,
                            app_id,
                            issued_at,
                            expires_at,
                        ],
                    )?;
                }
                None => {
                    tx.execute(
                        "UPDATE git_push_approve_attempt
                            SET state = 'resolved',
                                outcome = ?2,
                                failure_detail = ?3,
                                completed_at = ?4
                          WHERE attempt_id = ?1",
                        params![
                            attempt_id.as_uuid().to_string(),
                            outcome,
                            detail,
                            completed_at.as_millis(),
                        ],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Return every approve-attempt row for one staged push, ordered
    /// by `started_at` ascending (then by attempt_id as a stable
    /// tiebreaker for the rare same-millisecond case). The reject
    /// handler and boot reconcile both consume this view.
    pub fn approve_attempts_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Vec<GitPushApproveAttemptEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT attempt_id, push_request_id, operator, started_at,
                        state, outcome, completed_at,
                        new_app_tip, failure_detail,
                        mint_jti, mint_github_app_id, mint_issued_at, mint_expires_at
                   FROM git_push_approve_attempt
                  WHERE push_request_id = ?1
                  ORDER BY started_at ASC, attempt_id ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![push_request_id.as_uuid().to_string()],
                    git_push_approve_attempt_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }

    /// First attempt (oldest by `started_at`) whose state prevents
    /// reject from succeeding. Returns `None` when reject is allowed
    /// (no attempts, only `PrePatchFailure` attempts, or every
    /// blocker has been cleared by a v6 reconciliation row that
    /// supersedes it).
    pub fn reject_blocker_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<Option<RejectBlocker>, AuditError> {
        let attempts = self.approve_attempts_for_push(push_request_id)?;
        let superseded_ids = self.superseded_attempt_ids_for_push(push_request_id)?;
        Ok(attempts.into_iter().find_map(|attempt| {
            if superseded_ids.contains(&attempt.attempt_id) {
                return None;
            }
            match attempt.state {
                GitPushApproveAttemptState::Started
                | GitPushApproveAttemptState::Uncertain { .. } => {
                    Some(RejectBlocker::AttemptInFlight {
                        attempt_id: attempt.attempt_id,
                    })
                }
                GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                    GitPushApproveAttemptOutcome::Succeeded { .. } => {
                        Some(RejectBlocker::AlreadyApproved {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                        Some(RejectBlocker::PostPatchUncertain {
                            attempt_id: attempt.attempt_id,
                        })
                    }
                    GitPushApproveAttemptOutcome::PrePatchFailure { .. } => None,
                },
            }
        }))
    }

    /// Set of `attempt_id`s for a push that have been superseded by a
    /// v6 reconciliation row. Helper for `reject_blocker_for_push` so
    /// the in-Rust classification logic stays alongside the row-walk;
    /// pushing the filter into the underlying SQL would force
    /// `approve_attempts_for_push` (which is also the audit-history
    /// view) to decide whether to hide superseded rows or not.
    fn superseded_attempt_ids_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<std::collections::HashSet<ApproveAttemptId>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT supersedes_attempt_id
                   FROM git_push_approve_attempt
                  WHERE push_request_id = ?1
                    AND supersedes_attempt_id IS NOT NULL",
            )?;
            let mut out = std::collections::HashSet::new();
            let mut rows = stmt.query(params![push_request_id.as_uuid().to_string()])?;
            while let Some(row) = rows.next()? {
                let raw: String = row.get(0)?;
                let id = uuid::Uuid::parse_str(&raw)
                    .map(ApproveAttemptId::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("approve attempt row: supersedes id is not a uuid")
                    })?;
                out.insert(id);
            }
            Ok(out)
        })
    }

    /// Classify the staged push for the manual reconciliation handler.
    /// Picks the oldest non-superseded eligible predecessor (`Uncertain`
    /// with a boot-observed marker, or `Resolved(PostPatchFailure)`).
    /// Returns a typed [`ReconciliationTarget`] so the broker reply can
    /// distinguish "go ahead" from the four distinct "nothing to do"
    /// shapes without parsing prose.
    ///
    /// Composes the existing reads ([`Self::approve_attempts_for_push`],
    /// supersession-set lookup, boot-observed-set lookup) rather than
    /// pushing the classification down into one SQL query: each
    /// sub-read is already tested in isolation, and the classification
    /// is a small Rust match the schema is too coarse to express.
    pub fn classify_reconciliation_target(
        &self,
        push_request_id: RequestId,
    ) -> Result<ReconciliationTarget, AuditError> {
        let attempts = self.approve_attempts_for_push(push_request_id)?;
        if attempts.is_empty() {
            return Ok(ReconciliationTarget::NoAttempts);
        }
        let superseded = self.superseded_attempt_ids_for_push(push_request_id)?;
        let boot_observed = self.boot_observed_attempt_ids_for_push(push_request_id)?;

        // First non-superseded eligible attempt wins (started_at ASC).
        let mut in_flight = false;
        let mut eligible: Option<ApproveAttemptId> = None;

        for attempt in attempts {
            if superseded.contains(&attempt.attempt_id) {
                continue;
            }
            match &attempt.state {
                GitPushApproveAttemptState::Started => {
                    in_flight = true;
                }
                GitPushApproveAttemptState::Uncertain { .. } => {
                    if boot_observed.contains(&attempt.attempt_id) {
                        if eligible.is_none() {
                            eligible = Some(attempt.attempt_id);
                        }
                    } else {
                        in_flight = true;
                    }
                }
                GitPushApproveAttemptState::Resolved { outcome, .. } => match outcome {
                    GitPushApproveAttemptOutcome::PostPatchFailure { .. } => {
                        if eligible.is_none() {
                            eligible = Some(attempt.attempt_id);
                        }
                    }
                    GitPushApproveAttemptOutcome::Succeeded { .. }
                    | GitPushApproveAttemptOutcome::PrePatchFailure { .. } => {}
                },
            }
        }

        if let Some(attempt_id) = eligible {
            return Ok(ReconciliationTarget::Eligible { attempt_id });
        }
        if in_flight {
            return Ok(ReconciliationTarget::AttemptInFlight);
        }
        Ok(ReconciliationTarget::NothingToReconcile)
    }

    /// `attempt_id`s for one push that boot reconcile has observed as
    /// `Uncertain` survivors of a daemon restart — the live broker
    /// never writes these markers, so any row in the set is provably
    /// out from under the live worker. The reconciliation DAO requires
    /// a marker before admitting an `Uncertain` predecessor, and
    /// `classify_reconciliation_target` consults the same set so the
    /// `AttemptInFlight` reply means "wait for boot reconcile" rather
    /// than "wait forever."
    fn boot_observed_attempt_ids_for_push(
        &self,
        push_request_id: RequestId,
    ) -> Result<std::collections::HashSet<ApproveAttemptId>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT bo.attempt_id
                   FROM git_push_approve_attempt_boot_observed bo
                   JOIN git_push_approve_attempt a
                     ON a.attempt_id = bo.attempt_id
                  WHERE a.push_request_id = ?1",
            )?;
            let mut out = std::collections::HashSet::new();
            let mut rows = stmt.query(params![push_request_id.as_uuid().to_string()])?;
            while let Some(row) = rows.next()? {
                let raw: String = row.get(0)?;
                let id = uuid::Uuid::parse_str(&raw)
                    .map(ApproveAttemptId::from_uuid)
                    .map_err(|_| {
                        AuditError::Invariant("boot-observed row: attempt_id is not a uuid")
                    })?;
                out.insert(id);
            }
            Ok(out)
        })
    }

    /// Every approve-attempt row currently in a non-terminal state
    /// (`Started` or `Uncertain`), ordered by `started_at` ascending
    /// (then by `attempt_id` as a stable tiebreaker for the rare
    /// same-millisecond case). Consumed by boot reconcile to drive
    /// `Started` attempts to `Resolved(PrePatchFailure)` and to flag
    /// `Uncertain` attempts for operator review; the schema's
    /// forward-only triggers guarantee no `Resolved` row appears in
    /// the result set.
    ///
    /// The NOT EXISTS clause excludes attempts that a v6 reconciliation
    /// row already cleared — an `Uncertain` predecessor superseded by
    /// a successful manual reconciliation is no longer something boot
    /// reconcile needs to act on.
    pub fn list_blocking_approve_attempts(
        &self,
    ) -> Result<Vec<GitPushApproveAttemptEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT a.attempt_id, a.push_request_id, a.operator, a.started_at,
                        a.state, a.outcome, a.completed_at,
                        a.new_app_tip, a.failure_detail,
                        a.mint_jti, a.mint_github_app_id, a.mint_issued_at, a.mint_expires_at
                   FROM git_push_approve_attempt a
                  WHERE a.state IN ('started', 'uncertain')
                    AND NOT EXISTS (
                        SELECT 1 FROM git_push_approve_attempt b
                        WHERE b.supersedes_attempt_id = a.attempt_id
                    )
                  ORDER BY a.started_at ASC, a.attempt_id ASC",
            )?;
            let rows = stmt
                .query_map([], git_push_approve_attempt_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
}
