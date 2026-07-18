//! The generic two-phase audit-pair guard.
//!
//! [`EffectAuditTable`] generalises `proxy_table`'s `ProxyAuditTable` from "the
//! three structurally-identical proxy tables" to *any* `(request, outcome)` audit
//! pair: each effect table names its own row types, key, and column serialisers,
//! and the machinery here owns the **sequencing** — a session-open-checked
//! request-row insert, then the matching outcome-row insert — so no effect can be
//! recorded with only one half of the pair.
//!
//! The public surface is exactly three operations, and every one writes *both
//! halves or refuses*:
//! - [`AuditLog::begin_effect`] records the request row and returns a
//!   [`RecordedRequest`] guard that must be discharged with
//!   [`RecordedRequest::complete`] (the two-phase path: request row durable
//!   before the effect, outcome row after);
//! - [`AuditLog::record_effect_coalesced`] writes both rows in one transaction
//!   (the authority-free single-fsync path, e.g. the Nix-cache serve).
//!
//! This is the storage half of the "complete by construction" work
//! (`docs/plans/2026-07-18-brokered-effect-audit-enforcement.md`); the VM-HTTP
//! driver that makes every effect handler flow through it is a later stage.

// The two-phase guard (`begin_effect` / `RecordedRequest` / `complete`) and the
// coalesced writer are now `pub`, consumed by the VM-HTTP `broker_effect` driver
// in the `writ` crate. The `allow(dead_code)` stays: the flake-provision and
// git-push `EffectAuditTable` markers are `pub(crate)` and, until their own
// driver ports land, are only ever named as type arguments (never constructed),
// which the dead-code pass flags as "never constructed". Exempting the trait
// here exempts its impls' marker types, same as when the guard itself was
// crate-internal.
#![allow(dead_code)]

use std::marker::PhantomData;
use std::sync::Arc;

use rusqlite::Connection;

use super::validation::check_session_open;
use super::{AuditError, AuditLog};
use writ_core::core::SessionId;

/// Sealing module: `EffectAuditTable` can only be implemented by this crate's own
/// DAO markers. `insert_request`/`insert_outcome` receive the live `Connection`,
/// so an external implementation could run arbitrary SQL inside the guard's
/// transaction and bypass the typed append-only DAOs. `pub(crate)` (not private)
/// so the per-DAO modules across the crate can implement it, but downstream
/// crates cannot name it.
pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A `(request, outcome)` audit-table pair whose two rows join on one key column.
///
/// Sealed (via the crate-private `sealed` supertrait). Implementors supply the
/// per-table row types and their column serialisers; the guard supplies the
/// transaction sequencing and the invariants (session-open on the request,
/// request↔outcome key agreement).
///
/// `pub` so the VM-HTTP `broker_effect` driver in the `writ` crate can name it
/// as the `BrokeredEffect::Table` bound and drive `begin_effect`/`complete` over
/// it. It stays sealed: `sealed::Sealed` is crate-private, so no downstream type
/// can implement it — only this crate's own DAO markers. `#[allow(private_bounds)]`
/// silences the "private supertrait on a public trait" lint that the seal
/// necessarily produces; the seal is the point.
#[allow(private_bounds)]
pub trait EffectAuditTable: sealed::Sealed + 'static {
    /// Borrow-friendly request-row payload (columns are per-table).
    type RequestRow<'a>;
    /// Borrow-friendly outcome-row payload.
    type OutcomeRow<'a>;
    /// The identity column both rows share (`RequestId`, `PushRequestId`,
    /// `AgentRunId`, …). `Eq` so [`RecordedRequest::complete`] can bind an outcome
    /// to its request; these are distinct newtypes with no implicit conversion,
    /// which is why the guard is generic over the key rather than fixing it.
    type Key: Clone + Eq + Send + 'static;

    /// `*_request` / `*_outcome` table names. Compile-time constants: the DAOs
    /// interpolate them into SQL, so a runtime value would be an injection vector.
    const REQUEST_TABLE: &'static str;
    const OUTCOME_TABLE: &'static str;
    /// Diagnostic label for tracing and asserts; never enters SQL.
    const LABEL: &'static str;

    /// Insert (and validate) one request row. Runs inside the guard's transaction,
    /// after the session-open check.
    fn insert_request(conn: &Connection, row: &Self::RequestRow<'_>) -> Result<(), AuditError>;
    /// Insert (and validate) one outcome row. Runs inside a transaction.
    fn insert_outcome(conn: &Connection, row: &Self::OutcomeRow<'_>) -> Result<(), AuditError>;
    /// The session a request row is scoped to (checked for open-ness before insert).
    fn session_id(row: &Self::RequestRow<'_>) -> SessionId;
    /// The key carried by a request row; populates the guard.
    fn request_key(row: &Self::RequestRow<'_>) -> Self::Key;
    /// The key carried by an outcome row; checked against the guard in `complete`.
    fn outcome_key(row: &Self::OutcomeRow<'_>) -> Self::Key;
}

/// Opt-in marker for effect tables whose guard may be *abandoned* — discharged
/// with no outcome, deliberately leaving a dangling request row for
/// reconciliation (see [`RecordedRequest::abandon`]).
///
/// This is a deliberately narrow escape from the "complete or fail-fast"
/// contract. Most effects can *always* express a truthful outcome (a proxy
/// always has an HTTP status), so their pairing must stay airtight — and it does,
/// because `abandon` is a **compile error** unless the table opts in here. Only a
/// table whose effect can genuinely reach a state with no truthful outcome
/// (git-push's staging-IO failure) implements this.
///
/// Sealed transitively: [`EffectAuditTable`] is sealed via its crate-private
/// `sealed::Sealed` supertrait, so only this crate's own DAO markers can satisfy
/// this bound, and no downstream type can widen the escape hatch.
///
/// A proxy guard cannot be abandoned — `ClaudeProxyAuditTable` does not implement
/// `AbandonableEffect`, so the method does not exist for it (E0599):
///
/// ```compile_fail,E0599
/// fn cannot_abandon_a_proxy(
///     guard: writ_audit::RecordedRequest<writ_audit::ClaudeProxyAuditTable>,
/// ) {
///     guard.abandon();
/// }
/// ```
pub trait AbandonableEffect: EffectAuditTable {}

/// A request row that has been durably recorded and awaits its outcome.
///
/// The only way to obtain one is [`AuditLog::begin_effect`]. It is discharged
/// with [`RecordedRequest::complete`] (records the paired outcome — the ordinary
/// path) or, for the narrow case where no *truthful* outcome exists,
/// [`RecordedRequest::abandon`] (deliberately leaves the row dangling for
/// reconciliation). Dropping it without discharging is a bug (see the `Drop`
/// impl) — "an effect performed without its outcome row", the exact thing this
/// design exists to make unrepresentable.
#[must_use = "a begun effect must be completed (or explicitly abandoned), or it is unaudited"]
pub struct RecordedRequest<T: EffectAuditTable> {
    audit: Arc<AuditLog>,
    key: T::Key,
    /// Set the instant an outcome is *submitted* (see `complete`), not when the
    /// write succeeds — so a rejected or failed completion surfaces to the caller
    /// rather than also tripping the `Drop` backstop as an un-attempted effect.
    discharged: bool,
    _table: PhantomData<fn() -> T>,
}

impl<T: EffectAuditTable> std::fmt::Debug for RecordedRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omits the key so the impl needs no `Key: Debug` bound.
        f.debug_struct("RecordedRequest")
            .field("table", &T::LABEL)
            .field("discharged", &self.discharged)
            .finish_non_exhaustive()
    }
}

impl<T: EffectAuditTable> RecordedRequest<T> {
    /// The key of the request row this guard was begun with.
    pub fn key(&self) -> &T::Key {
        &self.key
    }

    /// Record the outcome row that pairs with this request, consuming the guard.
    pub fn complete(mut self, outcome: &T::OutcomeRow<'_>) -> Result<(), AuditError> {
        // Discharge BEFORE any early return: an outcome was submitted, so a
        // rejection or a write failure is surfaced to the caller and must not also
        // be re-recorded by `Drop` as an un-attempted effect.
        self.discharged = true;
        // Bind the outcome to THIS request: refuse an outcome keyed to a different
        // live guard for the same table, which the foreign key alone would not
        // catch (both keys reference the same table; the FK sees a valid parent).
        if T::outcome_key(outcome) != self.key {
            return Err(AuditError::Invariant(
                "outcome key does not match the guard's request",
            ));
        }
        self.audit.record_effect_outcome::<T>(outcome)
    }
}

impl<T: AbandonableEffect> RecordedRequest<T> {
    /// Discharge the guard *without* recording an outcome, deliberately leaving
    /// the request row dangling for reconciliation.
    ///
    /// Gated on [`AbandonableEffect`], so it is a *compile error* for any effect
    /// that has not explicitly opted in — the proxies (which always have an HTTP
    /// status to record) cannot reach this, keeping their pairing airtight.
    ///
    /// This is the narrow escape hatch for an effect that performed IO but cannot
    /// express a *truthful* outcome — e.g. git-push's staging-IO failure, where no
    /// `GitPushOutcomeResult` variant honestly describes "the host errored
    /// mid-stage". Fabricating an outcome would corrupt the log worse than a
    /// missing one (the same reasoning as the [`Drop`](Self::drop) backstop and
    /// the coalesced writer), so the dangling row is left instead — to be flagged
    /// by the boot-time unpaired-row scan
    /// ([`AuditLog::scan_unpaired_effect_rows`]) and resolved by the table's own
    /// recovery (or an operator).
    ///
    /// Marking the guard discharged is what distinguishes a *deliberate* dangling
    /// row from the `Drop` backstop's *accidental* one: `abandon` asserts the
    /// caller meant to leave no outcome, so it does not fail-fast. Prefer
    /// [`complete`](Self::complete) wherever a truthful outcome exists — a handler
    /// that abandons a path it could have completed leaves a spurious dangling row,
    /// which the Stage-0 audit-pair oracle catches in tests.
    pub fn abandon(mut self) {
        self.discharged = true;
    }
}

impl<T: EffectAuditTable> Drop for RecordedRequest<T> {
    fn drop(&mut self) {
        if self.discharged {
            return;
        }
        // A guard dropped without discharge is a bug: whoever holds it is meant to
        // complete it on every path. We do NOT fabricate an outcome row — no table
        // can always express a *truthful* "incomplete" outcome, and a fabricated
        // row would corrupt the log worse than a missing one. A genuine dangling
        // request is caught durably by the boot-time unpaired-row scan; here we
        // just fail fast in tests — but never while already unwinding, or the
        // second panic would abort the process and bury the original diagnostic.
        // (This crate has no `tracing` dependency by design — the shell that owns
        // completion, and emits `AUDIT_WRITE_FAILURE_TARGET`, is the `writ` crate.)
        if !std::thread::panicking() {
            debug_assert!(
                false,
                "RecordedRequest<{}> dropped without discharge",
                T::LABEL,
            );
        }
    }
}

impl AuditLog {
    /// Begin a two-phase effect: record its request row (session-open-checked, in
    /// its own committed transaction — the durability point that makes the request
    /// durable *before* the effect) and return a guard that must be completed with
    /// the matching outcome via [`RecordedRequest::complete`].
    pub fn begin_effect<T: EffectAuditTable>(
        self: &Arc<Self>,
        row: &T::RequestRow<'_>,
    ) -> Result<RecordedRequest<T>, AuditError> {
        let key = T::request_key(row);
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            check_session_open(&tx, T::session_id(row))?;
            T::insert_request(&tx, row)?;
            tx.commit()?;
            Ok(())
        })?;
        Ok(RecordedRequest {
            audit: Arc::clone(self),
            key,
            discharged: false,
            _table: PhantomData,
        })
    }

    /// Append an outcome row for a previously-begun request. Behind
    /// [`RecordedRequest::complete`]; `pub(crate)` so it cannot be reached without
    /// a guard.
    pub(crate) fn record_effect_outcome<T: EffectAuditTable>(
        &self,
        outcome: &T::OutcomeRow<'_>,
    ) -> Result<(), AuditError> {
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            T::insert_outcome(&tx, outcome)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Write a request row and its outcome row in a *single* transaction — one
    /// commit, one `fsync` — for authority-free read paths (the Nix-cache serve)
    /// where the request row need not be durable before the action.
    ///
    /// This is the throughput lever for those high-volume rows. The two-phase
    /// [`begin_effect`](AuditLog::begin_effect) + [`complete`](RecordedRequest::complete)
    /// pays two fsync'd commits per request; on the broker-VM audit DB (a virtiofs
    /// mount, where every `fsync` round-trips to the host) that serialized
    /// double-commit dominated agent-VM provisioning. Coalescing halves it, and —
    /// because both rows share one transaction — a request row never lands without
    /// its outcome. It is deliberately *not* used for writes that record granted
    /// authority: grants/mints keep the two-phase split so the request is durable
    /// before the action.
    ///
    /// One consequence is explicit and accepted: if the session **closes during
    /// the fetch**, this coalesced write is refused (the session-open check below,
    /// belt-and-braces with the `*_request_requires_open_session` trigger), and —
    /// unlike the two-phase path, whose pre-fetch request row survives a mid-fetch
    /// close — there is no earlier row to fall back on, so that cache read goes
    /// unrecorded as a structured row. It is bounded and benign: these paths grant
    /// no authority, the caller fails closed, and because the refusal is an
    /// `AuditError` the caller still emits an
    /// [`AUDIT_WRITE_FAILURE_TARGET`](crate::AUDIT_WRITE_FAILURE_TARGET) event.
    ///
    /// Refuses rows whose keys disagree (an outcome for an older request must
    /// never land beside a fresh dangling request).
    pub fn record_effect_coalesced<T: EffectAuditTable>(
        &self,
        request: &T::RequestRow<'_>,
        outcome: &T::OutcomeRow<'_>,
    ) -> Result<(), AuditError> {
        // Enforced at runtime, not just debug: a stripped assert could otherwise
        // commit the outcome against the wrong request in a release build.
        if T::request_key(request) != T::outcome_key(outcome) {
            return Err(AuditError::Invariant(
                "coalesced audit rows must share a key",
            ));
        }
        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            check_session_open(&tx, T::session_id(request))?;
            T::insert_request(&tx, request)?;
            T::insert_outcome(&tx, outcome)?;
            tx.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_session;
    use rusqlite::params;
    use writ_core::core::{RequestId, SessionRecord, UnixMillis};

    // A scratch effect table with a bespoke column shape (deliberately unlike the
    // proxy tables) that exercises the generic guard without any production
    // migration: a request row of (key, session, note) and an outcome of
    // (key, status).
    struct ScratchTable;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ScratchRequest {
        key: RequestId,
        session_id: SessionId,
        note: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ScratchOutcome {
        key: RequestId,
        status: i64,
    }

    impl sealed::Sealed for ScratchTable {}
    impl EffectAuditTable for ScratchTable {
        type RequestRow<'a> = ScratchRequest;
        type OutcomeRow<'a> = ScratchOutcome;
        type Key = RequestId;
        const REQUEST_TABLE: &'static str = "scratch_request";
        const OUTCOME_TABLE: &'static str = "scratch_outcome";
        const LABEL: &'static str = "Scratch";

        fn insert_request(conn: &Connection, row: &ScratchRequest) -> Result<(), AuditError> {
            if row.note.is_empty() {
                return Err(AuditError::Invariant("scratch note must not be empty"));
            }
            conn.execute(
                "INSERT INTO scratch_request (key, session_id, note) VALUES (?1, ?2, ?3)",
                params![
                    row.key.as_uuid().to_string(),
                    row.session_id.as_uuid().to_string(),
                    row.note,
                ],
            )?;
            Ok(())
        }

        fn insert_outcome(conn: &Connection, row: &ScratchOutcome) -> Result<(), AuditError> {
            conn.execute(
                "INSERT INTO scratch_outcome (key, status) VALUES (?1, ?2)",
                params![row.key.as_uuid().to_string(), row.status],
            )?;
            Ok(())
        }

        fn session_id(row: &ScratchRequest) -> SessionId {
            row.session_id
        }
        fn request_key(row: &ScratchRequest) -> RequestId {
            row.key
        }
        fn outcome_key(row: &ScratchOutcome) -> RequestId {
            row.key
        }
    }

    // The scratch table opts into abandonment so the `abandon` test below can
    // exercise the gated method; the real production opt-in is git-push.
    impl AbandonableEffect for ScratchTable {}

    fn install_scratch_tables(log: &AuditLog) {
        log.with_conn_mut(|c| {
            c.execute_batch(
                r#"
CREATE TABLE scratch_request (
    key        TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(session_id),
    note       TEXT NOT NULL
);
CREATE TABLE scratch_outcome (
    key    TEXT PRIMARY KEY REFERENCES scratch_request(key),
    status INTEGER NOT NULL
);
"#,
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn dump_request(log: &AuditLog) -> Vec<(String, String, String)> {
        log.with_conn(|c| {
            let mut stmt =
                c.prepare("SELECT key, session_id, note FROM scratch_request ORDER BY rowid")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    fn dump_outcome(log: &AuditLog) -> Vec<(String, i64)> {
        log.with_conn(|c| {
            let mut stmt = c.prepare("SELECT key, status FROM scratch_outcome ORDER BY rowid")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    fn open_log() -> (Arc<AuditLog>, SessionRecord) {
        let log = Arc::new(AuditLog::open_in_memory().unwrap());
        install_scratch_tables(&log);
        let s = sample_session();
        log.open_session(&s).unwrap();
        (log, s)
    }

    #[test]
    fn begin_then_complete_writes_the_pair() {
        let (log, s) = open_log();
        let key = RequestId::new();
        let guard = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key,
                session_id: s.session_id,
                note: "hello".into(),
            })
            .unwrap();
        assert_eq!(guard.key(), &key);
        // Request row is durable before the outcome.
        assert_eq!(dump_request(&log).len(), 1);
        assert!(dump_outcome(&log).is_empty());

        guard
            .complete(&ScratchOutcome { key, status: 200 })
            .unwrap();
        assert_eq!(dump_outcome(&log), vec![(key.as_uuid().to_string(), 200)]);
    }

    #[test]
    fn begin_rejects_closed_and_missing_session() {
        let (log, s) = open_log();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();
        let closed = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key: RequestId::new(),
                session_id: s.session_id,
                note: "x".into(),
            })
            .unwrap_err();
        assert!(matches!(closed, AuditError::Invariant("session is closed")));

        let missing = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key: RequestId::new(),
                session_id: SessionId::new(),
                note: "x".into(),
            })
            .unwrap_err();
        assert!(matches!(
            missing,
            AuditError::Invariant("session does not exist")
        ));
        assert!(dump_request(&log).is_empty());
    }

    #[test]
    fn complete_rejects_an_outcome_for_a_different_request() {
        let (log, s) = open_log();
        let key = RequestId::new();
        let guard = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key,
                session_id: s.session_id,
                note: "hello".into(),
            })
            .unwrap();
        // An outcome keyed to some *other* request must be refused, and no outcome
        // row written.
        let err = guard
            .complete(&ScratchOutcome {
                key: RequestId::new(),
                status: 200,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::Invariant("outcome key does not match the guard's request")
        ));
        assert!(dump_outcome(&log).is_empty());
    }

    #[test]
    fn coalesced_writes_both_and_rejects_key_mismatch_and_closed_session() {
        let (log, s) = open_log();
        let key = RequestId::new();
        log.record_effect_coalesced::<ScratchTable>(
            &ScratchRequest {
                key,
                session_id: s.session_id,
                note: "hi".into(),
            },
            &ScratchOutcome { key, status: 204 },
        )
        .unwrap();
        assert_eq!(dump_request(&log).len(), 1);
        assert_eq!(dump_outcome(&log), vec![(key.as_uuid().to_string(), 204)]);

        // Mismatched keys: nothing written.
        let mismatch = log
            .record_effect_coalesced::<ScratchTable>(
                &ScratchRequest {
                    key: RequestId::new(),
                    session_id: s.session_id,
                    note: "hi".into(),
                },
                &ScratchOutcome {
                    key: RequestId::new(),
                    status: 204,
                },
            )
            .unwrap_err();
        assert!(matches!(
            mismatch,
            AuditError::Invariant("coalesced audit rows must share a key")
        ));
        assert_eq!(
            dump_request(&log).len(),
            1,
            "no new request row on mismatch"
        );

        // Closed session: refused, nothing written.
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_060))
            .unwrap();
        let key2 = RequestId::new();
        let closed = log
            .record_effect_coalesced::<ScratchTable>(
                &ScratchRequest {
                    key: key2,
                    session_id: s.session_id,
                    note: "hi".into(),
                },
                &ScratchOutcome {
                    key: key2,
                    status: 204,
                },
            )
            .unwrap_err();
        assert!(matches!(closed, AuditError::Invariant("session is closed")));
        assert_eq!(
            dump_request(&log).len(),
            1,
            "no request row for closed session"
        );
    }

    // `abandon` is the deliberate counterpart to the panicking bare drop below: it
    // discharges the guard *without* an outcome (no panic, no fabricated row),
    // leaving the request row dangling for the boot-time scan to flag. This must
    // hold in debug *and* release — abandoning is intentional, never a bug.
    #[test]
    fn abandon_leaves_the_request_dangling_without_an_outcome_or_panic() {
        let (log, s) = open_log();
        let key = RequestId::new();
        let guard = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key,
                session_id: s.session_id,
                note: "hello".into(),
            })
            .unwrap();
        assert_eq!(dump_request(&log).len(), 1);

        // Discharge with no outcome. Unlike the bare drop below this must NOT
        // panic (even with debug assertions on): the caller asserts the dangling
        // row is intentional.
        guard.abandon();

        assert_eq!(
            dump_request(&log).len(),
            1,
            "the request row is left in place"
        );
        assert!(
            dump_outcome(&log).is_empty(),
            "abandon writes no outcome row"
        );
        // The dangling row is exactly what the boot-time unpaired-row scan flags.
        assert_eq!(
            log.count_unpaired_effect_request_rows("scratch_request", "scratch_outcome", "key")
                .unwrap(),
            1,
        );
    }

    // A guard dropped without discharge fails fast via the `Drop` `debug_assert`.
    // That assert is compiled out under `--release`, so this test only applies —
    // and only runs — with debug assertions on; otherwise `#[should_panic]` would
    // itself fail because nothing panicked.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "dropped without discharge")]
    fn dropping_a_guard_without_discharge_panics_in_debug() {
        let (log, s) = open_log();
        let guard = log
            .begin_effect::<ScratchTable>(&ScratchRequest {
                key: RequestId::new(),
                session_id: s.session_id,
                note: "hello".into(),
            })
            .unwrap();
        drop(guard); // no complete()
    }
}
