//! Flake-input provisioning audit DAO and row parsing.
//!
//! Unlike the Claude/OpenAI/Nix-cache tables this is not an HTTP proxy
//! shape, so it does not share [`super::proxy_table`]'s generic writers:
//! a provisioning request carries the flake checkout and target cache it
//! provisions (not method/target/route), and an outcome carries the
//! archived store-path count and total bytes (not an HTTP status). The
//! two-phase, append-only, open-session-gated structure is the same; the
//! columns are this domain's own.

use rusqlite::{OptionalExtension, Row, params};

use super::validation::{labeled_invariant, u64_to_sql_i64};
use super::{AuditError, AuditLog};
use crate::core::{RequestId, SessionId, UnixMillis};

const LABEL: &str = "Flake provision";

/// A provisioning attempt recorded before `nix flake archive` is run, so
/// the attempted host egress is durable even if the broker dies mid-fetch.
#[derive(Debug)]
pub struct FlakeProvisionRequestRecord<'a> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub flake_dir: &'a str,
    pub cache_dir: &'a str,
    pub input_count: u64,
}

/// The observed result of a provisioning run. Success carries the archive
/// metrics; failure carries the reason (timeout, non-zero exit, or
/// over-budget). Modelled as a sum so a row can never claim both metrics
/// and an error.
#[derive(Debug)]
pub enum FlakeProvisionResult<'a> {
    Success {
        archived_path_count: u64,
        archived_bytes: u64,
    },
    Failure {
        error: &'a str,
    },
}

#[derive(Debug)]
pub struct FlakeProvisionOutcomeRecord<'a> {
    pub request_id: RequestId,
    pub completed_at: UnixMillis,
    pub result: FlakeProvisionResult<'a>,
}

/// Fully-hydrated row returned by
/// [`AuditLog::list_flake_provision_requests_for_session`]. `completed_at`
/// and `outcome` are `None` when the request was recorded but no matching
/// outcome row exists yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeProvisionAuditEntry {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub received_at: UnixMillis,
    pub flake_dir: String,
    pub cache_dir: String,
    pub input_count: u64,
    pub completed_at: Option<UnixMillis>,
    pub outcome: Option<FlakeProvisionAuditOutcome>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlakeProvisionAuditOutcome {
    Success {
        archived_path_count: u64,
        archived_bytes: u64,
    },
    Failure {
        error: String,
    },
}

impl AuditLog {
    /// Persist a provisioning request before `nix flake archive` is run.
    /// The matching outcome is appended with
    /// [`AuditLog::record_flake_provision_outcome`].
    pub fn record_flake_provision_request(
        &self,
        r: &FlakeProvisionRequestRecord<'_>,
    ) -> Result<(), AuditError> {
        if r.flake_dir.is_empty() {
            return Err(labeled_invariant(
                LABEL,
                "flake directory must not be empty",
            ));
        }
        if r.cache_dir.is_empty() {
            return Err(labeled_invariant(
                LABEL,
                "cache directory must not be empty",
            ));
        }
        let input_count = u64_to_sql_i64(r.input_count, LABEL)?;

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
                "INSERT INTO flake_provision_request (
                     request_id,
                     session_id,
                     received_at,
                     flake_dir,
                     cache_dir,
                     input_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.request_id.as_uuid().to_string(),
                    r.session_id.as_uuid().to_string(),
                    r.received_at.as_millis(),
                    r.flake_dir,
                    r.cache_dir,
                    input_count,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Append the observed outcome for a previously-recorded provisioning
    /// request. A separate row so the fetch is never attempted before the
    /// request itself is durable; the FK enforces that the request exists.
    pub fn record_flake_provision_outcome(
        &self,
        r: &FlakeProvisionOutcomeRecord<'_>,
    ) -> Result<(), AuditError> {
        let (status, archived_path_count, archived_bytes, error) = match &r.result {
            FlakeProvisionResult::Success {
                archived_path_count,
                archived_bytes,
            } => (
                "success",
                u64_to_sql_i64(*archived_path_count, LABEL)?,
                u64_to_sql_i64(*archived_bytes, LABEL)?,
                None,
            ),
            FlakeProvisionResult::Failure { error } => {
                if error.is_empty() {
                    return Err(labeled_invariant(LABEL, "failure error must not be empty"));
                }
                ("failure", 0, 0, Some(*error))
            }
        };

        self.with_conn_mut(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO flake_provision_outcome (
                     request_id,
                     completed_at,
                     status,
                     archived_path_count,
                     archived_bytes,
                     error
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.request_id.as_uuid().to_string(),
                    r.completed_at.as_millis(),
                    status,
                    archived_path_count,
                    archived_bytes,
                    error,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn list_flake_provision_requests_for_session(
        &self,
        id: SessionId,
    ) -> Result<Vec<FlakeProvisionAuditEntry>, AuditError> {
        self.with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT
                     r.request_id,
                     r.session_id,
                     r.received_at,
                     r.flake_dir,
                     r.cache_dir,
                     r.input_count,
                     o.completed_at,
                     o.status,
                     o.archived_path_count,
                     o.archived_bytes,
                     o.error
                 FROM flake_provision_request r
                 LEFT JOIN flake_provision_outcome o ON o.request_id = r.request_id
                 WHERE r.session_id = ?1
                 ORDER BY r.received_at ASC, r.rowid ASC",
            )?;
            let rows = stmt
                .query_map(
                    params![id.as_uuid().to_string()],
                    flake_provision_audit_entry_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect::<Result<Vec<_>, _>>()
        })
    }
}

fn flake_provision_audit_entry_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<Result<FlakeProvisionAuditEntry, AuditError>> {
    let request_id_str: String = row.get(0)?;
    let session_id_str: String = row.get(1)?;
    let received_at: i64 = row.get(2)?;
    let flake_dir: String = row.get(3)?;
    let cache_dir: String = row.get(4)?;
    let input_count: i64 = row.get(5)?;
    let completed_at: Option<i64> = row.get(6)?;
    let status: Option<String> = row.get(7)?;
    let archived_path_count: Option<i64> = row.get(8)?;
    let archived_bytes: Option<i64> = row.get(9)?;
    let error: Option<String> = row.get(10)?;

    let parse = || -> Result<FlakeProvisionAuditEntry, AuditError> {
        let request_id = uuid::Uuid::parse_str(&request_id_str).map_err(|_| {
            AuditError::Invariant("Flake provision audit row: request_id not a uuid")
        })?;
        let session_id = uuid::Uuid::parse_str(&session_id_str).map_err(|_| {
            AuditError::Invariant("Flake provision audit row: session_id not a uuid")
        })?;
        let input_count = u64::try_from(input_count)
            .map_err(|_| AuditError::Invariant("Flake provision audit input count is negative"))?;

        let outcome = match status.as_deref() {
            None => None,
            Some("success") => {
                if error.is_some() {
                    return Err(AuditError::Invariant(
                        "Flake provision audit success row has an error",
                    ));
                }
                Some(FlakeProvisionAuditOutcome::Success {
                    archived_path_count: nonneg(archived_path_count, "archived path count")?,
                    archived_bytes: nonneg(archived_bytes, "archived bytes")?,
                })
            }
            Some("failure") => match error {
                Some(error) if !error.is_empty() => {
                    Some(FlakeProvisionAuditOutcome::Failure { error })
                }
                _ => {
                    return Err(AuditError::Invariant(
                        "Flake provision audit failure row lacks an error",
                    ));
                }
            },
            Some(_) => {
                return Err(AuditError::Invariant(
                    "Flake provision audit status is invalid",
                ));
            }
        };

        Ok(FlakeProvisionAuditEntry {
            request_id: RequestId::from_uuid(request_id),
            session_id: SessionId::from_uuid(session_id),
            received_at: UnixMillis::from_millis(received_at),
            flake_dir,
            cache_dir,
            input_count,
            completed_at: completed_at.map(UnixMillis::from_millis),
            outcome,
        })
    };
    Ok(parse())
}

fn nonneg(value: Option<i64>, what: &'static str) -> Result<u64, AuditError> {
    let value = value.ok_or(AuditError::Invariant(match what {
        "archived path count" => "Flake provision audit outcome row missing archived path count",
        _ => "Flake provision audit outcome row missing archived bytes",
    }))?;
    u64::try_from(value).map_err(|_| {
        AuditError::Invariant(match what {
            "archived path count" => "Flake provision audit archived path count is negative",
            _ => "Flake provision audit archived bytes is negative",
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::sample_session;

    fn request(
        request_id: RequestId,
        session_id: SessionId,
    ) -> FlakeProvisionRequestRecord<'static> {
        FlakeProvisionRequestRecord {
            request_id,
            session_id,
            received_at: UnixMillis::from_millis(1_700_000_100),
            flake_dir: "/work/repo",
            cache_dir: "/cache/flake",
            input_count: 3,
        }
    }

    #[test]
    fn request_then_success_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_flake_provision_request(&request(request_id, s.session_id))
            .unwrap();
        log.record_flake_provision_outcome(&FlakeProvisionOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_200),
            result: FlakeProvisionResult::Success {
                archived_path_count: 5,
                archived_bytes: 4096,
            },
        })
        .unwrap();

        let entries = log
            .list_flake_provision_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(
            entries,
            vec![FlakeProvisionAuditEntry {
                request_id,
                session_id: s.session_id,
                received_at: UnixMillis::from_millis(1_700_000_100),
                flake_dir: "/work/repo".to_string(),
                cache_dir: "/cache/flake".to_string(),
                input_count: 3,
                completed_at: Some(UnixMillis::from_millis(1_700_000_200)),
                outcome: Some(FlakeProvisionAuditOutcome::Success {
                    archived_path_count: 5,
                    archived_bytes: 4096,
                }),
            }]
        );
    }

    #[test]
    fn request_then_failure_outcome_roundtrips() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_flake_provision_request(&request(request_id, s.session_id))
            .unwrap();
        log.record_flake_provision_outcome(&FlakeProvisionOutcomeRecord {
            request_id,
            completed_at: UnixMillis::from_millis(1_700_000_200),
            result: FlakeProvisionResult::Failure {
                error: "nix flake archive timed out after 300s",
            },
        })
        .unwrap();

        let entries = log
            .list_flake_provision_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].outcome,
            Some(FlakeProvisionAuditOutcome::Failure {
                error: "nix flake archive timed out after 300s".to_string(),
            })
        );
    }

    #[test]
    fn request_without_outcome_has_none_outcome() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();

        log.record_flake_provision_request(&request(request_id, s.session_id))
            .unwrap();
        let entries = log
            .list_flake_provision_requests_for_session(s.session_id)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].completed_at, None);
        assert_eq!(entries[0].outcome, None);
    }

    #[test]
    fn request_rejects_closed_or_missing_session() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        log.close_session(s.session_id, UnixMillis::from_millis(1_700_000_050))
            .unwrap();

        let closed = log
            .record_flake_provision_request(&request(RequestId::new(), s.session_id))
            .unwrap_err();
        assert!(
            matches!(closed, AuditError::Invariant("session is closed")),
            "got: {closed:?}"
        );

        let missing = log
            .record_flake_provision_request(&request(RequestId::new(), SessionId::new()))
            .unwrap_err();
        assert!(
            matches!(missing, AuditError::Invariant("session does not exist")),
            "got: {missing:?}"
        );
    }

    #[test]
    fn request_rejects_empty_paths() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();

        let mut empty_flake = request(RequestId::new(), s.session_id);
        empty_flake.flake_dir = "";
        assert!(matches!(
            log.record_flake_provision_request(&empty_flake)
                .unwrap_err(),
            AuditError::LabeledInvariant {
                label: "Flake provision",
                message: "flake directory must not be empty"
            }
        ));

        let mut empty_cache = request(RequestId::new(), s.session_id);
        empty_cache.cache_dir = "";
        assert!(matches!(
            log.record_flake_provision_request(&empty_cache)
                .unwrap_err(),
            AuditError::LabeledInvariant {
                label: "Flake provision",
                message: "cache directory must not be empty"
            }
        ));
    }

    #[test]
    fn outcome_rejects_empty_failure_error() {
        let log = AuditLog::open_in_memory().unwrap();
        let s = sample_session();
        log.open_session(&s).unwrap();
        let request_id = RequestId::new();
        log.record_flake_provision_request(&request(request_id, s.session_id))
            .unwrap();

        let err = log
            .record_flake_provision_outcome(&FlakeProvisionOutcomeRecord {
                request_id,
                completed_at: UnixMillis::from_millis(1_700_000_200),
                result: FlakeProvisionResult::Failure { error: "" },
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::LabeledInvariant {
                label: "Flake provision",
                message: "failure error must not be empty"
            }
        ));
    }

    #[test]
    fn outcome_without_request_is_rejected_by_foreign_key() {
        let log = AuditLog::open_in_memory().unwrap();
        let err = log
            .record_flake_provision_outcome(&FlakeProvisionOutcomeRecord {
                request_id: RequestId::new(),
                completed_at: UnixMillis::from_millis(1),
                result: FlakeProvisionResult::Success {
                    archived_path_count: 1,
                    archived_bytes: 1,
                },
            })
            .unwrap_err();
        let AuditError::Sqlite(e) = err else {
            panic!("expected sqlite FK error, got: {err:?}");
        };
        assert!(
            e.to_string().to_lowercase().contains("foreign key"),
            "expected FK violation, got: {e}"
        );
    }
}
