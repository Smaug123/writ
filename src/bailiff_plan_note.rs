//! Bailiff-owned plan-submission note primitive. Defines the
//! `PlanNote` body and the `refs/notes/bailiff/v1/plans/<plan-id>` ref
//! scheme bailiff uses to attest "writ ran agent run R for plan P and
//! produced the signed envelope at OID O in writ's repo".
//!
//! This is slice C1 of `docs/plans/2026-05-14-bailiff-split.md`: a
//! pure data layer with no IO and no CLI. The write helper that uses
//! this lands in slice C2; the `bailiff plan submit` CLI verb that
//! drives it lands in slice C3.
//!
//! `PlanId` is a fresh bailiff-side type — not the `agent_plan::PlanId`
//! that's leaving writ in slice G. Keeping them distinct now means
//! the slice-G strip can delete `agent_plan` wholesale instead of
//! threading a renaming through bailiff at the same time.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::{NotesRef, NotesRefError, SshSignature};
use crate::protocol::SignedRunMetadata;
use crate::vm_git::GitObjectId;

/// Notes-ref prefix for every bailiff-managed plan. The `<plan-id>`
/// segment is appended verbatim; see [`plan_submission_ref`].
///
/// The `v1` segment is owned by bailiff and bumps independently of
/// writ's own `v1` namespace — per the slice-B pinned design
/// decisions, each owner-namespace evolves on its own schedule.
pub const BAILIFF_PLAN_NOTES_REF_PREFIX: &str = "refs/notes/bailiff/v1/plans/";

/// Identifies one bailiff-managed plan workflow. Stable across the
/// submission, any future reviews, and the decision — every
/// per-plan artefact attaches to the same ref derived from this id.
///
/// UUID v4 under the hood, the same shape (transparent serde, debug
/// label, FromStr) as writ's other newtypes (`AgentRunId`,
/// `SessionId`, the soon-to-leave `agent_plan::PlanId`). Bailiff
/// allocates the id on submit; writ never sees it.
#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(Uuid);

impl PlanId {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for PlanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for PlanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BailiffPlanId({})", self.0)
    }
}

impl FromStr for PlanId {
    type Err = uuid::Error;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(raw)?))
    }
}

/// Notes ref where bailiff stores every artefact for `plan_id` — the
/// submission note in slice C, plus any future per-plan curation
/// notes (decisions, reviews, aborts) in slices D and E. One ref per
/// plan keeps a plan's history under a single git-notes namespace, so
/// `git notes --ref=<ref> list` is the complete history of one plan
/// and `git update-ref -d <ref>` deletes one plan's history cleanly.
///
/// The returned ref is always well-formed: the prefix is a static
/// `refs/...` path, the UUID display form contains only hex digits
/// and hyphens, and `NotesRef::try_new` rejects nothing under those
/// constraints. `expect` is therefore correct, not a TODO.
pub fn plan_submission_ref(plan_id: PlanId) -> NotesRef {
    NotesRef::try_new(format!("{BAILIFF_PLAN_NOTES_REF_PREFIX}{plan_id}"))
        .expect("static prefix + UUID display is always a valid NotesRef")
}

/// Deterministic seed-blob bytes for `plan_id`. Whoever writes (or
/// later reads) the submission note hashes these bytes via
/// `git hash-object`; the resulting OID is the target the note
/// attaches to inside [`plan_submission_ref`]. Determinism matters
/// because reading a plan note requires recomputing the seed OID
/// from the plan id alone — no separate registry needed.
///
/// We use the plan id's canonical string form (lowercase hyphenated
/// UUID) so the seed bytes are stable across endianness and have an
/// obvious mapping to the plan id any operator sees.
pub fn plan_seed_blob_bytes(plan_id: PlanId) -> Vec<u8> {
    plan_id.to_string().into_bytes()
}

/// A bailiff-owned attestation that writ ran an agent for `plan_id`
/// and produced the signed output reachable at `writ_output_oid` in
/// writ's repo. Stored as the body of one note under
/// [`plan_submission_ref`].
///
/// What this carries:
/// - `plan_id`: bailiff's identifier for the workflow.
/// - `purpose`: the opaque tag bailiff sent on `RunAgent`; recorded
///   verbatim for cross-correlation with writ's audit row.
/// - `writ_output_oid`: the *notes-target* OID inside writ's
///   `refs/notes/writ/v1/agent-outputs` ref — a per-run seed object
///   the writ-side `RunAgent` handler hashed from the run id. The
///   signed envelope itself lives in the *note body* attached at
///   this target (per slice B's "envelope in note body, not a
///   separate blob" decision), so a reader fetches
///   `refs/notes/writ/v1/agent-outputs` into bailiff's repo and runs
///   `git notes --ref=refs/notes/writ/v1/agent-outputs show
///   <writ_output_oid>` to retrieve the envelope bytes. `cat-file
///   <writ_output_oid>` returns the seed object, not the envelope.
/// - `signed_metadata`: the full `SignedRunMetadata` writ returned.
///   Carries the originating prompt hash, output envelope hash,
///   granted capabilities, exit code, completion time, session id,
///   and the fingerprint of writ's signing key.
/// - `signature`: detached SSH signature over `signed_metadata`'s
///   canonical bytes. Verifies against the keyring entry resolved by
///   `signed_metadata.signing_key_fingerprint`.
///
/// The prompt hash and output envelope hash live in
/// `signed_metadata` (writ signed them), so the plan note does not
/// duplicate them at the top level — a verifier reads the metadata
/// to learn them.
///
/// `deny_unknown_fields` catches an unexpected key at parse time
/// rather than silently dropping it. A future field addition is a
/// schema bump (`v1` → `v2` in the ref prefix); silently accepting
/// extra fields would let a writer-side regression sneak past the
/// reader.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanNote {
    pub plan_id: PlanId,
    pub purpose: String,
    pub writ_output_oid: GitObjectId,
    pub signed_metadata: SignedRunMetadata,
    pub signature: SshSignature,
}

impl PlanNote {
    /// Canonical byte representation of the note body. Compact JSON
    /// (no whitespace) with keys emitted in struct-declaration order
    /// — the same canonicalisation `SignedRunMetadata::canonical_bytes`
    /// uses, so a reader can rely on identical parse/re-emit
    /// semantics across both layers.
    ///
    /// The bytes returned here are what gets written as the body of
    /// the git note. They are *not* covered by writ's signature —
    /// writ signs only `signed_metadata`'s canonical bytes; the
    /// note's framing (this struct) is bailiff's own.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("PlanNote serialises to JSON without IO; cannot fail")
    }

    /// Inverse of [`Self::canonical_bytes`]. Fails on malformed JSON,
    /// on any unknown top-level field (`deny_unknown_fields`), or on
    /// any nested validation error from the field types (`PlanId`,
    /// `GitObjectId`, `SshSignature`, `SignedRunMetadata`).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PlanNoteParseError> {
        serde_json::from_slice(bytes).map_err(PlanNoteParseError::Json)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlanNoteParseError {
    #[error("plan-note body is not valid canonical JSON: {0}")]
    Json(#[source] serde_json::Error),
}

/// Reasons [`plan_submission_ref`] would fail to construct a
/// `NotesRef`. None are reachable for any caller using
/// [`PlanId::new`] / [`PlanId::from_str`] — the type means we only
/// ever feed validated UUIDs through — but the error type exists so
/// a future schema change (e.g. allowing operator-chosen ids) has a
/// place to surface validation failures.
#[derive(Debug, thiserror::Error)]
pub enum PlanSubmissionRefError {
    #[error("invalid notes ref: {0}")]
    InvalidRef(#[from] NotesRefError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_run::AgentRunId;
    use crate::core::SessionId;
    use crate::core::{CapabilitySet, RepoRef, Sha256Hex, SshKeyFingerprint, UnixMillis};

    fn sample_repo() -> RepoRef {
        RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        }
    }

    fn sample_sha256(byte: char) -> Sha256Hex {
        Sha256Hex::try_new(byte.to_string().repeat(64)).unwrap()
    }

    fn sample_ssh_fingerprint() -> SshKeyFingerprint {
        SshKeyFingerprint::try_new(format!("SHA256:{}", "a".repeat(43))).unwrap()
    }

    fn sample_signature() -> SshSignature {
        SshSignature::try_new(
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ...\n-----END SSH SIGNATURE-----",
        )
        .unwrap()
    }

    fn sample_signed_metadata() -> SignedRunMetadata {
        SignedRunMetadata {
            run_id: AgentRunId::new(),
            session_id: SessionId::new(),
            prompt_sha256: sample_sha256('a'),
            output_envelope_sha256: sample_sha256('b'),
            capabilities: vec![CapabilitySet::WorkspaceRead {
                repo: sample_repo(),
            }],
            exit_code: 0,
            completed_at: UnixMillis::from_millis(1_700_000_000_000),
            signing_key_fingerprint: sample_ssh_fingerprint(),
        }
    }

    fn sample_output_oid() -> GitObjectId {
        GitObjectId::new("c".repeat(40)).unwrap()
    }

    fn sample_plan_note() -> PlanNote {
        PlanNote {
            plan_id: PlanId::new(),
            purpose: "plan-stage".into(),
            writ_output_oid: sample_output_oid(),
            signed_metadata: sample_signed_metadata(),
            signature: sample_signature(),
        }
    }

    /// `plan_submission_ref` produces a ref under the documented
    /// prefix with the plan id appended verbatim. Pin both pieces so
    /// a regression that drops the `v1` segment (or appends an
    /// unexpected suffix) is caught.
    #[test]
    fn plan_submission_ref_lives_under_bailiff_v1_plans_prefix() {
        let plan_id = PlanId::new();
        let r = plan_submission_ref(plan_id);
        assert!(
            r.as_str().starts_with(BAILIFF_PLAN_NOTES_REF_PREFIX),
            "ref `{}` does not start with `{}`",
            r.as_str(),
            BAILIFF_PLAN_NOTES_REF_PREFIX,
        );
        let tail = r
            .as_str()
            .strip_prefix(BAILIFF_PLAN_NOTES_REF_PREFIX)
            .unwrap();
        assert_eq!(tail, plan_id.to_string());
    }

    /// Distinct plans must produce distinct refs. A regression that
    /// collapses every plan to the same ref (e.g. dropping the
    /// `plan_id` segment) would silently overwrite history.
    #[test]
    fn plan_submission_ref_is_unique_per_plan() {
        let a = PlanId::new();
        let b = PlanId::new();
        assert_ne!(a, b, "PlanId::new must not collide");
        assert_ne!(plan_submission_ref(a), plan_submission_ref(b));
    }

    /// The seed blob bytes are the plan id's canonical string form.
    /// Determinism is the contract: any future writer must compute
    /// the same OID via `git hash-object` as any future reader.
    #[test]
    fn plan_seed_blob_bytes_is_plan_id_string() {
        let plan_id = PlanId::new();
        let bytes = plan_seed_blob_bytes(plan_id);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), plan_id.to_string());
    }

    /// `PlanId::from_str` round-trips through Display.
    #[test]
    fn plan_id_display_parse_round_trips() {
        let p = PlanId::new();
        let s = p.to_string();
        let back: PlanId = s.parse().unwrap();
        assert_eq!(p, back);
    }

    /// Canonical bytes round-trip: serialise → parse → re-serialise
    /// must reproduce the same bytes. Mirrors the
    /// `SignedRunMetadata::canonical_bytes` round-trip pin so any
    /// reader can re-compute the canonical form locally and compare.
    #[test]
    fn plan_note_canonical_bytes_round_trip_is_stable() {
        let note = sample_plan_note();
        let first = note.canonical_bytes();
        let parsed = PlanNote::from_canonical_bytes(&first).unwrap();
        let second = parsed.canonical_bytes();
        assert_eq!(first, second);
    }

    /// Pin the canonical wire shape: a compact JSON object with the
    /// five top-level keys in struct-declaration order, each value in
    /// its own canonical form. A reviewer reading this string sees
    /// exactly what the writer must emit.
    #[test]
    fn plan_note_canonical_bytes_pin_field_order() {
        let note = sample_plan_note();
        let bytes = note.canonical_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Top-level field order, no whitespace. `signed_metadata` and
        // `signature` carry JSON-escaped values whose literal byte
        // form differs from their `Display`; pin the *positions* of
        // every top-level key rather than reconstructing the full
        // wire bytes here. That's enough to catch a field-order
        // regression while leaving inner-value canonicalisation to
        // each field type's own round-trip test (covered by
        // `signed_run_metadata_canonical_bytes_*` in `protocol.rs`).
        let positions: Vec<usize> = [
            "\"plan_id\":",
            "\"purpose\":",
            "\"writ_output_oid\":",
            "\"signed_metadata\":",
            "\"signature\":",
        ]
        .into_iter()
        .map(|key| s.find(key).unwrap_or_else(|| panic!("missing {key}: {s}")))
        .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "field order regression — positions={positions:?}, actual: {s}",
        );
        assert!(s.starts_with('{'), "actual: {s}");
        assert!(s.ends_with('}'), "actual: {s}");
    }

    /// Different notes produce different canonical bytes. Basic
    /// distinctness — a regression that collapses every payload to
    /// the same bytes surfaces immediately.
    #[test]
    fn plan_note_canonical_bytes_distinguish_distinct_payloads() {
        let a = sample_plan_note();
        let mut b = sample_plan_note();
        b.purpose = "different".into();
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// `deny_unknown_fields` rejects extra top-level keys. A future
    /// field addition is a schema bump (the `v1` segment in the ref
    /// prefix); silently accepting unknown fields would let a writer
    /// regression slip past readers that don't know the new field.
    #[test]
    fn plan_note_rejects_unknown_top_level_fields() {
        let note = sample_plan_note();
        let mut value: serde_json::Value = serde_json::to_value(&note).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::String("nope".into()));
        let s = serde_json::to_vec(&value).unwrap();
        let err = PlanNote::from_canonical_bytes(&s).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("extra") || msg.contains("unknown field"),
            "expected unknown-field error, got: {msg}"
        );
    }

    /// `PlanId` serialises transparently — the wire form is a bare
    /// UUID string, not a wrapped object. Pin this so a future
    /// macro tweak that produces `{"plan_id": {"0": "uuid"}}`
    /// is caught.
    #[test]
    fn plan_id_serialises_as_bare_uuid_string() {
        let plan_id = PlanId::new();
        let j = serde_json::to_value(plan_id).unwrap();
        assert_eq!(j, serde_json::Value::String(plan_id.to_string()));
    }

    /// `PlanNote` JSON round-trips. Standard pin; mirrors the
    /// `run_agent_completed_roundtrips` style elsewhere.
    #[test]
    fn plan_note_json_roundtrips() {
        let note = sample_plan_note();
        let bytes = note.canonical_bytes();
        let back = PlanNote::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, note);
    }
}
