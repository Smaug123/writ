//! Bailiff-owned per-plan note primitives. Defines the
//! `refs/notes/bailiff/v1/plans/<plan-id>` ref scheme that holds every
//! artefact bailiff records about one plan workflow, plus the two
//! note bodies that live under it today:
//!
//! - [`PlanNote`] — slice C's submission attestation: "writ ran agent
//!   run R for plan P and produced the signed envelope at OID O in
//!   writ's repo."
//! - [`DecisionNote`] — slice D1's operator verdict: "plan P was
//!   accepted/rejected at time T by D."
//!
//! Both attach under the same per-plan ref but at distinct
//! deterministic seed OIDs — [`plan_submission_seed_blob_bytes`] and
//! [`plan_decision_seed_blob_bytes`] — so they coexist without
//! colliding. Slice C1 of `docs/plans/2026-05-14-bailiff-split.md`
//! introduced the submission piece; slice D1 of
//! `docs/plans/2026-05-16-slice-d1-decide.md` adds the decision piece.
//! Everything here is pure data with no IO and no CLI; the write
//! helpers live in [`crate::bailiff_plan_write`].
//!
//! `PlanId` is a fresh bailiff-side type — not the `agent_plan::PlanId`
//! that's leaving writ in slice G. Keeping them distinct now means
//! the slice-G strip can delete `agent_plan` wholesale instead of
//! threading a renaming through bailiff at the same time.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bailiff_decision::{Decider, Decision};
use crate::core::{NotesRef, NotesRefError, SshSignature, UnixMillis};
use crate::protocol::SignedRunMetadata;
use crate::vm_git::GitObjectId;

/// Notes-ref prefix for every bailiff-managed plan. The `<plan-id>`
/// segment is appended verbatim; see [`plan_notes_ref`].
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
pub fn plan_notes_ref(plan_id: PlanId) -> NotesRef {
    NotesRef::try_new(format!("{BAILIFF_PLAN_NOTES_REF_PREFIX}{plan_id}"))
        .expect("static prefix + UUID display is always a valid NotesRef")
}

/// Deterministic seed-blob bytes for the **submission** note under
/// [`plan_notes_ref`]`(plan_id)`. Whoever writes (or later reads)
/// the submission note hashes these bytes via `git hash-object`; the
/// resulting OID is the target the note attaches to. Determinism
/// matters because reading a plan note requires recomputing the seed
/// OID from the plan id alone — no separate registry needed.
///
/// We use the plan id's canonical string form (lowercase hyphenated
/// UUID) so the seed bytes are stable across endianness and have an
/// obvious mapping to the plan id any operator sees.
///
/// Sibling helpers under the same notes ref derive a different seed
/// for the same plan id — see [`plan_decision_seed_blob_bytes`] for
/// the slice-D1 decision note. Distinct seeds let the two notes
/// coexist under one per-plan ref without colliding.
pub fn plan_submission_seed_blob_bytes(plan_id: PlanId) -> Vec<u8> {
    plan_id.to_string().into_bytes()
}

/// Deterministic seed-blob bytes for the **decision** note under
/// [`plan_notes_ref`]`(plan_id)`. The `<plan_id>::decision` suffix
/// distinguishes the decision target from the submission target
/// produced by [`plan_submission_seed_blob_bytes`] (which is the
/// bare plan id) so the two notes attach to different objects under
/// the same notes ref.
///
/// The suffix is a literal ASCII `::decision` rather than e.g.
/// `/decision` so the seed bytes themselves never look like a path
/// fragment a casual reader might misinterpret as a ref subpath.
pub fn plan_decision_seed_blob_bytes(plan_id: PlanId) -> Vec<u8> {
    format!("{plan_id}::decision").into_bytes()
}

/// A bailiff-owned attestation that writ ran an agent for `plan_id`
/// and produced the signed output reachable at `writ_output_oid` in
/// writ's repo. Stored as the body of one note under
/// [`plan_notes_ref`].
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

/// A bailiff-owned record of one operator verdict on `plan_id`.
/// Stored as the body of one note under [`plan_notes_ref`] at the
/// seed OID derived from [`plan_decision_seed_blob_bytes`] — distinct
/// from the [`PlanNote`] target so the submission and decision notes
/// coexist under one per-plan ref.
///
/// What this carries:
/// - `plan_id`: bailiff's identifier for the workflow this verdict
///   applies to. The same id whose [`PlanNote`] lives next door under
///   the same notes ref.
/// - `outcome`: accept or reject. Bailiff does no auto-anything; the
///   `Rejected` variant simply means "this plan is dead, the operator
///   does whatever they want next." See [`Decision`] for the rename
///   away from the legacy `RejectedRestart` naming.
/// - `decider`: attribution string. Today the bailiff CLI writes
///   `cli:<USER>`; a future orchestrator agent may write
///   `agent:<run_id>`. [`Decider`] enforces the byte-length and
///   no-NUL bounds at the wire boundary.
/// - `decided_at`: when the verdict was recorded, in unix-epoch
///   milliseconds. Matches `SignedRunMetadata.completed_at`'s
///   timestamp shape so audit-log replays can interleave bailiff
///   verdicts with writ-side run timestamps without conversion.
///
/// **D1 ships unsigned.** The parent split doc defers bailiff's own
/// signing primitives; writ's submission signature on the sibling
/// [`PlanNote`] remains the trust anchor for the plan-as-a-whole. A
/// future schema bump can add a signature field local to this struct.
///
/// **D1 is idempotent.** The write helper rejects a second decision
/// for the same plan id rather than silently overwriting — the
/// operator workflow for "I want to change my mind" is "the plan is
/// dead, submit a new one." A future `v2` ref-prefix bump can switch
/// to per-decision UUIDs for an append-only history if we ever want
/// one; the seed-OID convention pinned here is the migration target.
///
/// `deny_unknown_fields` catches an unexpected key at parse time
/// rather than silently dropping it. Same defence the sibling
/// [`PlanNote`] uses: any future field addition is a schema bump
/// (`v1` → `v2` in the ref prefix); silently accepting extra fields
/// would let a writer-side regression sneak past the reader.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionNote {
    pub plan_id: PlanId,
    pub outcome: Decision,
    pub decider: Decider,
    pub decided_at: UnixMillis,
}

impl DecisionNote {
    /// Canonical byte representation of the note body. Compact JSON
    /// (no whitespace) with keys emitted in struct-declaration order
    /// — the same canonicalisation [`PlanNote::canonical_bytes`] uses.
    ///
    /// The bytes returned here are what gets written as the body of
    /// the git note. D1 does not sign decisions (see the type-level
    /// docstring); the slice-G or successor follow-up that does will
    /// sign exactly these bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("DecisionNote serialises to JSON without IO; cannot fail")
    }

    /// Inverse of [`Self::canonical_bytes`]. Fails on malformed JSON,
    /// on any unknown top-level field (`deny_unknown_fields`), or on
    /// any nested validation error from the field types
    /// ([`PlanId`], [`Decision`], [`Decider`], [`UnixMillis`]).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecisionNoteParseError> {
        serde_json::from_slice(bytes).map_err(DecisionNoteParseError::Json)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecisionNoteParseError {
    #[error("decision-note body is not valid canonical JSON: {0}")]
    Json(#[source] serde_json::Error),
}

/// Reasons [`plan_notes_ref`] would fail to construct a
/// `NotesRef`. None are reachable for any caller using
/// [`PlanId::new`] / [`PlanId::from_str`] — the type means we only
/// ever feed validated UUIDs through — but the error type exists so
/// a future schema change (e.g. allowing operator-chosen ids) has a
/// place to surface validation failures.
#[derive(Debug, thiserror::Error)]
pub enum PlanNotesRefError {
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

    /// `plan_notes_ref` produces a ref under the documented
    /// prefix with the plan id appended verbatim. Pin both pieces so
    /// a regression that drops the `v1` segment (or appends an
    /// unexpected suffix) is caught.
    #[test]
    fn plan_notes_ref_lives_under_bailiff_v1_plans_prefix() {
        let plan_id = PlanId::new();
        let r = plan_notes_ref(plan_id);
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
    fn plan_notes_ref_is_unique_per_plan() {
        let a = PlanId::new();
        let b = PlanId::new();
        assert_ne!(a, b, "PlanId::new must not collide");
        assert_ne!(plan_notes_ref(a), plan_notes_ref(b));
    }

    /// The seed blob bytes are the plan id's canonical string form.
    /// Determinism is the contract: any future writer must compute
    /// the same OID via `git hash-object` as any future reader.
    #[test]
    fn plan_submission_seed_blob_bytes_is_plan_id_string() {
        let plan_id = PlanId::new();
        let bytes = plan_submission_seed_blob_bytes(plan_id);
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

    // --- DecisionNote --------------------------------------------------------

    fn sample_decider() -> Decider {
        Decider::try_new("cli:alice").unwrap()
    }

    fn sample_decision_note() -> DecisionNote {
        DecisionNote {
            plan_id: PlanId::new(),
            outcome: Decision::Accepted,
            decider: sample_decider(),
            decided_at: UnixMillis::from_millis(1_700_000_000_456),
        }
    }

    /// Submission and decision seed bytes for the same plan id MUST
    /// differ — colliding here would make the two notes share an
    /// attach OID under the per-plan ref, so the second write would
    /// silently clobber the first. This is the load-bearing invariant
    /// of the two-seeds-per-plan design; pin it explicitly.
    #[test]
    fn submission_and_decision_seed_bytes_are_distinct_for_same_plan_id() {
        let plan_id = PlanId::new();
        let submission = plan_submission_seed_blob_bytes(plan_id);
        let decision = plan_decision_seed_blob_bytes(plan_id);
        assert_ne!(
            submission, decision,
            "submission and decision seed bytes collided for {plan_id}",
        );
    }

    /// Pin the literal decision-seed shape: `<plan_id>::decision`. A
    /// reader hashes this exact byte sequence via `git hash-object`
    /// to recover the attach OID, so a future change to the suffix
    /// would silently make every existing decision note unreadable.
    #[test]
    fn plan_decision_seed_blob_bytes_is_plan_id_with_decision_suffix() {
        let plan_id = PlanId::new();
        let bytes = plan_decision_seed_blob_bytes(plan_id);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            format!("{plan_id}::decision"),
        );
    }

    /// Distinct plan ids produce distinct decision seed bytes. A
    /// regression that drops `plan_id` from the seed (e.g. by
    /// hard-coding `"::decision"`) would silently collapse every
    /// plan's decision into the same OID.
    #[test]
    fn plan_decision_seed_blob_bytes_is_unique_per_plan() {
        let a = PlanId::new();
        let b = PlanId::new();
        assert_ne!(a, b, "PlanId::new must not collide");
        assert_ne!(
            plan_decision_seed_blob_bytes(a),
            plan_decision_seed_blob_bytes(b),
        );
    }

    /// Canonical bytes round-trip: serialise → parse → re-serialise
    /// must reproduce the same bytes. Same shape pin as
    /// `plan_note_canonical_bytes_round_trip_is_stable`.
    #[test]
    fn decision_note_canonical_bytes_round_trip_is_stable() {
        let note = sample_decision_note();
        let first = note.canonical_bytes();
        let parsed = DecisionNote::from_canonical_bytes(&first).unwrap();
        let second = parsed.canonical_bytes();
        assert_eq!(first, second);
    }

    /// Pin the canonical wire shape: compact JSON object with the
    /// four top-level keys in struct-declaration order, no
    /// whitespace. A reader can re-compute these bytes locally and
    /// compare against the note body.
    #[test]
    fn decision_note_canonical_bytes_pin_field_order() {
        let note = sample_decision_note();
        let bytes = note.canonical_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        let positions: Vec<usize> = [
            "\"plan_id\":",
            "\"outcome\":",
            "\"decider\":",
            "\"decided_at\":",
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

    /// `outcome` serialises as the snake_case string `Decision` uses,
    /// not a wrapped object. A regression to `{"outcome":{"Accepted":null}}`
    /// would break every reader.
    #[test]
    fn decision_note_outcome_serialises_as_snake_case_string() {
        for d in [Decision::Accepted, Decision::Rejected] {
            let note = DecisionNote {
                outcome: d,
                ..sample_decision_note()
            };
            let bytes = note.canonical_bytes();
            let s = std::str::from_utf8(&bytes).unwrap();
            let expected = format!("\"outcome\":\"{}\"", d.as_str());
            assert!(
                s.contains(&expected),
                "expected wire to contain {expected:?}, got {s}",
            );
        }
    }

    /// `deny_unknown_fields` rejects extra top-level keys. Same
    /// schema-bump argument as `plan_note_rejects_unknown_top_level_fields`.
    #[test]
    fn decision_note_rejects_unknown_top_level_fields() {
        let note = sample_decision_note();
        let mut value: serde_json::Value = serde_json::to_value(&note).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::String("nope".into()));
        let s = serde_json::to_vec(&value).unwrap();
        let err = DecisionNote::from_canonical_bytes(&s).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("extra") || msg.contains("unknown field"),
            "expected unknown-field error, got: {msg}",
        );
    }

    /// Distinct payloads produce distinct canonical bytes.
    #[test]
    fn decision_note_canonical_bytes_distinguish_distinct_payloads() {
        let a = sample_decision_note();
        let b = DecisionNote {
            outcome: Decision::Rejected,
            ..a.clone()
        };
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    /// `DecisionNote` JSON round-trips. Standard pin.
    #[test]
    fn decision_note_json_roundtrips() {
        let note = sample_decision_note();
        let bytes = note.canonical_bytes();
        let back = DecisionNote::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, note);
    }

    /// Decision-note parsing runs through [`Decider::try_new`] at the
    /// wire boundary: an oversize or NUL-bearing decider in JSON is
    /// rejected at parse rather than reaching the in-memory note.
    /// Pinning the boundary check on `DecisionNote` (not just on
    /// `Decider`) catches a future refactor that swaps `Decider` for
    /// a raw `String` field and accidentally drops validation.
    #[test]
    fn decision_note_rejects_invalid_decider_at_wire_boundary() {
        let plan_id = PlanId::new();
        let oversize = "x".repeat(crate::bailiff_decision::MAX_DECIDER_BYTES + 1);
        let body = serde_json::json!({
            "plan_id": plan_id,
            "outcome": "accepted",
            "decider": oversize,
            "decided_at": 1_700_000_000_456_i64,
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(DecisionNote::from_canonical_bytes(&bytes).is_err());

        let empty = serde_json::json!({
            "plan_id": plan_id,
            "outcome": "accepted",
            "decider": "",
            "decided_at": 1_700_000_000_456_i64,
        });
        let bytes = serde_json::to_vec(&empty).unwrap();
        assert!(DecisionNote::from_canonical_bytes(&bytes).is_err());
    }
}
