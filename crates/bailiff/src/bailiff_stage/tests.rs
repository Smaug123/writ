//! Unit tests for the phase vocabulary's pure parts: the stage⇒axis
//! derivations, the prompt splice, and the two `RunAgent` bindings.
//!
//! The *sequencing* the two runner functions implement is checked
//! elsewhere and deliberately not re-asserted here: `tests/
//! rpc_trace_baseline.rs` pins the exact `ClientMessage` sequence each
//! stage puts on the wire, which is a stronger statement than any
//! assertion this module could make about the same code.

use super::*;
use proptest::prelude::*;
use std::path::PathBuf;
use writ::core::RepoRef;
use writ::vm_git::{GitCloneRepo, WorkspaceWarmMode};

/// The precondition is the `PlanStage` of the same name for all three
/// agent-run stages. Written out rather than derived so that a future
/// stage whose precondition is *not* its namesake (a variant-implement
/// gated on the parent's state, say) has to change this test
/// deliberately.
#[test]
fn each_agent_stage_gates_on_its_namesake_plan_stage() {
    assert_eq!(AgentStage::Submit.precondition(), PlanStage::Submit);
    assert_eq!(AgentStage::Review.precondition(), PlanStage::Review);
    assert_eq!(AgentStage::Implement.precondition(), PlanStage::Implement);
}

/// `AgentStage` is `PlanStage` minus `Decide`. The point of the type
/// is that "compose a prompt for the decide stage" is unrepresentable,
/// so the two vocabularies must stay in this exact relationship: every
/// agent stage has a plan stage, and exactly one plan stage has no
/// agent stage.
#[test]
fn agent_stages_are_the_plan_stages_that_run_an_agent() {
    let from_agent: Vec<PlanStage> = AgentStage::ALL.iter().map(|s| s.precondition()).collect();
    let missing: Vec<PlanStage> = PlanStage::ALL
        .iter()
        .copied()
        .filter(|p| !from_agent.contains(p))
        .collect();
    assert_eq!(
        missing,
        vec![PlanStage::Decide],
        "`decide` is the only plan stage with no agent run",
    );
    assert_eq!(
        from_agent.len(),
        AgentStage::ALL.len(),
        "two agent stages must not share a precondition",
    );
}

/// Submit *produces* the plan body, so it splices nothing; the other
/// two consume it. `plan_body_stage` and `PlanBodyStage::stage` must
/// be mutual inverses, or the refined vocabulary would be a second
/// encoding of the stage set rather than a subset of it.
#[test]
fn the_body_consuming_stages_are_exactly_review_and_implement() {
    assert_eq!(AgentStage::Submit.plan_body_stage(), None);
    let refined: Vec<AgentStage> = AgentStage::ALL
        .iter()
        .filter_map(|s| s.plan_body_stage())
        .map(|b| b.stage())
        .collect();
    assert_eq!(
        refined,
        vec![AgentStage::Review, AgentStage::Implement],
        "plan_body_stage and PlanBodyStage::stage must round-trip",
    );
    assert_eq!(refined.len(), PlanBodyStage::ALL.len());
}

/// The two separators, verbatim, and distinct. These bytes are inside
/// every composed prompt the RPC trace fixtures record, so this test
/// and `review_happy` / `implement_happy` fail together on drift — but
/// this one names the stage, which the fixture diff does not.
///
/// The inequality is the load-bearing half: a reviewer prompt that
/// framed the plan as approved would be a lie about an undecided plan,
/// which is the mistake the plan doc records under "The stage order
/// was wrong".
#[test]
fn separators_are_the_pre_slice_3_bytes_and_differ_by_stage() {
    assert_eq!(
        PlanBodyStage::Review.separator(),
        "\n\n---\n\n# Proposed plan\n\n",
    );
    assert_eq!(
        PlanBodyStage::Implement.separator(),
        "\n\n---\n\n# Approved plan\n\n",
    );
    assert_ne!(
        PlanBodyStage::Review.separator(),
        PlanBodyStage::Implement.separator(),
    );
}

/// Moved from `bailiff_plan_review::compose_tests` when the composer
/// it covered became a binding over [`splice_plan_body`]. The
/// concatenation is exact — no trimming, no re-encoding, no extra
/// newline — for the reviewer's framing.
#[test]
fn reviewer_separator_appears_verbatim_between_instructions_and_body() {
    let composed = splice_plan_body(
        "Evaluate the plan.",
        PlanBodyStage::Review,
        "# Plan\n\nDo a thing.\n",
    )
    .unwrap();
    assert_eq!(
        composed.as_str(),
        "Evaluate the plan.\n\n---\n\n# Proposed plan\n\n# Plan\n\nDo a thing.\n",
    );
}

/// Moved from `bailiff_plan_implement::compose_tests`, likewise. Kept
/// distinct from the reviewer case above rather than parameterised:
/// the two literal expectations are what pin that the *framings* did
/// not swap, which a shared helper reading `stage.separator()` would
/// not catch.
#[test]
fn implementer_separator_appears_verbatim_between_feature_prompt_and_body() {
    let composed = splice_plan_body(
        "Rename foo to bar.",
        PlanBodyStage::Implement,
        "# Plan\n\nDo a thing.\n",
    )
    .unwrap();
    assert_eq!(
        composed.as_str(),
        "Rename foo to bar.\n\n---\n\n# Approved plan\n\n# Plan\n\nDo a thing.\n",
    );
}

#[test]
fn splice_rejects_a_combined_prompt_over_the_byte_cap() {
    let head = "x".repeat(writ::agent_run::MAX_AGENT_PROMPT_BYTES);
    let err = splice_plan_body(&head, PlanBodyStage::Implement, "p").unwrap_err();
    assert!(err.to_string().contains("exceeding"), "{err}");
}

proptest! {
    /// `splice_plan_body` is a structural concatenation for either
    /// stage: the result starts with the head, ends with the body,
    /// contains the separator, and its length is the sum of the three
    /// parts. Anything else would mean the composed prompt was
    /// re-encoding or trimming its inputs.
    #[test]
    fn splice_is_head_then_separator_then_body(
        head in "[ -~]{1,1024}",
        body in "[ -~]{1,1024}",
        stage_index in 0usize..PlanBodyStage::ALL.len(),
    ) {
        let stage = PlanBodyStage::ALL[stage_index];
        let combined = splice_plan_body(&head, stage, &body).unwrap();
        let s = combined.as_str();
        prop_assert!(s.starts_with(&head), "missing prefix");
        prop_assert!(s.ends_with(&body), "missing suffix");
        prop_assert!(s.contains(stage.separator()), "missing separator");
        prop_assert_eq!(
            s.len(),
            head.len() + stage.separator().len() + body.len(),
        );
    }
}

fn sample_workspace() -> AgentVmWorkspaceBootstrap {
    AgentVmWorkspaceBootstrap {
        repo: GitCloneRepo::new(RepoRef {
            owner: "smaug123".into(),
            name: "writ".into(),
        })
        .unwrap(),
        destination: Some(PathBuf::from("/workspace/writ")),
        warm: WorkspaceWarmMode::DevShell,
    }
}

fn sample_inputs() -> StageRunInputs {
    StageRunInputs {
        prompt: AgentPrompt::try_new("composed-prompt").unwrap(),
        capabilities: vec![CapabilitySet::WorkspaceWrite {
            repo: RepoRef {
                owner: "smaug123".into(),
                name: "writ".into(),
            },
        }],
        purpose: "plan-implement".into(),
        writ_output_ref: NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap(),
    }
}

/// Moved verbatim in substance from `bailiff_plan_implement`'s
/// `build_request_tests` when the binding it covered moved here.
///
/// Every VM-relevant field reaches the `RunAgentRequest` writd sees:
/// the workspace bootstrap (so dispatch routes into the VM arm), the
/// agent kind and model (required by that arm, which picks no
/// default), and `session_id: None` — passing a caller-supplied id
/// alongside a bootstrap is what `run_agent_in_vm` rejects with "VM
/// mode mints its own audit session".
#[test]
fn broker_request_threads_workspace_and_agent_identity() {
    let inputs = sample_inputs();
    let session = BrokerSession {
        workspace: sample_workspace(),
        agent_kind: AgentKind::Claude,
        agent_model: "claude-opus-4-7".into(),
    };
    let expected_capabilities = inputs.capabilities.clone();
    let expected_purpose = inputs.purpose.clone();
    let expected_ref = inputs.writ_output_ref.clone();
    let req = broker_run_agent_request(inputs, session.clone());

    assert_eq!(req.prompt.as_str(), "composed-prompt");
    assert_eq!(req.capabilities, expected_capabilities);
    assert_eq!(req.purpose, expected_purpose);
    assert_eq!(req.output_ref, expected_ref);
    assert_eq!(
        req.session_id, None,
        "VM mode mints its own audit session; bailiff must not pre-open one",
    );
    assert_eq!(
        req.workspace.as_ref(),
        Some(&session.workspace),
        "workspace bootstrap must thread through verbatim",
    );
    assert_eq!(req.agent_kind, Some(session.agent_kind));
    assert_eq!(req.agent_model.as_deref(), Some("claude-opus-4-7"));
}

/// The mirror-image invariant, which had no test before slice 3: a run
/// bound to a session bailiff owns must carry that id and *no*
/// workspace bootstrap. A bootstrap here would silently reroute the
/// run into the VM arm, which then rejects the request for carrying a
/// session id — so the two fields are a pair, and each binding
/// function fixes both.
#[test]
fn owned_request_binds_the_session_and_carries_no_workspace() {
    let session_id = SessionId::new();
    let req = owned_run_agent_request(sample_inputs(), session_id);

    assert_eq!(req.session_id, Some(session_id));
    assert_eq!(
        req.workspace, None,
        "a workspace bootstrap would route an owned-session run into the VM arm",
    );
    assert_eq!(
        req.agent_kind, None,
        "agent identity was fixed at OpenSession",
    );
    assert_eq!(req.agent_model, None);
}
