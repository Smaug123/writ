//! Orchestrator-side workflow helpers. Lives outside the broker so the
//! plan/review/execute prompt composition (and the workflow vocabulary
//! it carries) does not leak into the capability-broker code.
//!
//! See `docs/plans/2026-05-14-bailiff-split.md` for the broader split;
//! this module is slice 1 — pure prompt composition lifted out of
//! `agent_plan.rs`. The broker still persists [`PlanBody`] and
//! [`Stage`]; only the *interpretation* (splice the body into the
//! agent's effective prompt) lives here.

use crate::agent_plan::{PlanBody, Stage};
use crate::agent_run::{AgentPrompt, AgentPromptError};

/// Separator the implementer's effective prompt uses between the
/// feature-request prompt and the approved plan body. See
/// [`compose_implementer_prompt`].
pub const PLAN_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Approved plan\n\n";

/// Separator the reviewer's effective prompt uses between the
/// operator-supplied reviewer instructions and the plan body under
/// evaluation. Distinct from [`PLAN_PROMPT_SEPARATOR`] because the
/// reviewer is judging the plan, not executing against an approved
/// one — `# Proposed plan` makes that frame explicit so an LLM reading
/// the combined prompt cannot mistake the artifact's status. See
/// [`compose_reviewer_prompt`].
pub const REVIEWER_PROMPT_SEPARATOR: &str = "\n\n---\n\n# Proposed plan\n\n";

/// Build the implementer's effective prompt from the original
/// feature-request prompt that produced the plan and the accepted plan
/// body. Per §"Implementer prompt construction" of
/// `docs/plans/2026-05-11-agent-plans.md`, reviewer feedback stays
/// *out* of the composed prompt by default: it's for the decision, not
/// for execution.
///
/// The two inputs are joined by [`PLAN_PROMPT_SEPARATOR`], which adds
/// a clear visual boundary (`---` plus an `# Approved plan` heading)
/// so an LLM reading the combined prompt cannot mistake one segment
/// for the other. Returns [`AgentPromptError`] iff the combined byte
/// length exceeds [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`].
pub fn compose_implementer_prompt(
    feature_prompt: &AgentPrompt,
    plan_body: &PlanBody,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined = String::with_capacity(
        feature_prompt.as_str().len() + PLAN_PROMPT_SEPARATOR.len() + plan_body.as_str().len(),
    );
    combined.push_str(feature_prompt.as_str());
    combined.push_str(PLAN_PROMPT_SEPARATOR);
    combined.push_str(plan_body.as_str());
    AgentPrompt::try_new(combined)
}

/// Build the reviewer's effective prompt from the operator-supplied
/// reviewer instructions and the plan body the reviewer is voting on.
/// Mirrors [`compose_implementer_prompt`] but uses
/// [`REVIEWER_PROMPT_SEPARATOR`] (`# Proposed plan`) because the plan
/// has not been accepted at the point the reviewer reads it — the
/// reviewer's job is to produce the verdict that drives the accept /
/// request_changes / reject decision (see
/// `docs/plans/2026-05-11-agent-plans.md` §"Conceptual model").
/// Returns [`AgentPromptError`] iff the combined byte length exceeds
/// [`crate::agent_run::MAX_AGENT_PROMPT_BYTES`].
pub fn compose_reviewer_prompt(
    reviewer_prompt: &AgentPrompt,
    plan_body: &PlanBody,
) -> Result<AgentPrompt, AgentPromptError> {
    let mut combined = String::with_capacity(
        reviewer_prompt.as_str().len() + REVIEWER_PROMPT_SEPARATOR.len() + plan_body.as_str().len(),
    );
    combined.push_str(reviewer_prompt.as_str());
    combined.push_str(REVIEWER_PROMPT_SEPARATOR);
    combined.push_str(plan_body.as_str());
    AgentPrompt::try_new(combined)
}

/// Returns `true` iff [`compose_effective_prompt`] would consume a
/// plan body for runs in this `stage`. The VM-side wrapper consults
/// this to decide whether to call `GET /v1/plans/<id>` before
/// composing the prompt: fetching only when the dispatcher will use
/// the result keeps the two in sync (a previous regression — caught
/// by codex on PR #80 — let the wrapper skip the fetch for review
/// runs and silently bypass the reviewer composition arm).
pub fn stage_consumes_plan_body(stage: Stage) -> bool {
    match stage {
        Stage::Plan => false,
        Stage::Review | Stage::Execute => true,
    }
}

/// Returns the prompt the VM-side wrapper should feed the LLM, given
/// the run's stage and the plan body (when one was fetched).
/// `(Stage::Execute, Some(body))` composes via
/// [`compose_implementer_prompt`]; `(Stage::Review, Some(body))`
/// composes via [`compose_reviewer_prompt`]; every other combination
/// passes the caller's prompt through unchanged. `Stage::Plan` never
/// reads a plan, and `Stage::Review` without a body only arises if
/// `validate_stage_read_plan_binding` was bypassed — passthrough is
/// the conservative answer there.
///
/// `plan_body` is `Some` exactly when the broker handed back a
/// `read_plan_id` *and* the writ-vm wrapper successfully fetched the
/// plan body for it. The wrapper decides whether to fetch via
/// [`stage_consumes_plan_body`] — keep the two in step.
pub fn compose_effective_prompt(
    feature_prompt: &AgentPrompt,
    stage: Stage,
    plan_body: Option<&PlanBody>,
) -> Result<AgentPrompt, AgentPromptError> {
    match (stage, plan_body) {
        (Stage::Execute, Some(body)) => compose_implementer_prompt(feature_prompt, body),
        (Stage::Review, Some(body)) => compose_reviewer_prompt(feature_prompt, body),
        _ => Ok(feature_prompt.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_implementer_prompt_concatenates_with_separator() {
        let feature = AgentPrompt::new("Fix the foo widget.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();
        let combined = compose_implementer_prompt(&feature, &plan).unwrap();
        let expected =
            format!("Fix the foo widget.{PLAN_PROMPT_SEPARATOR}# Plan\n\nReplace bar with baz.",);
        assert_eq!(combined.as_str(), expected);
        // Both inputs survive as substrings, separated by the marker.
        assert!(combined.as_str().contains(feature.as_str()));
        assert!(combined.as_str().contains(plan.as_str()));
        assert!(combined.as_str().contains(PLAN_PROMPT_SEPARATOR));
    }

    #[test]
    fn compose_implementer_prompt_errors_when_combined_exceeds_agent_prompt_limit() {
        // Feature prompt at the AgentPrompt limit, plus a non-empty plan
        // body and the separator, must overflow.
        let feature = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        let err = compose_implementer_prompt(&feature, &plan).unwrap_err();
        // AgentPromptError formats as "agent prompt is N bytes, ...".
        let msg = err.to_string();
        assert!(msg.contains("exceeding"), "{msg}");
    }

    #[test]
    fn compose_reviewer_prompt_concatenates_with_separator() {
        let reviewer = AgentPrompt::new("Evaluate the plan against the feature request.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();
        let combined = compose_reviewer_prompt(&reviewer, &plan).unwrap();
        let expected = format!(
            "Evaluate the plan against the feature request.{REVIEWER_PROMPT_SEPARATOR}# Plan\n\nReplace bar with baz.",
        );
        assert_eq!(combined.as_str(), expected);
        assert!(combined.as_str().contains(reviewer.as_str()));
        assert!(combined.as_str().contains(plan.as_str()));
        assert!(combined.as_str().contains(REVIEWER_PROMPT_SEPARATOR));
        // The reviewer separator must not lie about the plan's status.
        // The implementer's `# Approved plan` heading would mislead a
        // reviewer LLM; pin the separators apart so a future rewording
        // can't silently equate them.
        assert!(!combined.as_str().contains(PLAN_PROMPT_SEPARATOR));
    }

    #[test]
    fn compose_reviewer_prompt_errors_when_combined_exceeds_agent_prompt_limit() {
        let reviewer = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        let err = compose_reviewer_prompt(&reviewer, &plan).unwrap_err();
        assert!(err.to_string().contains("exceeding"), "{err}");
    }

    #[test]
    fn compose_effective_prompt_composes_for_execute_and_review_with_plan_body() {
        let feature = AgentPrompt::new("Fix the foo widget.");
        let plan = PlanBody::try_new("# Plan\n\nReplace bar with baz.").unwrap();

        // Execute + Some(plan) — composes via compose_implementer_prompt.
        let composed_execute =
            compose_effective_prompt(&feature, Stage::Execute, Some(&plan)).unwrap();
        let expected_execute = compose_implementer_prompt(&feature, &plan).unwrap();
        assert_eq!(composed_execute.as_str(), expected_execute.as_str());
        assert!(composed_execute.as_str().contains(PLAN_PROMPT_SEPARATOR));

        // Review + Some(plan) — composes via compose_reviewer_prompt.
        let composed_review =
            compose_effective_prompt(&feature, Stage::Review, Some(&plan)).unwrap();
        let expected_review = compose_reviewer_prompt(&feature, &plan).unwrap();
        assert_eq!(composed_review.as_str(), expected_review.as_str());
        assert!(composed_review.as_str().contains(REVIEWER_PROMPT_SEPARATOR));

        // The two separators must not collide: an implementer's prompt
        // must not be mistakable for a reviewer's prompt and vice
        // versa, because the LLM's reading of the plan depends on which
        // role it has been told it is performing.
        assert!(
            !composed_execute
                .as_str()
                .contains(REVIEWER_PROMPT_SEPARATOR)
        );
        assert!(!composed_review.as_str().contains(PLAN_PROMPT_SEPARATOR));

        // Every remaining (stage, plan_body) pair passes the prompt
        // through unchanged. Plan-stage never carries a plan body and
        // Review-without-a-body is rejected at start time by
        // `validate_stage_read_plan_binding`; passthrough is defensive.
        for (stage, body) in [
            (Stage::Plan, None),
            (Stage::Plan, Some(&plan)),
            (Stage::Review, None),
            (Stage::Execute, None),
        ] {
            let result = compose_effective_prompt(&feature, stage, body).unwrap();
            assert_eq!(
                result.as_str(),
                feature.as_str(),
                "stage={stage:?} body_is_some={}: expected passthrough",
                body.is_some(),
            );
        }
    }

    #[test]
    fn compose_effective_prompt_errors_when_composition_exceeds_limit() {
        let feature = AgentPrompt::new("x".repeat(crate::agent_run::MAX_AGENT_PROMPT_BYTES));
        let plan = PlanBody::try_new("p").unwrap();
        for stage in [Stage::Execute, Stage::Review] {
            let err = compose_effective_prompt(&feature, stage, Some(&plan)).unwrap_err();
            assert!(
                err.to_string().contains("exceeding"),
                "stage={stage:?}: {err}"
            );
        }
    }

    /// The wrapper-side fetch predicate
    /// ([`stage_consumes_plan_body`]) must agree with the
    /// dispatcher's match in [`compose_effective_prompt`]: a stage
    /// consumes a plan body iff handing the dispatcher a body for
    /// that stage produces a different prompt than passthrough.
    /// Pins them together so the regression caught on PR #80 — where
    /// the wrapper skipped the fetch for review-stage and the
    /// dispatcher's new arm was unreachable — cannot recur.
    #[test]
    fn stage_consumes_plan_body_agrees_with_compose_effective_prompt() {
        let feature = AgentPrompt::new("feature prompt");
        let plan = PlanBody::try_new("plan body").unwrap();
        for stage in [Stage::Plan, Stage::Review, Stage::Execute] {
            let composed = compose_effective_prompt(&feature, stage, Some(&plan)).unwrap();
            let consumed = composed.as_str() != feature.as_str();
            assert_eq!(consumed, stage_consumes_plan_body(stage), "stage={stage:?}",);
        }
    }
}
