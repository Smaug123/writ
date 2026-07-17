//! Example-based tests for replay commit-message rendering and
//! trailer-block detection.

use super::test_support::*;
use super::*;
use crate::git_push_trailers::{TrailerKey, TrailerValue};

#[test]
fn render_message_returns_original_when_no_trailers() {
    let bundle = sample_object_id('a');
    let out = render_replay_message("subject\n\nbody\n", &[], &bundle);
    assert_eq!(out, "subject\n\nbody\n");
}

#[test]
fn render_message_appends_fixed_trailer_after_blank_line_when_body_is_prose() {
    let bundle = sample_object_id('a');
    let trailer = TrailerSource::Fixed {
        key: TrailerKey::new("Co-authored-by").unwrap(),
        value: TrailerValue::new("Octocat <octocat@example.invalid>").unwrap(),
    };
    let out = render_replay_message("subject\n\nbody\n", &[trailer], &bundle);
    assert_eq!(
        out,
        "subject\n\nbody\n\nCo-authored-by: Octocat <octocat@example.invalid>\n",
    );
}

#[test]
fn render_message_appends_to_existing_trailer_block_with_single_newline() {
    let bundle = sample_object_id('a');
    let trailer = TrailerSource::Fixed {
        key: TrailerKey::new("Replay-source").unwrap(),
        value: TrailerValue::new("writ-broker").unwrap(),
    };
    let original = "subject\n\nbody\n\nCo-authored-by: Alice <alice@example.invalid>\n";
    let out = render_replay_message(original, &[trailer], &bundle);
    // Single trailer block at the end — no blank line between
    // the existing Co-authored-by and our new Replay-source.
    assert_eq!(
        out,
        "subject\n\nbody\n\nCo-authored-by: Alice <alice@example.invalid>\n\
             Replay-source: writ-broker\n",
    );
}

/// Regression test: a single-line subject that happens to match
/// trailer syntax (e.g. a conventional-commits subject like
/// `feat: foo`) is the subject, not a trailer block. The new
/// trailer must be separated by a blank line so
/// `git interpret-trailers --parse` recognises it.
#[test]
fn render_message_treats_trailer_shaped_subject_as_subject_not_trailer_block() {
    let bundle = sample_object_id('a');
    let trailer = TrailerSource::OriginalCommitSha {
        key: TrailerKey::new("Replay-from").unwrap(),
    };
    let out = render_replay_message("Fix: bug\n", &[trailer], &bundle);
    // Blank line between subject and the appended trailer block:
    // git's parser requires this separation, and our walker has
    // to honour it or replayed commits lose their provenance
    // trailer to the parser.
    assert_eq!(
        out,
        format!("Fix: bug\n\nReplay-from: {}\n", bundle.as_str())
    );
}

#[test]
fn trailer_block_detection_rejects_single_paragraph_message() {
    // Even though the line itself matches trailer syntax, with
    // no blank-line separation there is no trailer block to
    // append to — git treats this as a subject.
    assert!(!message_ends_with_trailer_block("Fix: bug\n"));
}

#[test]
fn render_message_substitutes_bundle_sha_in_dynamic_trailer() {
    let bundle = sample_object_id('c');
    let trailer = TrailerSource::OriginalCommitSha {
        key: TrailerKey::new("Replay-from").unwrap(),
    };
    let out = render_replay_message("msg\n", &[trailer], &bundle);
    assert_eq!(out, format!("msg\n\nReplay-from: {}\n", bundle.as_str()),);
}

#[test]
fn render_message_handles_empty_original() {
    let bundle = sample_object_id('a');
    let trailer = TrailerSource::Fixed {
        key: TrailerKey::new("Replay-source").unwrap(),
        value: TrailerValue::new("writ-broker").unwrap(),
    };
    let out = render_replay_message("", &[trailer], &bundle);
    assert_eq!(out, "Replay-source: writ-broker\n");
}

#[test]
fn render_message_strips_redundant_trailing_newlines() {
    let bundle = sample_object_id('a');
    let trailer = TrailerSource::Fixed {
        key: TrailerKey::new("Replay-source").unwrap(),
        value: TrailerValue::new("writ-broker").unwrap(),
    };
    let out = render_replay_message("subject\n\nbody\n\n\n\n", &[trailer], &bundle);
    // The body retains its single trailing newline; the trailer
    // block sits one blank line below it; the whole message
    // ends with exactly one newline.
    assert_eq!(out, "subject\n\nbody\n\nReplay-source: writ-broker\n",);
}

#[test]
fn trailer_block_detection_recognises_well_formed_block() {
    assert!(message_ends_with_trailer_block(
        "subject\n\nCo-authored-by: Alice <a@x>\nSigned-off-by: Bob <b@x>\n",
    ));
}

#[test]
fn trailer_block_detection_rejects_prose_last_paragraph() {
    assert!(!message_ends_with_trailer_block(
        "subject\n\nthis is prose\n"
    ));
}

#[test]
fn trailer_block_detection_rejects_mixed_paragraph() {
    // The last paragraph has one trailer line followed by a
    // prose line. Strict matching: not a trailer block.
    assert!(!message_ends_with_trailer_block(
        "subject\n\nCo-authored-by: Alice <a@x>\nand some prose here\n",
    ));
}
