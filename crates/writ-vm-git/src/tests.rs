//! Tests for the host<->guest VM-git wire types (clone/push request shapes, object-id/branch parsing). Split out of `lib.rs` (an inline `#[cfg(test)]` module); tests unchanged.

use super::*;
use proptest::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn repo(owner: &str, name: &str) -> GitCloneRepo {
    format!("{owner}/{name}").parse().unwrap()
}

fn ascii_alnum() -> impl Strategy<Value = char> {
    prop_oneof![
        (b'a'..=b'z').prop_map(char::from),
        (b'A'..=b'Z').prop_map(char::from),
        (b'0'..=b'9').prop_map(char::from),
    ]
}

fn owner_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        ascii_alnum().prop_map(|ch| ch.to_string()),
        (
            ascii_alnum(),
            prop::collection::vec(prop_oneof![ascii_alnum(), Just('-')], 0..37,),
            ascii_alnum(),
        )
            .prop_map(|(first, middle, last)| {
                std::iter::once(first)
                    .chain(middle)
                    .chain(std::iter::once(last))
                    .collect()
            }),
    ]
}

fn repo_name_strategy() -> impl Strategy<Value = String> {
    (
        ascii_alnum(),
        prop::collection::vec(prop_oneof![ascii_alnum(), Just('_'), Just('-')], 0..99),
    )
        .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
}

fn ref_component_strategy() -> impl Strategy<Value = String> {
    (
        prop_oneof![ascii_alnum(), Just('_')],
        prop::collection::vec(prop_oneof![ascii_alnum(), Just('_'), Just('-')], 0..20),
    )
        .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
}

fn git_ref_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(ref_component_strategy(), 1..5).prop_map(|components| {
        let mut raw = components.join("/");
        raw.truncate(255);
        raw
    })
}

fn git_branch_strategy() -> impl Strategy<Value = String> {
    git_ref_strategy()
}

fn git_branch_oracle_char_strategy() -> impl Strategy<Value = char> {
    prop_oneof![
        ascii_alnum(),
        Just('/'),
        Just('.'),
        Just('_'),
        Just('-'),
        Just('@'),
        Just('{'),
        Just(' '),
        Just('~'),
        Just('^'),
        Just(':'),
        Just('?'),
        Just('*'),
        Just('['),
        Just('\\'),
    ]
}

fn git_branch_oracle_candidate_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        git_branch_strategy(),
        invalid_git_branch_strategy(),
        prop::collection::vec(git_branch_oracle_char_strategy(), 0..40)
            .prop_map(|chars| chars.into_iter().collect()),
    ]
}

fn object_id_strategy() -> impl Strategy<Value = String> {
    "[0-9a-fA-F]{40}"
}

fn invalid_git_ref_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        "[A-Za-z0-9._/-]{0,40}".prop_map(|suffix| format!("-{suffix}")),
        "[A-Za-z0-9._-]{0,40}".prop_map(|suffix| format!("/{suffix}")),
        "[A-Za-z0-9._-]{0,40}".prop_map(|prefix| format!("{prefix}/")),
        "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}//x")),
        "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}..x")),
        "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}@{{x")),
        "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}/.hidden")),
        "[A-Za-z0-9._-]{0,20}".prop_map(|prefix| format!("{prefix}.lock/x")),
        "[A-Za-z0-9_-]{0,20}".prop_map(|prefix| format!("{prefix}.")),
        Just("@".to_string()),
        "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix}:x")),
        "[A-Za-z0-9._/-]{0,20}".prop_map(|prefix| format!("{prefix} x")),
    ]
}

fn invalid_git_branch_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        invalid_git_ref_strategy(),
        "[A-Za-z0-9_-]{1,20}".prop_map(|component| format!("feature/{component}./y")),
        Just("HEAD".to_string()),
        git_ref_strategy().prop_map(|branch| format!("refs/heads/{branch}")),
    ]
}

fn sample_object_id(nibble: char) -> GitObjectId {
    std::iter::repeat_n(nibble, GIT_OBJECT_ID_HEX_BYTES)
        .collect::<String>()
        .parse()
        .unwrap()
}

fn push_metadata() -> VmGitPushMetadata {
    VmGitPushMetadata::new(
        repo("owner", "repo"),
        "feature/x".parse().unwrap(),
        Some(sample_object_id('1')),
        sample_object_id('2'),
    )
}

fn push_request() -> VmGitPushRequest {
    VmGitPushRequest::new(push_metadata(), b"bundle-bytes".to_vec()).unwrap()
}

fn push_limits() -> VmGitPushBodyLimits {
    VmGitPushBodyLimits::new(4096, 1024, 1024).unwrap()
}

fn required_test_tool(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| panic!("PATH must contain {name} for vm_git tests"));
    for dir in std::env::split_paths(&path) {
        let candidate = if dir.is_absolute() {
            dir.join(name)
        } else {
            std::env::current_dir().unwrap().join(dir).join(name)
        };
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("{name} not found on PATH for vm_git tests");
}

fn git_check_ref_format_branch_accepts(raw: &str) -> bool {
    Command::new(required_test_tool("git"))
        .args(["check-ref-format", "--branch", raw])
        .envs(writ_core::git_env::CLEAN_GIT_CONFIG_ENV)
        .output()
        .unwrap_or_else(|err| panic!("failed to run git check-ref-format: {err}"))
        .status
        .success()
}

proptest! {
    #[test]
    fn vm_clone_request_roundtrips_any_valid_generated_repo(
        owner in owner_strategy(),
        name in repo_name_strategy(),
    ) {
        let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
        let clone_repo = GitCloneRepo::new(repo_ref.clone()).unwrap();
        let request = VmGitCloneRequest::new(clone_repo, None);

        let json = serde_json::to_string(&request).unwrap();
        let roundtrip: VmGitCloneRequest = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
        prop_assert_eq!(roundtrip, request);
    }

    #[test]
    fn git_ref_roundtrips_any_valid_generated_ref(raw in git_ref_strategy()) {
        let parsed = GitCloneRef::new(raw.clone()).unwrap();
        let reparsed: GitCloneRef = parsed.as_str().parse().unwrap();
        prop_assert_eq!(reparsed, parsed.clone());
        prop_assert_eq!(parsed.as_str(), raw.as_str());
    }

    #[test]
    fn generated_invalid_git_refs_are_rejected(raw in invalid_git_ref_strategy()) {
        prop_assert!(
            raw.parse::<GitCloneRef>().is_err(),
            "accepted invalid ref {raw:?}"
        );
    }

    #[test]
    fn git_branch_roundtrips_any_valid_generated_name(raw in git_branch_strategy()) {
        let parsed = GitBranchName::new(raw.clone()).unwrap();
        let reparsed: GitBranchName = parsed.as_str().parse().unwrap();
        prop_assert_eq!(reparsed, parsed.clone());
        prop_assert_eq!(parsed.as_str(), raw.as_str());
        prop_assert_eq!(parsed.as_heads_ref(), format!("refs/heads/{raw}"));
    }

    #[test]
    fn generated_invalid_git_branches_are_rejected(raw in invalid_git_branch_strategy()) {
        prop_assert!(
            raw.parse::<GitBranchName>().is_err(),
            "accepted invalid branch {raw:?}"
        );
    }

    #[test]
    fn git_branch_validator_matches_git_check_ref_format_branch_and_broker_rules(
        raw in git_branch_oracle_candidate_strategy(),
    ) {
        let git_accepts = git_check_ref_format_branch_accepts(&raw);
        let expected = git_accepts
            && !raw.starts_with("refs/")
            && raw != "@"
            && !raw.split('/').any(|component| component.ends_with('.'));
        let actual = raw.parse::<GitBranchName>().is_ok();

        prop_assert_eq!(
            actual,
            expected,
            "validator disagrees with git check-ref-format plus broker branch rules for {:?}",
            raw
        );
    }

    #[test]
    fn object_ids_roundtrip_and_normalize_to_lowercase(raw in object_id_strategy()) {
        let parsed: GitObjectId = raw.parse().unwrap();
        prop_assert_eq!(parsed.as_str(), raw.to_ascii_lowercase());
        let json = serde_json::to_string(&parsed).unwrap();
        let roundtrip: GitObjectId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(roundtrip, parsed);
    }

    #[test]
    fn flake_provision_request_roundtrips_any_valid_generated_coordinates(
        owner in owner_strategy(),
        name in repo_name_strategy(),
        rev in object_id_strategy(),
    ) {
        let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
        let request = VmFlakeProvisionRequest::new(
            GitCloneRepo::new(repo_ref.clone()).unwrap(),
            rev.parse().unwrap(),
        );

        let json = serde_json::to_string(&request).unwrap();
        let roundtrip: VmFlakeProvisionRequest = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
        prop_assert_eq!(roundtrip, request);
    }

    #[test]
    fn vm_push_metadata_roundtrips_any_valid_generated_fields(
        owner in owner_strategy(),
        name in repo_name_strategy(),
        branch in git_branch_strategy(),
        expected in proptest::option::of(object_id_strategy()),
        new_head in object_id_strategy(),
    ) {
        let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
        let metadata = VmGitPushMetadata::new(
            GitCloneRepo::new(repo_ref.clone()).unwrap(),
            branch.parse().unwrap(),
            expected.map(|raw| raw.parse().unwrap()),
            new_head.parse().unwrap(),
        );

        let json = serde_json::to_string(&metadata).unwrap();
        let roundtrip: VmGitPushMetadata = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
        prop_assert_eq!(roundtrip, metadata);
    }

    #[test]
    fn vm_push_staged_receipt_roundtrips_any_valid_generated_fields(
        owner in owner_strategy(),
        name in repo_name_strategy(),
        branch in git_branch_strategy(),
        expected in proptest::option::of(object_id_strategy()),
        new_head in object_id_strategy(),
        staged_at in any::<i64>(),
    ) {
        let repo_ref: RepoRef = format!("{owner}/{name}").parse().unwrap();
        let receipt = VmGitPushStagedReceipt::new(
            GitCloneRepo::new(repo_ref.clone()).unwrap(),
            branch.parse().unwrap(),
            expected.map(|raw| raw.parse().unwrap()),
            new_head.parse().unwrap(),
            RequestId::new(),
            UnixMillis::from_millis(staged_at),
        );

        let json = serde_json::to_string(&receipt).unwrap();
        let roundtrip: VmGitPushStagedReceipt = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(roundtrip.repo().as_repo_ref(), &repo_ref);
        prop_assert_eq!(roundtrip, receipt);
    }
}

#[test]
fn clone_request_with_ref_roundtrips_wire_shape() {
    let request = VmGitCloneRequest::new(
        repo("owner", "repo.name"),
        Some("feature/x".parse().unwrap()),
    );
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["repo"], "owner/repo.name");
    assert_eq!(value["ref"], "feature/x");
    assert_eq!(
        serde_json::from_value::<VmGitCloneRequest>(value).unwrap(),
        request
    );
}

#[test]
fn flake_provision_request_wire_shape_is_repo_and_rev() {
    let request = VmFlakeProvisionRequest::new(
        repo("owner", "repo.name"),
        "0123456789abcdef0123456789abcdef01234567".parse().unwrap(),
    );
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["repo"], "owner/repo.name");
    assert_eq!(value["rev"], "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(
        serde_json::from_value::<VmFlakeProvisionRequest>(value).unwrap(),
        request
    );
}

#[test]
fn flake_provision_response_is_tagged_by_status() {
    let request_id = RequestId::new();
    let provisioned = VmFlakeProvisionResponse::Provisioned {
        request_id,
        input_count: 3,
        archived_path_count: 7,
        archived_bytes: 4096,
    };
    let value = serde_json::to_value(&provisioned).unwrap();
    assert_eq!(value["status"], "provisioned");
    assert_eq!(value["input_count"], 3);
    assert_eq!(value["archived_path_count"], 7);
    assert_eq!(value["archived_bytes"], 4096);
    assert_eq!(value["request_id"], request_id.to_string());
    assert_eq!(
        serde_json::from_value::<VmFlakeProvisionResponse>(value).unwrap(),
        provisioned
    );

    let not_cached = serde_json::to_value(VmFlakeProvisionResponse::MirrorNotCached).unwrap();
    assert_eq!(not_cached["status"], "mirror_not_cached");
    assert_eq!(
        serde_json::from_value::<VmFlakeProvisionResponse>(not_cached).unwrap(),
        VmFlakeProvisionResponse::MirrorNotCached
    );
}

#[test]
fn malformed_repos_are_rejected_before_planning() {
    for raw in [
        "no-slash",
        "/repo",
        "owner/",
        "-owner/repo",
        "owner-/repo",
        "owner/repo name",
        "owner/..",
        "owner/foo.git",
        "owner/repo/path",
    ] {
        assert!(raw.parse::<GitCloneRepo>().is_err(), "accepted {raw:?}");
    }
}

#[test]
fn malformed_refs_are_rejected_before_planning() {
    for raw in [
        "",
        "-main",
        "/main",
        "main/",
        "feature//x",
        "feature..x",
        "feature@{1}",
        "branch.lock",
        "feature.lock/x",
        "feature/.hidden",
        "main.",
        "feature/x.",
        "@",
        "has space",
        "has:colon",
        "has*star",
        "unicodé",
    ] {
        assert!(raw.parse::<GitCloneRef>().is_err(), "accepted {raw:?}");
    }
}

#[test]
fn malformed_branches_are_rejected_before_planning() {
    for raw in [
        "",
        "HEAD",
        "refs/heads/main",
        "-main",
        "/main",
        "main/",
        "feature//x",
        "feature..x",
        "feature@{1}",
        "branch.lock",
        "feature.lock/x",
        "feature/.hidden",
        "main.",
        "feature/x.",
        "@",
        "has space",
        "has:colon",
        "has*star",
        "unicodé",
    ] {
        assert!(raw.parse::<GitBranchName>().is_err(), "accepted {raw:?}");
    }
}

#[test]
fn malformed_object_ids_are_rejected_before_planning() {
    for raw in [
        "",
        "1",
        "111111111111111111111111111111111111111",
        "11111111111111111111111111111111111111111",
        "111111111111111111111111111111111111111g",
        "111111111111111111111111111111111111111/",
    ] {
        assert!(raw.parse::<GitObjectId>().is_err(), "accepted {raw:?}");
    }
}

#[test]
fn error_response_wire_shape_is_stable() {
    let response = VmGitCloneErrorResponse::new(VmGitCloneErrorCode::InvalidRequest, "bad repo");
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["error"], "invalid_request");
    assert_eq!(value["message"], "bad repo");
    assert_eq!(
        serde_json::from_value::<VmGitCloneErrorResponse>(value).unwrap(),
        response
    );
}

#[test]
fn push_error_response_wire_shape_is_stable() {
    let response =
        VmGitPushErrorResponse::new(VmGitPushErrorCode::ValidationFailed, "bad ancestry");
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(value["error"], "validation_failed");
    assert_eq!(value["message"], "bad ancestry");
    assert_eq!(
        serde_json::from_value::<VmGitPushErrorResponse>(value).unwrap(),
        response
    );
}

#[test]
fn push_metadata_wire_shape_and_authorization_request_are_stable() {
    let metadata = push_metadata();
    let value = serde_json::to_value(&metadata).unwrap();
    assert_eq!(value["repo"], "owner/repo");
    assert_eq!(value["branch"], "feature/x");
    assert_eq!(
        value["expected_remote_head"],
        "1111111111111111111111111111111111111111"
    );
    assert_eq!(
        value["new_head"],
        "2222222222222222222222222222222222222222"
    );
    assert_eq!(
        serde_json::from_value::<VmGitPushMetadata>(value).unwrap(),
        metadata
    );

    match metadata.authorization_request() {
        CapabilityRequest::GitHub(GitHubRequest::Contents { access, repo }) => {
            assert_eq!(access, GitHubAccess::Write);
            assert_eq!(repo.to_string(), "owner/repo");
        }
        other => panic!("unexpected authorization request: {other:?}"),
    }
}

#[test]
fn push_metadata_branch_creation_serialises_expected_head_as_null() {
    let metadata = VmGitPushMetadata::new(
        repo("owner", "repo"),
        "feature/x".parse().unwrap(),
        None,
        sample_object_id('2'),
    );
    let value = serde_json::to_value(&metadata).unwrap();
    assert_eq!(value["expected_remote_head"], serde_json::Value::Null);
    assert_eq!(
        serde_json::from_value::<VmGitPushMetadata>(value).unwrap(),
        metadata
    );
}

#[test]
fn push_metadata_rejects_missing_expected_remote_head_key() {
    let json = serde_json::json!({
        "repo": "owner/repo",
        "branch": "feature/x",
        "new_head": "2222222222222222222222222222222222222222",
    });
    let result = serde_json::from_value::<VmGitPushMetadata>(json);
    assert!(
        result.is_err(),
        "missing expected_remote_head key should be rejected (got {:?})",
        result.ok()
    );
}

#[test]
fn push_request_body_parser_splits_metadata_and_bundle() {
    let request = push_request();
    let body = encode_vm_git_push_request_body(&request).unwrap();

    let parsed = parse_vm_git_push_request_body(&body, push_limits()).unwrap();

    assert_eq!(parsed, request);
}

#[test]
fn push_request_body_parser_rejects_malformed_envelopes() {
    let request = push_request();
    let body = encode_vm_git_push_request_body(&request).unwrap();

    assert!(matches!(
        parse_vm_git_push_request_body(&body[..7], push_limits()),
        Err(VmGitPushBodyError::MissingMetadataLength)
    ));

    let mut truncated = 20u64.to_be_bytes().to_vec();
    truncated.extend_from_slice(b"{}");
    assert!(matches!(
        parse_vm_git_push_request_body(&truncated, push_limits()),
        Err(VmGitPushBodyError::TruncatedMetadata { .. })
    ));

    let mut invalid_metadata = 1u64.to_be_bytes().to_vec();
    invalid_metadata.extend_from_slice(b"{");
    invalid_metadata.extend_from_slice(b"bundle");
    assert!(matches!(
        parse_vm_git_push_request_body(&invalid_metadata, push_limits()),
        Err(VmGitPushBodyError::InvalidMetadata(_))
    ));

    let metadata = serde_json::to_vec(&push_metadata()).unwrap();
    let mut empty_bundle = (metadata.len() as u64).to_be_bytes().to_vec();
    empty_bundle.extend_from_slice(&metadata);
    assert!(matches!(
        parse_vm_git_push_request_body(&empty_bundle, push_limits()),
        Err(VmGitPushBodyError::EmptyBundle)
    ));
}

#[test]
fn push_request_body_parser_enforces_independent_limits() {
    let request = push_request();
    let body = encode_vm_git_push_request_body(&request).unwrap();

    assert!(matches!(
        parse_vm_git_push_request_body(
            &body,
            VmGitPushBodyLimits::new(body.len() - 1, 1024, 1024).unwrap()
        ),
        Err(VmGitPushBodyError::BodyTooLarge { .. })
    ));

    assert!(matches!(
        parse_vm_git_push_request_body(&body, VmGitPushBodyLimits::new(4096, 1, 1024).unwrap()),
        Err(VmGitPushBodyError::MetadataTooLarge { .. })
    ));

    assert!(matches!(
        parse_vm_git_push_request_body(&body, VmGitPushBodyLimits::new(4096, 1024, 1).unwrap()),
        Err(VmGitPushBodyError::BundleTooLarge { .. })
    ));
}

#[test]
fn push_staged_receipt_wire_shape_is_stable() {
    let push_request_id = RequestId::new();
    let staged_at = UnixMillis::from_millis(1_700_000_000_123);
    let receipt = VmGitPushStagedReceipt::new(
        repo("owner", "repo"),
        "main".parse().unwrap(),
        Some(sample_object_id('a')),
        sample_object_id('b'),
        push_request_id,
        staged_at,
    );
    assert_eq!(receipt.push_request_id(), push_request_id);
    assert_eq!(receipt.staged_at(), staged_at);
    let value = serde_json::to_value(&receipt).unwrap();
    assert_eq!(value["repo"], "owner/repo");
    assert_eq!(value["branch"], "main");
    assert_eq!(
        value["expected_remote_head"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        value["new_head"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        value["push_request_id"],
        serde_json::json!(push_request_id.to_string())
    );
    assert_eq!(value["staged_at"], staged_at.as_millis());
    assert_eq!(
        serde_json::from_value::<VmGitPushStagedReceipt>(value).unwrap(),
        receipt
    );
}

#[test]
fn push_staged_receipt_serialises_branch_creation_expected_head_as_null() {
    let receipt = VmGitPushStagedReceipt::new(
        repo("owner", "repo"),
        "feature/x".parse().unwrap(),
        None,
        sample_object_id('b'),
        RequestId::new(),
        UnixMillis::from_millis(1_700_000_000_123),
    );
    let value = serde_json::to_value(&receipt).unwrap();
    assert_eq!(value["expected_remote_head"], serde_json::Value::Null);
    assert_eq!(
        serde_json::from_value::<VmGitPushStagedReceipt>(value).unwrap(),
        receipt
    );
}

#[test]
fn push_staged_receipt_rejects_missing_expected_remote_head_key() {
    let json = serde_json::json!({
        "repo": "owner/repo",
        "branch": "feature/x",
        "new_head": "2222222222222222222222222222222222222222",
        "push_request_id": RequestId::new().to_string(),
        "staged_at": 1_700_000_000_123_i64,
    });
    let result = serde_json::from_value::<VmGitPushStagedReceipt>(json);
    assert!(
        result.is_err(),
        "missing expected_remote_head key should be rejected (got {:?})",
        result.ok()
    );
}

#[test]
fn push_request_debug_reports_bundle_length_not_bundle_bytes() {
    let request = VmGitPushRequest::new(push_metadata(), b"secret bundle bytes".to_vec()).unwrap();
    let debug = format!("{request:?}");
    assert!(debug.contains("bundle_bytes"));
    assert!(debug.contains("19"));
    assert!(!debug.contains("secret bundle bytes"));
}

#[test]
fn clone_route_and_bundle_content_type_are_pinned() {
    assert_eq!(VM_GIT_CLONE_PATH, "/v1/git/clone");
    assert_eq!(VM_GIT_PUSH_PATH, "/v1/git/push");
    assert_eq!(VM_FLAKE_PROVISION_PATH, "/v1/nix/flake/provision");
    assert_eq!(GIT_BUNDLE_CONTENT_TYPE, "application/x-git-bundle");
    assert_eq!(
        GIT_PUSH_BUNDLE_CONTENT_TYPE,
        "application/vnd.writ.git-push-bundle"
    );
}

#[test]
fn nix_develop_command_args_pin_bounded_build_no_lockfile_envelope() {
    assert_eq!(
        nix_develop_command_args(DEFAULT_DEVSHELL_ATTR),
        vec![
            "--option",
            "builders",
            "",
            "--option",
            "max-jobs",
            GUEST_DEVSHELL_WARM_MAX_JOBS,
            "--option",
            "fallback",
            "false",
            "develop",
            "--no-write-lock-file",
            ".#default",
            "--command",
        ]
    );
}

#[test]
fn nix_print_dev_env_command_args_pin_bounded_build_no_lockfile_no_shell_envelope() {
    // Identical envelope to the develop warm, but `print-dev-env`: the
    // strict warm must never invoke `nix develop`'s interactive-shell
    // resolution (nixpkgs#bashInteractive), which demands paths outside
    // the pre-warmed closure.
    assert_eq!(
        nix_print_dev_env_command_args(DEFAULT_DEVSHELL_ATTR),
        vec![
            "--option",
            "builders",
            "",
            "--option",
            "max-jobs",
            GUEST_DEVSHELL_WARM_MAX_JOBS,
            "--option",
            "fallback",
            "false",
            "print-dev-env",
            "--no-write-lock-file",
            ".#default",
        ]
    );
}

#[test]
fn nix_substituters_override_args_pin_full_replacement_envelope() {
    // `substituters`, not `extra-substituters`: the strict warm must
    // *replace* the session default, or the upstream-proxying substituter
    // would remain reachable and the override would enforce nothing.
    assert_eq!(
        nix_substituters_override_args("http://192.168.252.1:51375/v1/nix/prewarm"),
        vec![
            "--option",
            "substituters",
            "http://192.168.252.1:51375/v1/nix/prewarm",
        ]
    );
}

/// Extract the `--option <key> <value>` pairs from the leading run of the
/// arg vector (before the `develop` subcommand).
fn nix_develop_options(attr: &str) -> std::collections::HashMap<String, String> {
    let args = nix_develop_command_args(attr);
    let develop = args.iter().position(|a| a == "develop").unwrap();
    let mut options = std::collections::HashMap::new();
    let mut i = 0;
    while i < develop {
        assert_eq!(args[i], "--option", "non-option arg before `develop`");
        options.insert(args[i + 1].clone(), args[i + 2].clone());
        i += 3;
    }
    options
}

#[test]
fn nix_develop_warm_substitutes_first_but_permits_bounded_local_build() {
    let options = nix_develop_options(DEFAULT_DEVSHELL_ATTR);

    // No remote builders, and a failed *substitution* is a hard error
    // rather than a from-source rebuild (which could need egress).
    assert_eq!(options.get("builders").map(String::as_str), Some(""));
    assert_eq!(options.get("fallback").map(String::as_str), Some("false"));

    // `max-jobs` must be non-zero so the guest can locally realise the
    // handful of `allowSubstitutes = false` / `preferLocalBuild` setup-hook
    // derivations (e.g. `cargoHelperFunctionsHook`) that Nix refuses to
    // substitute. At zero, those are unrealisable and the warm fails.
    let max_jobs: u32 = options
        .get("max-jobs")
        .expect("max-jobs option is set")
        .parse()
        .expect("max-jobs is an integer");
    assert!(max_jobs > 0, "max-jobs must be non-zero, got {max_jobs}");
}

/// Every way a guest can fail to declare a version it speaks, and the one way
/// it can succeed.
///
/// Duplicates are [`GuestContract::Malformed`] rather than first-wins: a request
/// carrying two contradictory declarations is not one the broker should pick a
/// winner for. That is only true if *undecodable* occurrences are counted too —
/// dropping them before counting would let a valid header plus a junk one look
/// like a single valid declaration, which is why `parse` takes bytes and decides
/// for itself rather than being handed pre-filtered strings.
#[test]
fn a_contract_declaration_is_well_formed_only_when_it_is_a_single_version() {
    use crate::GuestContract;

    assert_eq!(
        GuestContract::parse(Vec::<&[u8]>::new()),
        GuestContract::Absent
    );
    assert_eq!(
        GuestContract::parse([b"3".as_slice()]),
        GuestContract::Version(3)
    );
    assert_eq!(
        GuestContract::parse([b" 3 ".as_slice()]),
        GuestContract::Version(3),
    );
    assert_eq!(
        GuestContract::parse([b"not-a-version".as_slice()]),
        GuestContract::Malformed,
    );
    // A header value is opaque octets, so this is a request a guest can really
    // send; it must not decode to "no declaration".
    assert_eq!(
        GuestContract::parse([&[0xff, 0xfe][..]]),
        GuestContract::Malformed,
    );
    assert_eq!(
        GuestContract::parse([b"3".as_slice(), b"4".as_slice()]),
        GuestContract::Malformed,
    );
    assert_eq!(
        GuestContract::parse([b"3".as_slice(), &[0xff][..]]),
        GuestContract::Malformed,
        "an undecodable second occurrence must not be dropped, leaving one valid declaration",
    );
}
