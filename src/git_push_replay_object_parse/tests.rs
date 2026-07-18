//! Tests for git object-graph parsing in the push-replay pipeline. Split out of `git_push_replay_object_parse.rs` (an inline `#[cfg(test)]` module); tests unchanged.

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use time::macros::datetime;

use super::*;

fn sample_object_id(nibble: char) -> GitObjectId {
    GitObjectId::new(std::iter::repeat_n(nibble, 40).collect::<String>()).unwrap()
}

fn sample_identity(name: &str) -> CommitIdentity {
    CommitIdentity::new(
        name,
        format!("{name}@example.invalid"),
        datetime!(2024-01-15 10:30:45 UTC),
    )
    .expect("sample date formats")
}

// ============== Parser unit tests ==============

#[test]
fn parse_commit_object_minimal_round_trip() {
    let commit = StagingCommit {
        tree: sample_object_id('a'),
        parents: vec![sample_object_id('b'), sample_object_id('c')],
        author: sample_identity("Alice"),
        committer: sample_identity("Bob"),
        message: "first line\n\nbody\n".to_string(),
    };
    let bytes = serialize_commit_object(&commit);
    let parsed = parse_commit_object(&bytes).expect("round-trip parse");
    assert_eq!(parsed, commit);
}

#[test]
fn parse_commit_object_skips_unknown_headers() {
    let commit = StagingCommit {
        tree: sample_object_id('a'),
        parents: vec![],
        author: sample_identity("Alice"),
        committer: sample_identity("Bob"),
        message: "x\n".to_string(),
    };
    // Inject a gpgsig-style folded header between committer and
    // the blank line. The parser must absorb it without
    // disturbing the surrounding fields.
    let mut bytes = serialize_commit_object(&commit);
    let blank_pos = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("commit always has a blank line before the body");
    let injection = b"gpgsig -----BEGIN PGP SIGNATURE-----\n garbage continuation\n -----END PGP SIGNATURE-----\n";
    bytes.splice(blank_pos + 1..blank_pos + 1, injection.iter().copied());

    let parsed = parse_commit_object(&bytes).expect("parser should skip unknown headers");
    assert_eq!(parsed, commit);
}

#[test]
fn parse_commit_object_rejects_duplicate_tree() {
    // A second `tree` line is now caught by the strict
    // header-order state machine — once `tree` has been consumed
    // the parser is in `ExpectParentOrAuthor` and any later
    // `tree` fails as out-of-order. The duplicate-tree shape is
    // a subset of that condition, so the test's expectation
    // shifted from `DuplicateHeader` to `OutOfOrderHeader`.
    let mut commit = StagingCommit {
        tree: sample_object_id('a'),
        parents: vec![],
        author: sample_identity("Alice"),
        committer: sample_identity("Bob"),
        message: "x\n".to_string(),
    };
    let mut bytes = serialize_commit_object(&commit);
    commit.tree = sample_object_id('d');
    let dup = format!("tree {}\n", commit.tree.as_str());
    bytes.splice(0..0, dup.bytes());
    let err = parse_commit_object(&bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::OutOfOrderHeader(ref k) if k == "tree"),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_missing_tree() {
    // A truly empty header section (blank line immediately) is
    // the only path through the parser that surfaces a
    // `MissingHeader("tree")`: a commit that has *some* headers
    // but no tree is now rejected earlier by the state machine
    // as `OutOfOrderHeader`. Exercise the missing-everything
    // shape here and the missing-via-disorder shape in
    // `parse_commit_object_rejects_disordered_missing_tree`.
    let bytes = b"\nmsg";
    let err = parse_commit_object(bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::MissingHeader("tree")),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_disordered_missing_tree() {
    // When a commit has author/committer but no tree, the state
    // machine catches the disorder before the
    // `MissingHeader("tree")` fallback runs. Either error variant
    // is correct; pin down the current behaviour.
    let bytes = b"author Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nmsg";
    let err = parse_commit_object(bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::OutOfOrderHeader(ref k) if k == "author"),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_truncated_before_blank() {
    let bytes = b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    let err = parse_commit_object(bytes).unwrap_err();
    assert!(matches!(err, ParseObjectError::Truncated), "got: {err:?}");
}

#[test]
fn parse_commit_object_rejects_extension_header_before_author() {
    // Git's commit format prescribes a strict prefix:
    //   tree → parent* → author → committer
    // Extension/unknown headers (encoding, gpgsig, mergetag,
    // ...) are only legal in the optional section *after*
    // committer. A staging commit that places an extension
    // header earlier — e.g. between `tree` and `author` — is
    // rejected by Git, but a permissive parser would silently
    // drop the header and accept the commit, laundering a
    // different commit object into the walker's input. Reject
    // unknown headers that appear before `committer`.
    let bytes = b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                  encoding UTF-8\n\
                  author Alice <a@x> 0 +0000\n\
                  committer Alice <a@x> 0 +0000\n\
                  \n\
                  msg\n";
    let err = parse_commit_object(bytes).expect_err("must reject early extension header");
    assert!(
        matches!(err, ParseObjectError::MalformedHeader(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_nul_in_message() {
    // `git fsck --strict` rejects NUL bytes in a commit's body
    // as `nulInCommit`. The parser is the trust boundary for
    // untrusted staging objects; without an explicit reject,
    // `from_utf8` succeeds (NUL is a valid UTF-8 code point) and
    // the NUL passes through to anything downstream that uses
    // the message as a delimiter.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
    bytes.push(b'\n');
    bytes.extend_from_slice(b"before");
    bytes.push(0);
    bytes.extend_from_slice(b"after\n");
    let err = parse_commit_object(&bytes).expect_err("must reject NUL in body");
    assert!(
        matches!(err, ParseObjectError::NulInMessage),
        "got: {err:?}"
    );
}

#[test]
fn parse_identity_rejects_angle_brackets_inside_name_or_email() {
    // `rfind('<')` plus `ends_with('>')` happily accepts
    // identities whose name or email field contains an
    // angle-bracket of its own — e.g. `A > B <a@e> 0 +0000`
    // (name carries `>`) or `Alice <a<b@e> 0 +0000` (email
    // carries a stray `<`). `git fsck --strict` rejects these
    // as `badName`/`badEmail`; allowing them lets a crafted
    // staging commit reach `create_commit` carrying garbage
    // characters GitHub would otherwise refuse.
    let cases: &[&[u8]] = &[
        b"A > B <a@e> 0 +0000",
        b"Alice <a<b@e> 0 +0000",
        b"Alice <a>b@e> 0 +0000",
    ];
    for bad in cases {
        let err = parse_identity(bad).expect_err("delimiter-in-field must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedIdentity(_)),
            "got for {bad:?}: {err:?}"
        );
    }
}

#[test]
fn parse_tree_object_rejects_non_blob_dot_gitmodules() {
    // `.gitmodules` is parsed by git as a submodule manifest,
    // and `git fsck --strict` requires it to be a regular blob.
    // A symlink/subtree/submodule entry by that name would
    // silently subvert that interpretation when the walker
    // pushes the tree downstream. Reject those kinds at the
    // parser boundary; blob and executable remain valid file
    // shapes.
    for (mode_bytes, label) in [
        (&b"120000"[..], "symlink"),
        (&b"40000"[..], "subtree"),
        (&b"160000"[..], "submodule"),
    ] {
        for name in [".gitmodules", ".GitModules", ".GITMODULES"] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(mode_bytes);
            bytes.extend_from_slice(b" ");
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
            let err = parse_tree_object(&bytes).expect_err("non-blob `.gitmodules` must reject");
            assert!(
                matches!(err, ParseObjectError::MalformedTreeEntry(ref msg) if msg.contains(".gitmodules")),
                "got for {label} {name:?}: {err:?}"
            );
        }
    }
    // Boundary: a regular-file `.gitmodules` still parses.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 .gitmodules\0");
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    parse_tree_object(&bytes).expect("blob `.gitmodules` must parse");
}

#[test]
fn parse_tree_object_rejects_dot_git_protected_aliases() {
    // `git fsck --strict` reports `hasDotgit` not just for the
    // literal `.git` but for every name that resolves to it on
    // NTFS/HFS: trailing-dot/space forms like `.git.` and `.git `,
    // and the 8.3 short-name alias `git~<digits>`. A crafted
    // staging tree carrying such a name passes through to GitHub
    // and then collides with the working-tree metadata on a
    // Windows checkout. Reject the full protected-name family at
    // the parser boundary, not just the exact `.git` literal.
    for bad in [
        ".git.", ".GIT.", ".git ", ".git . ", "git~1", "GIT~1", "git~12", "Git~1",
    ] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 ");
        bytes.extend_from_slice(bad.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        let err = parse_tree_object(&bytes).expect_err("protected `.git` alias must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedTreeEntry(_)),
            "got for {bad:?}: {err:?}"
        );
    }
    // Boundary: names that merely *start* with `git` but are not
    // protected aliases must still parse. `git`, `gitignore`,
    // `git~`, `git~abc` are not 8.3 short-name forms.
    for ok in ["git", "gitignore", "git~", "git~abc", "git1"] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 ");
        bytes.extend_from_slice(ok.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        parse_tree_object(&bytes).unwrap_or_else(|err| {
            panic!("non-alias {ok:?} must parse: {err:?}");
        });
    }
}

#[test]
fn parse_tree_object_rejects_ntfs_separator_dot_git_aliases() {
    // NTFS treats `:` as an alternate-data-stream separator and
    // `\` as a path separator: `.git:foo` resolves to `.git`
    // (its default unnamed stream when `foo` does not exist),
    // and `.git\foo` resolves to `foo` inside the `.git`
    // directory. Git's `is_ntfs_dotgit` examines the prefix up
    // to the first such separator and reports `hasDotgit` if
    // that prefix is an alias for `.git`. The earlier predicate
    // stripped only trailing dots/spaces, so a crafted staging
    // tree carrying `.git:foo` slipped past validation.
    for bad in [
        ".git:foo",
        ".GIT:foo",
        ".git\\foo",
        ".git.:foo",
        "git~1:foo",
        "git~1\\foo",
    ] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 ");
        bytes.extend_from_slice(bad.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        let err = parse_tree_object(&bytes).expect_err("NTFS alias prefix must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedTreeEntry(_)),
            "got for {bad:?}: {err:?}"
        );
    }
}

#[test]
fn parse_tree_object_rejects_non_blob_dot_gitmodules_ntfs_aliases() {
    // A symlink/subtree/submodule named `.gitmodules:foo` is
    // resolved by NTFS as `.gitmodules` (default ADS), which
    // `git fsck --strict` reports as `gitmodulesSymlink`. The
    // earlier predicate missed every `:` / `\` separator
    // variant. Apply the same NTFS-aware predicate here too.
    let alias_names = [
        ".gitmodules:foo",
        ".GITMODULES:foo",
        ".gitmodules\\foo",
        ".gitmodules.:foo",
        "gitmod~1:foo",
        "gitmod~1\\foo",
    ];
    for (mode_bytes, label) in [
        (&b"120000"[..], "symlink"),
        (&b"40000"[..], "subtree"),
        (&b"160000"[..], "submodule"),
    ] {
        for name in alias_names {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(mode_bytes);
            bytes.extend_from_slice(b" ");
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
            let err = parse_tree_object(&bytes).expect_err("NTFS `.gitmodules` alias must reject");
            assert!(
                matches!(err, ParseObjectError::MalformedTreeEntry(_)),
                "got for {label} {name:?}: {err:?}"
            );
        }
    }
}

#[test]
fn parse_tree_object_rejects_non_blob_dot_gitmodules_aliases() {
    // The same protected-name family that aliases to `.git`
    // applies to `.gitmodules` (8.3 short name `gitmod~<digits>`,
    // trailing-dot/space variants, case insensitive). A
    // symlink/subtree/submodule entry by any of those names is
    // rejected by git as a malformed submodule manifest. The
    // earlier exact-match check missed every alias.
    let alias_names = [
        ".gitmodules.",
        ".GITMODULES.",
        ".Gitmodules.",
        ".gitmodules ",
        "gitmod~1",
        "GITMOD~1",
        "gitmod~12",
    ];
    for (mode_bytes, label) in [
        (&b"120000"[..], "symlink"),
        (&b"40000"[..], "subtree"),
        (&b"160000"[..], "submodule"),
    ] {
        for name in alias_names {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(mode_bytes);
            bytes.extend_from_slice(b" ");
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
            let err =
                parse_tree_object(&bytes).expect_err("non-blob `.gitmodules` alias must reject");
            assert!(
                matches!(err, ParseObjectError::MalformedTreeEntry(_)),
                "got for {label} {name:?}: {err:?}"
            );
        }
    }
}

#[test]
fn parse_commit_object_rejects_uppercase_header_sha() {
    // `GitObjectId::new` accepts both lowercase and uppercase hex
    // and stores the value lowercased. That is harmless inside the
    // VM, but at the parser boundary it is a normalization path:
    // a crafted commit whose `tree`/`parent` header carries
    // uppercase hex round-trips through the parser as a *different*
    // commit (with lowercase hex) and therefore a different SHA.
    // The walker forwards this different commit to GitHub's
    // create-commit API. `git fsck` does not directly flag
    // uppercase SHAs but the no-normalization trust boundary
    // requires bit-for-bit round-trip, so reject them here.
    for header in ["tree", "parent"] {
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(header.as_bytes());
        header_bytes.push(b' ');
        // Uppercase hex with 'A' to ensure the upper-case branch
        // triggers regardless of `GitObjectId`'s tolerance.
        header_bytes.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        let mut bytes = Vec::new();
        if header == "tree" {
            bytes.extend_from_slice(&header_bytes);
        } else {
            bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
            bytes.extend_from_slice(&header_bytes);
        }
        bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
        bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
        bytes.push(b'\n');
        bytes.extend_from_slice(b"msg\n");
        let err = parse_commit_object(&bytes).expect_err("uppercase header SHA must be rejected");
        assert!(
            matches!(err, ParseObjectError::MalformedHeader(_)),
            "got for {header:?}: {err:?}"
        );
    }
}

#[test]
fn parse_identity_rejects_missing_space_before_email() {
    // `git fsck` rejects identity lines like `Alice<a@e> ...`
    // (`missingSpaceBeforeEmail`) and `<a@e> ...`
    // (`missingNameBeforeEmail`). Without the space the parser
    // currently treats `Alice` as the name and silently
    // re-emits `Alice <a@e>` on serialize, laundering a
    // different valid identity. The leading-space empty-name
    // form `" <a@e>"` remains accepted.
    let err = parse_identity(b"Alice<a@example.invalid> 0 +0000")
        .expect_err("missing space before `<` must be rejected");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(_)),
        "got: {err:?}"
    );
    let err = parse_identity(b"<a@example.invalid> 0 +0000")
        .expect_err("absent space before `<` must be rejected");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(_)),
        "got: {err:?}"
    );
    // Boundary: the canonical empty-name form still parses.
    parse_identity(b" <a@example.invalid> 0 +0000").expect("empty-name form must still parse");
}

#[test]
fn parse_commit_object_rejects_parent_after_author() {
    // Per the git object format, `parent` headers belong in the
    // strict prefix `tree → parent* → author → committer`, before
    // `author`. A crafted staging commit could carry a stray
    // `parent` line later to launder ancestry through the replay
    // walker — either onto a SHA the walker has already replayed
    // (giving a published commit ancestry the source bundle did
    // not have) or onto a SHA it hasn't, breaking replay loudly
    // with `UnmappedParent`. Silently dropping the stray line is
    // its own kind of laundering: a crafted commit whose parents
    // do not match the bytes the walker pushes downstream is
    // accepted as a different valid commit. Reject the malformed
    // shape outright.
    let commit = StagingCommit {
        tree: sample_object_id('a'),
        parents: vec![sample_object_id('b')],
        author: sample_identity("Alice"),
        committer: sample_identity("Bob"),
        message: "msg\n".to_string(),
    };
    let mut bytes = serialize_commit_object(&commit);
    let blank_pos = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("commit always has a blank line before the body");
    let stray = format!("parent {}\n", sample_object_id('f').as_str());
    bytes.splice(blank_pos + 1..blank_pos + 1, stray.bytes());

    let err = parse_commit_object(&bytes).expect_err("parent after committer must be rejected");
    assert!(
        matches!(err, ParseObjectError::OutOfOrderHeader(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_committer_before_author() {
    // Git's commit format pins the order
    //   tree → parent* → author → committer
    // `git fsck` rejects a commit whose `committer` precedes its
    // `author` (it flags `missingAuthor`/`missingCommitter` for
    // the resulting malformed prefix); without an explicit state
    // machine the parser would collect both fields into their
    // option slots and re-emit them in canonical order on
    // serialize, laundering a malformed commit into a valid one.
    let bytes = b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                  committer Alice <a@x> 0 +0000\n\
                  author Alice <a@x> 0 +0000\n\
                  \n\
                  msg\n";
    let err = parse_commit_object(bytes).expect_err("must reject committer before author");
    assert!(
        matches!(err, ParseObjectError::OutOfOrderHeader(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_parent_after_committer_state_check() {
    // Belt-and-braces variant of the parent-after-author test:
    // even after `committer` (i.e. in the extensions phase), a
    // `parent` line is not a valid extension header — it is a
    // member of the strict prefix that must not reappear.
    let bytes = b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                  author Alice <a@x> 0 +0000\n\
                  committer Alice <a@x> 0 +0000\n\
                  parent bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
                  \n\
                  msg\n";
    let err = parse_commit_object(bytes).expect_err("parent in extension phase must be rejected");
    assert!(
        matches!(err, ParseObjectError::OutOfOrderHeader(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_continuation_on_required_header() {
    // Folded continuation lines (a leading SP marks a continuation
    // of the previous header value) are only legal in the optional
    // extension-header section after `committer` — `gpgsig` is the
    // motivating example. A continuation on `tree`/`parent`/
    // `author`/`committer` is a malformed header value that git
    // does not produce; accepting it (by swallowing the
    // continuation) lets a crafted commit launder its byte form
    // through the parser while presenting a canonical re-emit.
    // Build the bytes by concatenation so the leading SP on the
    // continuation line is not consumed by Rust's `\<newline>`
    // string escape.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b" sneaky continuation\n");
    bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
    bytes.push(b'\n');
    bytes.extend_from_slice(b"msg\n");
    let err = parse_commit_object(&bytes).expect_err("continuation on required header must reject");
    assert!(
        matches!(err, ParseObjectError::UnexpectedContinuation),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_rejects_nul_in_identity_header() {
    // `git fsck --strict` rejects NUL bytes anywhere inside a
    // commit's header section as `nulInHeader`. The existing
    // NUL-in-body check only fires after the blank line, so a
    // crafted staging commit can hide a NUL in the author/
    // committer line (or any extension header) and still parse.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    bytes.extend_from_slice(b"author Al");
    bytes.push(0);
    bytes.extend_from_slice(b"ice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
    bytes.push(b'\n');
    bytes.extend_from_slice(b"msg\n");
    let err = parse_commit_object(&bytes).expect_err("NUL in author must be rejected");
    assert!(matches!(err, ParseObjectError::NulInHeader), "got: {err:?}");
}

#[test]
fn parse_commit_object_rejects_nul_in_extension_header() {
    // The extensions phase still must reject NUL: `git fsck`
    // treats any NUL in the header section as `nulInHeader`
    // regardless of which header it lives in, so a NUL hidden in
    // a `gpgsig` continuation would otherwise pass straight
    // through the parser into wherever the walker re-emits it.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"gpgsig BEGIN\n");
    bytes.extend_from_slice(b" cont");
    bytes.push(0);
    bytes.extend_from_slice(b"inuation\n");
    bytes.push(b'\n');
    bytes.extend_from_slice(b"msg\n");
    let err = parse_commit_object(&bytes).expect_err("NUL in continuation must be rejected");
    assert!(matches!(err, ParseObjectError::NulInHeader), "got: {err:?}");
}

#[test]
fn parse_tree_object_rejects_unsorted_entries() {
    // `git fsck --strict` reports `treeNotSorted` for trees whose
    // entries are not in git's required tree-comparison order
    // (byte-wise on the name, with subdirectories sorting as if
    // they had a trailing `/`). Without enforcement, a crafted
    // staging tree carrying entries in arbitrary order is
    // accepted, hashed differently from what git would have
    // produced, and replayed onto GitHub's create-tree API as if
    // well-formed.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 b");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    bytes.extend_from_slice(b"100644 a");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('b').as_str()));
    let err = parse_tree_object(&bytes).expect_err("unsorted entries must be rejected");
    assert!(
        matches!(err, ParseObjectError::TreeNotSorted { .. }),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_enforces_directory_trailing_slash_in_sort() {
    // Git's tree comparison treats directories as if they had a
    // trailing `/`. So file `a` (terminator `\0` = 0x00) < file
    // `a-` (next byte `-` = 0x2D) < dir `a` (virtual `/` = 0x2F)
    // < file `a0` (next byte `0` = 0x30). A naive byte-compare of
    // the stored names would place dir `a` next to file `a`,
    // missing the sort violation when dir `a` immediately follows
    // a name like `a-` whose bytes sort *before* `a/` but *after*
    // a plain `a`. Pin this down: emit file `a-` then dir `a`,
    // which is correctly sorted under git's rules (`a-` < `a/`).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 a-");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    bytes.extend_from_slice(b"40000 a");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('b').as_str()));
    parse_tree_object(&bytes).expect("a- < a/ is correctly sorted");

    // Now reverse: dir `a` (sorts as `a/`) followed by file `a-`
    // (sorts as `a-`) violates ordering since `a/` > `a-`.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"40000 a");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    bytes.extend_from_slice(b"100644 a-");
    bytes.push(0);
    bytes.extend_from_slice(&hex_decode(sample_object_id('b').as_str()));
    let err = parse_tree_object(&bytes).expect_err("dir `a` then file `a-` violates tree sort");
    assert!(
        matches!(err, ParseObjectError::TreeNotSorted { .. }),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_rejects_dot_git_case_insensitive() {
    // `git fsck --strict` rejects tree entries named `.git` (and
    // case variants like `.GIT`, `.Git`) as `hasDotgit`. A
    // crafted staging tree carrying such an entry would otherwise
    // pass through to GitHub's create-tree API; reject at the
    // parser boundary.
    for bad in [".git", ".GIT", ".Git", ".gIt"] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 ");
        bytes.extend_from_slice(bad.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        let err = parse_tree_object(&bytes).expect_err("must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedTreeEntry(_)),
            "got for {bad:?}: {err:?}"
        );
    }
}

#[test]
fn parse_tree_object_rejects_duplicate_entry_names() {
    // `git fsck --strict` reports `duplicateEntries` for trees
    // that carry the same path twice. The GitHub create-tree API
    // applies last-write-wins, so accepting duplicates here would
    // let a crafted staging tree silently choose which object a
    // path resolves to on the published side. Reject during
    // parsing.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 README\0");
    bytes.extend_from_slice(&hex_decode(sample_object_id('1').as_str()));
    bytes.extend_from_slice(b"100644 README\0");
    bytes.extend_from_slice(&hex_decode(sample_object_id('2').as_str()));
    let err = parse_tree_object(&bytes).expect_err("must reject duplicate path");
    assert!(
        matches!(err, ParseObjectError::MalformedTreeEntry(ref msg) if msg.contains("duplicate")),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_round_trip_mixed_kinds() {
    // Entries are listed in git's required tree-comparison order
    // (`treeNotSorted` enforcement runs in `parse_tree_object`):
    // submodules sort as files (\0 terminator), only subtrees
    // sort as `name/`. So under byte ordering:
    //   README < link < run.sh < src < vendor.
    let tree = StagingTree {
        entries: vec![
            StagingTreeEntry {
                path: "README".to_string(),
                kind: TreeEntryKind::Blob,
                sha: sample_object_id('1'),
            },
            StagingTreeEntry {
                path: "link".to_string(),
                kind: TreeEntryKind::Symlink,
                sha: sample_object_id('3'),
            },
            StagingTreeEntry {
                path: "run.sh".to_string(),
                kind: TreeEntryKind::Executable,
                sha: sample_object_id('2'),
            },
            StagingTreeEntry {
                path: "src".to_string(),
                kind: TreeEntryKind::Subtree,
                sha: sample_object_id('4'),
            },
            StagingTreeEntry {
                path: "vendor".to_string(),
                kind: TreeEntryKind::Submodule,
                sha: sample_object_id('5'),
            },
        ],
    };
    let bytes = serialize_tree_object(&tree);
    let parsed = parse_tree_object(&bytes).expect("round-trip parse");
    assert_eq!(parsed, tree);
}

#[test]
fn parse_tree_object_rejects_zero_padded_subtree_mode() {
    // `git fsck --strict` reports `zeroPaddedFilemode` for a tree
    // entry whose subtree mode is stored as the zero-padded
    // `040000` instead of the canonical `40000`. Accepting it
    // here would normalise the entry on serialize (`40000`),
    // letting a crafted staging tree launder a different valid
    // tree out of an invalid one.
    let mut padded = Vec::new();
    padded.extend_from_slice(b"040000 src\0");
    padded.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    let err = parse_tree_object(&padded).expect_err("padded subtree mode must reject");
    assert!(
        matches!(err, ParseObjectError::UnknownTreeMode(ref m) if m == "040000"),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_rejects_null_sha() {
    // A tree entry whose 20-byte SHA is all zeros is
    // syntactically a 40-hex-zero object id, which our
    // `GitObjectId` constructor happily accepts. `git fsck
    // --strict` flags this as `nullSha1`: it never references a
    // real object, and a submodule entry carrying the null SHA
    // would otherwise pass straight through to GitHub's
    // create-tree API as a literal commit reference. Other kinds
    // would fail later as missing-object lookups; reject at the
    // parser boundary so the failure shape is uniform.
    for kind_mode in ["100644", "100755", "120000", "40000", "160000"] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(kind_mode.as_bytes());
        bytes.extend_from_slice(b" name\0");
        bytes.extend_from_slice(&[0u8; 20]);
        let err = parse_tree_object(&bytes).expect_err("null SHA must reject");
        assert!(
            matches!(err, ParseObjectError::NullSha),
            "got for mode {kind_mode}: {err:?}"
        );
    }
}

#[test]
fn parse_identity_rejects_zero_padded_seconds() {
    // `git fsck --strict` reports `zeroPaddedDate` for an
    // author/committer line whose seconds field has a leading
    // zero (e.g. `01`). Without an explicit check, `i64::parse`
    // accepts the digits and `serialize_identity` re-emits the
    // canonical `1`, turning a malformed commit into a different
    // valid one. `0` itself is the only legal leading-zero form.
    let err =
        parse_identity(b"Alice <a@example.invalid> 01 +0000").expect_err("seconds=01 must reject");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("seconds")),
        "got: {err:?}"
    );
    // Boundary: 0 is the legal zero form.
    parse_identity(b"Alice <a@example.invalid> 0 +0000").expect("seconds=0 must parse");
}

#[test]
fn parse_identity_rejects_signed_seconds() {
    // `git fsck --strict` reports `badDate` for seconds fields
    // that carry a leading `+` or `-`. `i64::parse` accepts both
    // and `serialize_identity` strips the sign on a positive
    // value, again laundering a malformed commit into a valid
    // one.
    for bad in [&b"Alice <a@e> +1 +0000"[..], &b"Alice <a@e> -1 +0000"[..]] {
        let err = parse_identity(bad).expect_err("signed seconds must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("seconds")),
            "got for {bad:?}: {err:?}"
        );
    }
}

#[test]
fn parse_identity_rejects_negative_zero_offset() {
    // `-0000` is fsck-clean: `git hash-object -t commit`
    // accepts it. But `time::UtcOffset::from_whole_seconds(0)`
    // collapses the sign, and `serialize_identity` then re-emits
    // `+0000`, changing the commit's byte form. The parser is
    // explicitly a no-normalization boundary, so reject `-0000`
    // here and let the caller treat it as malformed at the
    // staging boundary.
    let err = parse_identity(b"Alice <a@example.invalid> 1700000000 -0000")
        .expect_err("`-0000` offset must reject");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("-0000")),
        "got: {err:?}"
    );
    // Boundary: a non-zero negative offset still parses (it
    // carries information `+0000` would not).
    parse_identity(b"Alice <a@example.invalid> 1700000000 -0330").expect("`-0330` is still valid");
}

#[test]
fn parse_commit_object_rejects_explicit_non_utf8_encoding() {
    // Git emits an `encoding` extension header when
    // `i18n.commitEncoding` is non-UTF-8. The body is then
    // expected to be bytes in that encoding (e.g. ISO-8859-1).
    // The parser is a UTF-8-only trust boundary: silently
    // dropping the `encoding` header and then UTF-8-decoding the
    // body would either succeed for a UTF-8-shaped Latin-1
    // string and re-emit a different commit, or fail with a
    // confusing `NonUtf8Message`. Reject explicitly so the
    // failure shape is informative.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
    bytes.extend_from_slice(b"encoding ISO-8859-1\n");
    bytes.push(b'\n');
    bytes.extend_from_slice(b"msg\n");
    let err = parse_commit_object(&bytes).expect_err("non-UTF-8 commit encoding must reject");
    assert!(
        matches!(err, ParseObjectError::UnsupportedEncoding(ref enc) if enc == "ISO-8859-1"),
        "got: {err:?}"
    );
}

#[test]
fn parse_commit_object_accepts_explicit_utf8_encoding_header() {
    // Some emitters spell out the default — `encoding UTF-8` is
    // a no-op extension header. The parser must accept it (case
    // insensitive) so legitimate commits that happen to carry
    // it parse without error. The header is dropped from the
    // structured form (the walker has no field to carry it on
    // re-emit), which is acceptable because the canonical form
    // git itself emits omits it.
    for spelling in ["UTF-8", "utf-8", "Utf-8"] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        bytes.extend_from_slice(b"author Alice <a@x> 0 +0000\n");
        bytes.extend_from_slice(b"committer Alice <a@x> 0 +0000\n");
        bytes.extend_from_slice(format!("encoding {spelling}\n").as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(b"msg\n");
        parse_commit_object(&bytes)
            .unwrap_or_else(|err| panic!("{spelling:?} must parse: {err:?}"));
    }
}

#[test]
fn parse_tree_object_rejects_unknown_mode() {
    // 100000 is not a recognized git mode.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100000 oddball\0");
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    let err = parse_tree_object(&bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::UnknownTreeMode(ref m) if m == "100000"),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_rejects_truncated_sha() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 short\0");
    bytes.extend_from_slice(&[0u8; 19]); // one byte short
    let err = parse_tree_object(&bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::MalformedTreeEntry(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_rejects_slash_in_entry_name() {
    // Crafted bundles can ferry a tree object whose entry name
    // contains '/'. The walker would later pass that path
    // verbatim to GitHub's create-tree API, which interprets it
    // as a directory separator — silently normalising the
    // invalid `a/b` tree into a different valid two-level tree
    // and laundering it through the parser.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"100644 a/b\0");
    bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
    let err = parse_tree_object(&bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::MalformedTreeEntry(ref msg) if msg.contains("path separator")),
        "got: {err:?}"
    );
}

#[test]
fn parse_tree_object_rejects_dot_and_dotdot_and_empty() {
    for bad in [".", "..", ""] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 ");
        bytes.extend_from_slice(bad.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex_decode(sample_object_id('a').as_str()));
        let err = parse_tree_object(&bytes).expect_err("must reject");
        assert!(
            matches!(err, ParseObjectError::MalformedTreeEntry(_)),
            "got for {bad:?}: {err:?}"
        );
    }
}

#[test]
fn parse_identity_handles_negative_offset() {
    // Halifax, NS would emit `-0330`.
    let bytes = b"Halifax <hx@example.invalid> 1700000000 -0330";
    let identity = parse_identity(bytes).expect("negative tz parses");
    // Round-trip: serialize and parse should match.
    let serialized = serialize_identity(&identity);
    assert_eq!(serialized, "Halifax <hx@example.invalid> 1700000000 -0330");
}

#[test]
fn parse_identity_handles_empty_name() {
    let bytes = b" <only-email@example.invalid> 1700000000 +0000";
    let identity = parse_identity(bytes).expect("empty-name identity parses");
    assert_eq!(identity.name(), "");
    assert_eq!(identity.email(), "only-email@example.invalid");
}

#[test]
fn parse_tz_offset_rejects_minutes_at_or_above_sixty() {
    // An attacker-controlled staging-repo commit could carry
    // e.g. `+1260`, which used to be silently normalized to
    // 13:00 — laundering a different commit timestamp through
    // the parser. Now the MM field is rejected unless it lies
    // in 00..=59.
    let err = parse_tz_offset("+1260").expect_err("MM=60 must fail");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("00..=59")),
        "got: {err:?}"
    );
    // Boundary: 59 is still accepted.
    parse_tz_offset("+1259").expect("MM=59 is valid");
    // Boundary: 99 is rejected for the same reason.
    let err = parse_tz_offset("-0099").expect_err("MM=99 must fail");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(_)),
        "got: {err:?}"
    );
}

#[test]
fn parse_tz_offset_rejects_multibyte_chars_without_panic() {
    // `+1é2` is 5 bytes but the 2nd char `é` straddles bytes
    // 1..3, so a `&str`-based slice would panic on a non-char
    // boundary. The parser must surface this as a Malformed
    // error instead.
    let err = parse_tz_offset("+1é2").expect_err("multibyte tz must fail cleanly");
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(ref msg) if msg.contains("ASCII digits")),
        "got: {err:?}"
    );

    // Sanity: a 5-byte string whose last byte is a UTF-8
    // continuation should also fail cleanly, not panic.
    let err = parse_tz_offset("+0é0").err();
    assert!(err.is_some(), "expected Err, got Ok");

    // And a fully-multibyte 5-byte string ("é" + "é" = 4 bytes,
    // pad to 5 with "X").
    let err = parse_tz_offset("ééX").err();
    assert!(err.is_some(), "expected Err, got Ok");
}

#[test]
fn parse_identity_rejects_missing_angle_brackets() {
    let bytes = b"Alice email-without-brackets 1700000000 +0000";
    let err = parse_identity(bytes).unwrap_err();
    assert!(
        matches!(err, ParseObjectError::MalformedIdentity(_)),
        "got: {err:?}"
    );
}

// ============== Property tests ==============

fn arb_object_id() -> impl Strategy<Value = GitObjectId> {
    // Exclude the all-zero SHA so a tree-entry round-trip cannot
    // hit `NullSha` by chance. In practice 1-in-2^160 means this
    // filter never fires, but generating by construction is the
    // robust default.
    prop::collection::vec(any::<u8>(), 20)
        .prop_filter("not all zero (git fsck: nullSha1)", |bytes| {
            bytes.iter().any(|b| *b != 0)
        })
        .prop_map(|bytes| GitObjectId::new(hex_encode(&bytes)).unwrap())
}

fn arb_name() -> impl Strategy<Value = String> {
    // Names exclude `<`, `>`, and `\n` so they don't collide
    // with git's identity framing.
    prop::collection::vec(
        prop::char::any().prop_filter("no framing chars", |c| {
            *c != '<' && *c != '>' && *c != '\n' && *c != '\0'
        }),
        0..32,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>().trim().to_string())
}

fn arb_email() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::char::any().prop_filter("no framing chars", |c| {
            *c != '<' && *c != '>' && *c != '\n' && *c != ' ' && *c != '\0'
        }),
        1..32,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn arb_identity() -> impl Strategy<Value = CommitIdentity> {
    (
        arb_name(),
        arb_email(),
        // Seconds field is non-negative: the parser rejects
        // leading `+`/`-` (git fsck: `badDate`) and leading zeros
        // (git fsck: `zeroPaddedDate`). Bound the upper end well
        // inside OffsetDateTime's representable window.
        0_i64..2_000_000_000_i64,
        // Whole-minute offset between -14:00 and +14:00 (the
        // wider range OffsetDateTime accepts).
        -14_i32 * 60..=14_i32 * 60,
    )
        .prop_map(|(name, email, ts, offset_minutes)| {
            let offset = time::UtcOffset::from_whole_seconds(offset_minutes * 60).unwrap();
            let dt = OffsetDateTime::from_unix_timestamp(ts)
                .unwrap()
                .to_offset(offset);
            CommitIdentity::new(name, email, dt).unwrap()
        })
}

fn arb_message() -> impl Strategy<Value = String> {
    // Body bytes are unconstrained UTF-8 *except* NUL, which the
    // parser rejects to match `git fsck`'s `nulInCommit` rule.
    // Generating NUL here would make the round-trip property
    // observe a parse error that is not actually a round-trip
    // bug, so strip it at the source.
    ".*".prop_map(|s: String| s.replace('\0', ""))
}

fn arb_staging_commit() -> impl Strategy<Value = StagingCommit> {
    (
        arb_object_id(),
        prop_vec(arb_object_id(), 0..4),
        arb_identity(),
        arb_identity(),
        arb_message(),
    )
        .prop_map(
            |(tree, parents, author, committer, message)| StagingCommit {
                tree,
                parents,
                author,
                committer,
                message,
            },
        )
}

fn arb_tree_entry_kind() -> impl Strategy<Value = TreeEntryKind> {
    prop_oneof![
        Just(TreeEntryKind::Blob),
        Just(TreeEntryKind::Executable),
        Just(TreeEntryKind::Symlink),
        Just(TreeEntryKind::Subtree),
        Just(TreeEntryKind::Submodule),
    ]
}

fn arb_tree_path() -> impl Strategy<Value = String> {
    // Path bytes exclude '\0' (entry terminator), SP (mode/path
    // separator), and '/' (rejected by the parser because the
    // walker forwards entry names verbatim to GitHub's
    // create-tree API). We also exclude the reserved names ".",
    // "..", and case variants of ".git" at the post-collection
    // stage so the round-trip property is not at the mercy of
    // chance.
    prop::collection::vec(
        prop::char::any().prop_filter("no framing chars", |c| *c != '\0' && *c != ' ' && *c != '/'),
        1..32,
    )
    .prop_filter_map("non-reserved name", |chars| {
        let s: String = chars.into_iter().collect();
        if s == "."
            || s == ".."
            || is_dot_git_protected_alias(&s)
            || is_dot_gitmodules_protected_alias(&s)
        {
            // `.gitmodules` is excluded outright so the random
            // kind in `arb_staging_tree_entry` cannot pair the
            // name with a non-blob mode and trip the parser's
            // kind-aware rejection. Same predicates the parser
            // itself uses so the generator never produces an
            // input the parser rejects.
            None
        } else {
            Some(s)
        }
    })
}

fn arb_staging_tree_entry() -> impl Strategy<Value = StagingTreeEntry> {
    (arb_tree_path(), arb_tree_entry_kind(), arb_object_id())
        .prop_map(|(path, kind, sha)| StagingTreeEntry { path, kind, sha })
}

fn arb_staging_tree() -> impl Strategy<Value = StagingTree> {
    // Dedupe by path so the generator cannot violate the parser's
    // no-duplicate-entries rule by chance, then sort by git's
    // tree-comparison order so the parser's `treeNotSorted` check
    // never fires on a legitimately well-formed StagingTree.
    // Without sorting the round-trip property would observe a
    // parse error that is not actually a round-trip bug.
    prop_vec(arb_staging_tree_entry(), 0..16).prop_map(|entries| {
        let mut seen = std::collections::HashSet::new();
        let mut entries: Vec<_> = entries
            .into_iter()
            .filter(|e| seen.insert(e.path.clone()))
            .collect();
        entries.sort_by(|a, b| {
            tree_entry_cmp(
                &a.path,
                matches!(a.kind, TreeEntryKind::Subtree),
                &b.path,
                matches!(b.kind, TreeEntryKind::Subtree),
            )
        });
        StagingTree { entries }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn commit_serialize_parse_round_trips(commit in arb_staging_commit()) {
        let bytes = serialize_commit_object(&commit);
        let parsed = parse_commit_object(&bytes).expect("round-trip parse");
        prop_assert_eq!(parsed, commit);
    }

    #[test]
    fn tree_serialize_parse_round_trips(tree in arb_staging_tree()) {
        let bytes = serialize_tree_object(&tree);
        let parsed = parse_tree_object(&bytes).expect("round-trip parse");
        prop_assert_eq!(parsed, tree);
    }
}
