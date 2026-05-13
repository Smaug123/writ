//! Pure parsers for the on-disk byte format of git commit and tree
//! objects, plus their inverses.
//!
//! The walker that replays a staging repo onto GitHub never sees git
//! objects directly: it asks a [`crate::git_push_replay_walker::GitObjectSource`]
//! for typed `StagingCommit` / `StagingTree` values and lets the
//! source decide how to decode the raw bytes a `git cat-file` (or
//! similar) returns. This module contains the byte → struct half of
//! that decoder, isolated from any I/O so the same code is shared
//! between the production source, dry-run oracles, and property
//! tests.
//!
//! Each `parse_*` function has a `serialize_*` inverse, and a
//! property test asserts `parse(serialize(x)) == x` over a large
//! generator-supplied population. That oracle is the main correctness
//! lever here: the staging repo is untrusted (it is materialised
//! inside the guest VM from data the agent controls), so a parser
//! that silently re-shapes invalid input could let an attacker
//! launder a different valid object out of an invalid one. We
//! therefore validate aggressively at the boundary — see
//! [`validate_tree_entry_name`] and [`parse_tz_offset`] for two
//! concrete examples — and reject anything `git fsck` would.
//!
//! Until the production `git cat-file` source lands in a follow-up
//! change, the only callers of these parsers are this file's own
//! tests, so the public-but-unused items would otherwise generate
//! `dead_code` warnings.
#![cfg_attr(not(test), allow(dead_code))]

use std::num::ParseIntError;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::git_push_replay_walker::{StagingCommit, StagingTree, StagingTreeEntry};
use crate::github_git_db::{CommitIdentity, TreeEntryKind};
use crate::vm_git::{GitObjectId, GitObjectIdError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseObjectError {
    #[error("unterminated header line in commit object")]
    UnterminatedHeader,
    #[error("commit object truncated before blank line / body")]
    Truncated,
    #[error("commit header line {0:?} is malformed (no SP separator)")]
    MalformedHeader(String),
    #[error("commit has duplicate `{0}` header")]
    DuplicateHeader(&'static str),
    #[error("commit is missing required `{0}` header")]
    MissingHeader(&'static str),
    #[error("commit header SHA in `{key}` line is not a valid object id: {source}")]
    InvalidHeaderSha {
        key: &'static str,
        #[source]
        source: GitObjectIdError,
    },
    #[error("identity line is not valid UTF-8: {0}")]
    NonUtf8Identity(#[source] std::str::Utf8Error),
    #[error("identity line is malformed: {0}")]
    MalformedIdentity(String),
    #[error("commit message is not valid UTF-8: {0}")]
    NonUtf8Message(#[source] std::str::Utf8Error),
    #[error("tree entry header is malformed: {0}")]
    MalformedTreeEntry(String),
    #[error("tree entry mode {0:?} is not recognized")]
    UnknownTreeMode(String),
    #[error("tree entry path is not valid UTF-8: {0}")]
    NonUtf8TreePath(#[source] std::str::Utf8Error),
    #[error("tree entry SHA is invalid: {0}")]
    InvalidTreeSha(#[source] GitObjectIdError),
}

/// Parse the raw bytes of a git commit object into a [`StagingCommit`].
///
/// Accepts the canonical on-disk format (the same bytes
/// `git cat-file --batch` and `git hash-object -t commit --stdin`
/// produce / consume). Unknown headers — notably `gpgsig` with its
/// continuation lines — are skipped, since the walker re-signs (or
/// leaves unsigned) commits on the App side.
pub(crate) fn parse_commit_object(bytes: &[u8]) -> Result<StagingCommit, ParseObjectError> {
    let mut tree: Option<GitObjectId> = None;
    let mut parents: Vec<GitObjectId> = Vec::new();
    let mut author: Option<CommitIdentity> = None;
    let mut committer: Option<CommitIdentity> = None;

    let mut cursor = 0;
    loop {
        if cursor >= bytes.len() {
            return Err(ParseObjectError::Truncated);
        }
        if bytes[cursor] == b'\n' {
            cursor += 1;
            break;
        }
        let header_start = cursor;
        let header_end =
            find_byte(bytes, b'\n', header_start).ok_or(ParseObjectError::UnterminatedHeader)?;
        cursor = header_end + 1;
        // Absorb continuation lines (a leading SP marks a folded
        // continuation; we discard the value since we never use
        // multi-line headers).
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            let next_lf =
                find_byte(bytes, b'\n', cursor).ok_or(ParseObjectError::UnterminatedHeader)?;
            cursor = next_lf + 1;
        }

        let header_line = &bytes[header_start..header_end];
        let sp = header_line.iter().position(|b| *b == b' ').ok_or_else(|| {
            ParseObjectError::MalformedHeader(String::from_utf8_lossy(header_line).into_owned())
        })?;
        let key = &header_line[..sp];
        let value = &header_line[sp + 1..];
        match key {
            b"tree" => {
                if tree.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("tree"));
                }
                tree = Some(parse_sha(value, "tree")?);
            }
            b"parent" => parents.push(parse_sha(value, "parent")?),
            b"author" => {
                if author.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("author"));
                }
                author = Some(parse_identity(value)?);
            }
            b"committer" => {
                if committer.is_some() {
                    return Err(ParseObjectError::DuplicateHeader("committer"));
                }
                committer = Some(parse_identity(value)?);
            }
            _ => {
                // Unknown header (gpgsig, mergetag, encoding, etc.).
                // Skip it: replay never preserves arbitrary headers.
            }
        }
    }

    let tree = tree.ok_or(ParseObjectError::MissingHeader("tree"))?;
    let author = author.ok_or(ParseObjectError::MissingHeader("author"))?;
    let committer = committer.ok_or(ParseObjectError::MissingHeader("committer"))?;
    let message_bytes = &bytes[cursor..];
    let message = std::str::from_utf8(message_bytes)
        .map_err(ParseObjectError::NonUtf8Message)?
        .to_string();

    Ok(StagingCommit {
        tree,
        parents,
        author,
        committer,
        message,
    })
}

/// Reverse of [`parse_commit_object`].
///
/// Emits headers in the order `tree`, then each `parent` in slot
/// order, then `author`, then `committer`, then a blank line, then
/// the message bytes verbatim. The output is the canonical git
/// commit format git itself emits — no signature, no encoding
/// directive — so `git hash-object -t commit --stdin` over these
/// bytes returns the SHA git would assign to a commit holding this
/// `StagingCommit`'s data.
///
/// Used by the dry-run orchestrator's hash-equivalence oracle in
/// a follow-up slice; until then it is exercised exclusively by
/// the parser round-trip property test.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn serialize_commit_object(commit: &StagingCommit) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"tree ");
    out.extend_from_slice(commit.tree.as_str().as_bytes());
    out.push(b'\n');
    for parent in &commit.parents {
        out.extend_from_slice(b"parent ");
        out.extend_from_slice(parent.as_str().as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"author ");
    out.extend_from_slice(serialize_identity(&commit.author).as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"committer ");
    out.extend_from_slice(serialize_identity(&commit.committer).as_bytes());
    out.push(b'\n');
    out.push(b'\n');
    out.extend_from_slice(commit.message.as_bytes());
    out
}

/// Parse the raw bytes of a git tree object into a [`StagingTree`].
///
/// Each entry is `<mode> SP <path> NUL <20-raw-byte-sha>`, with no
/// separator between entries.
pub(crate) fn parse_tree_object(bytes: &[u8]) -> Result<StagingTree, ParseObjectError> {
    let mut entries = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let sp = bytes[cursor..]
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| {
                ParseObjectError::MalformedTreeEntry("missing SP between mode and path".to_string())
            })?;
        let mode_bytes = &bytes[cursor..cursor + sp];
        let mode_str = std::str::from_utf8(mode_bytes).map_err(|_| {
            ParseObjectError::MalformedTreeEntry(format!("tree mode is not ASCII: {mode_bytes:?}"))
        })?;
        let kind = parse_tree_entry_kind(mode_str)?;
        cursor += sp + 1;

        let nul = bytes[cursor..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| {
                ParseObjectError::MalformedTreeEntry(
                    "missing NUL after tree entry path".to_string(),
                )
            })?;
        let path_bytes = &bytes[cursor..cursor + nul];
        let path = std::str::from_utf8(path_bytes)
            .map_err(ParseObjectError::NonUtf8TreePath)?
            .to_string();
        validate_tree_entry_name(&path)?;
        cursor += nul + 1;

        if cursor + 20 > bytes.len() {
            return Err(ParseObjectError::MalformedTreeEntry(
                "tree entry truncated before 20-byte SHA".to_string(),
            ));
        }
        let sha_bytes = &bytes[cursor..cursor + 20];
        let sha =
            GitObjectId::new(hex_encode(sha_bytes)).map_err(ParseObjectError::InvalidTreeSha)?;
        cursor += 20;

        entries.push(StagingTreeEntry { path, kind, sha });
    }
    Ok(StagingTree { entries })
}

/// Returns `Err` if `name` is not a legal tree entry name per git's
/// own rules: empty, `.`, `..`, or containing `/`.
///
/// The staging repo is untrusted, and `git bundle unbundle` together
/// with `git cat-file --batch` happily ferry malformed tree entries
/// through (`git fsck` rejects them, but we do not run it). Any
/// entry name the walker later passes to GitHub's create-tree API
/// is treated by GitHub as a literal path component. An entry like
/// `a/b` would silently re-interpret as a nested subtree, laundering
/// a different valid tree out of an invalid one; `"."` / `".."` /
/// the empty string would similarly re-shape as directory navigation.
/// Reject them at the parser boundary so the rest of the pipeline
/// only ever sees well-formed path components.
fn validate_tree_entry_name(name: &str) -> Result<(), ParseObjectError> {
    if name.is_empty() {
        return Err(ParseObjectError::MalformedTreeEntry(
            "tree entry name is empty".to_string(),
        ));
    }
    if name == "." || name == ".." {
        return Err(ParseObjectError::MalformedTreeEntry(format!(
            "tree entry name is reserved: {name:?}"
        )));
    }
    if name.contains('/') {
        return Err(ParseObjectError::MalformedTreeEntry(format!(
            "tree entry name contains path separator: {name:?}"
        )));
    }
    Ok(())
}

/// Reverse of [`parse_tree_object`]. Emits each entry in the order
/// supplied by the caller, using the canonical (leading-zero-stripped)
/// mode for subtrees.
///
/// See the dead-code note on [`serialize_commit_object`].
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn serialize_tree_object(tree: &StagingTree) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in &tree.entries {
        out.extend_from_slice(canonical_tree_mode(entry.kind).as_bytes());
        out.push(b' ');
        out.extend_from_slice(entry.path.as_bytes());
        out.push(0);
        out.extend_from_slice(&hex_decode(entry.sha.as_str()));
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
fn canonical_tree_mode(kind: TreeEntryKind) -> &'static str {
    // Tree-object on-disk modes omit the leading zero for
    // directories (40000), matching what `git hash-object` emits.
    // Other modes carry their full 6 digits.
    match kind {
        TreeEntryKind::Blob => "100644",
        TreeEntryKind::Executable => "100755",
        TreeEntryKind::Symlink => "120000",
        TreeEntryKind::Subtree => "40000",
        TreeEntryKind::Submodule => "160000",
    }
}

fn parse_tree_entry_kind(mode: &str) -> Result<TreeEntryKind, ParseObjectError> {
    match mode {
        "100644" => Ok(TreeEntryKind::Blob),
        "100755" => Ok(TreeEntryKind::Executable),
        "120000" => Ok(TreeEntryKind::Symlink),
        // Accept both shapes for subtrees: on-disk the leading zero
        // is stripped, but some tools (and historical bundles) emit
        // the padded form.
        "40000" | "040000" => Ok(TreeEntryKind::Subtree),
        "160000" => Ok(TreeEntryKind::Submodule),
        other => Err(ParseObjectError::UnknownTreeMode(other.to_string())),
    }
}

fn parse_sha(value: &[u8], key: &'static str) -> Result<GitObjectId, ParseObjectError> {
    let text = std::str::from_utf8(value).map_err(|_| {
        ParseObjectError::MalformedHeader(format!("`{key}` header value is not ASCII: {value:?}"))
    })?;
    GitObjectId::new(text).map_err(|source| ParseObjectError::InvalidHeaderSha { key, source })
}

fn parse_identity(value: &[u8]) -> Result<CommitIdentity, ParseObjectError> {
    let text = std::str::from_utf8(value).map_err(ParseObjectError::NonUtf8Identity)?;
    let (rest, tz_str) = text.rsplit_once(' ').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity {text:?} has no timezone field"))
    })?;
    let (name_email, seconds_str) = rest.rsplit_once(' ').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity {text:?} has no seconds field"))
    })?;
    let (name, email) = parse_name_email(name_email)?;
    let seconds: i64 = seconds_str.parse().map_err(|err: ParseIntError| {
        ParseObjectError::MalformedIdentity(format!(
            "identity seconds field {seconds_str:?} is not an i64: {err}"
        ))
    })?;
    let offset = parse_tz_offset(tz_str)?;
    let date = OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|err| {
            ParseObjectError::MalformedIdentity(format!(
                "unix timestamp {seconds} is out of range: {err}"
            ))
        })?
        .to_offset(offset);
    CommitIdentity::new(name, email, date).map_err(|err| {
        ParseObjectError::MalformedIdentity(format!("could not build identity: {err}"))
    })
}

fn parse_name_email(s: &str) -> Result<(&str, &str), ParseObjectError> {
    if !s.ends_with('>') {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity name<email> does not end with `>`: {s:?}"
        )));
    }
    let inner = &s[..s.len() - 1];
    let lt = inner.rfind('<').ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!("identity name<email> is missing `<`: {s:?}"))
    })?;
    let name_end = if lt > 0 && inner.as_bytes()[lt - 1] == b' ' {
        lt - 1
    } else {
        lt
    };
    let name = &inner[..name_end];
    let email = &inner[lt + 1..];
    Ok((name, email))
}

fn parse_tz_offset(s: &str) -> Result<time::UtcOffset, ParseObjectError> {
    // The staging repo is untrusted, so a commit object can carry
    // arbitrary UTF-8 in the timezone slot. `s.len()` counts bytes,
    // but `s[1..3]` on a string with a multibyte character (e.g.
    // `+1é2` — 5 bytes, 4 chars) would slice across a UTF-8
    // boundary and panic. Operate on the byte array and verify
    // each digit position is ASCII before any numeric parse.
    let bytes = s.as_bytes();
    if bytes.len() != 5 {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "timezone field {s:?} must be ±HHMM"
        )));
    }
    let sign: i32 = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => {
            return Err(ParseObjectError::MalformedIdentity(format!(
                "timezone field {s:?} must start with `+` or `-`"
            )));
        }
    };
    let hours = parse_two_ascii_digits(&bytes[1..3]).ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone hours field in {s:?} is not 2 ASCII digits"
        ))
    })?;
    let minutes = parse_two_ascii_digits(&bytes[3..5]).ok_or_else(|| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone minutes field in {s:?} is not 2 ASCII digits"
        ))
    })?;
    // The MM half is a base-60 field; values >= 60 would normalize
    // into the hours half and silently shift the commit timestamp.
    // Reject them up front: the staging repo is untrusted, so an
    // attacker that can choose the timezone string could otherwise
    // launder a different timestamp through the parser.
    if minutes >= 60 {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "timezone minutes field in {s:?} is not in 00..=59: {minutes}"
        )));
    }
    let total = sign * (i32::from(hours) * 3600 + i32::from(minutes) * 60);
    time::UtcOffset::from_whole_seconds(total).map_err(|err| {
        ParseObjectError::MalformedIdentity(format!(
            "timezone field {s:?} resolves to invalid offset: {err}"
        ))
    })
}

fn parse_two_ascii_digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

#[cfg_attr(not(test), allow(dead_code))]
fn serialize_identity(identity: &CommitIdentity) -> String {
    // CommitIdentity guarantees the stored RFC3339 string round-trips
    // through `time::OffsetDateTime::parse` — the constructor was the
    // formatter that produced it. The `expect` here pins that
    // invariant: a failure would mean someone removed the constructor's
    // validation, not bad input.
    let dt = OffsetDateTime::parse(identity.date_rfc3339(), &Rfc3339)
        .expect("CommitIdentity stores RFC3339 produced by `time` itself");
    let seconds = dt.unix_timestamp();
    let offset_seconds = dt.offset().whole_seconds();
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs_seconds = offset_seconds.unsigned_abs();
    let hours = abs_seconds / 3600;
    let minutes = (abs_seconds % 3600) / 60;
    format!(
        "{} <{}> {} {}{:02}{:02}",
        identity.name(),
        identity.email(),
        seconds,
        sign,
        hours,
        minutes,
    )
}

fn find_byte(haystack: &[u8], needle: u8, from: usize) -> Option<usize> {
    haystack[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|i| i + from)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing into String never fails");
    }
    s
}

#[cfg_attr(not(test), allow(dead_code))]
fn hex_decode(hex: &str) -> Vec<u8> {
    debug_assert_eq!(hex.len() % 2, 0, "GitObjectId is always even-length hex");
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
fn hex_nibble(byte: u8) -> u8 {
    // GitObjectId validates hex on construction, so we only ever
    // see ASCII hex bytes here.
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("GitObjectId invariant violated: non-hex byte {byte}"),
    }
}

#[cfg(test)]
mod tests {
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
            matches!(err, ParseObjectError::DuplicateHeader("tree")),
            "got: {err:?}"
        );
    }

    #[test]
    fn parse_commit_object_rejects_missing_tree() {
        let bytes = b"author Alice <a@x> 0 +0000\ncommitter Alice <a@x> 0 +0000\n\nmsg";
        let err = parse_commit_object(bytes).unwrap_err();
        assert!(
            matches!(err, ParseObjectError::MissingHeader("tree")),
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
    fn parse_tree_object_round_trip_mixed_kinds() {
        let tree = StagingTree {
            entries: vec![
                StagingTreeEntry {
                    path: "README".to_string(),
                    kind: TreeEntryKind::Blob,
                    sha: sample_object_id('1'),
                },
                StagingTreeEntry {
                    path: "run.sh".to_string(),
                    kind: TreeEntryKind::Executable,
                    sha: sample_object_id('2'),
                },
                StagingTreeEntry {
                    path: "link".to_string(),
                    kind: TreeEntryKind::Symlink,
                    sha: sample_object_id('3'),
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
    fn parse_tree_object_accepts_padded_subtree_mode() {
        let canonical = StagingTree {
            entries: vec![StagingTreeEntry {
                path: "src".to_string(),
                kind: TreeEntryKind::Subtree,
                sha: sample_object_id('a'),
            }],
        };
        let mut padded = Vec::new();
        padded.extend_from_slice(b"040000 src\0");
        padded.extend_from_slice(&hex_decode(canonical.entries[0].sha.as_str()));
        let parsed = parse_tree_object(&padded).expect("padded subtree mode accepted");
        assert_eq!(parsed, canonical);
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
        prop::collection::vec(any::<u8>(), 20)
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
            // Bound the timestamp to a range comfortably inside
            // OffsetDateTime's representable window.
            -2_000_000_000_i64..2_000_000_000_i64,
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
        // Body bytes are unconstrained UTF-8.
        ".*".prop_map(|s: String| s)
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
        // create-tree API). We also exclude the reserved names "."
        // and ".." at the post-collection stage.
        prop::collection::vec(
            prop::char::any()
                .prop_filter("no framing chars", |c| *c != '\0' && *c != ' ' && *c != '/'),
            1..32,
        )
        .prop_filter_map("non-reserved name", |chars| {
            let s: String = chars.into_iter().collect();
            if s == "." || s == ".." { None } else { Some(s) }
        })
    }

    fn arb_staging_tree_entry() -> impl Strategy<Value = StagingTreeEntry> {
        (arb_tree_path(), arb_tree_entry_kind(), arb_object_id())
            .prop_map(|(path, kind, sha)| StagingTreeEntry { path, kind, sha })
    }

    fn arb_staging_tree() -> impl Strategy<Value = StagingTree> {
        prop_vec(arb_staging_tree_entry(), 0..16).prop_map(|entries| StagingTree { entries })
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
}
