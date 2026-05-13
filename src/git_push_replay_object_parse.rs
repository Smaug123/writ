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
    #[error("commit message contains a NUL byte (git fsck: nulInCommit)")]
    NulInMessage,
    #[error("commit header line contains a NUL byte (git fsck: nulInHeader)")]
    NulInHeader,
    #[error(
        "commit header {0:?} appears out of the required `tree → parent* → author → committer` order"
    )]
    OutOfOrderHeader(String),
    #[error(
        "required commit header has a folded continuation line (only post-committer extension headers may fold)"
    )]
    UnexpectedContinuation,
    #[error(
        "tree entries are not in git's tree-comparison order (git fsck: treeNotSorted): {prev:?} >= {curr:?}"
    )]
    TreeNotSorted { prev: String, curr: String },
    #[error("tree entry header is malformed: {0}")]
    MalformedTreeEntry(String),
    #[error("tree entry mode {0:?} is not recognized")]
    UnknownTreeMode(String),
    #[error("tree entry path is not valid UTF-8: {0}")]
    NonUtf8TreePath(#[source] std::str::Utf8Error),
    #[error("tree entry SHA is invalid: {0}")]
    InvalidTreeSha(#[source] GitObjectIdError),
    #[error("tree entry SHA is all zeros (git fsck: nullSha1)")]
    NullSha,
    #[error(
        "commit declares unsupported `encoding {0:?}` — only UTF-8 (the canonical, header-absent default) is accepted at this trust boundary"
    )]
    UnsupportedEncoding(String),
}

/// Parse the raw bytes of a git commit object into a [`StagingCommit`].
///
/// Accepts the canonical on-disk format (the same bytes
/// `git cat-file --batch` and `git hash-object -t commit --stdin`
/// produce / consume). Unknown headers — notably `gpgsig` with its
/// continuation lines — are skipped, since the walker re-signs (or
/// leaves unsigned) commits on the App side.
pub(crate) fn parse_commit_object(bytes: &[u8]) -> Result<StagingCommit, ParseObjectError> {
    // Header order is a strict prefix
    //   tree → parent* → author → committer
    // followed by an optional section of extension headers (gpgsig,
    // mergetag, encoding, ...). Track the current phase explicitly
    // so the parser does not silently re-shape malformed input that
    // git itself rejects.
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Phase {
        ExpectTree,
        ExpectParentOrAuthor,
        ExpectCommitter,
        Extensions,
    }
    let mut phase = Phase::ExpectTree;
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
        let header_line = &bytes[header_start..header_end];
        // `git fsck --strict` flags NUL in the header section as
        // `nulInHeader`. NUL is valid UTF-8, so without an explicit
        // check it would pass through to identity strings, extension
        // headers, etc.
        if header_line.contains(&0) {
            return Err(ParseObjectError::NulInHeader);
        }
        cursor = header_end + 1;

        let sp = header_line.iter().position(|b| *b == b' ').ok_or_else(|| {
            ParseObjectError::MalformedHeader(String::from_utf8_lossy(header_line).into_owned())
        })?;
        let key = &header_line[..sp];
        let value = &header_line[sp + 1..];

        // Decide whether continuations are allowed for this header.
        // Only post-committer extension headers (gpgsig, mergetag,
        // ...) may fold; a continuation on tree/parent/author/
        // committer means a malformed header value that git does not
        // produce, and consuming it silently would launder the
        // commit's byte form into a different valid one.
        let allow_continuation = match key {
            b"tree" => {
                if phase != Phase::ExpectTree {
                    return Err(ParseObjectError::OutOfOrderHeader("tree".to_string()));
                }
                tree = Some(parse_sha(value, "tree")?);
                phase = Phase::ExpectParentOrAuthor;
                false
            }
            b"parent" => {
                if phase != Phase::ExpectParentOrAuthor {
                    return Err(ParseObjectError::OutOfOrderHeader("parent".to_string()));
                }
                parents.push(parse_sha(value, "parent")?);
                false
            }
            b"author" => {
                if phase != Phase::ExpectParentOrAuthor {
                    return Err(ParseObjectError::OutOfOrderHeader("author".to_string()));
                }
                author = Some(parse_identity(value)?);
                phase = Phase::ExpectCommitter;
                false
            }
            b"committer" => {
                if phase != Phase::ExpectCommitter {
                    return Err(ParseObjectError::OutOfOrderHeader("committer".to_string()));
                }
                committer = Some(parse_identity(value)?);
                phase = Phase::Extensions;
                false
            }
            other => {
                if phase != Phase::Extensions {
                    return Err(ParseObjectError::MalformedHeader(format!(
                        "unexpected header {:?} before committer",
                        String::from_utf8_lossy(other)
                    )));
                }
                // The `encoding` header tells git that the message
                // body is in a non-default encoding. Silently
                // dropping it and then UTF-8-decoding the body would
                // either re-emit a different commit (if the bytes
                // happened to be valid UTF-8) or fail later with a
                // confusing `NonUtf8Message`. The trust boundary
                // here is UTF-8-only; accept only an explicit
                // `encoding utf-8` (the canonical default).
                if other == b"encoding" {
                    let value_str = std::str::from_utf8(value).map_err(|_| {
                        ParseObjectError::UnsupportedEncoding(
                            String::from_utf8_lossy(value).into_owned(),
                        )
                    })?;
                    if !value_str.eq_ignore_ascii_case("utf-8") {
                        return Err(ParseObjectError::UnsupportedEncoding(value_str.to_string()));
                    }
                }
                true
            }
        };

        // Now examine any continuation lines belonging to this
        // header. Reject early for required headers; absorb (after
        // NUL-checking) for extensions.
        if cursor < bytes.len() && bytes[cursor] == b' ' && !allow_continuation {
            return Err(ParseObjectError::UnexpectedContinuation);
        }
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            let next_lf =
                find_byte(bytes, b'\n', cursor).ok_or(ParseObjectError::UnterminatedHeader)?;
            let cont_line = &bytes[cursor..next_lf];
            if cont_line.contains(&0) {
                return Err(ParseObjectError::NulInHeader);
            }
            cursor = next_lf + 1;
        }
    }

    let tree = tree.ok_or(ParseObjectError::MissingHeader("tree"))?;
    let author = author.ok_or(ParseObjectError::MissingHeader("author"))?;
    let committer = committer.ok_or(ParseObjectError::MissingHeader("committer"))?;
    let message_bytes = &bytes[cursor..];
    // `git fsck --strict` flags NUL bytes in a commit body as
    // `nulInCommit`. NUL is a valid UTF-8 code point, so without an
    // explicit check the byte would pass straight through into the
    // `String` and on to anything downstream that treats the message
    // as a NUL-terminated value.
    if message_bytes.contains(&0) {
        return Err(ParseObjectError::NulInMessage);
    }
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
    // Tracks paths already emitted in this tree so duplicates can be
    // rejected. `git fsck --strict` flags duplicate entries as
    // `duplicateEntries`; GitHub's create-tree API resolves them with
    // last-write-wins, so accepting duplicates here would let a
    // crafted staging tree silently choose which object a path
    // resolves to on the published side.
    let mut seen_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Tracks the previous entry's name and "is-directory" flag so the
    // parser can enforce git's tree-comparison order (`git fsck`'s
    // `treeNotSorted` rule). Names are compared byte-by-byte, but a
    // subdirectory's name is treated as if it had a trailing `/`,
    // i.e. the byte immediately after the name is `/` (0x2F) for
    // directories and `\0` (0x00) for files. Without this check, a
    // crafted staging tree whose entries are out of order would be
    // hashed differently from what git would have produced.
    let mut prev_entry: Option<(String, bool)> = None;
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
        // `.gitmodules` is parsed by git as a submodule manifest;
        // `git fsck --strict` requires it to be a regular file. A
        // symlink/subtree/submodule entry by that name — or any of
        // the protected-name aliases that resolve to `.gitmodules`
        // on NTFS/HFS (`.GITMODULES.`, `gitmod~1`, …) — would
        // silently subvert that interpretation when the walker
        // forwards the entry to GitHub. Reject the non-blob shapes
        // here using the same alias predicate that
        // `validate_tree_entry_name` uses for `.git`.
        if is_dot_gitmodules_protected_alias(&path)
            && !matches!(kind, TreeEntryKind::Blob | TreeEntryKind::Executable)
        {
            return Err(ParseObjectError::MalformedTreeEntry(format!(
                "`.gitmodules` must be a regular file blob, not {kind:?}: {path:?}"
            )));
        }
        if !seen_paths.insert(path.clone()) {
            return Err(ParseObjectError::MalformedTreeEntry(format!(
                "duplicate tree entry name: {path:?}"
            )));
        }
        let curr_is_dir = matches!(kind, TreeEntryKind::Subtree);
        if let Some((prev_name, prev_is_dir)) = prev_entry.as_ref()
            && tree_entry_cmp(prev_name, *prev_is_dir, &path, curr_is_dir)
                != std::cmp::Ordering::Less
        {
            return Err(ParseObjectError::TreeNotSorted {
                prev: prev_name.clone(),
                curr: path.clone(),
            });
        }
        prev_entry = Some((path.clone(), curr_is_dir));
        cursor += nul + 1;

        if cursor + 20 > bytes.len() {
            return Err(ParseObjectError::MalformedTreeEntry(
                "tree entry truncated before 20-byte SHA".to_string(),
            ));
        }
        let sha_bytes = &bytes[cursor..cursor + 20];
        // `git fsck --strict` rejects the all-zero SHA as `nullSha1`:
        // it never references a real object. Submodule entries
        // carrying the null SHA would otherwise pass straight through
        // to GitHub's create-tree API; reject at the parser boundary
        // so the failure shape is uniform across kinds.
        if sha_bytes.iter().all(|b| *b == 0) {
            return Err(ParseObjectError::NullSha);
        }
        let sha =
            GitObjectId::new(hex_encode(sha_bytes)).map_err(ParseObjectError::InvalidTreeSha)?;
        cursor += 20;

        entries.push(StagingTreeEntry { path, kind, sha });
    }
    Ok(StagingTree { entries })
}

/// Git's tree-comparison ordering, returning `Less` if entry `a`
/// must sort before entry `b`.
///
/// Names are compared byte-by-byte over their common prefix; once
/// one name is exhausted, the comparison continues against a
/// "virtual" trailing byte that is `/` (0x2F) if that entry is a
/// subdirectory and `\0` (0x00) otherwise. This is the same
/// `base_name_compare` rule git uses to order tree entries on disk;
/// `git fsck --strict` reports `treeNotSorted` for any tree whose
/// entries are not strictly increasing under this order.
fn tree_entry_cmp(a: &str, a_is_dir: bool, b: &str, b_is_dir: bool) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let common = ab.len().min(bb.len());
    match ab[..common].cmp(&bb[..common]) {
        std::cmp::Ordering::Equal => {}
        other => return other,
    }
    let a_next = if ab.len() > common {
        ab[common]
    } else if a_is_dir {
        b'/'
    } else {
        0
    };
    let b_next = if bb.len() > common {
        bb[common]
    } else if b_is_dir {
        b'/'
    } else {
        0
    };
    a_next.cmp(&b_next)
}

/// Returns `Err` if `name` is not a legal tree entry name per git's
/// own rules: empty, `.`, `..`, `.git` (case-insensitive), or
/// containing `/`.
///
/// The staging repo is untrusted, and `git bundle unbundle` together
/// with `git cat-file --batch` happily ferry malformed tree entries
/// through (`git fsck` rejects them, but we do not run it). Any
/// entry name the walker later passes to GitHub's create-tree API
/// is treated by GitHub as a literal path component. An entry like
/// `a/b` would silently re-interpret as a nested subtree, laundering
/// a different valid tree out of an invalid one; `"."` / `".."` /
/// the empty string would similarly re-shape as directory navigation;
/// `.git` (and case variants) is what `git fsck` flags as `hasDotgit`
/// and would, on a checkout, collide with the working-tree metadata.
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
    if is_dot_git_protected_alias(name) {
        return Err(ParseObjectError::MalformedTreeEntry(format!(
            "tree entry name is reserved (git fsck hasDotgit): {name:?}"
        )));
    }
    if name.contains('/') {
        return Err(ParseObjectError::MalformedTreeEntry(format!(
            "tree entry name contains path separator: {name:?}"
        )));
    }
    Ok(())
}

/// True when `name` matches the protected-name family git's
/// `is_ntfs_dotgit` / HFS check flags as an alias for `.git` on a
/// case-folding or 8.3-short-name filesystem. We cover the two
/// shapes `git fsck --strict` actually reports as `hasDotgit`:
///
///   1. case-insensitive `.git` followed by zero or more ASCII `.`
///      / SP characters (trailing dots and spaces are invisible to
///      NTFS path resolution), and
///   2. case-insensitive `git~<digits>` — the 8.3 short-name form
///      auto-generated for `.git` on a Windows filesystem.
///
/// Catching only the literal `.git` would let a crafted staging
/// tree carrying e.g. `.git.` or `git~1` pass through to GitHub and
/// then collide with `.git` on a Windows checkout.
fn is_dot_git_protected_alias(name: &str) -> bool {
    is_protected_alias_for(name, ".git", "git")
}

/// True when `name` matches the protected-name family git's
/// `is_ntfs_dotgitmodules` flags as an alias for `.gitmodules`: the
/// case-insensitive literal with optional trailing dots/spaces, or
/// the 8.3 short-name form `gitmod~<digits>` (case insensitive).
fn is_dot_gitmodules_protected_alias(name: &str) -> bool {
    is_protected_alias_for(name, ".gitmodules", "gitmod")
}

fn is_protected_alias_for(name: &str, literal: &str, short_prefix: &str) -> bool {
    // NTFS and FAT silently drop trailing `.` and ` ` when
    // resolving a path component, so `.git.` and `.git ` both
    // resolve to `.git` on Windows. Strip those before the
    // case-insensitive literal compare.
    let core = name.trim_end_matches(['.', ' ']);
    if core.eq_ignore_ascii_case(literal) {
        return true;
    }
    // 8.3 short-name shape: <short_prefix><~><digits...>. We do
    // not require the digit run to be exactly one digit: `~1`
    // through `~99` are all valid generated short names, and
    // collisions push the suffix into multi-digit territory.
    let core_bytes = core.as_bytes();
    let prefix_bytes = short_prefix.as_bytes();
    if core_bytes.len() < prefix_bytes.len() + 2 {
        return false;
    }
    for (a, b) in core_bytes[..prefix_bytes.len()].iter().zip(prefix_bytes) {
        if !a.eq_ignore_ascii_case(b) {
            return false;
        }
    }
    let rest = &core_bytes[prefix_bytes.len()..];
    if rest.first() != Some(&b'~') {
        return false;
    }
    let digits = &rest[1..];
    !digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit())
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
    // Each mode is the canonical, leading-zero-stripped form git
    // itself emits when writing a tree. The padded form `040000`
    // for subtrees is rejected by `git fsck --strict` as
    // `zeroPaddedFilemode`; accepting it here would normalise the
    // entry on serialize back to `40000`, laundering a different
    // valid tree out of an invalid one.
    match mode {
        "100644" => Ok(TreeEntryKind::Blob),
        "100755" => Ok(TreeEntryKind::Executable),
        "120000" => Ok(TreeEntryKind::Symlink),
        "40000" => Ok(TreeEntryKind::Subtree),
        "160000" => Ok(TreeEntryKind::Submodule),
        other => Err(ParseObjectError::UnknownTreeMode(other.to_string())),
    }
}

fn parse_sha(value: &[u8], key: &'static str) -> Result<GitObjectId, ParseObjectError> {
    let text = std::str::from_utf8(value).map_err(|_| {
        ParseObjectError::MalformedHeader(format!("`{key}` header value is not ASCII: {value:?}"))
    })?;
    // Git emits SHAs in commit `tree`/`parent` headers as
    // lowercase hex. `GitObjectId::new` accepts both cases and
    // stores the value lowercased; if the parser took that path,
    // `serialize_commit_object` would re-emit a different commit
    // object than the staging bytes (uppercase → lowercase in the
    // header), which is a normalization path that violates the
    // parser's no-normalization trust boundary. Require lowercase
    // here so the bytes round-trip exactly.
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ParseObjectError::MalformedHeader(format!(
            "`{key}` header SHA contains uppercase hex (non-canonical): {text:?}"
        )));
    }
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
    // `git fsck --strict` reports `zeroPaddedDate` for a seconds
    // field with a leading zero (e.g. `01`) and `badDate` for a
    // leading `+` or `-`. `i64::parse` accepts both, and
    // `serialize_identity` would then emit the canonical form,
    // letting a malformed staging commit cross the parser as a
    // different valid commit. Validate the shape — `0` or
    // `[1-9][0-9]*` — before the numeric parse.
    let seconds_bytes = seconds_str.as_bytes();
    let valid_seconds_shape = matches!(seconds_bytes, [b'0'])
        || (seconds_bytes
            .first()
            .is_some_and(|b| (b'1'..=b'9').contains(b))
            && seconds_bytes.iter().all(|b| b.is_ascii_digit()));
    if !valid_seconds_shape {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity seconds field {seconds_str:?} must be `0` or unsigned decimal with no leading zero (git fsck: zeroPaddedDate/badDate)"
        )));
    }
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
    // Require a literal space immediately before `<` so the parser
    // does not silently re-shape `Alice<a@x>` (which git fsck flags
    // as `missingSpaceBeforeEmail`) or `<a@x>` (`missingNameBeforeEmail`)
    // into the canonical `Alice <a@x>` form on serialize. The
    // empty-name form is still accepted: `" <a@x>"` has `lt == 1`
    // and the byte before `<` is a space.
    if lt == 0 || inner.as_bytes()[lt - 1] != b' ' {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity {s:?} is missing the space before `<`"
        )));
    }
    let name = &inner[..lt - 1];
    let email = &inner[lt + 1..];
    // `rfind('<')` + `ends_with('>')` accepts inputs like
    // `A > B <a@e>` (name carries `>`) or `Alice <a<b@e>` (email
    // carries `<`). `git fsck --strict` rejects these as
    // `badName`/`badEmail`; allowing them lets a crafted staging
    // commit reach `create_commit` carrying garbage characters
    // GitHub would otherwise refuse.
    if name.contains('<') || name.contains('>') {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity name {name:?} contains `<` or `>`"
        )));
    }
    if email.contains('<') || email.contains('>') {
        return Err(ParseObjectError::MalformedIdentity(format!(
            "identity email {email:?} contains `<` or `>`"
        )));
    }
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
    // `-0000` is fsck-clean but loses its sign when collapsed into
    // `time::UtcOffset::from_whole_seconds(0)`; `serialize_identity`
    // would later re-emit `+0000` and produce a different commit
    // byte form. The parser is a no-normalization boundary, so
    // reject the sole offset whose sign would be silently dropped.
    if s == "-0000" {
        return Err(ParseObjectError::MalformedIdentity(
            "timezone field `-0000` loses its sign on round-trip (use `+0000`)".to_string(),
        ));
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
                let err =
                    parse_tree_object(&bytes).expect_err("non-blob `.gitmodules` must reject");
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
                let err = parse_tree_object(&bytes)
                    .expect_err("non-blob `.gitmodules` alias must reject");
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
            let err =
                parse_commit_object(&bytes).expect_err("uppercase header SHA must be rejected");
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
        let err =
            parse_commit_object(bytes).expect_err("parent in extension phase must be rejected");
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
        let err =
            parse_commit_object(&bytes).expect_err("continuation on required header must reject");
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
        let err = parse_identity(b"Alice <a@example.invalid> 01 +0000")
            .expect_err("seconds=01 must reject");
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
        parse_identity(b"Alice <a@example.invalid> 1700000000 -0330")
            .expect("`-0330` is still valid");
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
            prop::char::any()
                .prop_filter("no framing chars", |c| *c != '\0' && *c != ' ' && *c != '/'),
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
}
