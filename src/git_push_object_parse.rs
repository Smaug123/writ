//! Pure parsers for the on-disk byte format of git commit and tree
//! objects, plus their inverses.
//!
//! The walker that replays a staging repo onto GitHub never sees git
//! objects directly: it asks a [`crate::git_push_walker::GitObjectSource`]
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

use std::num::ParseIntError;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::git_push_walker::{StagingCommit, StagingTree, StagingTreeEntry};
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
    // NTFS treats `:` as an alternate-data-stream separator and
    // `\` as a path separator: `.git:foo` resolves to `.git` (its
    // unnamed default stream) and `.git\foo` resolves to `foo`
    // inside the `.git` directory. `/` is rejected earlier in
    // `validate_tree_entry_name` and so cannot reach here, but a
    // crafted staging tree can carry `\` or `:` and bypass an
    // exact-match check.  Match git's own `is_ntfs_dotgit`:
    // examine the prefix up to the first `\` or `:`, then strip
    // trailing `.` / ` ` (NTFS and FAT silently drop those at the
    // end of a component) and compare case-insensitively.
    let prefix_end = name.find(['\\', ':']).unwrap_or(name.len());
    let head = &name[..prefix_end];
    let core = head.trim_end_matches(['.', ' ']);
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
mod tests;
