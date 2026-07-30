//! Tests for the shared bare-repo notes wrapper (ref writes, fetch, atomic update). Split out of `notes_repo.rs` (an inline `#[cfg(test)]` module); tests unchanged.

use super::*;
use std::ffi::OsStr;
use std::fs;
use tempfile::TempDir;

fn notes_ref() -> NotesRef {
    NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
}

#[test]
fn init_or_open_creates_a_bare_repo() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bailiff-repo");
    let repo = NotesRepo::init_or_open(&path).unwrap();
    assert!(path.join("HEAD").is_file(), "HEAD should exist after init");
    assert!(path.join("objects").is_dir());
    assert!(path.join("refs").is_dir());
    // Canonicalised path resolves through any tmp symlinks.
    assert_eq!(repo.path(), path.canonicalize().unwrap());
}

#[test]
fn init_or_open_is_idempotent_across_calls() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bailiff-repo");
    let a = NotesRepo::init_or_open(&path).unwrap();
    let b = NotesRepo::init_or_open(&path).unwrap();
    assert_eq!(a.path(), b.path());
}

#[test]
fn open_rejects_a_plain_directory() {
    let tmp = TempDir::new().unwrap();
    let err = NotesRepo::open(tmp.path()).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::MissingHead { .. }),
        "got: {err:?}"
    );
}

#[test]
fn open_rejects_non_bare_repo() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("non-bare");
    // `git init` (no --bare) produces a working-directory repo
    // whose top-level layout includes `.git/` rather than the
    // bare layout. The validation must reject pointing at either
    // the worktree root or the inner `.git` dir.
    let status = Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let err = NotesRepo::open(&path).unwrap_err();
    // Top-level: no HEAD file at the worktree root.
    assert!(
        matches!(err, NotesRepoError::MissingHead { .. }),
        "got: {err:?}"
    );
    // Inner `.git`: HEAD exists but core.bare=false.
    let err_inner = NotesRepo::open(path.join(".git")).unwrap_err();
    assert!(
        matches!(err_inner, NotesRepoError::NotBare { value: Some(false) }),
        "got: {err_inner:?}"
    );
}

#[test]
fn open_rejects_repo_missing_head() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    fs::remove_file(repo.path().join("HEAD")).unwrap();
    let err = NotesRepo::open(repo.path()).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::MissingHead { .. }),
        "got: {err:?}"
    );
}

#[test]
fn open_rejects_repo_missing_objects() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    fs::remove_dir_all(repo.path().join("objects")).unwrap();
    let err = NotesRepo::open(repo.path()).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::MissingObjectsDir { .. }),
        "got: {err:?}"
    );
}

#[test]
fn open_rejects_repo_missing_refs() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    fs::remove_dir_all(repo.path().join("refs")).unwrap();
    let err = NotesRepo::open(repo.path()).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::MissingRefsDir { .. }),
        "got: {err:?}"
    );
}

#[test]
fn open_rejects_repo_with_commondir_marker() {
    // Worktrees of another repo have a `commondir` file at their
    // top level pointing at the parent's git dir; a NotesRepo
    // bare repo never has one. Plant the marker and confirm we
    // reject.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    fs::write(repo.path().join("commondir"), "../some/other/.git\n").unwrap();
    let err = NotesRepo::open(repo.path()).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::Worktree { .. }),
        "got: {err:?}"
    );
}

#[test]
fn open_rejects_repo_with_sha256_object_format() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("sha256-repo");
    let status = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg("--object-format=sha256")
        .arg("--quiet")
        .arg(&path)
        .status();
    match status {
        Ok(s) if s.success() => {}
        // Older Git builds without sha256 support can't run this
        // case; skip rather than fail. We don't need to test on
        // every Git version, just confirm the gate exists on Git
        // versions that *can* produce a sha256 repo.
        _ => return,
    }
    let err = NotesRepo::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            NotesRepoError::UnsupportedObjectFormat { ref value } if value == "sha256"
        ),
        "got: {err:?}"
    );
}

#[test]
fn write_note_round_trips_through_read_note() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let body = b"the signed envelope bytes go here";
    let seed = b"run-id-1";
    let target = repo.write_note(&nref, seed, body).unwrap();
    let read_back = repo.read_note(&nref, &target).unwrap();
    assert_eq!(read_back, body);
}

#[test]
fn write_note_keys_distinct_seeds_to_distinct_oids() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let a = repo.write_note(&nref, b"run-a", b"body A").unwrap();
    let b = repo.write_note(&nref, b"run-b", b"body B").unwrap();
    assert_ne!(a, b);
    assert_eq!(repo.read_note(&nref, &a).unwrap(), b"body A");
    assert_eq!(repo.read_note(&nref, &b).unwrap(), b"body B");
}

#[test]
fn write_note_with_same_seed_is_content_addressed() {
    // Same seed bytes ⇒ same blob OID, so the second note-add
    // tries to attach to an existing target. Without `-f`, `git
    // notes add` refuses to overwrite an existing note, which
    // surfaces as our `GitFailed` variant — the property that
    // makes accidental duplicate writes loud rather than silent.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let first = repo.write_note(&nref, b"seed", b"first body").unwrap();
    let err = repo.write_note(&nref, b"seed", b"second body").unwrap_err();
    match err {
        NotesRepoError::GitFailed { ref args, .. } => {
            assert!(
                args.iter().any(|a| a == "notes"),
                "expected the notes command to be the failure point, got: {args:?}"
            );
        }
        other => panic!("expected GitFailed from notes add, got: {other:?}"),
    }
    // The first note is still there.
    assert_eq!(repo.read_note(&nref, &first).unwrap(), b"first body");
}

#[test]
fn read_note_errors_on_missing_target() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    // Write *something* under the ref so the ref exists, but ask
    // for a different target — exercises "ref present, no note
    // at this oid" rather than "ref missing entirely".
    let _ = repo.write_note(&nref, b"seed", b"body").unwrap();
    let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
    let err = repo.read_note(&nref, &absent).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::GitFailed { .. }),
        "got: {err:?}"
    );
}

#[test]
fn notes_under_distinct_refs_do_not_collide() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let ref_a = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let ref_b = NotesRef::try_new("refs/notes/bailiff/v1/plans").unwrap();
    let target_a = repo.write_note(&ref_a, b"seed", b"under A").unwrap();
    let target_b = repo.write_note(&ref_b, b"seed", b"under B").unwrap();
    // Same seed ⇒ same OID; the note bodies live under different refs.
    assert_eq!(target_a, target_b);
    assert_eq!(repo.read_note(&ref_a, &target_a).unwrap(), b"under A");
    assert_eq!(repo.read_note(&ref_b, &target_b).unwrap(), b"under B");
}

#[test]
fn write_note_preserves_trailing_newline_in_body() {
    // `git notes show` appends a single trailing newline; the
    // read path strips exactly one. Bodies that end with one
    // newline must come back identical (not double-stripped).
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let body = b"body ending in a newline\n";
    let target = repo.write_note(&nref, b"seed", body).unwrap();
    assert_eq!(repo.read_note(&nref, &target).unwrap(), body);
}

#[test]
fn write_note_rejects_empty_body() {
    // `git notes add -C <empty-blob-oid>` succeeds without
    // attaching a note, so the helper must reject empty bodies
    // before they reach git rather than returning a target OID
    // that read_note cannot resolve.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let err = repo.write_note(&nref, b"seed", b"").unwrap_err();
    assert!(matches!(err, NotesRepoError::EmptyBody), "got: {err:?}");
}

#[test]
fn init_or_open_does_not_mutate_existing_non_bare_repo() {
    // Pointing `init_or_open` at the `.git` directory of a real
    // worktree must not run `git init --bare` against it: that
    // would flip core.bare and silently break the worktree. The
    // expected behaviour is to validate-only and surface the
    // mismatch as an open error.
    let tmp = TempDir::new().unwrap();
    let worktree = tmp.path().join("wt");
    let status = Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&worktree)
        .status()
        .unwrap();
    assert!(status.success());
    let git_dir = worktree.join(".git");
    // Capture HEAD + config before the call so we can confirm
    // init was not run against the existing repo.
    let head_before = fs::read(git_dir.join("HEAD")).unwrap();
    let config_before = fs::read(git_dir.join("config")).unwrap();
    let err = NotesRepo::init_or_open(&git_dir).unwrap_err();
    assert!(
        matches!(err, NotesRepoError::NotBare { value: Some(false) }),
        "got: {err:?}"
    );
    assert_eq!(fs::read(git_dir.join("HEAD")).unwrap(), head_before);
    assert_eq!(fs::read(git_dir.join("config")).unwrap(), config_before);
}

#[test]
fn fetch_from_remote_copies_notes_between_repos() {
    // The writ→bailiff handoff: writ writes a note in its bare
    // repo, bailiff fetches the notes ref from writ's repo, and
    // the resulting target OID is readable on bailiff's side
    // under the same notes ref. The fetched body must be
    // byte-identical to the source body.
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let nref = notes_ref();
    let body = b"signed envelope bytes";
    let target = source_repo.write_note(&nref, b"run-id", body).unwrap();

    dest_repo
        .fetch_from_remote(
            source_repo.path(),
            &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
        )
        .unwrap();

    let read_back = dest_repo.read_note(&nref, &target).unwrap();
    assert_eq!(read_back, body);
}

#[test]
fn fetch_from_remote_round_trips_binary_body() {
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let nref = notes_ref();
    let body: Vec<u8> = (0u8..=255).collect();
    let target = source_repo.write_note(&nref, b"run-id", &body).unwrap();

    dest_repo
        .fetch_from_remote(
            source_repo.path(),
            &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
        )
        .unwrap();

    assert_eq!(dest_repo.read_note(&nref, &target).unwrap(), body);
}

#[test]
fn fetch_from_remote_is_idempotent_under_repeated_calls() {
    // A second fetch with the same refspec is a no-op because
    // the dest refs are already current. The force flag (`+`)
    // makes the operation safe to repeat even if the source
    // moves; here we just confirm the second call doesn't error.
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let nref = notes_ref();
    let body = b"envelope";
    let target = source_repo.write_note(&nref, b"seed", body).unwrap();
    let refspecs = &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"];
    dest_repo
        .fetch_from_remote(source_repo.path(), refspecs)
        .unwrap();
    dest_repo
        .fetch_from_remote(source_repo.path(), refspecs)
        .unwrap();
    assert_eq!(dest_repo.read_note(&nref, &target).unwrap(), body);
}

#[test]
fn fetch_from_remote_picks_up_new_notes_on_subsequent_call() {
    // Fetching only mirrors what's in the source at the time of
    // the call; a later writ-side write must surface on bailiff's
    // side after another fetch. This is the load-bearing
    // operational property: bailiff polls writ.
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let nref = notes_ref();
    let refspecs = &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"];

    let first = source_repo
        .write_note(&nref, b"run-1", b"first envelope")
        .unwrap();
    dest_repo
        .fetch_from_remote(source_repo.path(), refspecs)
        .unwrap();
    assert_eq!(
        dest_repo.read_note(&nref, &first).unwrap(),
        b"first envelope"
    );

    let second = source_repo
        .write_note(&nref, b"run-2", b"second envelope")
        .unwrap();
    // The second note is not yet on bailiff's side.
    assert!(dest_repo.read_note(&nref, &second).is_err());
    dest_repo
        .fetch_from_remote(source_repo.path(), refspecs)
        .unwrap();
    assert_eq!(
        dest_repo.read_note(&nref, &second).unwrap(),
        b"second envelope"
    );
}

#[test]
fn fetch_from_remote_errors_on_missing_source() {
    // Pointing at a nonexistent path must surface as a GitFailed
    // error, not a panic or silent success. This is the
    // operator-misconfiguration case (wrong path in bailiff
    // config) and it must be loud.
    let tmp = TempDir::new().unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let bogus = tmp.path().join("does-not-exist");
    let err = dest_repo
        .fetch_from_remote(&bogus, &["+refs/notes/*:refs/notes/*"])
        .unwrap_err();
    assert!(
        matches!(err, NotesRepoError::GitFailed { .. }),
        "got: {err:?}"
    );
}

#[test]
fn fetch_from_remote_rejects_empty_refspecs() {
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    let err = dest_repo
        .fetch_from_remote(source_repo.path(), &[])
        .unwrap_err();
    assert!(matches!(err, NotesRepoError::EmptyRefspecs), "got: {err:?}");
}

#[test]
fn fetch_from_remote_with_no_matching_refs_succeeds() {
    // The source repo is empty (no notes refs at all). A glob
    // refspec produces no matches but git still treats that as
    // success — we just want a green return, not a typed error.
    let tmp = TempDir::new().unwrap();
    let source_repo = NotesRepo::init_or_open(tmp.path().join("writ-bare")).unwrap();
    let dest_repo = NotesRepo::init_or_open(tmp.path().join("bailiff-bare")).unwrap();
    dest_repo
        .fetch_from_remote(
            source_repo.path(),
            &["+refs/notes/writ/v1/*:refs/notes/writ/v1/*"],
        )
        .unwrap();
}

#[test]
fn write_note_handles_binary_body() {
    // The envelope bytes will not be UTF-8 in general (stdout/stderr
    // are arbitrary bytes). The pipe-to-stdin path must not
    // corrupt non-UTF-8 input.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let body: Vec<u8> = (0u8..=255).collect();
    let target = repo.write_note(&nref, b"seed", &body).unwrap();
    assert_eq!(repo.read_note(&nref, &target).unwrap(), body);
}

// The host-config-hardening tests below inspect the `Command`
// produced by `prepare_git_command` rather than mutating real
// process env. The properties they pin down:
//
// * The clean-recipe env (`HOME=/dev/null`,
//   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, and
//   a `GIT_CONFIG_COUNT` bounding the recipe's own numbered
//   pairs) is unconditionally set on the child — so a host-wide
//   `GIT_CONFIG_GLOBAL` pointing at a poisoned file,
//   `init.defaultObjectFormat = sha256` in `~/.gitconfig`,
//   `safe.bareRepository = explicit`, etc. cannot reach git.
// * Those numbered pairs impose `maintenance.auto=false` /
//   `gc.auto=0`, so the notes repo has no detached second
//   writer. That matters here specifically: `write_note` fetches
//   from a peer repo, and `git fetch` is the command that spawns
//   `git maintenance run --auto --quiet --detach`.
// * `PATH` flows from the supplied `InheritedEnv`, not from a
//   hidden `std::env::var_os` call — so production passes the
//   captured parent env explicitly and tests can substitute.
// * `--git-dir=<repo>` is the first arg — so an inherited
//   `GIT_DIR` cannot redirect us, and discovery (which a host
//   with `safe.bareRepository=explicit` disables) is never
//   consulted.
//
// Trusting git's documented semantics for `--local`,
// `--git-dir`, and `--object-format=sha1` is the load-bearing
// step; verifying that we *invoke* git with those flags is
// what these tests cover.
fn synthetic_env(path: &str) -> InheritedEnv {
    InheritedEnv {
        path: Some(OsString::from(path)),
    }
}

fn envs_of(cmd: &Command) -> HashMap<OsString, Option<OsString>> {
    cmd.get_envs()
        .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
        .collect()
}

#[test]
fn prepare_git_command_pins_clean_recipe_and_inherits_only_path() {
    let env = synthetic_env("/usr/bin:/bin");
    let cmd = prepare_git_command(Path::new("/some/repo"), &env);
    let envs = envs_of(&cmd);
    assert_eq!(
        envs.get(OsStr::new("PATH")),
        Some(&Some(OsString::from("/usr/bin:/bin"))),
        "PATH must flow from InheritedEnv, not std::env"
    );
    assert_eq!(
        envs.get(OsStr::new("HOME")),
        Some(&Some(OsString::from("/dev/null")))
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_GLOBAL")),
        Some(&Some(OsString::from("/dev/null"))),
        "child must see GIT_CONFIG_GLOBAL=/dev/null so a host-wide \
         poisoned global config cannot reach git"
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_NOSYSTEM")),
        Some(&Some(OsString::from("1")))
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_COUNT")),
        Some(&Some(OsString::from("2"))),
        "the count must bound the recipe's own numbered pairs, so an inherited \
         GIT_CONFIG_KEY_<n> is either overwritten or out of range"
    );
    // Asserted by value, not merely present: a notes repo rewritten by a
    // detached `git maintenance` while writd is reading its object graph is
    // the failure this suppresses.
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_KEY_0")),
        Some(&Some(OsString::from("maintenance.auto")))
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_VALUE_0")),
        Some(&Some(OsString::from("false")))
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_KEY_1")),
        Some(&Some(OsString::from("gc.auto")))
    );
    assert_eq!(
        envs.get(OsStr::new("GIT_CONFIG_VALUE_1")),
        Some(&Some(OsString::from("0")))
    );
}

#[test]
fn prepare_git_command_passes_repo_via_git_dir_arg() {
    // `--git-dir=<repo>` sidesteps both `GIT_DIR` env override
    // and `safe.bareRepository=explicit` discovery hardening.
    let env = synthetic_env("/usr/bin");
    let cmd = prepare_git_command(Path::new("/some/repo"), &env);
    let args: Vec<&OsStr> = cmd.get_args().collect();
    assert!(
        !args.is_empty(),
        "prepare_git_command must add at least --git-dir"
    );
    assert_eq!(args[0], OsStr::new("--git-dir=/some/repo"));
}

#[test]
fn prepare_git_command_omits_path_when_inherited_env_lacks_it() {
    // If the captured parent env has no PATH, the child should
    // get no PATH either — not a stale value from the wider
    // process. The other clean-recipe entries remain.
    let env = InheritedEnv { path: None };
    let cmd = prepare_git_command(Path::new("/some/repo"), &env);
    let envs = envs_of(&cmd);
    assert!(
        !envs.contains_key(OsStr::new("PATH")),
        "PATH must be absent when InheritedEnv carries None; got: {envs:?}"
    );
    assert_eq!(
        envs.get(OsStr::new("HOME")),
        Some(&Some(OsString::from("/dev/null")))
    );
}

// --- read_note_if_present / write_note_if_absent ----------------------

/// When the notes ref does not exist at all (fresh repo, never
/// written), `read_note_if_present` folds the failure into
/// `Ok(None)` instead of surfacing it as `NotesRepoError`.
#[test]
fn read_note_if_present_returns_none_when_ref_does_not_exist() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
    let res = repo.read_note_if_present(&nref, &absent).unwrap();
    assert!(res.is_none(), "expected None on missing ref, got: {res:?}");
}

/// When the notes ref exists but has no annotation at the target,
/// the result is also `Ok(None)`. Exercises the "ref present, no
/// note at this oid" branch of the absent-classifier.
#[test]
fn read_note_if_present_returns_none_when_ref_has_no_note_at_target() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    // Create the ref with one note keyed on a different seed.
    let _ = repo.write_note(&nref, b"some-other-seed", b"body").unwrap();
    let absent = GitObjectId::new("0000000000000000000000000000000000000000").unwrap();
    let res = repo.read_note_if_present(&nref, &absent).unwrap();
    assert!(res.is_none(), "expected None on missing note, got: {res:?}");
}

/// When a note is present, `read_note_if_present` returns the
/// same bytes [`NotesRepo::read_note`] would (i.e. `Some(body)`),
/// confirming the absent-classifier doesn't accidentally swallow
/// the present case.
#[test]
fn read_note_if_present_returns_some_body_when_note_exists() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let target = repo.write_note(&nref, b"seed-A", b"hello").unwrap();
    let body = repo.read_note_if_present(&nref, &target).unwrap();
    assert_eq!(body.as_deref(), Some(b"hello".as_slice()));
}

/// First call writes, returning `Written(target)`; the same
/// target is reachable via `read_note_if_present` afterwards.
/// Pins the success path before exercising the idempotent
/// branch.
#[test]
fn write_note_if_absent_writes_on_first_call() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let outcome = repo
        .write_note_if_absent(&nref, b"seed-A", b"body-A")
        .unwrap();
    match outcome {
        WriteOutcome::Written(target) => {
            let read_back = repo.read_note_if_present(&nref, &target).unwrap();
            assert_eq!(read_back.as_deref(), Some(b"body-A".as_slice()));
        }
        WriteOutcome::AlreadyPresent(target) => {
            panic!("first call should write, got AlreadyPresent({target})");
        }
    }
}

/// Second call against the same seed returns `AlreadyPresent`
/// without touching the existing body. Body bytes from the
/// second call's `body` argument are deliberately different so
/// any silent overwrite would surface.
#[test]
fn write_note_if_absent_is_idempotent_on_repeat_call() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let first = repo
        .write_note_if_absent(&nref, b"seed-A", b"first body")
        .unwrap();
    let target = match first {
        WriteOutcome::Written(oid) => oid,
        WriteOutcome::AlreadyPresent(oid) => panic!("first call should write, got {oid}"),
    };
    let second = repo
        .write_note_if_absent(&nref, b"seed-A", b"second body")
        .unwrap();
    match second {
        WriteOutcome::AlreadyPresent(oid) => assert_eq!(oid, target),
        WriteOutcome::Written(oid) => panic!("second call should be no-op, got {oid}"),
    }
    // The first body must still be the one attached.
    let body = repo.read_note(&nref, &target).unwrap();
    assert_eq!(body, b"first body");
}

/// Different seeds under the same ref each get their own
/// `Written` outcome; the existence check is keyed on the target
/// OID, not on "is there any note under this ref?".
#[test]
fn write_note_if_absent_distinguishes_seeds() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let a = repo
        .write_note_if_absent(&nref, b"seed-A", b"body-A")
        .unwrap();
    let b = repo
        .write_note_if_absent(&nref, b"seed-B", b"body-B")
        .unwrap();
    let target_a = match a {
        WriteOutcome::Written(o) => o,
        WriteOutcome::AlreadyPresent(o) => panic!("seed-A should write, got {o}"),
    };
    let target_b = match b {
        WriteOutcome::Written(o) => o,
        WriteOutcome::AlreadyPresent(o) => panic!("seed-B should write, got {o}"),
    };
    assert_ne!(
        target_a, target_b,
        "distinct seeds must hash to distinct targets"
    );
    assert_eq!(repo.read_note(&nref, &target_a).unwrap(), b"body-A");
    assert_eq!(repo.read_note(&nref, &target_b).unwrap(), b"body-B");
}

/// `write_note_if_absent` rejects empty bodies for the same
/// reason `write_note` does: `git notes add -C <empty-blob-oid>`
/// succeeds without attaching a note, so an empty body would
/// silently fail to write and the next idempotent probe would
/// see "no note" and write again forever.
#[test]
fn write_note_if_absent_rejects_empty_body() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let err = repo
        .write_note_if_absent(&nref, b"seed-A", b"")
        .unwrap_err();
    assert!(matches!(err, NotesRepoError::EmptyBody), "got: {err:?}");
}

/// Round-trip pin: writing under a seed and reading back via the
/// same seed recovers the body byte-for-byte. The writer hashes
/// the seed to derive the target OID; the reader hashes the same
/// seed and recovers the same OID, so the body comes back without
/// the caller ever materialising the target OID. This is the
/// content-addressed contract the helper exists to provide.
#[test]
fn read_note_at_seed_round_trips_through_write_note_if_absent() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let _ = repo
        .write_note_if_absent(&nref, b"seed-A", b"body-A")
        .unwrap();
    let read_back = repo.read_note_at_seed(&nref, b"seed-A").unwrap();
    assert_eq!(read_back.as_deref(), Some(b"body-A".as_slice()));
}

/// When no note is attached under the seed, `read_note_at_seed`
/// folds the absence into `Ok(None)` — same shape its underlying
/// `read_note_if_present` exposes. The fresh-ref case (no ref
/// at all) is one of the two absent branches `read_note_if_present`
/// already pins; pinning it again at the seed-level helper guards
/// against a future refactor that bypasses the absent-classifier.
#[test]
fn read_note_at_seed_returns_none_when_nothing_was_written() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let res = repo.read_note_at_seed(&nref, b"unwritten-seed").unwrap();
    assert!(res.is_none(), "expected None, got: {res:?}");
}

/// When a note is attached under a *different* seed, the asked-for
/// seed still resolves to `None`. Exercises the "ref present, no
/// note at this target" branch of the absent-classifier through
/// the seed-level helper.
#[test]
fn read_note_at_seed_returns_none_when_other_seed_was_written() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let _ = repo
        .write_note_if_absent(&nref, b"seed-A", b"body-A")
        .unwrap();
    let res = repo.read_note_at_seed(&nref, b"seed-B").unwrap();
    assert!(res.is_none(), "expected None for seed-B, got: {res:?}");
}

/// Read-path side-effect regression: probing for an absent note
/// must not materialise the seed blob in the object database.
/// The previous implementation called `git hash-object -w`, which
/// silently wrote a dangling seed blob on every read — polluting
/// the repo and breaking the helper on read-only mirrors. Pin
/// the no-write property by counting loose objects across the
/// probe.
#[test]
fn read_note_at_seed_does_not_write_seed_blob_to_object_database() {
    fn count_loose_objects(repo_path: &Path) -> usize {
        let mut total = 0usize;
        let objects = repo_path.join("objects");
        for entry in fs::read_dir(&objects).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            // Loose object subdirs are two hex chars; skip
            // `info/` and `pack/` and anything else.
            let name_str = name.to_string_lossy();
            if name_str.len() != 2 || !name_str.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            for inner in fs::read_dir(entry.path()).unwrap() {
                let _ = inner.unwrap();
                total += 1;
            }
        }
        total
    }

    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let nref = notes_ref();
    let before = count_loose_objects(repo.path());
    let _ = repo
        .read_note_at_seed(&nref, b"never-written-seed")
        .unwrap();
    let after = count_loose_objects(repo.path());
    assert_eq!(
        before, after,
        "read_note_at_seed must not write seed blobs (before={before}, after={after})",
    );
}

#[test]
fn list_refs_under_prefix_returns_empty_vec_on_empty_repo() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let refs = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap();
    assert!(refs.is_empty(), "expected empty vec, got: {refs:?}");
}

#[test]
fn list_refs_under_prefix_returns_refs_lexicographically_sorted() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let ref_c = NotesRef::try_new("refs/notes/bailiff/v1/plans/plan-c").unwrap();
    let ref_a = NotesRef::try_new("refs/notes/bailiff/v1/plans/plan-a").unwrap();
    let ref_b = NotesRef::try_new("refs/notes/bailiff/v1/plans/plan-b").unwrap();
    // Write in non-sorted order so the assertion pins git's
    // lexicographic default rather than insertion order.
    let _ = repo.write_note(&ref_c, b"seed-c", b"body-c").unwrap();
    let _ = repo.write_note(&ref_a, b"seed-a", b"body-a").unwrap();
    let _ = repo.write_note(&ref_b, b"seed-b", b"body-b").unwrap();
    let refs = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap();
    assert_eq!(refs, vec![ref_a, ref_b, ref_c]);
}

#[test]
fn list_refs_under_prefix_excludes_refs_outside_prefix() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let in_prefix = NotesRef::try_new("refs/notes/bailiff/v1/plans/plan-a").unwrap();
    let outside = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let _ = repo.write_note(&in_prefix, b"seed-in", b"body-in").unwrap();
    let _ = repo.write_note(&outside, b"seed-out", b"body-out").unwrap();
    let refs = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap();
    assert_eq!(refs, vec![in_prefix]);
}

#[test]
fn list_refs_under_prefix_returns_empty_vec_on_no_match() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    // Populate a different namespace so the repo isn't empty —
    // we want to assert the prefix filter, not the empty-repo
    // case (already covered in a sibling test).
    let nref = NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap();
    let _ = repo.write_note(&nref, b"seed", b"body").unwrap();
    let refs = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap();
    assert!(refs.is_empty(), "expected empty vec, got: {refs:?}");
}

#[test]
fn list_refs_under_prefix_surfaces_broken_refname_warning_as_error() {
    // Branch 1 of the stderr-warning property: a loose ref with
    // a name git's check-ref-format rejects (ASCII whitespace).
    // `git for-each-ref` emits
    // `warning: ignoring ref with broken name <name>` to stderr
    // and exits 0; without inspecting stderr the helper would
    // return only the surviving valid rows and pretend nothing
    // was missing. Pin that the warning surfaces as
    // `ForEachRefStderr` so corruption never masquerades as
    // "missing row".
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let valid_ref = NotesRef::try_new("refs/notes/bailiff/v1/plans/sentinel").unwrap();
    let real_oid = repo.write_note(&valid_ref, b"seed", b"body").unwrap();
    let plans_dir = repo.path().join("refs/notes/bailiff/v1/plans");
    fs::create_dir_all(&plans_dir).unwrap();
    fs::write(
        plans_dir.join("has space"),
        format!("{}\n", real_oid.as_str()),
    )
    .unwrap();
    let err = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap_err();
    match &err {
        NotesRepoError::ForEachRefStderr { stderr } => {
            assert!(
                stderr.contains("broken name"),
                "expected the broken-name warning, got: {stderr:?}",
            );
        }
        other => panic!("expected ForEachRefStderr, got: {other:?}"),
    }
}

#[test]
fn list_refs_under_prefix_does_not_deadlock_on_many_warnings() {
    // Pipe-buffer-fill regression. Each broken-ref warning git
    // writes to stderr is ~80 bytes; the Linux default pipe
    // buffer is 64 KiB, so on the order of 800 warnings is
    // enough to fill it. Plant well over that many so git's
    // stderr pipe fills before stdout closes — without the
    // concurrent stderr drain in `run_git_capturing_stderr` the
    // child blocks on its next stderr write, parent waits on
    // stdout forever, classic pipe-buffer deadlock. The test
    // asserts the call returns at all; a regression manifests
    // as the test-suite timeout. With the drain, it returns
    // promptly with `ForEachRefStderr`.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let plans_dir = repo.path().join("refs/notes/bailiff/v1/plans");
    fs::create_dir_all(&plans_dir).unwrap();
    for i in 0..3000 {
        fs::write(plans_dir.join(format!("bad-{i:04}")), "not-an-oid\n").unwrap();
    }
    let err = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap_err();
    match &err {
        NotesRepoError::ForEachRefStderr { .. } => {}
        other => panic!("expected ForEachRefStderr, got: {other:?}"),
    }
}

#[test]
fn list_refs_under_prefix_surfaces_broken_ref_contents_warning_as_error() {
    // Branch 2 of the stderr-warning property: a loose ref whose
    // name is fine but whose contents aren't a parseable OID.
    // `git for-each-ref` emits
    // `warning: ignoring broken ref <name>` to stderr and exits
    // 0, dropping the row from stdout. This is a separate git
    // shape from the broken-name case, and the previous narrow
    // match-on-substring would have missed it; pin that we
    // surface this too as `ForEachRefStderr` — the load-bearing
    // property is "any non-empty for-each-ref stderr means
    // corruption", not the specific phrasing.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let plans_dir = repo.path().join("refs/notes/bailiff/v1/plans");
    fs::create_dir_all(&plans_dir).unwrap();
    // Refname is fine; the contents (where the OID should live)
    // are not. git emits `ignoring broken ref` for this case.
    fs::write(plans_dir.join("bad-contents"), "not-an-oid\n").unwrap();
    let err = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap_err();
    match &err {
        NotesRepoError::ForEachRefStderr { stderr } => {
            assert!(
                stderr.contains("broken ref"),
                "expected the broken-ref-contents warning, got: {stderr:?}",
            );
        }
        other => panic!("expected ForEachRefStderr, got: {other:?}"),
    }
}

#[test]
fn list_refs_under_prefix_surfaces_corruption_as_error() {
    // Operator-corruption case: someone plants a loose ref whose
    // name contains a non-ASCII whitespace character (U+00A0,
    // NBSP). Git's refname rules forbid ASCII whitespace, but
    // its loose-ref scanner walks the filesystem and doesn't
    // re-validate names against check-ref-format; `for-each-ref
    // --format=%(refname)` will happily emit a name our
    // `NotesRef::try_new` refuses. The helper must surface that
    // as `ForEachRefRefnameInvalid` rather than silently
    // dropping the row — operators must never have corruption
    // masquerade as "no rows here".
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    // Write a real note first to get a valid OID the bad loose
    // ref can point at — git's loose-ref reader rejects a
    // ref whose contents aren't a parseable OID, but accepts
    // any 40-hex string regardless of whether that object
    // exists locally.
    let valid_ref = NotesRef::try_new("refs/notes/bailiff/v1/plans/sentinel").unwrap();
    let real_oid = repo.write_note(&valid_ref, b"seed", b"body").unwrap();
    let plans_dir = repo.path().join("refs/notes/bailiff/v1/plans");
    fs::create_dir_all(&plans_dir).unwrap();
    let bad_name = "has\u{00a0}nbsp";
    fs::write(plans_dir.join(bad_name), format!("{}\n", real_oid.as_str())).unwrap();
    let err = repo
        .list_refs_under_prefix("refs/notes/bailiff/v1/plans/")
        .unwrap_err();
    match &err {
        NotesRepoError::ForEachRefRefnameInvalid { raw, .. } => {
            assert!(
                raw.contains('\u{00a0}'),
                "expected raw refname to carry the NBSP, got: {raw:?}",
            );
        }
        NotesRepoError::GitFailed { .. } => {}
        other => panic!("expected corruption-surfaced error, got: {other:?}"),
    }
}

// The supervision tests below drive `run_git` against a *fake* `git` on a
// synthetic `PATH`, because the properties under test — "a wedged child is
// killed at the deadline", "a flooding child is rejected rather than buffered" —
// cannot be provoked from real git without an actual wedged filesystem.
//
// These are the protections `notes_repo` previously lacked entirely. It had a
// spawn retry and no timeout; `clean_git` had a timeout and no spawn retry. Each
// helper looked complete on its own, so a hung `git fetch` here hung a bailiff
// workflow forever and a `git for-each-ref` over a corrupted ref namespace could
// buffer without bound.

/// Absolute path to a real `sleep`, located on the *test process's* PATH.
///
/// The fake `git` runs under a synthetic PATH containing nothing but itself, so a
/// script that needs a long-lived child must name the binary outright rather than
/// rely on a lookup that would silently fail (and turn "hangs forever" into
/// "exits 127" — passing the test for the wrong reason).
fn sleep_program() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH").expect("PATH must be set in tests");
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("sleep");
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
            && (meta.permissions().mode() & 0o111) != 0
        {
            return candidate;
        }
    }
    panic!("`sleep` must be on PATH for the notes_repo supervision tests");
}

/// Install an executable `git` in `dir` whose body is `body`, and return an
/// `InheritedEnv` whose `PATH` finds it and nothing else.
fn fake_git_env(dir: &Path, body: &str) -> InheritedEnv {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("git");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    InheritedEnv {
        path: Some(OsString::from(dir.as_os_str())),
    }
}

/// A `git` that never exits must be killed at the deadline, not waited on
/// forever. Bailiff's note fetches run through here, so an unbounded wait is a
/// workflow that hangs with no diagnosis.
#[test]
fn run_git_times_out_on_a_child_that_never_exits() {
    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    // Sleep far longer than the test's timeout, writing nothing.
    let env = fake_git_env(&bin, &format!("exec {} 600", sleep_program().display()));
    let started = std::time::Instant::now();
    let err = run_git_with_limits(
        tmp.path(),
        ["for-each-ref"],
        None,
        CaptureOutput::Capture,
        &env,
        GitLimits {
            timeout: Duration::from_millis(300),
            stdout_cap: 64 * 1024,
        },
        OnBornDead::Retry,
    )
    .expect_err("a child that never exits must not be waited on forever");
    assert!(
        matches!(err, NotesRepoError::GitTimedOut { .. }),
        "expected GitTimedOut, got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the call must return at the deadline, not on the child's own schedule"
    );
}

/// A `git` that floods stdout must be rejected outright. A truncated prefix is
/// worse than an error for `for-each-ref` output, which is parsed one refname
/// per line: a prefix reads as a complete, shorter answer.
#[test]
fn run_git_rejects_a_child_that_floods_stdout() {
    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let env = fake_git_env(&bin, "while :; do printf 'refs/notes/flood\\n'; done");
    // A small cap (rather than the 64 MiB production bound) so the property is
    // provoked in milliseconds; the mechanism under test is identical, and
    // spinning a shell for 30s to reach 64 MiB would only add flakiness.
    let err = run_git_with_limits(
        tmp.path(),
        ["for-each-ref"],
        None,
        CaptureOutput::Capture,
        &env,
        GitLimits {
            timeout: Duration::from_secs(30),
            stdout_cap: 64 * 1024,
        },
        OnBornDead::Retry,
    )
    .expect_err("unbounded stdout must be rejected, not buffered");
    assert!(
        matches!(err, NotesRepoError::GitStdoutCapExceeded { cap, .. } if cap == 64 * 1024),
        "expected GitStdoutCapExceeded at the 64 KiB cap, got {err:?}"
    );
}

/// A `git` that floods *stderr* while exiting cleanly must still succeed — the
/// drain keeps only a bounded tail — and must not deadlock on a full pipe. This
/// is the `for-each-ref`-over-a-corrupt-namespace case the module already
/// reasoned about, now with an actual bound.
#[test]
fn run_git_tail_caps_a_flooding_stderr_without_deadlocking() {
    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let env = fake_git_env(
        &bin,
        "i=0; while [ $i -lt 4000 ]; do printf 'warning: ignoring ref with broken name\\n' 1>&2; \
         i=$((i+1)); done; printf 'refs/notes/ok\\n'; exit 0",
    );
    let (stdout, stderr) = run_git_capturing_stderr_with_limits(
        tmp.path(),
        ["for-each-ref"],
        None,
        CaptureOutput::Capture,
        &env,
        GitLimits::production(),
        OnBornDead::Retry,
    )
    .expect("a clean exit with verbose stderr must succeed");
    assert_eq!(stdout, b"refs/notes/ok\n");
    assert!(
        !stderr.is_empty() && stderr.len() <= NOTES_GIT_STDERR_TAIL_CAP,
        "stderr must be retained but bounded; got {} bytes",
        stderr.len()
    );
}

/// A helper the fake `git` forks into its own process group must not outlive the
/// run. Without a process-group kill, a `git` that leaves a credential helper or
/// a hook behind keeps the captured pipe open and the drain never reaches EOF.
#[test]
fn run_git_kills_a_lingering_helper_in_the_process_group() {
    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let marker = tmp.path().join("helper.pid");
    // Fork a long-lived helper that inherits the group, record its pid, then
    // exit 0 immediately. The supervisor must SIGKILL the group on the way out.
    let env = fake_git_env(
        &bin,
        &format!(
            "{sleep} 600 & printf '%s' \"$!\" > {marker}\nexit 0",
            sleep = sleep_program().display(),
            marker = marker.display()
        ),
    );
    run_git_with_limits(
        tmp.path(),
        ["for-each-ref"],
        None,
        CaptureOutput::Capture,
        &env,
        GitLimits::production(),
        OnBornDead::Retry,
    )
    .expect("the fake git exits 0");
    let pid: i32 = fs::read_to_string(&marker)
        .expect("helper pid marker")
        .trim()
        .parse()
        .expect("helper pid is numeric");
    // The group kill is synchronous with the run's return, but reaping is the
    // kernel's business; poll briefly for the helper to disappear.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if !alive {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "helper pid {pid} survived the run; the process group was not killed"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

// The born-dead-child tests below come from #354 (`f36b4c0`), which diagnosed
// the macOS "phantom SIGKILL": `spawn()` returns a pid whose process is already
// gone before it ran one instruction, roughly 1 spawn in 2000 under parallel-test
// load. They are preserved here across this branch's rewrite of these functions
// onto the shared supervisor. What moved is only *where* the probe is taken —
// the supervisor now owns the spawn, so it owns the observation — not what is
// claimed or when a retry is allowed.

/// A child that really ran is not retried, even when it dies by SIGKILL having
/// written nothing to the captured streams — the case that makes replaying a
/// mutating `git notes add` dangerous.
///
/// This exercises the *real* probe, so it pins production behaviour rather than
/// the loop mechanics: the fake git records an attempt (a stand-in for committing
/// a ref), then SIGKILLs itself.
#[test]
fn a_child_that_ran_is_not_retried_even_when_sigkilled() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    let attempts = dir.path().join("attempts");
    let fake_git = dir.path().join("git");
    std::fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\nprintf x >> {a}\nkill -9 $$\n",
            a = attempts.display()
        ),
    )
    .expect("write fake git");
    let mut perms = std::fs::metadata(&fake_git).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_git, perms).expect("chmod");

    let env = synthetic_env(dir.path().to_str().expect("utf8 tempdir"));
    let err = run_git_capturing_stderr(
        dir.path(),
        ["rev-parse"],
        None,
        CaptureOutput::Discard,
        &env,
        OnBornDead::Retry,
    )
    .expect_err("a child that ran and then died must be surfaced, not retried");

    assert!(
        matches!(err, NotesRepoError::GitFailed { .. }),
        "expected GitFailed, got {err:?}"
    );
    let ran = std::fs::read(&attempts).expect("attempts marker");
    assert_eq!(
        ran.len(),
        1,
        "a child that took effect must run exactly once; retrying it could \
         double a `notes add`"
    );
}

/// The retry loop re-runs the invocation when the probe proves the child never
/// existed, and returns the successful attempt's output.
///
/// A genuinely born-dead child cannot be forged on demand — the kernel decides —
/// so the probe is supplied here, which is what `supervised_git_probed` takes it
/// as an argument for. The child still has to die by SIGKILL for the predicate to
/// fire, so this drives both halves of the conjunction.
#[test]
fn a_child_proven_never_to_have_existed_is_retried() {
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    let marker = dir.path().join("died-once-already");
    let fake_git = dir.path().join("git");
    std::fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\nif [ ! -f {m} ]; then : > {m}; kill -9 $$; fi\nprintf survived\n",
            m = marker.display()
        ),
    )
    .expect("write fake git");
    let mut perms = std::fs::metadata(&fake_git).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_git, perms).expect("chmod");

    let mut command = Command::new(&fake_git);

    // Report "vanished" on the first attempt only, mimicking the kernel having
    // discarded that child.
    let probes = Cell::new(0usize);
    let (status, stdout, _stderr) = supervised_git_probed(
        &mut command,
        GitLimits::production(),
        None,
        StdoutMode::Capture {
            byte_cap: 64 * 1024,
        },
        || vec!["rev-parse".to_string()],
        OnBornDead::Retry,
        |_pid| {
            probes.set(probes.get() + 1);
            probes.get() == 1
        },
    )
    .expect("a replay-safe command is retried on the born-dead signature");

    assert!(status.success(), "the retry must reach a live child");
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "survived",
        "the retry must return the successful attempt's output"
    );
    assert_eq!(probes.get(), 2, "exactly one retry was needed");
}

// ---------------------------------------------------------------------------
// Compaction
//
// Writ suppresses git's background auto-maintenance in the repos it owns, so
// packing loose objects is now writ's job. These tests cover the shell: that
// compaction fires only over the threshold, that it really packs, and that the
// one non-obvious property it depends on holds — a note stays readable after
// the object it is attached to has been pruned. The policy itself (parsing and
// the threshold comparison) is property-tested in `compaction::tests`.
// ---------------------------------------------------------------------------

/// Count loose objects by walking `objects/??/` directly.
///
/// Deliberately shares no code with production: if a repack is supposed to have
/// packed the objects away, the evidence should be files missing from the disk,
/// not two callers of `parse_count_objects_verbose` agreeing with each other.
fn loose_objects_on_disk(repo: &Path) -> usize {
    let mut total = 0;
    for entry in fs::read_dir(repo.join("objects")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        // `objects/pack` and `objects/info` are not fanout directories.
        if name.len() != 2 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        total += fs::read_dir(entry.path()).unwrap().count();
    }
    total
}

/// Run a raw `git` command against `repo` through exactly the command builder
/// production uses, and require it to succeed.
///
/// For invocations production deliberately never makes. `gc --prune=now` is the
/// motivating one: it is how a test reaches the state a production `gc` reaches
/// only after the two-week prune grace has elapsed.
fn raw_git(repo: &Path, args: &[&str]) -> String {
    let mut command = prepare_git_command(repo, &InheritedEnv::from_process());
    command.args(args);
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn object_exists(repo: &Path, oid: &GitObjectId) -> bool {
    let mut command = prepare_git_command(repo, &InheritedEnv::from_process());
    command.args(["cat-file", "-e", oid.as_str()]);
    command.output().unwrap().status.success()
}

fn always_compact() -> CompactionThreshold {
    CompactionThreshold::new(LooseObjectCount::new(0))
}

#[test]
fn compaction_packs_the_loose_objects_note_writes_leave_behind() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let r = notes_ref();

    // A binary body among them: the packing must not disturb the byte-exactness
    // `write_note` goes to some trouble to preserve.
    let bodies: [&[u8]; 3] = [b"first envelope", &[0x00, 0xff, 0x1b, 0x7f, 0x0a], b"third"];
    let mut written = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let seed = format!("run-{i}").into_bytes();
        written.push((repo.write_note(&r, &seed, body).unwrap(), *body));
    }

    let before = loose_objects_on_disk(repo.path());
    assert!(
        before > 0,
        "note writes should have left loose objects to pack"
    );

    let outcome = repo.compact_if_needed_with(always_compact()).unwrap();
    assert_eq!(
        outcome,
        CompactionOutcome::Compacted {
            loose_objects_before: LooseObjectCount::new(before as u64),
            // Real git with `--cruft`: the unreachable seed blobs move into a
            // cruft pack, so nothing is left loose at all.
            loose_objects_after: LooseObjectCount::new(0),
        },
        "the outcome must report the measurement that triggered it, and what it \
         achieved"
    );

    // Zero, not merely fewer: modern git moves even the *unreachable* objects
    // (writ's seed blobs) into a cruft pack rather than leaving them loose. If a
    // git version without `gc.cruftPacks` ever lands here this assertion is what
    // will say so.
    assert_eq!(
        loose_objects_on_disk(repo.path()),
        0,
        "gc should have packed every loose object away"
    );

    for (oid, body) in &written {
        assert_eq!(
            &repo.read_note(&r, oid).unwrap(),
            body,
            "every note must read back byte-exact after compaction"
        );
    }
}

#[test]
fn compaction_below_the_threshold_touches_nothing() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let r = notes_ref();
    repo.write_note(&r, b"seed", b"body").unwrap();

    let before = loose_objects_on_disk(repo.path());
    let threshold = CompactionThreshold::new(LooseObjectCount::new(before as u64 + 1));
    let outcome = repo.compact_if_needed_with(threshold).unwrap();

    assert_eq!(
        outcome,
        CompactionOutcome::Skipped {
            loose_objects: LooseObjectCount::new(before as u64)
        }
    );
    // The real assertion: the objects are still loose, so no repack ran. A
    // `Skipped` outcome that had quietly gc'd anyway would pass the check above.
    assert_eq!(
        loose_objects_on_disk(repo.path()),
        before,
        "a skipped compaction must leave the object database untouched"
    );
}

#[test]
fn the_public_entry_point_uses_gits_own_threshold() {
    // The no-argument method is the only one production calls, so something has
    // to pin that it carries the production threshold rather than, say, zero. A
    // handful of notes is far below 6700, so it must skip.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    repo.write_note(&notes_ref(), b"seed", b"body").unwrap();

    let before = loose_objects_on_disk(repo.path());
    let outcome = repo.compact_if_needed().unwrap();

    assert!(
        matches!(outcome, CompactionOutcome::Skipped { .. }),
        "a repo with a handful of objects is nowhere near git's 6700; got {outcome:?}"
    );
    assert_eq!(loose_objects_on_disk(repo.path()), before);
}

#[test]
fn compaction_is_safe_to_repeat() {
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let r = notes_ref();
    let oid = repo.write_note(&r, b"seed", b"body").unwrap();

    for round in 0..3 {
        repo.compact_if_needed_with(always_compact())
            .unwrap_or_else(|e| panic!("compaction round {round} failed: {e}"));
        assert_eq!(
            repo.read_note(&r, &oid).unwrap(),
            b"body",
            "the note must survive round {round} of compaction"
        );
    }
}

#[test]
fn notes_stay_readable_after_a_gc_prunes_the_unreachable_seed_blob() {
    // The property compaction rests on, and the one that is not obvious.
    //
    // `write_note` attaches a note to a seed blob, and git-gc(1) is explicit
    // that "a note ... attached to an object does not contribute in keeping the
    // object alive". So writ's seed blobs are unreachable, and a `gc` will
    // eventually prune them once they age past the grace period. That is fine
    // *only* because a note lookup does not need the annotated object to exist:
    // the notes tree keys entries on the OID's hex string, not on a reference to
    // it. If a future git ever makes `notes show` resolve its argument as a
    // present object, compaction would start destroying readability of the audit
    // trail, and this test is what will catch it.
    //
    // `--prune=now` is the test's way of reaching the state production reaches
    // after two weeks. Production must never pass it — see `GC_ARGV`.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let r = notes_ref();
    let body: &[u8] = &[0x00, 0x01, 0xfe, 0xff, b'\n'];
    let seed_oid = repo.write_note(&r, b"run-id-seed", body).unwrap();

    assert!(
        object_exists(repo.path(), &seed_oid),
        "precondition: the seed blob exists before pruning"
    );
    let reachable = raw_git(repo.path(), &["rev-list", "--objects", "--all"]);
    assert!(
        !reachable
            .lines()
            .any(|l| l.split_whitespace().next() == Some(seed_oid.as_str())),
        "precondition: the seed blob is unreachable, so gc is entitled to prune it"
    );

    raw_git(repo.path(), &["gc", "--prune=now", "--quiet"]);

    assert!(
        !object_exists(repo.path(), &seed_oid),
        "precondition: gc --prune=now must actually have pruned the seed blob, \
         otherwise this test proves nothing about the pruned state"
    );
    assert_eq!(
        repo.read_note(&r, &seed_oid).unwrap(),
        body,
        "a note must still read back byte-exact after its seed blob is pruned"
    );
}

/// A `git` that reports plenty of loose objects and whose `gc` behaves as told,
/// recording each `gc` attempt as one line in `attempts`.
///
/// Compaction's motivating failure — a `gc` killed at the invocation deadline —
/// cannot be provoked in a test without waiting out that deadline, and it is not
/// the interesting part anyway: the gate turns on *any* failure. So the failure
/// is faked and the thing actually asserted is how many times writ tries.
fn counting_git_env(bin: &Path, attempts: &Path, gc: FakeGc) -> InheritedEnv {
    fs::create_dir_all(bin).unwrap();
    // A gc that works shrinks the repo; one that is ineffective leaves the count
    // exactly where it was, which is the `gc.cruftPacks=false` shape.
    // What `count-objects` does. `case` rather than `[` or `test` so this stays
    // within shell builtins (see below).
    let count_objects = match gc {
        FakeGc::Succeeds => {
            r#"echo "count: $((9000 - n * 1000))"; echo "packs: 0"; exit 0"#.to_string()
        }
        FakeGc::Fails | FakeGc::SucceedsWithoutPacking => {
            r#"echo "count: 9000"; echo "packs: 0"; exit 0"#.to_string()
        }
        FakeGc::MeasurementFails => "exit 1".to_string(),
        // Succeeds until a gc has run, then fails: the post-repack measurement is
        // the one that breaks.
        FakeGc::PostMeasurementFails => {
            r#"case "$n" in 0) echo "count: 9000"; echo "packs: 0"; exit 0 ;; *) exit 1 ;; esac"#
                .to_string()
        }
    };
    let gc_exit = match gc {
        FakeGc::Fails => 128,
        FakeGc::Succeeds
        | FakeGc::SucceedsWithoutPacking
        | FakeGc::MeasurementFails
        | FakeGc::PostMeasurementFails => 0,
    };
    fake_git_env(
        bin,
        // Two constraints on this script. The subcommand is not `$1`, because
        // production passes the repo as a leading `--git-dir=` argument, so flags
        // are skipped to find it. And it may use *only* shell builtins:
        // `fake_git_env` puts nothing but its own directory on `PATH`, so `wc`
        // and friends do not resolve — a `$(wc -l ...)` here silently yields the
        // `|| echo 0` fallback on every call, which reads as "the count never
        // moved".
        &format!(
            r#"for a in "$@"; do
  case "$a" in -*) continue ;; *) sub="$a"; break ;; esac
done
n=0
while IFS= read -r _; do n=$((n + 1)); done < '{attempts}' 2>/dev/null
case "$sub" in
  count-objects) {count_objects} ;;
  gc) echo attempt >> '{attempts}'; exit {gc_exit} ;;
  *) exit 0 ;;
esac"#,
            attempts = attempts.display(),
        ),
    )
}

/// How the fake `git` should behave, named rather than passed as an exit code so
/// each test reads as the scenario it is exercising.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FakeGc {
    /// Packs the repo: the count falls by 1000 per attempt.
    Succeeds,
    /// Refuses, as a real `gc` does when `gc.pid` names a live process.
    Fails,
    /// Returns success and packs nothing — the shape a repo takes when
    /// `gc.cruftPacks=false` keeps young unreachable objects loose.
    SucceedsWithoutPacking,
    /// `count-objects` itself fails, so compaction cannot even measure.
    MeasurementFails,
    /// The repack succeeds and the measurement that checks whether it helped
    /// fails — the one failure path that is not on the way *in*.
    PostMeasurementFails,
}

fn attempt_count(attempts: &Path) -> usize {
    fs::read_to_string(attempts).map_or(0, |s| s.lines().count())
}

/// Point a second handle at an existing repo through a different `git`.
///
/// The compaction gate is per-repo, keyed on the canonical path exactly as the
/// notes-write mutex is, so a handle built this way shares the real repo's gate.
fn handle_with_env(repo: &NotesRepo, env: InheritedEnv) -> NotesRepo {
    NotesRepo {
        canonical_path: repo.path().to_path_buf(),
        inherited_env: env,
    }
}

#[test]
fn a_failed_compaction_is_not_retried_by_the_very_next_note_write() {
    // Compaction runs on the request path, so a failure that repeats every
    // request is a permanent tax on every agent run — and the worst case is
    // self-sustaining: a `gc` killed at the deadline publishes nothing, so the
    // loose count is still above the threshold and the next request pays the
    // deadline again, forever, without ever compacting. That is strictly worse
    // than never compacting, which is what writ did before.
    //
    // So a failure must buy a pause. What is asserted is the number of attempts,
    // not the outcome type alone: an implementation that returned `Deferred`
    // while still shelling out to `gc` would satisfy the weaker check and none of
    // the intent.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let attempts = tmp.path().join("gc-attempts");
    let failing = handle_with_env(
        &repo,
        counting_git_env(&tmp.path().join("bin"), &attempts, FakeGc::Fails),
    );

    failing
        .compact_if_needed_with(always_compact())
        .expect_err("the fake gc exits non-zero, so the first attempt must fail");
    assert_eq!(attempt_count(&attempts), 1, "the first attempt must run gc");

    let second = failing
        .compact_if_needed_with(always_compact())
        .expect("a deferred compaction is not an error: the note write succeeded");
    assert!(
        matches!(second, CompactionOutcome::Deferred { .. }),
        "a compaction that failed moments ago must be deferred, not retried; got {second:?}"
    );
    assert_eq!(
        attempt_count(&attempts),
        1,
        "the second write must not spawn gc again — that repeat is the whole cost \
         being bounded here"
    );
}

#[test]
fn a_successful_compaction_leaves_the_gate_open_for_the_next_one() {
    // The mirror of the test above, and the reason the gate cannot simply be
    // "compact once per hour": a repo that is successfully packing must go on
    // packing at whatever rate its loose-object count demands.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let attempts = tmp.path().join("gc-attempts");
    let succeeding = handle_with_env(
        &repo,
        counting_git_env(&tmp.path().join("bin"), &attempts, FakeGc::Succeeds),
    );

    for round in 1..=3 {
        let outcome = succeeding
            .compact_if_needed_with(always_compact())
            .expect("the fake gc succeeds");
        assert!(
            matches!(outcome, CompactionOutcome::Compacted { .. }),
            "round {round} must compact; got {outcome:?}"
        );
        assert_eq!(
            attempt_count(&attempts),
            round,
            "every round above the threshold must run gc"
        );
    }
}

#[test]
fn a_measurement_that_fails_also_buys_a_pause() {
    // The gate has to sit in front of `count-objects`, not just in front of `gc`.
    // Measuring is itself a git invocation against the object directory, and a
    // slow or damaged one can hold it to the full deadline — so a gate consulted
    // only after a successful measurement leaves precisely the per-request cost
    // it exists to remove.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let attempts = tmp.path().join("gc-attempts");
    let broken = handle_with_env(
        &repo,
        counting_git_env(&tmp.path().join("bin"), &attempts, FakeGc::MeasurementFails),
    );

    broken
        .compact_if_needed_with(always_compact())
        .expect_err("count-objects exits non-zero, so the measurement must fail");

    let second = broken
        .compact_if_needed_with(always_compact())
        .expect("the pause is not an error");
    assert!(
        matches!(second, CompactionOutcome::Deferred { .. }),
        "a failed measurement must close the gate just as a failed gc does; got {second:?}"
    );
}

#[test]
fn a_failure_after_the_repack_buys_a_pause_like_any_other() {
    // The failure path that is not on the way in: the repack ran, and the
    // measurement checking whether it helped is the thing that fails. Nothing
    // about it makes repeating it cheaper — it is the same object directory, and
    // the loose count is still over the threshold, so an ungated return means the
    // next request measures *and* repacks again.
    //
    // This is the third distinct exit that has to record the same fact, which is
    // why the recording no longer lives at the exits at all: the attempt cannot
    // touch the gate, and its caller writes it in exactly one place.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let attempts = tmp.path().join("gc-attempts");
    let broken = handle_with_env(
        &repo,
        counting_git_env(
            &tmp.path().join("bin"),
            &attempts,
            FakeGc::PostMeasurementFails,
        ),
    );

    broken
        .compact_if_needed_with(always_compact())
        .expect_err("the measurement after the repack fails");
    assert_eq!(attempt_count(&attempts), 1, "the repack itself did run");

    let second = broken
        .compact_if_needed_with(always_compact())
        .expect("the pause is not an error");
    assert!(
        matches!(second, CompactionOutcome::Deferred { .. }),
        "a failure after the repack must close the gate too; got {second:?}"
    );
    assert_eq!(
        attempt_count(&attempts),
        1,
        "and must not let the next write run another full repack"
    );
}

#[test]
fn a_gc_that_packs_nothing_does_not_run_again_on_the_next_write() {
    // Succeeding and achieving something are different. Measured on git 2.54:
    // with `gc.cruftPacks=false`, a `gc` returns zero and leaves young
    // unreachable objects — writ's seed blobs are exactly that — loose, so the
    // count does not move. `GC_ARGV` imposes `--cruft` against that specific
    // cause, but since success is what leaves the gate open, an ineffective
    // repack would otherwise run a full `gc` on every request forever, for any
    // cause at all. So progress is checked rather than assumed.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let attempts = tmp.path().join("gc-attempts");
    let ineffective = handle_with_env(
        &repo,
        counting_git_env(
            &tmp.path().join("bin"),
            &attempts,
            FakeGc::SucceedsWithoutPacking,
        ),
    );

    let first = ineffective
        .compact_if_needed_with(always_compact())
        .expect("the fake gc exits zero, so the call succeeds");
    assert_eq!(
        first,
        CompactionOutcome::Compacted {
            loose_objects_before: LooseObjectCount::new(9000),
            loose_objects_after: LooseObjectCount::new(9000),
        },
        "the outcome must report both counts, so 'ran' and 'helped' stay distinguishable"
    );
    assert_eq!(attempt_count(&attempts), 1);

    let second = ineffective
        .compact_if_needed_with(always_compact())
        .expect("the pause is not an error");
    assert!(
        matches!(second, CompactionOutcome::Deferred { .. }),
        "a gc that moved nothing must not be repeated immediately; got {second:?}"
    );
    assert_eq!(
        attempt_count(&attempts),
        1,
        "the second write must not spawn another full repack"
    );
}

#[test]
fn compaction_holds_the_prune_grace_open_against_the_repos_own_config() {
    // The concurrency argument on `compact_if_needed` rests on the prune grace:
    // an object written by another process but not yet referenced survives
    // because its mtime is newer than the prune date. That grace is git's
    // *default*, and a default is not a guarantee.
    //
    // Repo-local config outlives the hardened recipe by design —
    // `GIT_CONFIG_NOSYSTEM` and `GIT_CONFIG_GLOBAL=/dev/null` silence the system
    // and global files, and nothing silences `<repo>/config`. Measured on git
    // 2.54: with `gc.pruneExpire=now` set there, a plain `gc` prunes a
    // freshly-written unreferenced object immediately, and the grace writ
    // documents is simply gone. So writ imposes the date on the command line,
    // where it overrides the config, rather than inheriting it.
    let tmp = TempDir::new().unwrap();
    let repo = NotesRepo::init_or_open(tmp.path().join("r")).unwrap();
    let r = notes_ref();

    raw_git(repo.path(), &["config", "gc.pruneExpire", "now"]);

    // A seed blob is exactly the object at risk: freshly written, and unreachable
    // (git-gc(1): a note does not keep its annotated object alive). It stands in
    // for the blob a concurrent writer has written but not yet referenced.
    let seed = repo.write_note(&r, b"run-id-seed", b"envelope").unwrap();
    assert!(
        object_exists(repo.path(), &seed),
        "precondition: the seed blob exists before compaction"
    );
    let reachable = raw_git(repo.path(), &["rev-list", "--objects", "--all"]);
    assert!(
        !reachable
            .lines()
            .any(|l| l.split_whitespace().next() == Some(seed.as_str())),
        "precondition: the seed blob is unreachable, so only the grace protects it"
    );

    repo.compact_if_needed_with(always_compact()).unwrap();

    assert!(
        object_exists(repo.path(), &seed),
        "a freshly-written unreferenced object must survive compaction even when \
         the repo's own config says to prune immediately; otherwise the grace \
         period `compact_if_needed` documents is not something writ actually has"
    );
}

#[test]
fn the_compaction_argv_carries_no_pruning_aggression_or_lock_override() {
    // Pinned exactly, so widening it is a deliberate edit to a test that says
    // why each flag is present or absent. See `GC_ARGV` for the reasoning.
    assert_eq!(GC_ARGV, ["gc", "--quiet", "--prune=2.weeks.ago", "--cruft"]);

    // Both imposed settings are here because a repo-local config value can
    // otherwise break a guarantee this policy states: the grace that protects a
    // concurrent writer, and the cruft packing without which a successful `gc`
    // can leave the count exactly where it was.
    assert!(
        GC_ARGV.contains(&"--cruft"),
        "compaction must impose cruft packing: with gc.cruftPacks=false a gc \
         succeeds while packing none of writ's young unreachable seed blobs"
    );

    assert_eq!(
        GC_ARGV[0], "gc",
        "must be `gc`, not `maintenance`: only `gc` takes the gc.pid lock"
    );

    // An earlier version of this test forbade `--prune` outright, on the
    // reasoning that git's default grace was already what writ wanted. That was
    // the bug: the default is overridable from `<repo>/config`, so inheriting it
    // means writ's documented grace can be moved by a file writ does not write.
    // What must hold is not "no prune flag" but "a prune date that is not now".
    let prune: Vec<&&str> = GC_ARGV
        .iter()
        .filter(|a| a.starts_with("--prune"))
        .collect();
    assert_eq!(
        prune.len(),
        1,
        "exactly one prune date must be imposed, so there is no last-one-wins \
         ambiguity about which grace applies"
    );
    assert_eq!(
        *prune[0], GC_PRUNE_GRACE,
        "the imposed date must be git's own default, spelled out"
    );
    for immediate in ["--prune=now", "--prune=all", "--prune=0"] {
        assert_ne!(
            *prune[0], immediate,
            "compaction must never prune immediately: the grace is writ's only \
             concurrent-writer mitigation in a bare repo"
        );
    }

    for forbidden in ["--aggressive", "--force", "--detach", "gc.pruneExpire"] {
        assert!(
            !GC_ARGV.iter().any(|arg| arg.contains(forbidden)),
            "compaction must never pass {forbidden}"
        );
    }
}
