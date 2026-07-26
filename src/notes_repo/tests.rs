//! Tests for the shared bare-repo notes wrapper (ref writes, fetch, atomic update). Split out of `notes_repo.rs` (an inline `#[cfg(test)]` module); tests unchanged.

use super::*;
use std::ffi::OsStr;
use std::fs;
use tempfile::TempDir;

fn notes_ref() -> NotesRef {
    NotesRef::try_new("refs/notes/writ/v1/agent-outputs").unwrap()
}

#[test]
fn spawn_is_retryable_only_for_transient_resource_errors() {
    // EAGAIN is the failure confirmed under parallel-test fork
    // pressure (RLIMIT_NPROC); ENOMEM / EMFILE / ENFILE are the same
    // all-or-nothing "spawn refused" class.
    for errno in [libc::EAGAIN, libc::ENOMEM, libc::EMFILE, libc::ENFILE] {
        assert!(
            spawn_is_retryable(&io::Error::from_raw_os_error(errno)),
            "errno {errno} should be retryable",
        );
    }
    // Permanent failures must fail fast, not spin on a retry.
    for errno in [libc::ENOENT, libc::EACCES] {
        assert!(
            !spawn_is_retryable(&io::Error::from_raw_os_error(errno)),
            "errno {errno} must not be retryable",
        );
    }
    // An error with no OS errno (e.g. a synthetic kind) is permanent.
    assert!(!spawn_is_retryable(&io::Error::from(
        io::ErrorKind::NotFound
    )));
}

#[test]
fn spawn_with_retry_succeeds_after_transient_failures() {
    let mut attempts = 0u32;
    let got = spawn_with_retry(Duration::from_secs(5), || {
        attempts += 1;
        if attempts < 3 {
            Err(io::Error::from_raw_os_error(libc::EAGAIN))
        } else {
            Ok("spawned")
        }
    });
    assert_eq!(got.unwrap(), "spawned");
    assert_eq!(attempts, 3, "should retry twice, then succeed on the third");
}

#[test]
fn spawn_with_retry_gives_up_after_the_deadline_on_persistent_transient() {
    let mut attempts = 0u32;
    let started = Instant::now();
    let got: io::Result<()> = spawn_with_retry(Duration::from_millis(20), || {
        attempts += 1;
        Err(io::Error::from_raw_os_error(libc::EAGAIN))
    });
    // Bounded by time, not a fixed count: it gives up once the deadline
    // elapses, having retried more than once.
    assert_eq!(got.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert!(attempts > 1, "should retry at least once before giving up");
    assert!(
        started.elapsed() >= Duration::from_millis(20),
        "should not give up before the deadline"
    );
}

#[test]
fn spawn_with_retry_does_not_retry_permanent_errors() {
    let mut attempts = 0u32;
    let got: io::Result<()> = spawn_with_retry(Duration::from_secs(5), || {
        attempts += 1;
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    });
    assert!(got.is_err());
    assert_eq!(attempts, 1, "a permanent error must not be retried");
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
//   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`,
//   `GIT_CONFIG_COUNT=0`) is unconditionally set on the child —
//   so a host-wide `GIT_CONFIG_GLOBAL` pointing at a poisoned
//   file, `init.defaultObjectFormat = sha256` in `~/.gitconfig`,
//   `safe.bareRepository = explicit`, etc. cannot reach git.
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

/// The born-dead predicate is a proof, not a heuristic: it fires only when the
/// proof-of-life probe found no process at all AND the child died by SIGKILL.
///
/// The negative cases are the important ones. A child that ran and was killed
/// (probe found it alive) must never be retried, and neither must a clean
/// exit. The earlier formulation of this predicate keyed on empty
/// stdout/stderr instead, which is unsound: `CaptureOutput::Discard` makes
/// stdout empty by construction, so a `notes add` killed *after* committing
/// its ref would have been replayed.
#[test]
fn only_a_child_that_never_existed_counts_as_having_run_nothing() {
    let sigkilled = ExitStatus::from_raw(9);
    let clean_exit = ExitStatus::from_raw(0);

    assert!(
        child_ran_nothing(true, &sigkilled),
        "vanished before running and SIGKILLed: the flake, safe to re-run"
    );
    assert!(
        !child_ran_nothing(false, &sigkilled),
        "a child the probe found ALIVE ran, and must not be re-run even though \
         it died by the same signal"
    );
    assert!(
        !child_ran_nothing(true, &clean_exit),
        "a clean exit is not the flake, whatever the probe saw"
    );
    assert!(
        !child_ran_nothing(false, &clean_exit),
        "an ordinary successful child is never retried"
    );
}

/// A child that really ran is not retried, even when it dies by SIGKILL having
/// written nothing to the captured streams — the case that makes replaying a
/// mutating `git notes add` dangerous.
///
/// This exercises the *real* probe, so it pins the production behaviour rather
/// than the loop mechanics: the fake git records an attempt (a stand-in for
/// committing a ref), then SIGKILLs itself.
#[test]
fn a_child_that_ran_is_not_retried_even_when_sigkilled() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
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
/// A genuinely born-dead child cannot be forged on demand — the kernel decides
/// — so the probe is supplied here, which is what `run_git_child_probed` takes
/// it as an argument for. The child still has to die by SIGKILL for the
/// predicate to fire, so this drives both halves of the conjunction.
#[test]
fn a_child_proven_never_to_have_existed_is_retried() {
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
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
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    // Report "vanished" on the first attempt only, mimicking the kernel having
    // discarded that child.
    let probes = Cell::new(0usize);
    let output = run_git_child_probed(&mut command, None, |_pid| {
        probes.set(probes.get() + 1);
        probes.get() == 1
    })
    .expect("a child proven never to have run is retried");

    assert!(output.status.success(), "the retry must reach a live child");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "survived",
        "the retry must return the successful attempt's output"
    );
    assert_eq!(probes.get(), 2, "exactly one retry was needed");
}
