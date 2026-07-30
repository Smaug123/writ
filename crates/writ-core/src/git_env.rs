//! The one hardened Git environment recipe, shared by every crate.
//!
//! Shelling out to `git` against untrusted input is only safe if git cannot
//! discover configuration the caller did not choose. That means denying *every*
//! config source at once: an override covering all but one still lets that one
//! through, and the resulting hole is invisible at the call site because the code
//! there looks careful.
//!
//! This module exists because that is exactly what happened, in two distinct
//! ways. First, the recipe was written out longhand at eight call sites and they
//! drifted: one used `GIT_CONFIG_SYSTEM=/dev/null` where the others used
//! `GIT_CONFIG_NOSYSTEM=1`, and three omitted `GIT_CONFIG_COUNT=0`. Second, the
//! recipe was *documented* as covering `GIT_CONFIG_PARAMETERS` via
//! `GIT_CONFIG_COUNT=0`, and it did not; see that entry below. Nothing about
//! either mistake read as wrong.
//!
//! Scope of that second mistake, precisely: every *production* caller
//! (`clean_git`, `notes_repo`, `git_push_objects_cat_file`, `flake_provision`)
//! also calls `env_clear`, which removes `GIT_CONFIG_PARAMETERS` whether or not
//! the recipe names it, so none of them was ever exposed. What was exposed was
//! the test helpers, which layer the recipe over an inherited environment — so a
//! developer or CI machine with `GIT_CONFIG_PARAMETERS` set could have had it
//! reach the test gits. Naming the variable here therefore fixes real test
//! hermeticity and is defence in depth for production, rather than closing a live
//! hole in the broker. The recipe should be sufficient on its own regardless:
//! "it happens to be safe because every current caller also does something else"
//! is not a property worth relying on.
//!
//! It lives in `writ-core` rather than beside its main consumer so that the host
//! daemon, the guest client, and every crate's test helpers can all derive from
//! the same constant. A recipe that some crates cannot reach is a recipe those
//! crates will re-type.
//!
//! Being *reachable* turned out not to be the same as being *reached*. When this
//! module was introduced, the sentence above described the guest client as a
//! consumer while `writ-vm-client`'s four git runners applied no recipe at all —
//! and every duplication guard passed, because none of them asks whether a given
//! git spawn is hardened; they ask whether the recipe is spelled out twice. That
//! is what `a_git_named_helper_must_apply_the_recipe_to_its_own_command` in
//! `tests/shared_hardening_helpers.rs` now checks, and its doc comment is honest
//! about remaining a backstop: the durable form of this invariant is a
//! construction boundary, where a runnable git `Command` cannot be obtained
//! without the recipe having been applied.
//!
//! ## What each variable denies
//!
//! * `GIT_CONFIG_NOSYSTEM=1` — `/etc/gitconfig`. Preferred over
//!   `GIT_CONFIG_SYSTEM=/dev/null`: it is a categorical refusal rather than a
//!   redirect, so it cannot be defeated by a path that becomes readable.
//! * `GIT_CONFIG_GLOBAL=/dev/null` — `~/.gitconfig` and
//!   `$XDG_CONFIG_HOME/git/config`.
//! * `GIT_CONFIG_COUNT` — bounds the numbered `GIT_CONFIG_KEY_<n>` /
//!   `GIT_CONFIG_VALUE_<n>` pairs: git reads slots `0..count` and ignores the
//!   rest. `0` in [`GIT_CONFIG_DENY_ENV`], which denies the channel outright and
//!   is easy to forget precisely because it looks like a no-op.
//!   [`CLEAN_GIT_CONFIG_ENV`] instead sets the count to the number of pairs *it*
//!   fills, which denies inherited pairs just as completely — an inherited slot
//!   below the count is overwritten, and one at or above it is out of range. See
//!   "What the clean recipe imposes" below.
//! * `GIT_CONFIG_PARAMETERS=` (empty) — the *separate* channel git uses
//!   internally to propagate `-c` overrides to subprocesses. Git parses it
//!   independently of `GIT_CONFIG_COUNT`, so zeroing the count does **not**
//!   neutralise it: with `GIT_CONFIG_COUNT=0` set, an inherited
//!   `GIT_CONFIG_PARAMETERS="'core.pager=INJECTED'"` still reaches git
//!   (verified against git 2.x). A comment in this codebase claimed otherwise
//!   for some time, which is exactly why it is now a listed entry rather than
//!   an assumption. Empty parses as "no parameters"; unsetting would also work,
//!   but an explicit empty value survives being merged into an env a caller
//!   builds up in any order.
//!
//! And one variable that must be *removed* rather than set
//! ([`GIT_CONFIG_REMOVE_ENV`]):
//!
//! * `GIT_CONFIG` — `git config` treats this as `--file`, so it overrides the
//!   whole recipe for exactly the command writ uses to *validate* a repo
//!   (`core.bare`, `extensions.objectformat`). None of the settings above
//!   neutralises it. It cannot be handled by setting a value: `GIT_CONFIG=/dev/null`
//!   makes `git config <name> <value>` fail to lock and silently lose the write,
//!   which is worse than the disease. It also cannot be expressed as a
//!   `(name, value)` pair at all — which is why [`apply_clean_git_config`] and its
//!   siblings, not the constants, are the sanctioned way to apply the recipe.
//!   (Scope, measured on git 2.54: `GIT_CONFIG` affects `git config` only — a
//!   non-config command ignores it — and with an explicit selector like `--local`
//!   git errors rather than silently reading the wrong file.)
//!
//! * `HOME=/dev/null` — dotfiles that helpers read regardless of the
//!   `GIT_CONFIG_*` overrides: credential helpers, hook scripts, and anything
//!   invoked via `core.editor` / `pre-receive`. Only in
//!   [`CLEAN_GIT_CONFIG_ENV`], because a caller that needs a real `HOME` (nix
//!   fetching a flake input) must still get the config denials.
//!
//! ## What the clean recipe *imposes*: no background maintenance
//!
//! Everything above denies configuration. [`GIT_IMPOSED_CONFIG`] asserts some,
//! and it is in [`CLEAN_GIT_CONFIG_ENV`] only:
//!
//! * `maintenance.auto=false` — stops `git maintenance run --auto --quiet
//!   --detach`, a process that outlives the command that spawned it and keeps
//!   writing to `objects/`.
//! * `gc.auto=0` — the older `git gc --auto` path. Measured on git 2.54 this is
//!   *not* what suppresses the spawn: `maintenance.auto=false` alone takes it to
//!   zero and `gc.auto=0` alone leaves it at one. It is kept for older git and
//!   for a direct `git gc --auto`, not because it is load-bearing here.
//!
//! writd runs git against repositories it owns and then reasons about what is in
//! them — object graphs, ancestry, which refs exist. A detached process
//! rewriting the store underneath that reasoning is exactly the nonlocal effect
//! this codebase rejects, and it is not hypothetical: it produced a CI failure
//! where `clone_local` enumerated `objects/pack/`, saw maintenance's transient
//! `.tmp-<pid>-pack-*.idx`, and got ENOENT when it opened it a moment later. The
//! pid in that filename belonged to neither the test nor its clone.
//!
//! `git fetch` is the whole live blast radius, which is worth knowing precisely
//! because it is smaller than it sounds. Measured on git 2.54, `fetch` spawns
//! maintenance and `notes add`, `hash-object -w` and `bundle unbundle` do not —
//! so of writd's own commands it is the notes-repo fetch and the push staging
//! store's fetch that were leaving a second writer behind. (`git commit` spawns
//! it too, which is what the fixtures hit.)
//!
//! **This does not remove writ's ability to compact.** The `*.auto` knobs gate
//! only the *uninvited* run: an explicit `git gc` still packs (verified — 90
//! loose objects to 0 under this recipe), as does `git maintenance run
//! --task=gc`. What the recipe buys is that compaction happens when writ says
//! so, not concurrently with a read writ is midway through. Deciding *when* writ
//! says so is a separate, still-open question; until it is answered these repos
//! accumulate loose objects, which is a disk cost rather than a correctness one.
//!
//! ### Why the denial set does not impose this
//!
//! [`GIT_CONFIG_DENY_ENV`]'s callers are nix fetching a flake input (git
//! operating on *nix's* caches) and the guest's own git inside the agent VM.
//! Suppressing auto-maintenance there would make writ responsible for compacting
//! directories it does not own, in the nix case, and would be pointless in the
//! guest case, where the whole filesystem dies with the VM. The denial set keeps
//! `GIT_CONFIG_COUNT=0`.
//!
//! ### What this mechanism cannot reach
//!
//! `git push` to a local path **strips `GIT_CONFIG_COUNT`** from the environment
//! it hands `receive-pack` (it is in git's `local_repo_env`, so config does not
//! leak across a repository boundary). The `GIT_CONFIG_KEY_<n>` variables
//! survive, but with no count git reads none of them, so `receive-pack` runs
//! with `maintenance.auto` unset and spawns maintenance in the destination
//! repository. Passing `-c` on the pushing command does not help either, for the
//! same reason. Verified directly, via a `--receive-pack` wrapper that dumped
//! what the child saw.
//!
//! Nothing in writd pushes into a repository it owns, so this is not a live hole
//! — but it is the kind of gap that reads as covered. A future path that does
//! would have to set the config *in the destination repository* instead.

/// The `GIT_CONFIG_*` overrides that deny git every configuration source.
///
/// Use this when the caller supplies its own `HOME` for another reason; use
/// [`CLEAN_GIT_CONFIG_ENV`] otherwise. Never use a subset.
pub const GIT_CONFIG_DENY_ENV: [(&str, &str); 4] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("GIT_CONFIG_PARAMETERS", ""),
];

/// Git config settings the clean recipe *imposes*, as `(name, value)` config
/// pairs rather than environment variables.
///
/// Different in kind from everything else in this module: the rest of the recipe
/// denies configuration, and this asserts some. See the module docs for what
/// writd is buying and what it is taking on.
pub const GIT_IMPOSED_CONFIG: [(&str, &str); 2] = [("maintenance.auto", "false"), ("gc.auto", "0")];

/// Variables the recipe must *remove* rather than set. See the module docs for
/// why `GIT_CONFIG` cannot be neutralised with a value.
///
/// Because this exists, the constants alone are never the whole recipe. Prefer
/// [`apply_clean_git_config`] / [`apply_git_config_denials`].
pub const GIT_CONFIG_REMOVE_ENV: [&str; 1] = ["GIT_CONFIG"];

/// [`GIT_CONFIG_DENY_ENV`] plus `HOME=/dev/null` plus [`GIT_IMPOSED_CONFIG`]:
/// the full recipe for a caller operating on a repository writd owns.
///
/// Note `GIT_CONFIG_COUNT` is **not** `0` here, which is the one place this
/// recipe reads differently from the denial set. The numbered channel is how the
/// imposed settings are delivered, and the count is what makes an *inherited*
/// numbered pair unreachable: git reads slots `0..count`, and every slot below
/// the count is filled below. Keep them in step — `git_env`'s tests fail if the
/// count and the pairs ever disagree.
pub const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 9] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "2"),
    ("GIT_CONFIG_PARAMETERS", ""),
    ("HOME", "/dev/null"),
    ("GIT_CONFIG_KEY_0", "maintenance.auto"),
    ("GIT_CONFIG_VALUE_0", "false"),
    ("GIT_CONFIG_KEY_1", "gc.auto"),
    ("GIT_CONFIG_VALUE_1", "0"),
];

/// Apply the full hardened recipe to `command`: set [`CLEAN_GIT_CONFIG_ENV`] and
/// remove [`GIT_CONFIG_REMOVE_ENV`].
///
/// **Use this rather than `.envs(CLEAN_GIT_CONFIG_ENV)`.** The recipe is not just
/// a set of values — `GIT_CONFIG` has to be *removed* — so applying the constant
/// alone leaves a hole that looks nothing like a hole at the call site.
/// `tests/shared_hardening_helpers.rs` enforces this: using the constants outside
/// this module fails that guard.
///
/// Returns `command` so it drops into a builder chain:
/// `apply_clean_git_config(&mut Command::new(git)).args(args).output()`.
///
/// Note this *adds* the overrides; it does not clear the inherited environment.
/// A caller that must also strip inherited `GIT_DIR` / `GIT_WORK_TREE` /
/// `GIT_OBJECT_DIRECTORY` has to call `env_clear` itself and re-add whatever it
/// genuinely needs (typically just `PATH`) — the two concerns are separate, and
/// conflating them here would silently break callers that rely on inheritance.
/// A caller that does `env_clear` gets the removal for free but should still call
/// this, so the recipe stays correct if the `env_clear` is ever dropped.
pub fn apply_clean_git_config(command: &mut std::process::Command) -> &mut std::process::Command {
    for (name, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(name, value);
    }
    for name in GIT_CONFIG_REMOVE_ENV {
        command.env_remove(name);
    }
    command
}

/// [`apply_clean_git_config`] for a tokio command.
#[cfg(feature = "host")]
pub fn apply_clean_git_config_async(
    command: &mut tokio::process::Command,
) -> &mut tokio::process::Command {
    for (name, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(name, value);
    }
    for name in GIT_CONFIG_REMOVE_ENV {
        command.env_remove(name);
    }
    command
}

/// The config *denials* only, for a caller that supplies its own `HOME` (nix
/// fetching a flake input needs a writable one). Still removes `GIT_CONFIG`.
///
/// Note the difference from [`apply_clean_git_config`] is not only `HOME`: this
/// also imposes nothing, so a caller using it gets no auto-maintenance
/// suppression and its git *may* leave a detached background writer in whatever
/// repository it touches. That is deliberate for the two callers this has — nix's
/// own caches and the guest's git inside the VM, neither of which writd should
/// take over compacting — and wrong for anything operating on a repository writd
/// owns. See the module docs.
pub fn apply_git_config_denials(command: &mut std::process::Command) -> &mut std::process::Command {
    for (name, value) in GIT_CONFIG_DENY_ENV {
        command.env(name, value);
    }
    for name in GIT_CONFIG_REMOVE_ENV {
        command.env_remove(name);
    }
    command
}

/// [`apply_git_config_denials`] for a tokio command.
#[cfg(feature = "host")]
pub fn apply_git_config_denials_async(
    command: &mut tokio::process::Command,
) -> &mut tokio::process::Command {
    for (name, value) in GIT_CONFIG_DENY_ENV {
        command.env(name, value);
    }
    for name in GIT_CONFIG_REMOVE_ENV {
        command.env_remove(name);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate `git` on `PATH`, or `None` where there is none — the tests that
    /// ask real git a question skip rather than fail so the suite stays
    /// portable.
    fn git_on_path() -> Option<std::path::PathBuf> {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("git"))
                .find(|candidate| candidate.is_file())
        })
    }

    /// A scratch directory named after the test that owns it, so parallel tests
    /// in this module cannot collide on one pid-derived name.
    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("writ-git-env-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Look a name up in the clean recipe.
    fn clean(name: &str) -> Option<&'static str> {
        CLEAN_GIT_CONFIG_ENV
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| *value)
    }

    /// The clean recipe is the denial set, plus `HOME`, plus the imposed
    /// config — and the only entry it is allowed to disagree with the denial
    /// set about is `GIT_CONFIG_COUNT`, which is the imposition's own channel.
    ///
    /// Written as a test rather than a const expression because the array
    /// lengths are part of the public shape: if someone adds a variable to one
    /// constant and forgets the other, the divergence this module exists to
    /// prevent reappears inside the module itself.
    #[test]
    fn clean_recipe_is_the_denial_set_plus_home_and_the_imposed_config() {
        for (name, value) in GIT_CONFIG_DENY_ENV {
            if name == "GIT_CONFIG_COUNT" {
                continue;
            }
            assert_eq!(
                clean(name),
                Some(value),
                "the clean recipe must carry every denial unchanged; {name} differs"
            );
        }
        assert_eq!(clean("HOME"), Some("/dev/null"));
        // Everything else must be accounted for by the imposition's channel, so
        // a variable smuggled into one constant and not the other is caught.
        let accounted: usize = GIT_CONFIG_DENY_ENV.len() + 1 + 2 * GIT_IMPOSED_CONFIG.len();
        assert_eq!(
            CLEAN_GIT_CONFIG_ENV.len(),
            accounted,
            "the clean recipe is the denials, HOME, and one key/value pair per \
             imposed setting — nothing else: {CLEAN_GIT_CONFIG_ENV:?}"
        );
    }

    /// `GIT_CONFIG_COUNT` is the recipe's only *load-bearing* number: git reads
    /// `GIT_CONFIG_KEY_<n>` for `n` in `0..count`, so an inherited pair is
    /// unreachable exactly when the recipe itself fills every slot below the
    /// count.
    ///
    /// That is the property that lets the clean recipe use the numbered channel
    /// to *impose* config while the denial set still uses `count=0` to refuse
    /// it. Get the count wrong by one and the recipe either drops a setting it
    /// believes it made or reads a slot an attacker filled — neither of which
    /// looks wrong at a call site.
    #[test]
    fn the_imposed_config_fills_exactly_the_slots_the_count_declares() {
        assert_eq!(
            clean("GIT_CONFIG_COUNT"),
            Some(GIT_IMPOSED_CONFIG.len().to_string().as_str()),
            "the count must equal the number of imposed settings"
        );
        for (index, (name, value)) in GIT_IMPOSED_CONFIG.iter().enumerate() {
            assert_eq!(
                clean(&format!("GIT_CONFIG_KEY_{index}")),
                Some(*name),
                "slot {index} must name the imposed setting"
            );
            assert_eq!(
                clean(&format!("GIT_CONFIG_VALUE_{index}")),
                Some(*value),
                "slot {index} must carry the imposed value"
            );
        }
        // No stray slot at or above the count: it would be silently ignored by
        // git, so the recipe would claim a setting it never makes.
        let beyond = GIT_IMPOSED_CONFIG.len();
        assert_eq!(clean(&format!("GIT_CONFIG_KEY_{beyond}")), None);
        assert_eq!(clean(&format!("GIT_CONFIG_VALUE_{beyond}")), None);
        // The denial set imposes nothing, so it must keep the refusing count.
        assert!(
            GIT_CONFIG_DENY_ENV.contains(&("GIT_CONFIG_COUNT", "0")),
            "the denial set must keep count=0; it imposes no config of its own"
        );
    }

    /// The imposition actually stops the detached writer, asked of real git
    /// rather than derived from the documentation.
    ///
    /// `git fetch` is the reason this matters: it is the one command writd runs
    /// against its own repositories (the notes repo and the push staging store)
    /// that spawns `git maintenance run --auto --quiet --detach`, a process
    /// that outlives the fetch and keeps writing to `objects/`. Measured on git
    /// 2.54: one spawn without the imposition, zero with it — and `notes add`,
    /// `hash-object -w` and `bundle unbundle` spawn none either way, so `fetch`
    /// is the whole live blast radius.
    #[test]
    fn the_recipe_stops_git_fetch_spawning_detached_maintenance() {
        let Some(git) = git_on_path() else {
            eprintln!("skipping: no `git` on PATH");
            return;
        };
        let dir = scratch("no-detached-maintenance");
        let source = dir.join("source.git");
        let destination = dir.join("destination.git");

        // Built with plumbing only (`hash-object`, `commit-tree`,
        // `update-ref`), none of which runs auto-maintenance. The setup
        // therefore cannot itself leave a detached child racing the assertion
        // — which matters when this test is run with the imposition reverted,
        // to check it fails for the stated reason.
        let run = |args: &[&std::ffi::OsStr], stdin: &'static str| -> String {
            let mut command = std::process::Command::new(&git);
            apply_clean_git_config(&mut command);
            command
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .env("GIT_AUTHOR_DATE", "1700000000 +0000")
                .env("GIT_COMMITTER_DATE", "1700000000 +0000")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            let mut child = command.spawn().expect("git must be spawnable");
            {
                use std::io::Write;
                let mut sink = child.stdin.take().expect("piped stdin");
                sink.write_all(stdin.as_bytes()).expect("write stdin");
            }
            let out = child.wait_with_output().expect("git must complete");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let os = std::ffi::OsStr::new;
        for repo in [&source, &destination] {
            run(&[os("init"), os("-q"), os("--bare"), repo.as_os_str()], "");
        }
        let git_dir = format!("--git-dir={}", source.display());
        let tree = run(
            &[
                os(&git_dir),
                os("hash-object"),
                os("-t"),
                os("tree"),
                os("-w"),
                os("--stdin"),
            ],
            "",
        );
        let commit = run(
            &[
                os(&git_dir),
                os("commit-tree"),
                os(&tree),
                os("-m"),
                os("c"),
            ],
            "",
        );
        run(
            &[
                os(&git_dir),
                os("update-ref"),
                os("refs/heads/main"),
                os(&commit),
            ],
            "",
        );

        // `GIT_TRACE` names every child git spawns, so the detached
        // maintenance process is visible whether or not it goes on to do work
        // — which is the point: the hazard is the second writer existing, not
        // it deciding to repack.
        let mut fetch = std::process::Command::new(&git);
        apply_clean_git_config(&mut fetch);
        let output = fetch
            .arg(format!("--git-dir={}", destination.display()))
            .args(["fetch", "--no-tags", "-q"])
            .arg(&source)
            .arg("+refs/heads/*:refs/remotes/s/*")
            .env("GIT_TRACE", "1")
            .output()
            .expect("git fetch must run");
        let trace = String::from_utf8_lossy(&output.stderr).into_owned();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            output.status.success(),
            "the fetch must succeed for this assertion to mean anything: {trace}"
        );
        let spawned: Vec<&str> = trace
            .lines()
            .filter(|line| {
                line.contains("run_command: git maintenance")
                    || line.contains("run_command: git gc")
            })
            .collect();
        assert!(
            spawned.is_empty(),
            "the recipe must leave no background writer behind, but git spawned:\n  {}",
            spawned.join("\n  ")
        );
    }

    /// The recipe actually stops a config injection, checked against real `git`
    /// rather than against our belief about what the variables do.
    ///
    /// This exists because the belief was wrong: the recipe carried a comment
    /// asserting `GIT_CONFIG_COUNT=0` disabled inherited `GIT_CONFIG_PARAMETERS`,
    /// and it does not — git parses that variable on an independent path, so
    /// `-c`-style overrides sailed straight through a recipe documented as
    /// denying everything. No test over the constant's *shape* could have caught
    /// that; only asking git could. Skips (rather than fails) where `git` is
    /// absent so the suite stays portable.
    #[test]
    fn the_recipe_blocks_a_real_git_config_injection() {
        let Some(git) = git_on_path() else {
            eprintln!("skipping: no `git` on PATH");
            return;
        };

        // Inject through every env channel a caller could inherit, then confirm
        // none reaches git once the recipe is layered on top — which is the
        // order a caller adding the recipe to an inherited environment produces.
        // A config file the recipe must not let git reach via `GIT_CONFIG`
        // (which `git config` honours as `--file`).
        let dir = scratch("injection");
        let evil = dir.join("evil.cfg");
        std::fs::write(&evil, "[core]\n\tpager = INJECTED\n").expect("write evil config");

        // A *complete* inherited numbered environment: count 9 with every slot
        // 0..=8 filled. Both halves of that matter.
        //
        // Slots the recipe fills (0 and 1) must be overwritten; slots above its
        // count must be out of range. Injecting only at slot 0 would pass for
        // the wrong reason now that the recipe no longer sets
        // `GIT_CONFIG_COUNT=0` — the count is the only thing keeping the upper
        // slots unreachable, and nothing else here would notice it drifting up.
        //
        // And the injection has to fill *every* slot to be worth anything,
        // because a count naming a slot that is unset is a fatal git error
        // ("missing config key GIT_CONFIG_KEY_2", exit 128) rather than a silent
        // read. A sparse injection therefore fails this test via git refusing to
        // start, which would pass whether or not the recipe had bounded the
        // channel at all. Checked, rather than assumed: filled 0..=8 inline,
        // git happily returns INJECTED.
        let mut command = std::process::Command::new(&git);
        command
            .args(["config", "--get", "core.pager"])
            .env("GIT_CONFIG_PARAMETERS", "'core.pager=INJECTED'")
            .env("GIT_CONFIG_COUNT", "9")
            .env("GIT_CONFIG", &evil);
        for slot in 0..9 {
            command
                .env(format!("GIT_CONFIG_KEY_{slot}"), "core.pager")
                .env(format!("GIT_CONFIG_VALUE_{slot}"), "INJECTED");
        }
        apply_clean_git_config(&mut command);

        let output = command
            .output()
            .expect("git config must be runnable once located on PATH");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("INJECTED"),
            "the hardened recipe let a config injection through: {stdout:?}"
        );
        assert!(
            !output.status.success(),
            "core.pager must be unset under the recipe; git printed {stdout:?}"
        );

        // The other half of the same claim: the settings the recipe *does*
        // impose must actually arrive. A recipe that denied everything
        // including its own imposition would pass the assertions above.
        for (name, value) in GIT_IMPOSED_CONFIG {
            let mut probe = std::process::Command::new(&git);
            probe.args(["config", "--get", name]);
            apply_clean_git_config(&mut probe);
            let got = probe.output().expect("git config must run");
            assert_eq!(
                String::from_utf8_lossy(&got.stdout).trim(),
                value,
                "the recipe must impose {name}={value}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every config source is denied. Pinned by name so dropping one — the
    /// original bug — fails here rather than in production.
    #[test]
    fn every_git_config_source_is_denied() {
        for required in [
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
        ] {
            assert!(
                GIT_CONFIG_DENY_ENV
                    .iter()
                    .any(|(name, _)| *name == required),
                "{required} must be in the denial set"
            );
        }
        // `GIT_CONFIG_SYSTEM` is deliberately absent: `GIT_CONFIG_NOSYSTEM=1`
        // supersedes it, and setting both invites confusion about which wins.
        assert!(
            !GIT_CONFIG_DENY_ENV
                .iter()
                .any(|(name, _)| *name == "GIT_CONFIG_SYSTEM"),
            "prefer GIT_CONFIG_NOSYSTEM=1 over redirecting GIT_CONFIG_SYSTEM"
        );
    }

    #[test]
    fn apply_sets_every_entry_and_removes_git_config() {
        let mut command = std::process::Command::new("/bin/true");
        apply_clean_git_config(&mut command);
        let seen: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (name, value) in CLEAN_GIT_CONFIG_ENV {
            assert!(
                seen.iter()
                    .any(|(k, v)| k == name && v.as_deref() == Some(value)),
                "{name}={value:?} must reach the command; saw {seen:?}"
            );
        }
        // A removal shows up as an explicit `None`, which is what distinguishes
        // "unset it" from "never mentioned it" when the parent env is inherited.
        for name in GIT_CONFIG_REMOVE_ENV {
            assert!(
                seen.iter().any(|(k, v)| k == name && v.is_none()),
                "{name} must be removed, not merely absent; saw {seen:?}"
            );
        }
    }
}
