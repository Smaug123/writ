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
//! * `GIT_CONFIG_COUNT=0` — the numbered `GIT_CONFIG_KEY_<n>` /
//!   `GIT_CONFIG_VALUE_<n>` pairs. Easy to forget precisely because it looks
//!   like a no-op.
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

/// Variables the recipe must *remove* rather than set. See the module docs for
/// why `GIT_CONFIG` cannot be neutralised with a value.
///
/// Because this exists, the constants alone are never the whole recipe. Prefer
/// [`apply_clean_git_config`] / [`apply_git_config_denials`].
pub const GIT_CONFIG_REMOVE_ENV: [&str; 1] = ["GIT_CONFIG"];

/// [`GIT_CONFIG_DENY_ENV`] plus `HOME=/dev/null`: the full recipe for a caller
/// with no legitimate use for a home directory.
pub const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 5] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("GIT_CONFIG_PARAMETERS", ""),
    ("HOME", "/dev/null"),
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

    /// The full recipe is the denial set plus `HOME`, and nothing else. Written as
    /// a test rather than a const expression because the array lengths are part of
    /// the public shape: if someone adds a variable to one constant and forgets
    /// the other, the divergence this module exists to prevent reappears inside
    /// the module itself.
    #[test]
    fn clean_recipe_is_the_denial_set_plus_home() {
        assert_eq!(
            CLEAN_GIT_CONFIG_ENV[..GIT_CONFIG_DENY_ENV.len()],
            GIT_CONFIG_DENY_ENV,
            "the clean recipe must begin with the full denial set"
        );
        assert_eq!(
            &CLEAN_GIT_CONFIG_ENV[GIT_CONFIG_DENY_ENV.len()..],
            &[("HOME", "/dev/null")],
            "the clean recipe must add exactly HOME on top of the denial set"
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
        let Some(git) = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("git"))
                .find(|candidate| candidate.is_file())
        }) else {
            eprintln!("skipping: no `git` on PATH");
            return;
        };

        // Inject through both env channels a caller could inherit, then confirm
        // neither reaches git once the recipe is layered on top — which is the
        // order a caller adding the recipe to an inherited environment produces.
        // A config file the recipe must not let git reach via `GIT_CONFIG`
        // (which `git config` honours as `--file`).
        let dir =
            std::env::temp_dir().join(format!("writ-git-env-injection-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let evil = dir.join("evil.cfg");
        std::fs::write(&evil, "[core]\n\tpager = INJECTED\n").expect("write evil config");

        let mut command = std::process::Command::new(&git);
        command
            .args(["config", "--get", "core.pager"])
            .env("GIT_CONFIG_PARAMETERS", "'core.pager=INJECTED'")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.pager")
            .env("GIT_CONFIG_VALUE_0", "INJECTED")
            .env("GIT_CONFIG", &evil);
        apply_clean_git_config(&mut command);

        let output = command
            .output()
            .expect("git config must be runnable once located on PATH");
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("INJECTED"),
            "the hardened recipe let a config injection through: {stdout:?}"
        );
        assert!(
            !output.status.success(),
            "core.pager must be unset under the recipe; git printed {stdout:?}"
        );
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
