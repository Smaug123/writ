//! The one hardened Git environment recipe, shared by every crate.
//!
//! Shelling out to `git` against untrusted input is only safe if git cannot
//! discover configuration the caller did not choose. That means denying *every*
//! config source at once: an override that covers two of the three sources still
//! lets the third through, and the resulting hole is invisible at the call site
//! because the code there looks careful.
//!
//! This module exists because that is exactly what happened. The recipe was
//! written out longhand at half a dozen call sites, and they drifted: one used
//! `GIT_CONFIG_SYSTEM=/dev/null` where the others used `GIT_CONFIG_NOSYSTEM=1`,
//! and omitted `GIT_CONFIG_COUNT=0` — so an inherited `GIT_CONFIG_PARAMETERS`
//! still reached git. Nothing about the divergent site read as wrong.
//!
//! It lives in `writ-core` rather than beside its main consumer so that the host
//! daemon, the guest client, and every crate's test helpers can all derive from
//! the same constant. A recipe that some crates cannot reach is a recipe those
//! crates will re-type.
//!
//! ## What each variable denies
//!
//! * `GIT_CONFIG_NOSYSTEM=1` — `/etc/gitconfig`. Preferred over
//!   `GIT_CONFIG_SYSTEM=/dev/null`: it is a categorical refusal rather than a
//!   redirect, so it cannot be defeated by a path that becomes readable.
//! * `GIT_CONFIG_GLOBAL=/dev/null` — `~/.gitconfig` and
//!   `$XDG_CONFIG_HOME/git/config`.
//! * `GIT_CONFIG_COUNT=0` — any inherited `GIT_CONFIG_PARAMETERS` / numbered
//!   `GIT_CONFIG_KEY_<n>` pairs. Easy to forget precisely because it looks like
//!   a no-op.
//! * `HOME=/dev/null` — dotfiles that helpers read regardless of the
//!   `GIT_CONFIG_*` overrides: credential helpers, hook scripts, and anything
//!   invoked via `core.editor` / `pre-receive`. Only in
//!   [`CLEAN_GIT_CONFIG_ENV`], because a caller that needs a real `HOME` (nix
//!   fetching a flake input) must still get the config denials.

/// The `GIT_CONFIG_*` overrides that deny git every configuration source.
///
/// Use this when the caller supplies its own `HOME` for another reason; use
/// [`CLEAN_GIT_CONFIG_ENV`] otherwise. Never use a subset.
pub const GIT_CONFIG_DENY_ENV: [(&str, &str); 3] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
];

/// [`GIT_CONFIG_DENY_ENV`] plus `HOME=/dev/null`: the full recipe for a caller
/// with no legitimate use for a home directory.
pub const CLEAN_GIT_CONFIG_ENV: [(&str, &str); 4] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_COUNT", "0"),
    ("HOME", "/dev/null"),
];

/// Apply [`CLEAN_GIT_CONFIG_ENV`] to `command`.
///
/// Note this *adds* the overrides; it does not clear the inherited environment.
/// A caller that must also strip inherited `GIT_DIR` / `GIT_WORK_TREE` /
/// `GIT_OBJECT_DIRECTORY` has to call `env_clear` itself and re-add whatever it
/// genuinely needs (typically just `PATH`) — the two concerns are separate, and
/// conflating them here would silently break callers that rely on inheritance.
pub fn apply_clean_git_config(command: &mut std::process::Command) {
    for (name, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(name, value);
    }
}

/// [`apply_clean_git_config`] for a tokio command.
#[cfg(feature = "host")]
pub fn apply_clean_git_config_async(command: &mut tokio::process::Command) {
    for (name, value) in CLEAN_GIT_CONFIG_ENV {
        command.env(name, value);
    }
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

    /// Every config source is denied. Pinned by name so dropping one — the
    /// original bug — fails here rather than in production.
    #[test]
    fn every_git_config_source_is_denied() {
        for required in [
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
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
    fn apply_sets_every_entry_on_the_command() {
        let mut command = std::process::Command::new("/bin/true");
        apply_clean_git_config(&mut command);
        let seen: Vec<(String, String)> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.expect("recipe entries always set a value")
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect();
        for (name, value) in CLEAN_GIT_CONFIG_ENV {
            assert!(
                seen.iter().any(|(k, v)| k == name && v == value),
                "{name}={value} must reach the command; saw {seen:?}"
            );
        }
    }
}
