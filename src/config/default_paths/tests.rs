//! Properties of [`super::DefaultPath::resolve_from`].
//!
//! Written as properties over [`DEFAULT_PATHS`] rather than as a case per
//! location, because the bug this module exists to fix was a *copy* bug: six
//! near-identical resolvers, of which one had been fixed and five had not. A
//! test per location reproduces exactly that failure mode — it covers the
//! locations someone thought about. Quantifying over the table covers the
//! location added next year by someone who never read this file.

use super::*;
use proptest::prelude::*;

/// The four shapes an environment variable can take at this boundary.
///
/// `Some("")` is the interesting one and the reason this is an explicit
/// generator rather than `option::of(any::<String>())`: an exported-but-empty
/// variable is a single point in a space that uniform generation essentially
/// never hits, and it is the whole point of the code under test. Relative and
/// absolute are both here because they take different branches.
fn env_value() -> impl Strategy<Value = Option<OsString>> {
    prop_oneof![
        Just(None),
        Just(Some(OsString::from(""))),
        "[a-z]{1,8}(/[a-z]{1,8}){0,2}".prop_map(|s| Some(OsString::from(s))),
        "(/[a-z]{1,8}){1,3}".prop_map(|s| Some(OsString::from(s))),
    ]
}

fn default_path() -> impl Strategy<Value = DefaultPath> {
    proptest::sample::select(DEFAULT_PATHS.to_vec())
}

proptest! {
    /// Resolution never yields a relative path: it yields an absolute one or
    /// it fails.
    ///
    /// This is the property the pasted code violated in two independent ways,
    /// and it is stated as "absolute *or* an error" rather than "absolute"
    /// deliberately — the fix is not to invent a path when the environment
    /// gives none, so `Err` is a correct answer here and `/tmp/...` is not.
    #[test]
    fn resolution_never_yields_a_relative_path(
        path in default_path(),
        xdg in env_value(),
        home in env_value(),
    ) {
        if let Ok(resolved) = path.resolve_from(xdg.clone(), home.clone()) {
            prop_assert!(
                resolved.is_absolute(),
                "{} with XDG={xdg:?} HOME={home:?} resolved to the relative {resolved:?}",
                path.what,
            );
        }
    }

    /// An exported-but-empty variable is refused, *not* read as unset.
    ///
    /// This property replaces its own opposite. The first version asserted
    /// that empty and unset were indistinguishable — the natural reading, and
    /// the XDG convention — and that is a silent data move: an install running
    /// with `XDG_DATA_HOME=` resolves its audit database to a CWD-relative
    /// path today and *works*, so reinterpreting the variable relocates the
    /// database and takes the legacy-migration probe with it. Refusing is the
    /// only answer that leaves existing state where it is.
    ///
    /// Checked at both levels, because `unwrap_or_else` not firing on
    /// `Some("")` was the same trap as `var_os` not distinguishing it, and the
    /// original code had it twice.
    #[test]
    fn an_empty_variable_is_refused_rather_than_read_as_unset(
        path in default_path(),
        home in env_value(),
    ) {
        prop_assert_eq!(
            path.resolve_from(Some(OsString::from("")), home.clone()),
            Err(BaseDirError::Empty {
                what: path.what,
                var: path.xdg_var,
                override_hint: path.override_hint,
            }),
            "an empty {} must be refused, whatever HOME says", path.xdg_var,
        );
        prop_assert_eq!(
            path.resolve_from(None, Some(OsString::from(""))),
            Err(BaseDirError::Empty {
                what: path.what,
                var: "HOME",
                override_hint: path.override_hint,
            }),
        );
    }

    /// An empty variable never resolves to the path an *unset* one would.
    ///
    /// The sharp end of the property above, stated as the thing that must not
    /// happen rather than as the error that should: whatever writ does with
    /// `XDG_DATA_HOME=`, it must not be "silently use the HOME location",
    /// because that is where an existing CWD-relative install gets stranded.
    #[test]
    fn an_empty_variable_never_resolves_where_an_unset_one_would(
        path in default_path(),
        home in env_value(),
    ) {
        let with_empty = path.resolve_from(Some(OsString::from("")), home.clone());
        let with_unset = path.resolve_from(None, home);
        if let Ok(unset) = with_unset {
            prop_assert!(
                with_empty.as_ref() != Ok(&unset),
                "{} resolved an empty {} to {unset:?} — the same place unsetting it would, \
                 which silently relocates an install that relies on the current behaviour",
                path.what, path.xdg_var,
            );
        }
    }

    /// With nothing to derive from, writ refuses instead of guessing.
    ///
    /// Named for the specific guess it used to make: `/tmp`, a world-writable
    /// sticky directory, for the audit database and the secret store. The
    /// assertion is on the error rather than on the absence of `/tmp` in some
    /// resolved path, because "does not start with /tmp" would pass for any
    /// other bad guess.
    #[test]
    fn an_absent_environment_refuses_rather_than_inventing_a_path(
        path in default_path(),
    ) {
        prop_assert_eq!(
            path.resolve_from(None, None),
            Err(BaseDirError::NoBase {
                what: path.what,
                xdg_var: path.xdg_var,
                override_hint: path.override_hint,
            }),
        );
    }

    /// A resolved path always ends with one of the two declared suffixes, and
    /// which one is decided by the XDG variable alone.
    #[test]
    fn a_resolved_path_ends_with_the_suffix_its_branch_declares(
        path in default_path(),
        xdg in env_value(),
        home in env_value(),
    ) {
        let Ok(resolved) = path.resolve_from(xdg.clone(), home) else { return Ok(()) };
        let xdg_was_used = xdg.is_some_and(|v| !v.is_empty());
        let expected = if xdg_was_used { path.xdg_suffix } else { path.home_suffix };
        prop_assert!(
            resolved.ends_with(expected),
            "{} resolved to {resolved:?}, which does not end with {expected:?}",
            path.what,
        );
    }

    /// The current and legacy audit-DB locations agree on their base directory
    /// in *every* environment.
    ///
    /// The boot guard asks "is there a database at the old place?" and "where
    /// does the new place resolve to?" and refuses to start if the first is
    /// yes and the second is empty. If the two resolved the environment
    /// differently — as they would if only one were fixed — the guard would
    /// probe a directory the old database was never in, find nothing, and let
    /// writd fork audit history silently. The previous version of this test
    /// checked one environment: the process's own.
    #[test]
    fn the_audit_db_locations_share_a_base_in_every_environment(
        xdg in env_value(),
        home in env_value(),
    ) {
        // `resolve_from` is *handed* an XDG value, so it cannot observe which
        // variable the entry names — passing one value to both below silently
        // assumes they read the same one. Without this line the property
        // passes even when the two entries are pointed at different
        // variables, which is precisely the divergence it exists to forbid.
        prop_assert_eq!(
            AUDIT_DB.xdg_var, LEGACY_AUDIT_DB.xdg_var,
            "the audit-DB locations read different variables, so no environment \
             makes them comparable",
        );
        let current = AUDIT_DB.resolve_from(xdg.clone(), home.clone());
        let legacy = LEGACY_AUDIT_DB.resolve_from(xdg.clone(), home.clone());
        match (current, legacy) {
            // `writ/audit/audit.db` vs `writ/audit.db`: the shared base is the
            // new path's grandparent and the legacy path's parent.
            (Ok(current), Ok(legacy)) => prop_assert_eq!(
                current.parent().and_then(std::path::Path::parent),
                legacy.parent(),
                "current {:?} and legacy {:?} resolved to different bases",
                current, legacy,
            ),
            // Both must fail together, and for the same reason modulo the
            // `what` they name: one resolving while the other errors is the
            // divergence this property exists to forbid.
            (Err(current), Err(legacy)) => prop_assert_eq!(
                std::mem::discriminant(&current),
                std::mem::discriminant(&legacy),
            ),
            (current, legacy) => prop_assert!(
                false,
                "one audit-DB location resolved and the other did not: {current:?} vs {legacy:?}",
            ),
        }
    }
}

/// No two declared locations resolve to the same path — on *either* branch.
///
/// A copy-paste that left two entries sharing a suffix would otherwise be
/// invisible: each would resolve fine, and writ would put two different kinds
/// of state in one place. The audit database in particular must not share a
/// directory with anything, since the broker VM mounts its directory
/// read-write.
///
/// Both branches, because the suffixes are independent fields: an entry could
/// collide with another under `$XDG_…` while staying distinct under `$HOME`,
/// and checking only one branch would call that clean. The XDG branch is
/// driven with every variable set to the *same* base, which is both legal and
/// the case that makes distinct `xdg_var`s stop protecting anything.
#[test]
fn no_two_default_locations_collide() {
    let base = OsString::from("/base");
    for use_xdg in [false, true] {
        let branch = if use_xdg { "XDG" } else { "HOME" };
        let resolved: Vec<_> = DEFAULT_PATHS
            .iter()
            .map(|p| {
                let resolved = if use_xdg {
                    p.resolve_from(Some(base.clone()), None)
                } else {
                    p.resolve_from(None, Some(base.clone()))
                };
                (p.what, resolved.expect("an absolute base resolves"))
            })
            .collect();
        for (i, (what, path)) in resolved.iter().enumerate() {
            for (other_what, other) in &resolved[i + 1..] {
                assert_ne!(
                    path, other,
                    "on the {branch} branch, {what} and {other_what} resolve to the same path",
                );
            }
        }
    }
}

/// The secret store never lands inside the audit directory.
///
/// The broker VM mounts the audit database's *directory* read-write, so
/// anything else writ puts there becomes guest-writable. This is checked
/// against the resolved defaults rather than the declared suffixes because the
/// suffixes are what a future edit would change.
#[test]
fn the_secret_store_is_not_inside_the_audit_directory() {
    let home = Some(OsString::from("/home/writ"));
    let audit = AUDIT_DB
        .resolve_from(None, home.clone())
        .expect("an absolute HOME resolves");
    let audit_dir = audit.parent().expect("the audit DB has a parent");
    for other in DEFAULT_PATHS.iter().filter(|p| **p != AUDIT_DB) {
        let path = other
            .resolve_from(None, home.clone())
            .expect("an absolute HOME resolves");
        assert!(
            !path.starts_with(audit_dir),
            "{} resolves to {path:?}, inside the read-write-mounted {audit_dir:?}",
            other.what,
        );
    }
}

/// A relative variable is reported as such, naming the variable the operator
/// actually set — `HOME` when the fallback branch was taken, not the XDG
/// variable that was empty.
#[test]
fn a_relative_variable_names_itself_in_the_error() {
    assert_eq!(
        AUDIT_DB.resolve_from(Some(OsString::from("relative/dir")), None),
        Err(BaseDirError::Relative {
            what: AUDIT_DB.what,
            var: "XDG_DATA_HOME",
            path: PathBuf::from("relative/dir"),
            override_hint: AUDIT_DB.override_hint,
        }),
    );
    assert_eq!(
        AUDIT_DB.resolve_from(None, Some(OsString::from("relative/home"))),
        Err(BaseDirError::Relative {
            what: AUDIT_DB.what,
            var: "HOME",
            path: PathBuf::from("relative/home"),
            override_hint: AUDIT_DB.override_hint,
        }),
    );
}

/// Both suffixes on every entry are *relative*.
///
/// `PathBuf::join` replaces the whole path when handed an absolute argument,
/// so `PathBuf::from("/home/writ").join("/etc/writ")` is `/etc/writ` — the
/// base silently discarded. An entry declared with a leading slash would
/// therefore resolve to the same path for every operator on the machine,
/// pass `resolution_never_yields_a_relative_path` (it is absolute, after
/// all), and be wrong in a way no other property here notices.
#[test]
fn every_declared_suffix_is_relative() {
    for path in DEFAULT_PATHS {
        for (label, suffix) in [("xdg", path.xdg_suffix), ("home", path.home_suffix)] {
            assert!(
                !std::path::Path::new(suffix).is_absolute(),
                "{}'s {label} suffix {suffix:?} is absolute, so joining it discards the base",
                path.what,
            );
            assert!(
                !suffix.is_empty(),
                "{}'s {label} suffix is empty",
                path.what
            );
        }
        assert!(
            !path.override_hint.is_empty(),
            "{} names no override",
            path.what
        );
    }
}

/// Every entry lands under a `writ`-owned directory rather than directly in
/// the base the operator handed us.
///
/// Without this, an entry whose suffix was just `config.json` would put writ's
/// file straight into `$XDG_CONFIG_HOME` or `$HOME`, colliding with whatever
/// else lives there. Checked on the resolved path so it covers both branches.
#[test]
fn every_default_lands_under_a_writ_directory() {
    let home = Some(OsString::from("/home/writ"));
    for path in DEFAULT_PATHS {
        let resolved = path
            .resolve_from(None, home.clone())
            .expect("an absolute HOME resolves");
        assert!(
            resolved.components().any(|c| c.as_os_str() == "writ"),
            "{} resolves to {resolved:?}, which is not under a writ-owned directory",
            path.what,
        );
    }
}
