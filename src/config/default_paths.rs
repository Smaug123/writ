//! Where writ puts things when the operator has not said.
//!
//! Every path writ derives from the environment is *data* here — one
//! [`DefaultPath`] per location, naming the XDG variable that owns it, the two
//! suffixes, and how to override it — and [`DefaultPath::resolve_from`] is the
//! single function that turns one into a path. Before this, the same six-line
//! `if let Some(dir) = var_os(..)` block was copy-pasted once per location
//! across three crates, and the copies had drifted.
//!
//! # Why this refuses rather than guessing
//!
//! The pasted version had two holes, both of which produced a *working* writd
//! rather than a failure, which is why neither was noticed:
//!
//! - `var_os` returns `Some("")` for an exported-but-empty `XDG_DATA_HOME` — a
//!   real thing to find in a container or a stripped-down CI environment — and
//!   `PathBuf::from("").join("writ/audit/audit.db")` is the *relative*
//!   `writ/audit/audit.db`, resolved against whatever directory writd happened
//!   to be started in. `unwrap_or_else` does not fire on `Some("")` either, so
//!   the `HOME` fallback had the identical hole one level down.
//! - An unset `HOME` fell back to `/tmp`, putting the audit database, the
//!   signed-envelope repo, the secret store, and the daemon socket in a
//!   world-writable sticky directory.
//!
//! The second is the one that matters, and it is not hypothetical on writ's
//! primary platform: macOS sets no `XDG_RUNTIME_DIR`, so *every* macOS install
//! already takes the `HOME` branch for the socket and the UI bearer file — one
//! unset variable away from `/tmp`.
//!
//! Two of those locations are worse than "durable state in a shared
//! directory":
//!
//! - **The audit database is consulted as a live authorisation oracle**, not
//!   just as history. `vm_http::flake_provision` gates a guest's
//!   access to a private mirror on
//!   `AuditLog::session_holds_grant_authorising`, and rows are plain SQL with
//!   no signature and no hash chain. A database an attacker pre-created does
//!   not merely fabricate history — it fabricates *grants*. The
//!   dedicated-directory guard in `config::audit_dir` does not help: it
//!   checks that the directory holds nothing *foreign*, and a planted
//!   `audit.db` with the right name and one hard link is not foreign. It also
//!   only runs under `broker_placement = vm`.
//! - **The socket path is the daemon's whole identity to its clients.** writ
//!   performs no peer-credential check on the Unix socket, so a process that
//!   binds the path first *is* writd as far as `writ` and `bailiff` are
//!   concerned — and the honest daemon is then the one that fails, with
//!   `AddrInUse`, while the impostor collects capability requests.
//!
//! Neither hole is fixed by *normalising* — picking the `HOME` path when XDG
//! is empty, or a better guess than `/tmp`. Normalising **moves state**: an
//! install running today with `XDG_DATA_HOME=` resolves its audit database to
//! a CWD-relative path and works, so quietly rereading that environment as
//! "unset" would relocate the database *and* the legacy-migration probe that
//! guards it, leaving writd to open a fresh one. That is the same silent
//! history fork, reached from the other side.
//!
//! So an empty variable is refused rather than reinterpreted, which is the one
//! place this parts company with the XDG convention. Every distinguishable
//! environment gets a distinct, truthful answer and none of them relocates
//! anything: usable resolves, empty and relative are refused *by name*, and
//! only genuinely absent falls through. Correctness over availability — a
//! clear refusal naming the variable and the config key beats a forked
//! history.
//!
//! # What the pre-table resolvers did, for anyone migrating
//!
//! A refusal never tells an operator where their existing state *is*, because
//! that varied per location and a confidently wrong answer would send them
//! away from their own audit log. It is recorded here instead. Under the nine
//! hand-written resolvers this replaces:
//!
//! - **Seven** (config file, audit DB, legacy audit DB, notes repo, secret
//!   store, socket, UI bearer) joined the variable's value raw. An empty
//!   `XDG_…` or an empty `HOME` therefore produced a path *relative to writd's
//!   working directory*; an absent `HOME` produced `/tmp/{home_suffix}`.
//! - **`vm_http.work_root`** filtered an empty `XDG_STATE_HOME` but not an
//!   empty `HOME`: empty XDG used `$HOME/.local/state/writ/vm-work`, empty
//!   `HOME` went CWD-relative, absent `HOME` went to `/tmp`.
//! - **`agent_run_log_root`** filtered empty at both levels, so empty behaved
//!   as unset; absent or empty `HOME` produced `/tmp`.
//! - **The agent-VM state dir** filtered empty at both levels *and* rejected
//!   relative values, refusing outright when `HOME` was unset. It is the only
//!   one that never invented a path, and the one this module generalised.
//!
//! An operator moving off any of these should point the config key at the old
//! location rather than adjust the environment — see [`BaseDirError`].
//!
//! # What this does not do
//!
//! Resolving a path is not trusting it. Nothing here checks that the resolved
//! directory is owned by the right uid — and the mode-only checks that guard
//! the secret store, the socket parent, and the bearer file are all bypassable
//! by a macOS ACL, which `st_mode` does not reflect. That is a separate
//! question about *every* writ host directory however it was arrived at, and
//! it is deliberately not answered here.

use std::ffi::OsString;
use std::path::PathBuf;

/// Why writ could not derive a default path from the environment.
///
/// Both variants name the variable to fix *and* the override to set instead,
/// because the operator reading this did not choose the path — writ derived it
/// — and "cannot derive the audit database path" is not actionable without
/// knowing what writ consulted or what to write in the config.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BaseDirError {
    /// Neither the XDG variable nor `HOME` gave a usable base directory.
    #[error(
        "cannot derive the default path for {what}: neither ${xdg_var} nor $HOME is set. Set \
         {override_hint} to the path writ should use. (Setting ${xdg_var} or $HOME instead may \
         resolve somewhere other than this install's existing state — earlier versions fell back \
         to /tmp when $HOME was unset.)"
    )]
    NoBase {
        /// What writ was deriving, phrased for an operator.
        what: &'static str,
        /// The XDG variable that owns this location.
        xdg_var: &'static str,
        /// How to name the path explicitly instead.
        override_hint: &'static str,
    },
    /// A variable was exported with an empty value.
    ///
    /// Refused rather than read as "unset", because the two are *not* the same
    /// state here: `XDG_DATA_HOME=` currently resolves durable paths relative
    /// to writd's working directory, and quietly reinterpreting it would move
    /// state that already exists. See [`DefaultPath::resolve_from`].
    ///
    /// The remedy offered is deliberately "name the path", not "change the
    /// variable". Every environment change is potentially a *relocation*: it
    /// moves both the resolved path and the legacy-migration probe that guards
    /// it, so writd looks where the old database never was and starts a fresh
    /// history — the failure this module exists to prevent. Naming the path
    /// explicitly is the one remedy that cannot do that.
    ///
    /// It also does not claim where the old location *was*. It varied per
    /// entry: seven of the pre-table resolvers joined the empty value and
    /// produced a CWD-relative path, while three already filtered it and used
    /// `$HOME` — and the no-`HOME` fallbacks differed again. A confidently
    /// wrong path would send an operator away from their own audit log, which
    /// is worse than not naming one.
    #[error(
        "cannot derive the default path for {what}: ${var} is set but empty, which writ refuses \
         rather than guess at. Set {override_hint} to the path writ should use. (Changing ${var} \
         instead — including unsetting it — may resolve somewhere other than this install's \
         existing state.)"
    )]
    Empty {
        /// What writ was deriving, phrased for an operator.
        what: &'static str,
        /// The variable that was set to the empty string.
        var: &'static str,
        /// How to name the path explicitly instead.
        override_hint: &'static str,
    },
    /// A variable was set, but names a relative directory.
    ///
    /// Distinct from [`Self::NoBase`] because the fix is different: the
    /// operator did set the variable, and writ is telling them the value is
    /// unusable rather than missing. Joining a suffix onto a relative base
    /// yields a path resolved against writd's working directory, so the same
    /// install resolves to different state depending on where it was started.
    #[error(
        "cannot derive the default path for {what}: ${var} must be absolute, got {path:?}. Set \
         {override_hint} to the path writ should use. (Earlier versions accepted this and \
         resolved beneath writd's working directory, so changing ${var} to an absolute path may \
         resolve somewhere other than this install's existing state.)"
    )]
    Relative {
        /// What writ was deriving, phrased for an operator.
        what: &'static str,
        /// The variable whose value was relative.
        var: &'static str,
        /// The offending value.
        path: PathBuf,
        /// How to name the path explicitly instead.
        override_hint: &'static str,
    },
}

/// One location writ knows how to derive: which XDG variable owns it, where it
/// sits under that variable and under `$HOME`, and how to override it.
///
/// Inert data rather than a function per location, so the set of locations can
/// be enumerated and quantified over. [`DEFAULT_PATHS`] is what makes the
/// property tests total: "every location writ derives is absolute or an error"
/// is only worth asserting if a location added later is forced into the list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultPath {
    /// What this path is for, as it appears in a [`BaseDirError`] the operator
    /// reads. Lower-case and article-led ("the audit database"), because it is
    /// interpolated mid-sentence.
    pub what: &'static str,
    /// The config key or flag that names this path explicitly, quoted into the
    /// error so the operator has a way out that does not involve the
    /// environment at all.
    pub override_hint: &'static str,
    /// The XDG base-directory variable this location belongs under.
    pub xdg_var: &'static str,
    /// Where the location sits beneath `$XDG_…`.
    pub xdg_suffix: &'static str,
    /// Where it sits beneath `$HOME` when the XDG variable is unset. Carries
    /// the XDG default's own prefix (`.local/share`, `.config`, …), so the two
    /// suffixes are deliberately not derivable from one another.
    pub home_suffix: &'static str,
}

impl DefaultPath {
    /// Resolve against explicit environment values.
    ///
    /// The pure half, so the properties can quantify over environments without
    /// mutating process-global state that other tests in the same process
    /// would see.
    ///
    /// An exported-but-empty variable is an **error**, not a synonym for
    /// unset — the one place this deliberately parts company with the XDG
    /// convention.
    ///
    /// Treating it as unset is the obvious reading, and it is wrong here for a
    /// specific reason: it is not inert. An install running with
    /// `XDG_DATA_HOME=` today resolves its audit database to the CWD-relative
    /// `writ/audit/audit.db` and *works*. Silently reinterpreting that
    /// environment as "unset" would move the database to `$HOME/.local/share`
    /// — and move the legacy-migration probe with it, so the guard would look
    /// where the old database never was, find nothing, and let writd open a
    /// fresh one. That is the silent audit-history fork this whole module
    /// exists to prevent, arrived at from the other direction.
    ///
    /// So every distinguishable environment gets a distinct, truthful answer,
    /// and none of them relocates anything: set-and-usable resolves,
    /// set-and-empty and set-and-relative are refused by name, and only
    /// genuinely absent falls through to the next variable.
    pub fn resolve_from(
        &self,
        xdg: Option<OsString>,
        home: Option<OsString>,
    ) -> Result<PathBuf, BaseDirError> {
        let (base, var, suffix) = match xdg {
            Some(dir) => (dir, self.xdg_var, self.xdg_suffix),
            None => match home {
                Some(home) => (home, "HOME", self.home_suffix),
                None => {
                    return Err(BaseDirError::NoBase {
                        what: self.what,
                        xdg_var: self.xdg_var,
                        override_hint: self.override_hint,
                    });
                }
            },
        };
        if base.is_empty() {
            return Err(BaseDirError::Empty {
                what: self.what,
                var,
                override_hint: self.override_hint,
            });
        }
        let base = PathBuf::from(base);
        if !base.is_absolute() {
            return Err(BaseDirError::Relative {
                what: self.what,
                var,
                path: base,
                override_hint: self.override_hint,
            });
        }
        Ok(base.join(suffix))
    }

    /// Resolve against the process environment.
    pub fn resolve(&self) -> Result<PathBuf, BaseDirError> {
        self.resolve_from(std::env::var_os(self.xdg_var), std::env::var_os("HOME"))
    }

    /// The same location, but advising a different override.
    ///
    /// A location is shared; the advice for reaching it is not. `bailiff`
    /// fetches from writd's notes repo and so must name the *same*
    /// [`NOTES_REPO`] entry — that identity is the point — but an operator
    /// running `bailiff` cannot act on "set the `run_agent.notes_repo_path`
    /// config key", which is writd's. This keeps the shared field that must
    /// not diverge shared, and lets the field that is per-consumer vary.
    #[must_use]
    pub const fn with_override_hint(self, override_hint: &'static str) -> Self {
        Self {
            override_hint,
            ..self
        }
    }

    /// `configured` if the operator named a path, else this entry resolved
    /// against the environment.
    ///
    /// The shape every caller wants, given as one method so that "an absent
    /// config key means *this* location" is stated once per location rather
    /// than once per call site. An explicitly configured path is returned
    /// verbatim and is never checked against the entry: the operator's choice
    /// is the operator's, and the environment is not consulted at all.
    pub fn or_resolve(&self, configured: Option<PathBuf>) -> Result<PathBuf, BaseDirError> {
        match configured {
            Some(path) => Ok(path),
            None => self.resolve(),
        }
    }
}

/// The daemon config file.
///
/// First in the list because it is read before any other guard runs, and
/// because it is the only entry that is a direct code-execution primitive: the
/// config names executables writd later runs (`container`, `sudo`,
/// `pf_helper`, `spawn_command`), so a default that can land in a
/// world-writable directory is a default that can hand writd an attacker's
/// binary.
pub const CONFIG_FILE: DefaultPath = DefaultPath {
    what: "the daemon config file",
    override_hint: "`writd --config`",
    xdg_var: "XDG_CONFIG_HOME",
    xdg_suffix: "writ/config.json",
    home_suffix: ".config/writ/config.json",
};

/// The SQLite audit database — writ's system of record, and the oracle its
/// authorisation checks consult.
pub const AUDIT_DB: DefaultPath = DefaultPath {
    what: "the audit database",
    override_hint: "the `audit_db` config key (or `writd --audit-db`)",
    xdg_var: "XDG_DATA_HOME",
    xdg_suffix: "writ/audit/audit.db",
    home_suffix: ".local/share/writ/audit/audit.db",
};

/// The pre-2026-07 audit database location, before it moved into a dedicated
/// `audit/` directory.
///
/// Declared beside [`AUDIT_DB`] and resolved by the same function, which is
/// the point: the boot guard compares "is there a database at the old place"
/// against "where does the new place resolve to", and refuses to start if the
/// first is yes and the second is empty. If the two resolved the environment
/// differently — as they would if only one were fixed — the guard would probe
/// a directory the old database was never in, find nothing, and let writd fork
/// audit history silently. Sharing the resolver makes that divergence
/// unrepresentable rather than something a comment asks the next reader to
/// preserve.
pub const LEGACY_AUDIT_DB: DefaultPath = DefaultPath {
    what: "the legacy audit database",
    override_hint: "the `audit_db` config key (or `writd --audit-db`)",
    xdg_var: "XDG_DATA_HOME",
    xdg_suffix: "writ/audit.db",
    home_suffix: ".local/share/writ/audit.db",
};

/// writ's bare notes repo, holding signed run envelopes. A sibling of the
/// audit database so one backup of `writ/` captures both halves of the record.
pub const NOTES_REPO: DefaultPath = DefaultPath {
    what: "the notes repo",
    override_hint: "the `run_agent.notes_repo_path` config key",
    xdg_var: "XDG_DATA_HOME",
    xdg_suffix: "writ/repo",
    home_suffix: ".local/share/writ/repo",
};

/// The file secret store's base directory.
pub const SECRET_STORE: DefaultPath = DefaultPath {
    what: "the secret store",
    override_hint: "the `secret_store.path` config key",
    xdg_var: "XDG_DATA_HOME",
    xdg_suffix: "writ/secrets",
    home_suffix: ".local/share/writ/secrets",
};

/// Per-run agent stdout/stderr logs. Durable state, not scratch: the streams
/// outlive the run and are pointed at by `agent_run_outcome` audit rows.
pub const AGENT_RUN_LOG_ROOT: DefaultPath = DefaultPath {
    what: "the agent run log root",
    override_hint: "the `agent_run_log_root` config key",
    xdg_var: "XDG_DATA_HOME",
    xdg_suffix: "writ/agent-runs",
    home_suffix: ".local/share/writ/agent-runs",
};

/// The Unix socket writd listens on — and, absent any peer-credential check,
/// the daemon's entire identity to `writ` and `bailiff`.
pub const SOCKET: DefaultPath = DefaultPath {
    what: "the daemon socket",
    override_hint: "the `socket_path` config key (or `--socket` / `WRIT_SOCKET`)",
    xdg_var: "XDG_RUNTIME_DIR",
    xdg_suffix: "writ/writd.sock",
    home_suffix: ".local/run/writ/writd.sock",
};

/// The UI HTTP bearer token file — a credential, in the same directory as the
/// socket so one runtime directory holds everything a consumer needs to talk
/// to the daemon.
pub const UI_HTTP_BEARER: DefaultPath = DefaultPath {
    what: "the UI HTTP bearer file",
    override_hint: "the `ui_http.bearer_path` config key",
    xdg_var: "XDG_RUNTIME_DIR",
    xdg_suffix: "writ/ui-bearer",
    home_suffix: ".local/run/writ/ui-bearer",
};

/// The agent-VM HTTP work root. Scratch rather than durable state, but its
/// contents cross into the guest, so where it lands is not a free choice.
pub const VM_HTTP_WORK_ROOT: DefaultPath = DefaultPath {
    what: "the agent-VM work root",
    override_hint: "the `agent_vm.vm_http.work_root` config key",
    xdg_var: "XDG_STATE_HOME",
    xdg_suffix: "writ/vm-work",
    home_suffix: ".local/state/writ/vm-work",
};

/// Per-session agent-VM lifecycle state, used to reconcile VMs across a daemon
/// restart.
pub const AGENT_VM_STATE_DIR: DefaultPath = DefaultPath {
    what: "the agent-VM state directory",
    override_hint: "the `agent_vm.lifecycle.state_dir` config key (or `--state-dir` / \
                    `WRIT_AGENT_VM_STATE_DIR`)",
    xdg_var: "XDG_STATE_HOME",
    xdg_suffix: "writ/agent-vm-sessions",
    home_suffix: ".local/state/writ/agent-vm-sessions",
};

/// Every location writ derives from the environment.
///
/// Exists so the properties can quantify over *all* of them: a location added
/// without being listed here is a location no property covers, and that is a
/// gap someone has to notice rather than a test that fails. Keeping that claim
/// true is why the bespoke resolver that used to live in
/// `agent_vm_lifecycle::state_store` was folded in rather than left beside it.
///
/// Consumers outside this crate — `bailiff` has its own repo — declare their
/// own [`DefaultPath`] and resolve it with the same code; they are not in this
/// list because writ does not own them.
pub const DEFAULT_PATHS: &[DefaultPath] = &[
    CONFIG_FILE,
    AUDIT_DB,
    LEGACY_AUDIT_DB,
    NOTES_REPO,
    SECRET_STORE,
    AGENT_RUN_LOG_ROOT,
    SOCKET,
    UI_HTTP_BEARER,
    VM_HTTP_WORK_ROOT,
    AGENT_VM_STATE_DIR,
];

#[cfg(test)]
mod tests;
