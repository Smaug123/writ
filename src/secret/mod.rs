//! Persistent secret storage. In v1 this holds one long-lived secret — the
//! GitHub App RSA private key used to sign installation-token JWTs.
//!
//! The `SecretStore` trait has two implementations on day one (file and
//! keyring), which justifies the abstraction rather than violating
//! "no interface for one implementation". A future third backend (e.g.
//! Vault for shared team use) would slot in behind the same trait without
//! disturbing callers.

mod file;
mod keyring_store;

pub use file::FileSecretStore;
pub use keyring_store::KeyringSecretStore;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "permissions on {path} are too permissive: got mode {mode:o}, expected at most {expected:o}"
    )]
    UnsafePermissions {
        path: String,
        mode: u32,
        expected: u32,
    },

    #[error("{path} is not a directory")]
    NotADirectory { path: String },

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("invalid secret key {key:?}: {reason}")]
    InvalidKey { key: String, reason: &'static str },
}

/// A validated key under which a secret may be stored.
///
/// Parse-don't-validate: secret keys are restricted at construction time
/// (non-empty, no `/`, no NUL, no leading `.`) so the file backend can
/// map keys to filenames without worrying about path traversal, and all
/// backends can rely on the constraint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretKey(String);

impl SecretKey {
    pub fn new(key: impl Into<String>) -> Result<Self, SecretError> {
        let s: String = key.into();
        let reason = if s.is_empty() {
            Some("must not be empty")
        } else if s.contains('/') {
            Some("must not contain '/'")
        } else if s.contains('\0') {
            Some("must not contain NUL")
        } else if s.starts_with('.') {
            Some("must not start with '.'")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(SecretError::InvalidKey { key: s, reason });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Parse-don't-validate: run the same checks `new` performs so a config
/// file with an invalid key name fails at load time, not at first use.
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// Backing store for long-lived secrets. Implementations must be safe to
/// share across threads.
pub trait SecretStore: Send + Sync {
    /// Returns `Ok(None)` if the key is not present, `Ok(Some(...))` with
    /// the value otherwise. Non-"not found" errors bubble up.
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError>;

    /// Store `value` under `key`, overwriting any previous value.
    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError>;

    /// Remove `key`. Deleting a missing key is a no-op (returns `Ok(())`).
    fn delete(&self, key: &SecretKey) -> Result<(), SecretError>;
}

/// Allows the daemon to hold a `Box<dyn SecretStore>` when the backend
/// is chosen at runtime from config, without having to monomorphise the
/// entire server stack twice.
impl SecretStore for Box<dyn SecretStore> {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        (**self).get(key)
    }
    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        (**self).put(key, value)
    }
    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        (**self).delete(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_keys_are_accepted() {
        for k in [
            "github-app-private-key",
            "github-app-private-key.pem",
            "foo_bar",
            "a",
        ] {
            assert!(SecretKey::new(k).is_ok(), "rejected valid key {k:?}");
        }
    }

    #[test]
    fn invalid_keys_are_rejected() {
        for bad in ["", "with/slash", ".hidden", "nul\0byte"] {
            assert!(SecretKey::new(bad).is_err(), "accepted invalid key {bad:?}");
        }
    }
}
