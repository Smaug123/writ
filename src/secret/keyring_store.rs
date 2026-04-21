//! OS-keyring-backed secret store.
//!
//! Uses the `keyring` crate, which wraps macOS Keychain on Darwin and the
//! Secret Service (D-Bus) on Linux. On headless Linux hosts without a
//! running Secret Service daemon, prefer `FileSecretStore`.

use super::{SecretError, SecretKey, SecretStore};

#[derive(Debug)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Use `service` as the keyring service name under which all keys for
    /// this broker live. Separate brokers (or separate test runs) should
    /// use separate service names to avoid collisions.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &SecretKey) -> Result<keyring::Entry, SecretError> {
        keyring::Entry::new(&self.service, key.as_str())
            .map_err(|e| SecretError::Keyring(e.to_string()))
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        match self.entry(key)?.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Keyring(e.to_string())),
        }
    }

    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        self.entry(key)?
            .set_password(value)
            .map_err(|e| SecretError::Keyring(e.to_string()))
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Keyring(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Smoke test against the real platform keyring. Marked `#[ignore]`
    /// so `cargo test` doesn't pollute the user's keychain by default;
    /// run with `cargo test -- --ignored` to exercise it.
    #[test]
    #[ignore]
    fn roundtrip_against_real_keyring() {
        let service = format!("agent-infra-test-{}", Uuid::new_v4());
        let store = KeyringSecretStore::new(service.clone());
        let k = SecretKey::new("probe").unwrap();

        assert!(store.get(&k).unwrap().is_none());
        store.put(&k, "hello").unwrap();
        assert_eq!(store.get(&k).unwrap().as_deref(), Some("hello"));
        store.put(&k, "world").unwrap();
        assert_eq!(store.get(&k).unwrap().as_deref(), Some("world"));
        store.delete(&k).unwrap();
        assert!(store.get(&k).unwrap().is_none());
        // Deleting a missing key is a no-op.
        store.delete(&k).unwrap();
    }
}
