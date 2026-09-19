use std::collections::HashMap;
use std::sync::Mutex;

use crate::secret::{SecretError, SecretKey, SecretStore};

/// Process-local [`SecretStore`]: an unordered map under a mutex, no I/O, no
/// persistence. Enough for any test whose only need is to satisfy a
/// non-empty-registry invariant or to hand a signing key to the code under
/// test.
#[derive(Default)]
pub struct InMemorySecretStore(Mutex<HashMap<String, String>>);

impl SecretStore for InMemorySecretStore {
    fn get(&self, key: &SecretKey) -> Result<Option<String>, SecretError> {
        Ok(self.0.lock().unwrap().get(key.as_str()).cloned())
    }

    fn put(&self, key: &SecretKey, value: &str) -> Result<(), SecretError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.as_str().to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.0.lock().unwrap().remove(key.as_str());
        Ok(())
    }
}
