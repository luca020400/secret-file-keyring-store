use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use keyring_core::api::CredentialStoreApi;
use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};

use crate::cred::{Specifier, Wrapper};
use crate::service::Service;

/// Secret file credential store
pub struct Store {
    /// The unique ID for this store instance.
    pub id: String,
    pub(crate) service: Arc<Service>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id())
            .finish()
    }
}

impl Store {
    /// Open or create an encrypted store using an application-provided secret.
    ///
    /// The file and a sibling `<keyring_file>.lock` file are created if needed.
    pub fn new(keyring_file: impl AsRef<Path>, secret: &[u8]) -> Result<Arc<Self>> {
        let keyring_file = keyring_file.as_ref();
        if keyring_file.as_os_str().is_empty() {
            return Err(Error::Invalid(
                "keyring-file".to_string(),
                "cannot be empty".to_string(),
            ));
        }

        if secret.is_empty() {
            return Err(Error::Invalid(
                "secret".to_string(),
                "cannot be empty".to_string(),
            ));
        }

        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        let id = format!(
            "Crate version {}, Instantiated at {}",
            env!("CARGO_PKG_VERSION"),
            elapsed.as_secs_f64()
        );
        let service = Arc::new(Service::new(keyring_file, secret)?);
        Ok(Arc::new(Store { id, service }))
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Secret store, https://crates.io/crates/secret-file-keyring-store".to_string()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    /// See the keyring-core API docs.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["target", "label"], modifiers)?;
        let label = mods.get("label").map(|s| s.as_str());
        if label.map(|l| l.is_empty()).unwrap_or(false) {
            return Err(Error::Invalid(
                "label".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        let target = mods.get("target").map(|s| s.as_str());
        if target.map(|t| t.is_empty()).unwrap_or(false) {
            return Err(Error::Invalid(
                "target".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        Ok(Entry::new_with_credential(Specifier::new(
            self.service.clone(),
            label,
            target,
            service,
            user,
        )))
    }

    /// See the keyring-core API docs.
    ///
    /// All the key-value pairs are interpreted as attribute/value pairs to
    /// search for (case-sensitive) in the encrypted keyring file.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let ids = self.service.find_matching_items(spec)?;
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            results.push(Entry::new_with_credential(Wrapper::new(
                self.service.clone(),
                id,
            )));
        }
        Ok(results)
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
