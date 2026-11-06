use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use keyring_core::api::CredentialStoreApi;
use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};

use crate::cred::{Specifier, Wrapper};
use crate::service::Service;

/// Secret portal file credential store
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
    /// Create a store with the specified configuration.
    ///
    /// The required `keyring-file` key names the portal backend's encrypted JSON file.
    /// The file and a sibling `<keyring-file>.lock` file are created if needed;
    /// their parent directory must already exist.
    /// No other configuration keys are supported.
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        if config.keys().any(|key| *key != "keyring-file") {
            return Err(Error::NotSupportedByStore(
                "Unknown store configuration".to_string(),
            ));
        }
        let keyring_file = config
            .get("keyring-file")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::Invalid(
                    "keyring-file".to_string(),
                    "must be provided and cannot be empty".to_string(),
                )
            })?;

        Store::new_internal(Path::new(keyring_file))
    }

    fn new_internal(keyring_file: &Path) -> Result<Arc<Self>> {
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
        let service = Arc::new(Service::new(keyring_file)?);
        Ok(Arc::new(Store { id, service }))
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Secret portal store, https://crates.io/crates/zbus-secret-portal-keyring-store".to_string()
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
