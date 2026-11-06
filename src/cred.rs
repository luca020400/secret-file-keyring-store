use std::collections::HashMap;
use std::sync::Arc;

use keyring_core::Entry;
use keyring_core::api::{Credential, CredentialApi};
use keyring_core::error::{Error, Result};

use crate::service::Service;

/// The specifier for an item in the keyring file.
///
/// The label and target are captured from the modifiers
/// used when the specifier was created, so they are
/// available when a matching item needs to be created.
pub struct Specifier {
    store: Arc<Service>,
    /// The label given to an item created for the entry.
    pub label: String,
    /// The collection the item is created in, or `None` for the default collection.
    pub target: Option<String>,
    /// The service of the entry.
    pub service: String,
    /// The user of the entry.
    pub user: String,
}

impl std::fmt::Debug for Specifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Specifier")
            .field("label", &self.label)
            .field("target", &self.target)
            .field("service", &self.service)
            .field("user", &self.user)
            .finish()
    }
}

impl Specifier {
    /// Create a specifier.
    pub(crate) fn new(
        store: Arc<Service>,
        label: Option<&str>,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> Arc<Self> {
        let label = match label {
            None => format!("keyring:{user}@{service}"),
            Some(l) => l.to_string(),
        };
        Arc::new(Self {
            store,
            label,
            target: target.map(|s| s.to_string()),
            service: service.to_string(),
            user: user.to_string(),
        })
    }

    /// Returns the label on an existing, matching item.
    ///
    /// This may or may not match the one in the specifier.
    pub fn get_label(&self) -> Result<String> {
        let id = self.get_unique_item()?;
        self.store.get_label(id)
    }

    /// Sets the label on an existing, matching item.
    ///
    /// Note that this doesn't update the specifier. If you delete
    /// the item and recreate it, the label will come from the specifier.
    pub fn set_label(&self, label: &str) -> Result<()> {
        let id = self.get_unique_item()?;
        self.store.set_label(id, label)
    }

    /// Deletes the target collection in the specifier
    pub fn delete_target(&self) -> Result<()> {
        match self.target.clone() {
            None => Err(Error::Invalid("target".to_string(), "not set".to_string())),
            Some(s) => self.store.delete_collection(&s),
        }
    }

    fn get_unique_item(&self) -> Result<u64> {
        let ids = self.store.find_matching_items(&self.search_attributes())?;
        match ids.len() {
            0 => Err(Error::NoEntry),
            1 => Ok(ids[0]),
            _ => {
                let mut entries: Vec<Entry> = Vec::with_capacity(ids.len());
                for id in ids {
                    entries.push(Entry::new_with_credential(Wrapper::new(
                        self.store.clone(),
                        id,
                    )))
                }
                Err(Error::Ambiguous(entries))
            }
        }
    }

    /// Provide a HashMap of search attributes for this specifier.
    fn search_attributes(&self) -> HashMap<&str, &str> {
        let mut result: HashMap<&str, &str> = HashMap::new();
        result.insert("service", self.service.as_str());
        result.insert("username", self.user.as_str());
        if let Some(target) = &self.target {
            result.insert("target", target.as_str());
        }
        result
    }
}

impl CredentialApi for Specifier {
    /// See the keyring-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        // first try to find a unique, existing, matching item and set its password
        match self.get_unique_item() {
            Ok(p) => return self.store.set_secret(p, secret),
            Err(Error::NoEntry) => {}
            Err(err) => return Err(err),
        }
        // if there is no existing item, create one for this credential.
        let collection = self.target.clone().unwrap_or("default".to_string());
        self.store
            .create_item(&collection, &self.label, self.search_attributes(), secret)
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let id = self.get_unique_item()?;
        self.store.get_secret(id)
    }

    /// See the keyring-core API docs.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        let id = self.get_unique_item()?;
        self.store.get_attributes(id)
    }

    /// See the keyring-core API docs.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        for key in attributes.keys() {
            if *key == "target" || *key == "service" || *key == "username" {
                return Err(Error::Invalid(
                    key.to_string(),
                    "cannot be updated".to_string(),
                ));
            }
        }
        let id = self.get_unique_item()?;
        self.store.update_attributes(id, attributes)
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        let id = self.get_unique_item()?;
        self.store.delete(id)
    }

    /// See the keyring-core API docs.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        let id = self.get_unique_item()?;
        Ok(Some(Wrapper::new(self.store.clone(), id)))
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A wrapper around a stored item, identified by its ID.
pub struct Wrapper {
    store: Arc<Service>,
    id: u64,
}

impl std::fmt::Debug for Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wrapper").field("id", &self.id).finish()
    }
}

impl Wrapper {
    pub(crate) fn new(store: Arc<Service>, id: u64) -> Arc<Self> {
        Arc::new(Self { store, id })
    }

    /// Returns the label on the wrapped item.
    pub fn get_label(&self) -> Result<String> {
        self.store.get_label(self.id)
    }

    /// Sets the label on the wrapped item.
    pub fn set_label(&self, label: &str) -> Result<()> {
        self.store.set_label(self.id, label)
    }

    /// Gets the ID of the wrapped item.
    pub fn get_id(&self) -> u64 {
        self.id
    }
}

impl CredentialApi for Wrapper {
    /// See the keyring-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.store.set_secret(self.id, secret)
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        self.store.get_secret(self.id)
    }

    /// See the keyring-core API docs.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        self.store.get_attributes(self.id)
    }

    /// See the keyring-core API docs.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        self.store.update_attributes(self.id, attributes)
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        self.store.delete(self.id)
    }

    /// See the keyring-core API docs.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        self.store.ensure_exists(self.id)?;
        Ok(None)
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        let attributes = self.store.get_attributes(self.id).ok()?;
        if let Some(service) = attributes.get("service")
            && let Some(user) = attributes.get("username")
        {
            return Some((service.to_string(), user.to_string()));
        }
        None
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
