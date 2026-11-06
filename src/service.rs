/*!

Shared credential backend access.

This module provides read/write-lock-protected shared access from credentials
to the secret portal file store. Each store holds the singleton used by its creds.

*/

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use keyring_core::Result;

mod portal;

use portal::PortalService;

pub(crate) struct Service {
    store: RwLock<PortalService>,
}

impl Service {
    pub(crate) fn new(keyring_file: &Path) -> Result<Self> {
        Ok(Self {
            store: RwLock::new(PortalService::new(keyring_file)?),
        })
    }

    pub(crate) fn find_matching_items(&self, attributes: &HashMap<&str, &str>) -> Result<Vec<u64>> {
        let store = self
            .store
            .read()
            .expect("RwLock failure in credential store: please report a bug");
        store.find_matching_items(attributes)
    }

    pub(crate) fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
    ) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.create_item(collection, label, attributes, secret)
    }

    pub(crate) fn delete_collection(&self, collection: &str) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.delete_collection(collection)
    }

    pub(crate) fn ensure_exists(&self, id: u64) -> Result<()> {
        let store = self
            .store
            .read()
            .expect("RwLock failure in credential store: please report a bug");
        store.ensure_exists(id)
    }

    pub(crate) fn set_secret(&self, id: u64, secret: &[u8]) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.set_secret(id, secret)
    }

    pub(crate) fn get_secret(&self, id: u64) -> Result<Vec<u8>> {
        let store = self
            .store
            .read()
            .expect("RwLock failure in credential store: please report a bug");
        store.get_secret(id)
    }

    pub(crate) fn get_attributes(&self, id: u64) -> Result<HashMap<String, String>> {
        let store = self
            .store
            .read()
            .expect("RwLock failure in credential store: please report a bug");
        store.get_attributes(id)
    }

    pub(crate) fn update_attributes(
        &self,
        id: u64,
        attributes: &HashMap<&str, &str>,
    ) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.update_attributes(id, attributes)
    }

    pub(crate) fn delete(&self, id: u64) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.delete(id)
    }

    pub(crate) fn get_label(&self, id: u64) -> Result<String> {
        let store = self
            .store
            .read()
            .expect("RwLock failure in credential store: please report a bug");
        store.get_label(id)
    }

    pub(crate) fn set_label(&self, id: u64, label: &str) -> Result<()> {
        let store = self
            .store
            .write()
            .expect("RwLock failure in credential store: please report a bug");
        store.set_label(id, label)
    }
}
