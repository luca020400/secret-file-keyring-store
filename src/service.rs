/*!

Shared credential backend access.

This module provides mutex-protected shared access from credentials
to either Secret Service or the portal-encrypted file backend. Each store
holds the singleton used by its creds.

*/

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use zbus::zvariant::OwnedObjectPath;

use keyring_core::Result;

mod native;
mod portal;

use native::NativeService;
use portal::PortalService;

enum Backend<'a> {
    SecretService(NativeService<'a>),
    Portal(PortalService),
}

pub(crate) struct Service<'a> {
    ss: Mutex<Backend<'a>>,
}

impl Service<'_> {
    pub(crate) fn new(keyring_file: &Path) -> Result<Self> {
        let backend = match NativeService::new() {
            Ok(ss) => Backend::SecretService(ss),
            Err(_) => Backend::Portal(PortalService::new(keyring_file)?),
        };

        Ok(Self {
            ss: Mutex::new(backend),
        })
    }

    pub(crate) fn find_matching_items(
        &self,
        attributes: &HashMap<&str, &str>,
    ) -> Result<Vec<OwnedObjectPath>> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.find_matching_items(attributes),
            Backend::Portal(ss) => ss.find_matching_items(attributes),
        }
    }

    pub(crate) fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
    ) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.create_item(collection, label, attributes, secret),
            Backend::Portal(ss) => ss.create_item(collection, label, attributes, secret),
        }
    }

    pub(crate) fn delete_collection(&self, collection: &str) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.delete_collection(collection),
            Backend::Portal(ss) => ss.delete_collection(collection),
        }
    }

    pub(crate) fn ensure_unlocked(&self, path: &OwnedObjectPath) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.ensure_unlocked(path),
            Backend::Portal(ss) => ss.ensure_unlocked(path),
        }
    }

    pub(crate) fn set_secret(&self, path: &OwnedObjectPath, secret: &[u8]) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.set_secret(path, secret),
            Backend::Portal(ss) => ss.set_secret(path, secret),
        }
    }

    pub(crate) fn get_secret(&self, path: &OwnedObjectPath) -> Result<Vec<u8>> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.get_secret(path),
            Backend::Portal(ss) => ss.get_secret(path),
        }
    }

    pub(crate) fn get_attributes(&self, path: &OwnedObjectPath) -> Result<HashMap<String, String>> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.get_attributes(path),
            Backend::Portal(ss) => ss.get_attributes(path),
        }
    }

    pub(crate) fn update_attributes(
        &self,
        path: &OwnedObjectPath,
        attributes: &HashMap<&str, &str>,
    ) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.update_attributes(path, attributes),
            Backend::Portal(ss) => ss.update_attributes(path, attributes),
        }
    }

    pub(crate) fn delete(&self, path: &OwnedObjectPath) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.delete(path),
            Backend::Portal(ss) => ss.delete(path),
        }
    }

    pub(crate) fn get_label(&self, path: &OwnedObjectPath) -> Result<String> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.get_label(path),
            Backend::Portal(ss) => ss.get_label(path),
        }
    }

    pub(crate) fn set_label(&self, path: &OwnedObjectPath, label: &str) -> Result<()> {
        let backend = self
            .ss
            .lock()
            .expect("Mutex failure in credential store: please report a bug");
        match &*backend {
            Backend::SecretService(ss) => ss.set_label(path, label),
            Backend::Portal(ss) => ss.set_label(path, label),
        }
    }
}
