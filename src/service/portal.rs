//! Portal-backed encrypted file service.

mod secret;

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rand::TryRng;
use rand::rngs::SysRng;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use zbus::zvariant::OwnedObjectPath;

use serde::{Deserialize, Serialize};

use crate::errors::platform_failure;
use keyring_core::error::{Error, Result};

/// An encrypted credential store unlocked through the desktop Secret portal.
pub(super) struct PortalService {
    keyring_file: PathBuf,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
}

impl PortalService {
    /// Opens or creates the store at `keyring_file`, requesting its key from the portal.
    ///
    /// This blocks while the portal responds and may prompt the user for access.
    pub(super) fn new(keyring_file: &Path) -> Result<Self> {
        let keyring_file = keyring_file.to_path_buf();
        let existing = read_envelope(&keyring_file)?;
        let previous_token = existing.as_ref().and_then(|e| e.token.as_deref());

        let (secret, token) = secret::retrieve(previous_token)?;
        let token = token.or_else(|| previous_token.map(str::to_owned));

        // Get pre-existing salt or generate a new one.
        let salt = match &existing {
            Some(envelope) => envelope.salt,
            None => random::<SALT_LEN>()?,
        };

        let store = Self {
            keyring_file,
            key: derive(&secret, &salt),
            salt,
        };

        // Update the store if the token has changed.
        match existing {
            Some(envelope) => {
                let records = store.decrypt(&envelope)?;
                if envelope.token != token {
                    store.save(&records, token.as_deref())?;
                }
            }
            None => store.save(&[], token.as_deref())?,
        }

        Ok(store)
    }

    pub(super) fn find_matching_items(
        &self,
        attributes: &HashMap<&str, &str>,
    ) -> Result<Vec<OwnedObjectPath>> {
        let (_, records) = self.load()?;
        records
            .iter()
            .filter(|r| {
                attributes
                    .iter()
                    .all(|(k, v)| r.attributes.get(*k).is_some_and(|value| value == v))
            })
            .map(|r| {
                OwnedObjectPath::try_from(r.path.clone())
                    .map_err(|err| Error::BadStoreFormat(err.to_string()))
            })
            .collect()
    }

    pub(super) fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
    ) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        records.push(Record {
            secret: secret.to_vec(),
            path: format!("/portal/item_{:032x}", u128::from_ne_bytes(random()?)),
            label: label.to_string(),
            collection: collection.to_string(),
            attributes: attributes
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        });
        self.save(&records, envelope.token.as_deref())
    }

    pub(super) fn delete_collection(&self, collection: &str) -> Result<()> {
        if collection.eq("default") {
            return Err(Error::NotSupportedByStore(
                "You cannot delete the default collection".to_string(),
            ));
        }
        let (envelope, mut records) = self.load()?;
        if !records.iter().any(|r| r.collection == collection) {
            return Err(Error::NoEntry);
        }
        records.retain(|r| r.collection != collection);
        self.save(&records, envelope.token.as_deref())
    }

    /// Given an item's path, ensure it exists and is unlocked
    pub(super) fn ensure_unlocked(&self, path: &OwnedObjectPath) -> Result<()> {
        let (_, records) = self.load()?;
        position(&records, path).map(|_| ())
    }

    /// Given an item's path, set its secret.
    pub(super) fn set_secret(&self, path: &OwnedObjectPath, secret: &[u8]) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, path)?;
        records[index].secret = secret.to_vec();
        self.save(&records, envelope.token.as_deref())
    }

    /// Given an existing item's path, retrieve its secret.
    pub(super) fn get_secret(&self, path: &OwnedObjectPath) -> Result<Vec<u8>> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, path)?];
        Ok(item.secret.clone())
    }

    /// Given an existing item's path, retrieve its attributes.
    pub(super) fn get_attributes(&self, path: &OwnedObjectPath) -> Result<HashMap<String, String>> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, path)?];
        Ok(item.attributes.clone())
    }

    /// Given an existing item's path, update its attributes.
    pub(super) fn update_attributes(
        &self,
        path: &OwnedObjectPath,
        attributes: &HashMap<&str, &str>,
    ) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, path)?;
        let item = &mut records[index];
        for (k, v) in attributes {
            item.attributes.insert(k.to_string(), v.to_string());
        }
        self.save(&records, envelope.token.as_deref())
    }

    // Given an existing item's path, delete it.
    pub(super) fn delete(&self, path: &OwnedObjectPath) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        records.remove(position(&records, path)?);
        self.save(&records, envelope.token.as_deref())
    }

    // Given an existing item's path, return its label.
    pub(super) fn get_label(&self, path: &OwnedObjectPath) -> Result<String> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, path)?];
        Ok(item.label.clone())
    }

    // Given an existing item's path, set its label.
    pub(super) fn set_label(&self, path: &OwnedObjectPath, label: &str) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, path)?;
        records[index].label = label.to_string();
        self.save(&records, envelope.token.as_deref())
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.key.into())
    }

    fn decrypt(&self, envelope: &Envelope) -> Result<Vec<Record>> {
        if envelope.salt != self.salt {
            return Err(Error::BadStoreFormat("Store salt changed".into()));
        }

        let plaintext = self
            .cipher()
            .decrypt(
                &XNonce::from(envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad(&envelope.salt, envelope.token.as_deref()),
                },
            )
            .map_err(|_| Error::BadStoreFormat("Wrong secret or corrupted store".into()))?;

        serde_json::from_slice(&plaintext).map_err(|err| Error::BadStoreFormat(err.to_string()))
    }

    fn save(&self, records: &[Record], token: Option<&str>) -> Result<()> {
        let nonce = random::<NONCE_LEN>()?;
        let aad = aad(&self.salt, token);

        // Serialize records to JSON and encrypt.
        let plaintext = serde_json::to_vec(records).map_err(platform_failure)?;
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(platform_failure)?;

        let envelope = Envelope {
            version: VERSION,
            salt: self.salt,
            nonce,
            token: token.map(str::to_owned),
            ciphertext,
        };

        let bytes = serde_json::to_vec(&envelope).map_err(platform_failure)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.keyring_file)
            .map_err(platform_failure)?;
        file.write_all(&bytes).map_err(platform_failure)?;

        Ok(())
    }

    fn load(&self) -> Result<(Envelope, Vec<Record>)> {
        let envelope = read_envelope(&self.keyring_file)?
            .ok_or_else(|| Error::BadStoreFormat("Store file disappeared".into()))?;
        let records = self.decrypt(&envelope)?;
        Ok((envelope, records))
    }
}

fn read_envelope(keyring_file: &Path) -> Result<Option<Envelope>> {
    let bytes = match fs::read(keyring_file) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(platform_failure(e)),
    };

    let envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|err| Error::BadStoreFormat(err.to_string()))?;
    if envelope.version != VERSION {
        return Err(Error::BadStoreFormat("Unsupported store version".into()));
    }
    Ok(Some(envelope))
}

fn position(records: &[Record], path: &OwnedObjectPath) -> Result<usize> {
    records
        .iter()
        .position(|r| r.path == path.as_str())
        .ok_or(Error::NoEntry)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(platform_failure)?;
    Ok(bytes)
}

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

const VERSION: u32 = 1;
fn derive(secret: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut key = [0; KEY_LEN];
    let info = format!("portal-secret-service-keyring-store/{VERSION}/encryption-key");
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info.as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    token: Option<String>,
    ciphertext: Vec<u8>,
}

fn aad(salt: &[u8; SALT_LEN], token: Option<&str>) -> Vec<u8> {
    let token_bytes = token.unwrap_or("").as_bytes();
    let mut aad = Vec::with_capacity(4 + SALT_LEN + 1 + token_bytes.len());
    aad.extend_from_slice(&VERSION.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.push(token.is_some() as u8);
    aad.extend_from_slice(token_bytes);
    aad
}

#[derive(Serialize, Deserialize)]
struct Record {
    secret: Vec<u8>,
    path: String,
    label: String,
    collection: String,
    attributes: HashMap<String, String>,
}
