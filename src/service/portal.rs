//! Portal-backed encrypted file service.

mod secret;

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::TryRng;
use rand::rngs::SysRng;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

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
                    store.save(&records, token.as_deref(), envelope.next_id)?;
                }
            }
            None => store.save(&[], token.as_deref(), 0)?,
        }

        Ok(store)
    }

    pub(super) fn find_matching_items(&self, attributes: &HashMap<&str, &str>) -> Result<Vec<u64>> {
        let (_, records) = self.load()?;
        Ok(records
            .iter()
            .filter(|r| {
                attributes
                    .iter()
                    .all(|(k, v)| r.attributes.get(*k).is_some_and(|value| value == v))
            })
            .map(|r| r.id)
            .collect())
    }

    pub(super) fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
    ) -> Result<()> {
        let (mut envelope, mut records) = self.load()?;
        let id = envelope.next_id;
        envelope.next_id = id
            .checked_add(1)
            .ok_or_else(|| Error::BadStoreFormat("Record IDs exhausted".into()))?;
        records.push(Record {
            secret: secret.to_vec(),
            id,
            label: label.to_string(),
            collection: collection.to_string(),
            attributes: attributes
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        });
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
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
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
    }

    /// Given an item's ID, ensure it exists
    pub(super) fn ensure_exists(&self, id: u64) -> Result<()> {
        let (_, records) = self.load()?;
        position(&records, id).map(|_| ())
    }

    /// Given an item's ID, set its secret.
    pub(super) fn set_secret(&self, id: u64, secret: &[u8]) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, id)?;
        records[index].secret = secret.to_vec();
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
    }

    /// Given an existing item's ID, retrieve its secret.
    pub(super) fn get_secret(&self, id: u64) -> Result<Vec<u8>> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, id)?];
        Ok(item.secret.clone())
    }

    /// Given an existing item's ID, retrieve its attributes.
    pub(super) fn get_attributes(&self, id: u64) -> Result<HashMap<String, String>> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, id)?];
        Ok(item.attributes.clone())
    }

    /// Given an existing item's ID, update its attributes.
    pub(super) fn update_attributes(
        &self,
        id: u64,
        attributes: &HashMap<&str, &str>,
    ) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, id)?;
        let item = &mut records[index];
        for (k, v) in attributes {
            item.attributes.insert(k.to_string(), v.to_string());
        }
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
    }

    // Given an existing item's ID, delete it.
    pub(super) fn delete(&self, id: u64) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        records.remove(position(&records, id)?);
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
    }

    // Given an existing item's ID, return its label.
    pub(super) fn get_label(&self, id: u64) -> Result<String> {
        let (_, records) = self.load()?;
        let item = &records[position(&records, id)?];
        Ok(item.label.clone())
    }

    // Given an existing item's ID, set its label.
    pub(super) fn set_label(&self, id: u64, label: &str) -> Result<()> {
        let (envelope, mut records) = self.load()?;
        let index = position(&records, id)?;
        records[index].label = label.to_string();
        self.save(&records, envelope.token.as_deref(), envelope.next_id)
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
                    aad: &aad(&envelope.salt, envelope.token.as_deref(), envelope.next_id),
                },
            )
            .map_err(|_| Error::BadStoreFormat("Wrong secret or corrupted store".into()))?;

        serde_json::from_slice(&plaintext).map_err(|err| Error::BadStoreFormat(err.to_string()))
    }

    fn save(&self, records: &[Record], token: Option<&str>, next_id: u64) -> Result<()> {
        let nonce = random::<NONCE_LEN>()?;
        let aad = aad(&self.salt, token, next_id);

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
            next_id,
            salt: self.salt,
            nonce,
            token: token.map(str::to_owned),
            ciphertext,
        };

        let bytes = serde_json::to_vec(&envelope).map_err(platform_failure)?;

        let parent = self
            .keyring_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(platform_failure)?;
        temp.write_all(&bytes).map_err(platform_failure)?;
        temp.as_file().sync_all().map_err(platform_failure)?;
        temp.persist(&self.keyring_file).map_err(platform_failure)?;

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

fn position(records: &[Record], id: u64) -> Result<usize> {
    records
        .iter()
        .position(|r| r.id == id)
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
    let info = format!("zbus-secret-portal-keyring-store/{VERSION}/encryption-key");
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info.as_bytes(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    next_id: u64,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    token: Option<String>,
    ciphertext: Vec<u8>,
}

fn aad(salt: &[u8; SALT_LEN], token: Option<&str>, next_id: u64) -> Vec<u8> {
    let token_bytes = token.unwrap_or("").as_bytes();
    let mut aad = Vec::with_capacity(4 + 8 + SALT_LEN + 1 + token_bytes.len());
    aad.extend_from_slice(&VERSION.to_le_bytes());
    aad.extend_from_slice(&next_id.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.push(token.is_some() as u8);
    aad.extend_from_slice(token_bytes);
    aad
}

#[derive(Serialize, Deserialize)]
struct Record {
    secret: Vec<u8>,
    id: u64,
    label: String,
    collection: String,
    attributes: HashMap<String, String>,
}
