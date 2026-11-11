# Secret file keyring store

[![build](https://github.com/open-source-cooperative/secret-file-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/secret-file-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/secret-file-keyring-store.svg?style=flat-square)](https://crates.io/crates/secret-file-keyring-store) [![docs.rs](https://docs.rs/secret-file-keyring-store/badge.svg)](https://docs.rs/secret-file-keyring-store) [![codecov](https://codecov.io/gh/open-source-cooperative/secret-file-keyring-store/graph/badge.svg)](https://codecov.io/gh/open-source-cooperative/secret-file-keyring-store)

This library stores credentials in an encrypted JSON file for the keyring ecosystem.

## Usage

```rust
use secret_file_keyring_store::Store;

let store = Store::new("/path/to/application/keyring.json", &application_secret)?;
keyring_core::set_default_store(store);
```

## Store format

The file contains a JSON object with the following fields (format version 1):

| Field | Format | Meaning |
| --- | --- | --- |
| `version` | Unsigned 32-bit integer | Store format version, currently `1`. |
| `next_id` | Unsigned 64-bit integer | ID to assign to the next record. |
| `salt` | Base64 string encoding 16 bytes | Random salt generated when the store is first created. |
| `nonce` | Base64 string encoding 24 bytes | Random nonce generated on every write. |
| `ciphertext` | Base64 string | Encrypted records followed by the Poly1305 authentication tag. |

All Base64 values use the standard alphabet with padding.

After decryption, the payload is a UTF-8 JSON array of records.
An empty store encrypts [].

For example, the following is a decrypted payload containing a single record:

```json
[
  {
    "secret": "cGFzc3dvcmQ=",
    "id": 0,
    "label": "Example credential",
    "collection": "default",
    "attributes": {"service": "example", "username": "luca"}
  }
]
```

Each record contains the following fields:
- `secret`: The secret as a Base64 string.
- `id`: The numeric ID of the record.
- `label`: A human-readable label for the record.
- `collection`: The name of the collection to which the record belongs.
- `attributes`: A map of string attributes.

## Encryption

The application supplies a secret, HKDF-SHA256 derives a 32-byte encryption key
from that secret using the store's 16-byte salt and the string `secret-file-keyring-store/1/encryption-key`.

On each write, the complete record array is serialized to JSON and encrypted with
XChaCha20-Poly1305 using the derived key and a fresh 24-byte nonce.

The AAD used in XChaCha20-Poly1305 is the concatenation of the format version
(4 bytes, little-endian), `next_id` (8 bytes, little-endian), and the 16-byte salt.

The `ciphertext` field holds the encrypted bytes with the 16-byte Poly1305
authentication tag appended. The tag authenticates both the ciphertext and the AAD,
and is verified before any record is parsed.

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/secret-file-keyring-store/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
