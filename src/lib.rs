/*!
# Secret portal credential store for keyring

This crate stores credentials in an encrypted JSON file, using an application
secret retrieved from the desktop Secret portal. Opening a store may prompt
the user for access.

## Configuration

Use [`Store::new_with_configuration`] with the required `keyring-file` key:

```no_run
use std::collections::HashMap;
use zbus_secret_portal_keyring_store::Store;

let store = Store::new_with_configuration(&HashMap::from([
    ("keyring-file", "/path/to/application/keyring.json"),
]))?;
keyring_core::set_default_store(store);
# Ok::<(), keyring_core::Error>(())
```
## Credentials and attributes

Credentials are found by their `service` and `username` attributes. A `target`
modifier adds a target attribute and groups newly created items into the named
collection; otherwise items belong to the default collection. Searches span
all collections, so an entry without a target can match multiple items.
Ambiguous matches return [`keyring_core::Error::Ambiguous`].

The `label` modifier sets a new item's label; its default is
`keyring:{user}@{service}`. Labels are accessible through [`cred::Specifier`]
and [`cred::Wrapper`]. Each stored item has a stable ID exposed by
[`cred::Wrapper::get_id`]. Additional attributes can be searched and updated.
Specifier updates cannot change `service`, `username`, or `target`.
*/

/// Credentials for Secret portal file store.
pub mod cred;
pub mod errors;
mod service;
/// The credential store backed by the Secret portal.
pub mod store;
pub use store::Store;
#[cfg(test)]
mod tests;
