# Secret portal keyring store

[![build](https://github.com/open-source-cooperative/zbus-secret-portal-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/zbus-secret-portal-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/zbus-secret-portal-keyring-store.svg?style=flat-square)](https://crates.io/crates/zbus-secret-portal-keyring-store) [![docs.rs](https://docs.rs/zbus-secret-portal-keyring-store/badge.svg)](https://docs.rs/zbus-secret-portal-keyring-store) [![codecov](https://codecov.io/gh/open-source-cooperative/zbus-secret-portal-keyring-store/graph/badge.svg)](https://codecov.io/gh/open-source-cooperative/zbus-secret-portal-keyring-store)

This library stores credentials in an encrypted JSON file for the keyring ecosystem.
It retrieves the application's secret through the [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).

## Usage

```rust
use std::collections::HashMap;
use zbus_secret_portal_keyring_store::Store;

let store = Store::new_with_configuration(&HashMap::from([
    ("keyring-file", "/path/to/application/keyring.json"),
]))?;
keyring_core::set_default_store(store);
```

# Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/zbus-secret-portal-keyring-store/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
