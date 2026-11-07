# Secret file keyring store

[![build](https://github.com/open-source-cooperative/secret-file-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/secret-file-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/secret-file-keyring-store.svg?style=flat-square)](https://crates.io/crates/secret-file-keyring-store) [![docs.rs](https://docs.rs/secret-file-keyring-store/badge.svg)](https://docs.rs/secret-file-keyring-store) [![codecov](https://codecov.io/gh/open-source-cooperative/secret-file-keyring-store/graph/badge.svg)](https://codecov.io/gh/open-source-cooperative/secret-file-keyring-store)

This library stores credentials in an encrypted JSON file for the keyring ecosystem.

## Usage

```rust
use secret_file_keyring_store::Store;

let store = Store::new("/path/to/application/keyring.json", &application_secret)?;
keyring_core::set_default_store(store);
```

# Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/secret-file-keyring-store/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
