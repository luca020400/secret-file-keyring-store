//! Error utilities.

use keyring_core::error::Error;

/// Wrap an underlying error as a platform failure.
pub fn platform_failure(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::PlatformFailure(Box::new(err))
}
