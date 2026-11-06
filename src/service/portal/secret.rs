use std::collections::HashMap;
use std::io::Read;
use std::os::unix::net::UnixStream;

use zbus::blocking::Connection;
use zbus::zvariant::{Fd, OwnedObjectPath, OwnedValue, Value};

use crate::errors::platform_failure;
use keyring_core::error::{Error, Result};

#[zbus::proxy(
    interface = "org.freedesktop.portal.Secret",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait Secret {
    fn retrieve_secret(
        &self,
        fd: Fd<'_>,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.portal.Request",
    default_service = "org.freedesktop.portal.Desktop"
)]
trait Request {
    #[zbus(signal)]
    fn response(&self, response: u32, results: HashMap<String, OwnedValue>) -> zbus::Result<()>;
}

pub(crate) fn retrieve(previous_token: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
    let connection = Connection::session().map_err(platform_failure)?;

    // SENDER is the caller's unique name, with the initial ':' removed and all '.' replaced by '_'
    let sender = connection
        .unique_name()
        .ok_or_else(|| platform_failure(std::io::Error::other("Connection has no unique name")))?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");

    // TOKEN is a unique token that the caller provided
    // <snip> it is a good idea to use a per-library prefix combined with a random number.
    let handle_token = format!("keyring_{}_{}", std::process::id(), rand::random::<u64>());

    // The handle will be of the form /org/freedesktop/portal/desktop/request/SENDER/TOKEN
    let expected_handle =
        format!("/org/freedesktop/portal/desktop/request/{sender}/{handle_token}");
    let request = RequestProxyBlocking::builder(&connection)
        .path(expected_handle.as_str())
        .map_err(platform_failure)?
        .build()
        .map_err(platform_failure)?;
    let mut responses = request.receive_response().map_err(platform_failure)?;

    let (mut rx, tx) = UnixStream::pair().map_err(platform_failure)?;

    let mut options = HashMap::from([("handle_token", Value::from(handle_token.as_str()))]);
    if let Some(token) = previous_token {
        options.insert("token", Value::from(token));
    }

    let handle = SecretProxyBlocking::new(&connection)
        .map_err(platform_failure)?
        .retrieve_secret(Fd::from(&tx), options)
        .map_err(platform_failure)?;
    drop(tx);

    // It is recommended that the caller should verify that the returned handle is what it expected
    if handle.as_str() != expected_handle {
        return Err(platform_failure(std::io::Error::other(format!(
            "Secret portal returned unexpected request handle: expected {expected_handle}, got {handle}",
        ))));
    }

    let msg = responses.next().ok_or_else(|| {
        platform_failure(std::io::Error::other(
            "Portal disconnected before responding",
        ))
    })?;
    let args = msg.args().map_err(platform_failure)?;

    let status = *args.response();
    if status != 0 {
        return Err(Error::NoStorageAccess(Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Secret portal response {status}"),
        ))));
    }

    let results = args.results();
    let token = results
        .get("token")
        .map(|v| v.downcast_ref::<String>().map_err(platform_failure))
        .transpose()?;

    let mut secret = Vec::new();
    rx.read_to_end(&mut secret).map_err(platform_failure)?;

    Ok((secret, token))
}
