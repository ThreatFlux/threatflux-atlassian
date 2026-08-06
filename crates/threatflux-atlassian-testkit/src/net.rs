//! Loopback addresses for transport-level tests.

use std::net::TcpListener;

/// The literal loopback host the SDK's loopback host policy admits.
pub const LOOPBACK_HOST: &str = "127.0.0.1";

/// Returns a loopback port that refuses connections.
///
/// A listener is bound to claim an unused port and then dropped, so a connection
/// attempt fails at connect time rather than hanging. Nothing stops the kernel
/// from handing the port to another process afterwards, so call it immediately
/// before the connection under test.
///
/// # Panics
///
/// Panics if no loopback port can be bound at all.
pub fn closed_loopback_port() -> u16 {
    let listener =
        TcpListener::bind((LOOPBACK_HOST, 0)).expect("a loopback port should be bindable");
    let port = listener
        .local_addr()
        .expect("a bound listener should have an address")
        .port();
    drop(listener);
    port
}

/// Returns an `http://` URL on a loopback port that refuses connections.
pub fn closed_loopback_url() -> String {
    loopback_url(closed_loopback_port())
}

/// Returns the `http://` loopback URL for `port`.
pub fn loopback_url(port: u16) -> String {
    format!("http://{LOOPBACK_HOST}:{port}")
}

#[cfg(test)]
mod tests {
    use super::{closed_loopback_port, closed_loopback_url, loopback_url, LOOPBACK_HOST};
    use std::net::TcpStream;

    #[test]
    fn closed_port_refuses_connections() {
        let port = closed_loopback_port();
        assert!(TcpStream::connect((LOOPBACK_HOST, port)).is_err());
    }

    #[test]
    fn urls_are_loopback_http() {
        assert_eq!(loopback_url(8080), "http://127.0.0.1:8080");
        assert!(closed_loopback_url().starts_with("http://127.0.0.1:"));
    }
}
