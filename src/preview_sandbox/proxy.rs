// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The allowlist proxy for a command preview's fetch phase (ADR-027, "The
//! allowlist proxy"): an HTTP CONNECT proxy on loopback that admits only the
//! package registries, behind a fresh credential per fetch.
//!
//! This is a placeholder: it binds its listeners and closes every
//! connection, so the tests in `proxy_tests.rs` are red until the real proxy
//! replaces it.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::task::JoinHandle;

/// Name resolution for an allowlisted host.
#[async_trait]
pub(crate) trait Resolve: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The outbound dial, made only to an address that passed every check.
#[async_trait]
pub(crate) trait Connect: Send + Sync {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream>;
}

/// The host's own interface addresses, read on every call (never cached).
pub(crate) trait Interfaces: Send + Sync {
    fn addresses(&self) -> Vec<IpAddr>;
}

/// One fetch's proxy credential. No `Debug`: it carries the secret.
#[derive(Clone)]
pub(crate) struct Credential {
    secret: String,
}

impl Credential {
    /// The random token, URL-safe base64 without padding.
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }

    /// The `Proxy-Authorization` header value for this credential: `Basic `
    /// plus base64 of `<secret>:` (the secret is the proxy URL's user part).
    pub(crate) fn basic(&self) -> String {
        use base64::Engine as _;
        let raw = format!("{}:", self.secret);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }
}

/// The gateway's allowlist proxy: loopback TCP (IPv4, and IPv6 when
/// available, one port) plus a Unix-socket entry.
pub(crate) struct AllowlistProxy {
    port: u16,
    unix_path: PathBuf,
    tasks: Vec<JoinHandle<()>>,
}

impl AllowlistProxy {
    /// Bind `127.0.0.1:0`, the same port on `::1` if available, and a Unix
    /// socket in a fresh temp directory.
    pub(crate) async fn bind(
        _resolve: Arc<dyn Resolve>,
        _connect: Arc<dyn Connect>,
        _interfaces: Arc<dyn Interfaces>,
    ) -> io::Result<Self> {
        let v4 = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = v4.local_addr()?.port();
        let mut tasks = vec![tokio::spawn(close_tcp(v4))];
        if let Ok(v6) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await {
            tasks.push(tokio::spawn(close_tcp(v6)));
        }
        let dir = std::env::temp_dir().join(format!("mcp-gw-proxy-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let unix_path = dir.join("proxy.sock");
        let unix = UnixListener::bind(&unix_path)?;
        tasks.push(tokio::spawn(async move {
            while let Ok((stream, _)) = unix.accept().await {
                drop(stream);
            }
        }));
        Ok(Self {
            port,
            unix_path,
            tasks,
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }

    /// Start a fetch: a fresh credential, valid until [`Self::expire`].
    pub(crate) fn begin_fetch(&self) -> Credential {
        Credential {
            secret: "placeholder-credential".to_owned(),
        }
    }

    /// End a fetch: the credential stops working and its tunnels close.
    pub(crate) fn expire(&self, _credential: &Credential) {}
}

impl Drop for AllowlistProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn close_tcp(listener: TcpListener) {
    while let Ok((stream, _)) = listener.accept().await {
        drop(stream);
    }
}

#[cfg(test)]
#[path = "proxy_deny_vectors.rs"]
mod deny_vectors;

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
