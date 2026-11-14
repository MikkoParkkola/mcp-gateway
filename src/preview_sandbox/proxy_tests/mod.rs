// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! P1 rows C1-C11 (and R1-R3): the allowlist proxy admits only the three
//! registries on 443, behind a per-fetch credential, and dials only pinned,
//! permitted addresses. The three injected parts are unit-test fakes here, not
//! the `sandbox-fixtures` seams.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixStream};

use super::{AllowlistProxy, Connect, Credential, Interfaces, Owned, Resolve};

mod allowlist;
mod bounds;
mod credential;
mod deny;
mod deny_vectors;
mod hardening;
mod host_addresses;
mod session;
mod teardown;
mod tunnels;

/// A globally routable address no deny rule covers.
const GLOBAL: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
/// A second public address, distinct from [`GLOBAL`], that no deny rule covers.
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
const NPM: &str = "registry.npmjs.org";

/// Suspends a fake call until the test releases it (C10).
#[derive(Default)]
struct Gate {
    on: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Gate {
    fn close(&self) {
        self.on.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn pass(&self) {
        if self.on.load(std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
}

#[derive(Default)]
struct FakeResolve {
    table: Mutex<HashMap<String, Vec<IpAddr>>>,
    gate: Gate,
}

impl FakeResolve {
    fn set(&self, host: &str, addrs: Vec<IpAddr>) {
        self.table
            .lock()
            .expect("lock")
            .insert(host.to_owned(), addrs);
    }
}

#[async_trait]
impl Resolve for FakeResolve {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.gate.pass().await;
        self.table
            .lock()
            .expect("lock")
            .get(host)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
    }
}

/// Records every dial, then connects to the local echo server, or to `target`
/// when a row has set one.
struct FakeConnect {
    dials: Mutex<Vec<SocketAddr>>,
    echo: SocketAddr,
    gate: Gate,
    /// Runs as the dial completes, once the connection is made: a row's way to make
    /// something happen at the exact moment the dial completes.
    on_dial: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// A dial to this address never completes.
    hang: Mutex<Option<SocketAddr>>,
    /// A row's upstream. `None` dials the echo server.
    target: Mutex<Option<SocketAddr>>,
}

impl FakeConnect {
    fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().expect("lock").clone()
    }
}

#[async_trait]
impl Connect for FakeConnect {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.dials.lock().expect("lock").push(addr);
        if *self.hang.lock().expect("lock") == Some(addr) {
            std::future::pending::<()>().await;
        }
        self.gate.pass().await;
        let target = (*self.target.lock().expect("lock")).unwrap_or(self.echo);
        let stream = TcpStream::connect(target).await?;
        // After the connection is made, in the poll that returns it: the
        // dial is complete when the hook runs.
        if let Some(hook) = self.on_dial.lock().expect("lock").as_ref() {
            hook();
        }
        Ok(stream)
    }
}

/// The host's networks; `None` makes the read fail.
struct FakeInterfaces(Mutex<Option<Vec<Owned>>>);

impl Interfaces for FakeInterfaces {
    fn addresses(&self) -> io::Result<Vec<Owned>> {
        self.0
            .lock()
            .expect("lock")
            .clone()
            .ok_or_else(|| io::Error::other("the interface read failed"))
    }
}

struct Rig {
    proxy: AllowlistProxy,
    resolve: Arc<FakeResolve>,
    connect: Arc<FakeConnect>,
    interfaces: Arc<FakeInterfaces>,
}

/// A rig whose registry names resolve to [`GLOBAL`].
async fn rig() -> Rig {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let echo_addr = echo.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let resolve = Arc::new(FakeResolve::default());
    for host in [NPM, "pypi.org", "files.pythonhosted.org"] {
        resolve.set(host, vec![GLOBAL]);
    }
    let connect = Arc::new(FakeConnect {
        dials: Mutex::new(Vec::new()),
        echo: echo_addr,
        gate: Gate::default(),
        on_dial: Mutex::new(None),
        hang: Mutex::new(None),
        target: Mutex::new(None),
    });
    let interfaces = Arc::new(FakeInterfaces(Mutex::new(Some(Vec::new()))));
    let proxy = AllowlistProxy::bind(resolve.clone(), connect.clone(), interfaces.clone())
        .expect("proxy bind");
    Rig {
        proxy,
        resolve,
        connect,
        interfaces,
    }
}

fn begin(rig: &Rig) -> Credential {
    rig.proxy
        .begin_fetch(tokio::time::Instant::now() + Duration::from_secs(60))
        .expect("credential")
}

/// Raw CONNECT bytes for `authority`, with an optional auth header value.
fn connect_bytes(authority: &str, auth: Option<&str>) -> Vec<u8> {
    let mut s = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(v) = auth {
        write!(s, "Proxy-Authorization: {v}\r\n").expect("String write");
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// Read until the blank line ending the response head, or EOF or a timeout.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    let read = async {
        while !out.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte).await {
                Ok(1) => out.push(byte[0]),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(30), read).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// The numeric status of a response head; 0 when there is none (closed).
fn status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Send `bytes` and return the response head.
async fn send(rig: &Rig, bytes: &[u8]) -> String {
    match open(rig, bytes).await {
        Some(mut s) => s.head().await,
        None => String::new(),
    }
}

struct Opened(UnixStream);

impl Opened {
    async fn head(&mut self) -> String {
        read_head(&mut self.0).await
    }

    async fn echoes(&mut self) -> bool {
        tunnel_echoes(&mut self.0).await
    }

    /// True when the stream is dead: a write or read fails or hits EOF.
    async fn closed(&mut self) -> bool {
        !self.echoes().await
    }

    /// The same connection as a plain non-blocking socket, which answers a
    /// read at once, with no event loop between the caller and the kernel.
    fn into_plain(self) -> Plain {
        Plain(self.0.into_std().expect("std unix stream"))
    }
}

/// A connection read without an event loop (see [`Opened::into_plain`]).
struct Plain(std::os::unix::net::UnixStream);

impl Plain {
    /// True when the peer has already shut the connection down: the read
    /// answers end-of-file or a reset. A read that would block, or data, is
    /// false. Never awaits, so no proxy task runs between two calls.
    fn peer_has_shut_down(&mut self) -> bool {
        use std::io::{ErrorKind, Read as _};
        let mut byte = [0u8; 1];
        match self.0.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => e.kind() != ErrorKind::WouldBlock,
        }
    }
}

/// Connect and write `bytes`; `None` when the connection itself is refused.
async fn open(rig: &Rig, bytes: &[u8]) -> Option<Opened> {
    let mut s = UnixStream::connect(rig.proxy.unix_path()).await.ok()?;
    s.write_all(bytes).await.ok()?;
    Some(Opened(s))
}

/// CONNECT `authority` with `cred`'s header; the response status.
async fn connect_status(rig: &Rig, authority: &str, cred: &Credential) -> u16 {
    let bytes = connect_bytes(authority, Some(&cred.basic()));
    status(&send(rig, &bytes).await)
}

/// After a 200, bytes written to the tunnel come back from the echo server.
async fn tunnel_echoes<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S) -> bool {
    if s.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    matches!(
        tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && &buf == b"ping"
}

/// A test address literal.
fn ip(s: &str) -> IpAddr {
    s.parse().unwrap_or_else(|_| panic!("bad address {s}"))
}

/// The production parts on Linux: the host's interface read finds the loopback
/// address, so the deny check against the host's own addresses has something
/// to compare with.
#[cfg(target_os = "linux")]
#[test]
fn s8_the_system_interfaces_include_loopback() {
    let own = super::System.addresses().expect("getifaddrs answers");
    assert!(
        own.contains(&(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)),
        "the host's own addresses lack loopback: {own:?}"
    );
}
