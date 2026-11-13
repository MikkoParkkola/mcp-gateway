// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The allowlist proxy for a command preview's fetch phase (ADR-027, "The
//! allowlist proxy"): an HTTP CONNECT proxy on loopback that admits only the
//! package registries, behind a fresh credential per fetch.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the fetch session, a later part, calls the proxy")
)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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

/// The host's own interface addresses, read on every call (never cached). A
/// failed read refuses the CONNECT: an empty list would admit the host.
pub(crate) trait Interfaces: Send + Sync {
    fn addresses(&self) -> io::Result<Vec<IpAddr>>;
}

/// Fills a buffer from the OS random source; injectable so a row can make it
/// fail.
type Random = fn(&mut [u8]) -> io::Result<()>;

fn os_random(bytes: &mut [u8]) -> io::Result<()> {
    use ring::rand::SecureRandom as _;
    ring::rand::SystemRandom::new()
        .fill(bytes)
        .map_err(|_| io::Error::other("the OS random source failed"))
}

/// One fetch's proxy credential. No `Debug`: it carries the secret.
#[derive(Clone)]
pub(crate) struct Credential {
    secret: String,
}

impl Credential {
    /// 32 bytes from the OS random source, URL-safe base64 without padding,
    /// so it sits in a proxy URL's user part with no escaping.
    fn fresh(random: Random) -> io::Result<Self> {
        use base64::Engine as _;
        let mut bytes = [0u8; 32];
        random(&mut bytes)?;
        Ok(Self {
            secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        })
    }

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

/// One socket of a tunnel, kept as a duplicate descriptor so a revoke can shut
/// it down directly, without waiting for any task to be polled.
enum Half {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

impl Half {
    /// Both directions; a socket already closed is no error.
    fn shut(&self) {
        let _ = match self {
            Self::Tcp(s) => s.shutdown(std::net::Shutdown::Both),
            Self::Unix(s) => s.shutdown(std::net::Shutdown::Both),
        };
    }
}

/// The fetch in progress: its credential, the token that wakes every tunnel
/// task opened under it, and the sockets of every open tunnel.
struct Live {
    id: u64,
    credential: Credential,
    closed: CancellationToken,
    tunnels: HashMap<u64, [Half; 2]>,
    next_tunnel: u64,
}

impl Live {
    /// End the fetch: wake the tunnel tasks, and shut every tunnel's sockets
    /// now. Called with the fetch already taken out of the proxy, so nothing
    /// can register a tunnel into it any more.
    fn end(self) {
        self.closed.cancel();
        for halves in self.tunnels.values() {
            for half in halves {
                half.shut();
            }
        }
    }
}

struct Shared {
    live: Mutex<Option<Live>>,
    /// Counts fetches, so a tunnel admitted under one fetch can never be
    /// registered into the next.
    fetches: std::sync::atomic::AtomicU64,
    resolve: Arc<dyn Resolve>,
    connect: Arc<dyn Connect>,
    interfaces: Arc<dyn Interfaces>,
}

/// The gateway's allowlist proxy: loopback TCP (IPv4, and IPv6 when
/// available, one port) plus a Unix-socket entry.
pub(crate) struct AllowlistProxy {
    port: u16,
    unix_path: PathBuf,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    random: Random,
}

impl AllowlistProxy {
    /// Bind `127.0.0.1:0`, the same port on `::1` if available, and a Unix
    /// socket in a fresh owner-only temp directory. The listeners stay bound
    /// for the proxy's life; outside a fetch they answer 407 to everything.
    ///
    /// Synchronous on purpose: the sockets are bound with `std` and handed to
    /// tokio, so the gateway-lifetime proxy needs no `await` to exist. The
    /// accept tasks are spawned, so a runtime context must be current.
    pub(crate) fn bind(
        resolve: Arc<dyn Resolve>,
        connect: Arc<dyn Connect>,
        interfaces: Arc<dyn Interfaces>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            live: Mutex::new(None),
            fetches: std::sync::atomic::AtomicU64::new(0),
            resolve,
            connect,
            interfaces,
        });
        let v4 = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        v4.set_nonblocking(true)?;
        let port = v4.local_addr()?.port();
        let mut tasks = vec![tokio::spawn(serve_tcp(
            TcpListener::from_std(v4)?,
            shared.clone(),
        ))];
        let v6 = std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port))
            .and_then(|l| l.set_nonblocking(true).map(|()| l))
            .and_then(TcpListener::from_std);
        if let Ok(v6) = v6 {
            tasks.push(tokio::spawn(serve_tcp(v6, shared.clone())));
        }
        let dir = std::env::temp_dir().join(format!("mcp-gw-proxy-{}-{port}", std::process::id()));
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        let unix_path = dir.join("proxy.sock");
        let unix = std::os::unix::net::UnixListener::bind(&unix_path)?;
        unix.set_nonblocking(true)?;
        let unix = UnixListener::from_std(unix)?;
        let unix_shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok((stream, _)) = unix.accept().await {
                tokio::spawn(handle(stream, unix_shared.clone()));
            }
        }));
        Ok(Self {
            port,
            unix_path,
            shared,
            tasks,
            random: os_random,
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }

    /// How many tunnels the live fetch has open, for the rows.
    #[cfg(test)]
    pub(crate) fn open_tunnels(&self) -> usize {
        lock(&self.shared.live)
            .as_ref()
            .map_or(0, |l| l.tunnels.len())
    }

    /// Start a fetch: a fresh credential, valid until [`Self::revoke`]. Any
    /// earlier fetch's credential and tunnels end here too. A failed random
    /// source refuses this preview only; the gateway carries on.
    pub(crate) fn begin_fetch(&self) -> Result<Credential, super::Refusal> {
        // The old fetch leaves and the new one arrives under one lock hold,
        // so no tunnel can register into either in between.
        let mut live = lock(&self.shared.live);
        let old = live.take();
        let made = Credential::fresh(self.random).map(|credential| {
            let id = self
                .shared
                .fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *live = Some(Live {
                id,
                credential: credential.clone(),
                closed: CancellationToken::new(),
                tunnels: HashMap::new(),
                next_tunnel: 0,
            });
            credential
        });
        drop(live);
        if let Some(old) = old {
            old.end();
        }
        made.map_err(|e| super::Refusal::Step(format!("generating the fetch credential ({e})")))
    }

    /// Revoke a fetch's credential: it stops working and its tunnels close.
    pub(crate) fn revoke(&self, credential: &Credential) {
        let old = {
            let mut live = lock(&self.shared.live);
            if live
                .as_ref()
                .is_some_and(|l| l.credential.secret == credential.secret)
            {
                live.take()
            } else {
                None
            }
        };
        if let Some(old) = old {
            old.end();
        }
    }
}

impl Drop for AllowlistProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let live = lock(&self.shared.live).take();
        if let Some(live) = live {
            live.end();
        }
        if let Some(dir) = self.unix_path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// The lock holds no invariant a panic could break, so a poisoned one is used.
fn lock(m: &Mutex<Option<Live>>) -> std::sync::MutexGuard<'_, Option<Live>> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle(stream, shared.clone()));
    }
}

/// The only authorities a CONNECT may name, compared byte for byte: no case
/// folding, no trailing dot, no percent-decoding, port 443 written plainly.
const ALLOWED: [&str; 3] = [
    "registry.npmjs.org:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
];

/// The longest request head read; npm and uv send a few hundred bytes.
const MAX_HEAD: usize = 8 * 1024;

/// A refusal's status line. The text is fixed, so nothing a client sent
/// (the credential included) is ever echoed back.
#[derive(Clone, Copy, Debug)]
enum Status {
    BadRequest,
    AuthRequired,
    Forbidden,
    BadMethod,
    BadGateway,
}

impl Status {
    fn head(self) -> &'static [u8] {
        match self {
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::AuthRequired => b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"preview\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::BadMethod => b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        }
    }
}

/// A stream a tunnel can run over: its duplicate descriptor is what a revoke
/// shuts down.
trait Tunnel: AsyncRead + AsyncWrite + Unpin + Send {
    fn half(&self) -> io::Result<Half>;
}

impl Tunnel for TcpStream {
    fn half(&self) -> io::Result<Half> {
        use std::os::fd::AsFd as _;
        Ok(Half::Tcp(std::net::TcpStream::from(
            self.as_fd().try_clone_to_owned()?,
        )))
    }
}

impl Tunnel for tokio::net::UnixStream {
    fn half(&self) -> io::Result<Half> {
        use std::os::fd::AsFd as _;
        Ok(Half::Unix(std::os::unix::net::UnixStream::from(
            self.as_fd().try_clone_to_owned()?,
        )))
    }
}

/// The fetch a request was admitted under.
struct Fetch {
    id: u64,
    closed: CancellationToken,
}

/// Record a tunnel's two sockets under its fetch, if that fetch is still the
/// live one: the check and the insert are one lock hold, so a revoke either
/// sees the tunnel (and shuts it) or has already made this return `None`.
fn register(shared: &Shared, fetch: &Fetch, halves: [Half; 2]) -> Option<u64> {
    let mut live = lock(&shared.live);
    let live = live.as_mut().filter(|l| l.id == fetch.id)?;
    let id = live.next_tunnel;
    live.next_tunnel += 1;
    live.tunnels.insert(id, halves);
    Some(id)
}

/// Forget a finished tunnel's sockets.
fn unregister(shared: &Shared, fetch: &Fetch, tunnel: u64) {
    if let Some(live) = lock(&shared.live).as_mut().filter(|l| l.id == fetch.id) {
        live.tunnels.remove(&tunnel);
    }
}

async fn handle<S>(mut client: S, shared: Arc<Shared>)
where
    S: Tunnel,
{
    match admit(&mut client, &shared).await {
        Ok((mut upstream, fetch)) => {
            let halves = match (client.half(), upstream.half()) {
                (Ok(a), Ok(b)) => [a, b],
                _ => {
                    let _ = client.write_all(Status::BadGateway.head()).await;
                    return;
                }
            };
            // Registered before the 200 goes out: a fetch revoked meanwhile
            // never gets a tunnel it could use.
            let Some(tunnel) = register(&shared, &fetch, halves) else {
                let _ = client.write_all(Status::AuthRequired.head()).await;
                return;
            };
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_ok()
            {
                // A revoke shuts both sockets itself; the token is the
                // wake-up for this task.
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                    () = fetch.closed.cancelled() => {}
                }
            }
            unregister(&shared, &fetch, tunnel);
        }
        Err(status) => {
            tracing::debug!(?status, "preview proxy refused a request");
            let _ = client.write_all(status.head()).await;
        }
    }
}

/// Every check, in order; the tunnel's upstream and its fetch's close token
/// when all pass.
async fn admit<S>(client: &mut S, shared: &Shared) -> Result<(TcpStream, Fetch), Status>
where
    S: AsyncRead + Unpin,
{
    let head = read_head(client).await.ok_or(Status::BadRequest)?;
    let mut lines = head.split("\r\n");
    let parts: Vec<&str> = lines.next().unwrap_or_default().split(' ').collect();
    let [method, authority, version] = parts[..] else {
        return Err(Status::BadRequest);
    };
    if method != "CONNECT" {
        return Err(Status::BadMethod);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Status::BadRequest);
    }
    let mut auth = Vec::new();
    let mut host = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Status::BadRequest)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("proxy-authorization") {
            auth.push(value);
        } else if name.eq_ignore_ascii_case("host") {
            host.push(value);
        }
    }
    let fetch = authorized(&auth, shared).ok_or(Status::AuthRequired)?;
    if !ALLOWED.contains(&authority) {
        return Err(Status::Forbidden);
    }
    // A Host header, when sent, names the same place (with or without port).
    let name = authority.trim_end_matches(":443");
    match host[..] {
        [] => {}
        [h] if h == authority || h == name => {}
        _ => return Err(Status::BadRequest),
    }
    let addrs = shared
        .resolve
        .resolve(name)
        .await
        .map_err(|_| Status::BadGateway)?;
    if fetch.closed.is_cancelled() {
        return Err(Status::AuthRequired);
    }
    // One denied address refuses the whole answer, so a mixed answer cannot
    // fall through to its bad half on a retry.
    let own = shared
        .interfaces
        .addresses()
        .map_err(|_| Status::Forbidden)?;
    if addrs.is_empty() || addrs.iter().any(|a| denied(*a, &own)) {
        return Err(Status::Forbidden);
    }
    let mut upstream = None;
    for addr in addrs {
        if let Ok(s) = shared.connect.connect(SocketAddr::new(addr, 443)).await {
            upstream = Some(s);
            break;
        }
    }
    let upstream = upstream.ok_or(Status::BadGateway)?;
    if fetch.closed.is_cancelled() {
        return Err(Status::AuthRequired);
    }
    Ok((upstream, fetch))
}

/// The live fetch's close token when exactly one `Proxy-Authorization`
/// header carries its credential as `Basic base64(<secret>:)`.
fn authorized(auth: &[&str], shared: &Shared) -> Option<Fetch> {
    use base64::Engine as _;
    use subtle::ConstantTimeEq as _;
    let [value] = auth else { return None };
    let token = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let live = lock(&shared.live);
    let live = live.as_ref()?;
    let expected = format!("{}:", live.credential.secret);
    bool::from(decoded.ct_eq(expected.as_bytes())).then(|| Fetch {
        id: live.id,
        closed: live.closed.clone(),
    })
}

/// The SSRF deny list, or one of the host's own addresses. Mapped and
/// compatible IPv6 forms are unwrapped first (`is_private_or_reserved`
/// already unwraps them for its own ranges).
fn denied(addr: IpAddr, own: &[IpAddr]) -> bool {
    let plain = |a: IpAddr| match a {
        IpAddr::V6(v6) => v6.to_ipv4().map_or(a, IpAddr::V4),
        IpAddr::V4(_) => a,
    };
    crate::security::ssrf::is_private_or_reserved(addr)
        || own.iter().any(|o| plain(*o) == plain(addr))
}

/// The request head up to its blank line, read a byte at a time so no
/// tunnel bytes are consumed; `None` on EOF, oversize, non-UTF-8 or a
/// client too slow to send it.
// ponytail: byte-at-a-time reads; a few CONNECTs per preview, so the syscall
// count does not matter.
async fn read_head<S: AsyncRead + Unpin>(client: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let read = async {
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_HEAD || client.read(&mut byte).await.ok()? == 0 {
                return None;
            }
            head.push(byte[0]);
        }
        Some(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), read)
        .await
        .ok()??;
    head.truncate(head.len() - 4);
    String::from_utf8(head).ok()
}

/// The production parts on Linux: the system resolver (the proxy applies the
/// SSRF deny list to its answer itself and dials only what it checked), a
/// plain dial, and the host's interfaces through nix's safe `getifaddrs`.
#[cfg(target_os = "linux")]
pub(crate) struct System;

#[cfg(target_os = "linux")]
#[async_trait]
impl Resolve for System {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        use crate::security::ssrf::HostResolver as _;
        crate::security::ssrf::SystemResolver
            .lookup(host)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl Connect for System {
    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

#[cfg(target_os = "linux")]
impl Interfaces for System {
    fn addresses(&self) -> io::Result<Vec<IpAddr>> {
        let all = nix::ifaddrs::getifaddrs().map_err(io::Error::from)?;
        Ok(all
            .filter_map(|i| {
                let a = i.address?;
                a.as_sockaddr_in()
                    .map(|v4| IpAddr::V4(v4.ip()))
                    .or_else(|| a.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))
            })
            .collect())
    }
}

#[cfg(test)]
#[path = "proxy_tests/mod.rs"]
mod tests;
