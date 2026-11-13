// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The allowlist proxy for a command preview's fetch phase (ADR-027, "The
//! allowlist proxy"): an HTTP CONNECT proxy that serves one Unix socket in a
//! fresh owner-only directory, one proxy per preview, and admits only the
//! package registries, behind a fresh credential per fetch.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the fetch session, a later part, calls the proxy")
)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, UnixListener};
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
    /// 64 lowercase hex characters (32 random bytes), URL-safe as a proxy
    /// URL's password with no escaping.
    fn fresh(random: Random) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        random(&mut bytes)?;
        Ok(Self {
            secret: hex::encode(bytes),
        })
    }

    /// 64 lowercase hex characters (32 random bytes), URL-safe as a proxy
    /// URL's password with no escaping.
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }

    /// The `Proxy-Authorization` header value for this credential: `Basic `
    /// plus standard base64 of `x:<secret>` (user `x`, the secret as the
    /// password).
    pub(crate) fn basic(&self) -> String {
        use base64::Engine as _;
        let raw = format!("x:{}", self.secret);
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
    deadline: tokio::task::AbortHandle,
}

impl Live {
    /// End the fetch: wake the tunnel tasks, and shut every tunnel's sockets
    /// now. It runs with the proxy's `live` lock held, so a second revoker
    /// waits until every socket of this fetch is shut.
    fn end(self) {
        // Takes no lock on `live` and never awaits, so running it under that
        // lock cannot deadlock.
        self.deadline.abort();
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
    /// One permit per connection being served.
    permits: Arc<tokio::sync::Semaphore>,
    /// The time bounds; rows replace them.
    bounds: Mutex<Bounds>,
    /// Counts fetches, so a tunnel admitted under one fetch can never be
    /// registered into the next.
    fetches: std::sync::atomic::AtomicU64,
    resolve: Arc<dyn Resolve>,
    connect: Arc<dyn Connect>,
    interfaces: Arc<dyn Interfaces>,
    /// Runs at the start of a fetch's teardown, before its sockets shut.
    #[cfg(test)]
    on_end: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl Shared {
    /// End `live`. A test hook, when one is set, runs first.
    fn finish(&self, live: Live) {
        #[cfg(test)]
        {
            if let Some(hook) = self
                .on_end
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                hook();
            }
        }
        live.end();
    }

    fn revoke(&self, credential: &Credential) {
        // Finished under the lock: a second revoker waits for this teardown.
        let mut live = lock(&self.live);
        if let Some(old) = live.take_if(|l| l.credential.secret == credential.secret) {
            self.finish(old);
        }
    }
}

/// The gateway's allowlist proxy: one Unix socket in a fresh owner-only
/// directory, one proxy per preview.
pub(crate) struct AllowlistProxy {
    unix_path: PathBuf,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    random: Random,
}

impl AllowlistProxy {
    /// Bind one Unix socket in a fresh owner-only directory, one proxy per
    /// preview. The listener stays bound for the proxy's life; outside a
    /// fetch it answers 407 to everything.
    ///
    /// Synchronous on purpose: the sockets are bound with `std` and handed to
    /// tokio, so a preview's proxy needs no `await` to exist. The
    /// accept tasks are spawned, so a runtime context must be current.
    pub(crate) fn bind(
        resolve: Arc<dyn Resolve>,
        connect: Arc<dyn Connect>,
        interfaces: Arc<dyn Interfaces>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            live: Mutex::new(None),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            bounds: Mutex::new(BOUNDS),
            fetches: std::sync::atomic::AtomicU64::new(0),
            resolve,
            connect,
            interfaces,
            #[cfg(test)]
            on_end: Mutex::new(None),
        });
        // Every fallible step comes first, so a failure leaves no task or
        // directory behind; the task is spawned only once all is bound.
        let dir = private_dir()?;
        let unix_path = dir.join("proxy.sock");
        let unix = std::os::unix::net::UnixListener::bind(&unix_path)
            .and_then(|l| l.set_nonblocking(true).map(|()| l))
            .and_then(UnixListener::from_std)
            .inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&dir);
            })?;
        let tasks = vec![tokio::spawn(serve(unix, shared.clone()))];
        Ok(Self {
            unix_path,
            shared,
            tasks,
            random: os_random,
        })
    }

    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }

    /// Replace the time bounds, for the rows.
    #[cfg(test)]
    pub(crate) fn set_bounds(&self, bounds: Bounds) {
        *self
            .shared
            .bounds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = bounds;
    }

    /// How many tunnels the live fetch has open, for the rows.
    #[cfg(test)]
    pub(crate) fn open_tunnels(&self) -> usize {
        lock(&self.shared.live)
            .as_ref()
            .map_or(0, |l| l.tunnels.len())
    }

    /// Install `hook` to run at the start of the next teardown, for the rows.
    #[cfg(test)]
    pub(crate) fn set_on_end(&self, hook: Box<dyn Fn() + Send + Sync>) {
        *self
            .shared
            .on_end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// Start a fetch: a fresh credential, valid until [`Self::revoke`]. Any
    /// earlier fetch's credential and tunnels end here too. A failed random
    /// source refuses this preview only; the gateway carries on.
    ///
    /// The fetch ends at `deadline`.
    pub(crate) fn begin_fetch(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Credential, super::Refusal> {
        // The old fetch leaves and the new one arrives under one lock hold,
        // so no tunnel can register into either in between.
        let mut live = lock(&self.shared.live);
        let old = live.take();
        let made = Credential::fresh(self.random);
        if let Ok(credential) = &made {
            let id = self
                .shared
                .fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let shared = Arc::downgrade(&self.shared);
            let timer_credential = credential.clone();
            let timer = tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                if let Some(shared) = shared.upgrade() {
                    shared.revoke(&timer_credential);
                }
            });
            *live = Some(Live {
                id,
                credential: credential.clone(),
                closed: CancellationToken::new(),
                tunnels: HashMap::new(),
                next_tunnel: 0,
                deadline: timer.abort_handle(),
            });
        }
        if let Some(old) = old {
            self.shared.finish(old);
        }
        drop(live);
        made.map_err(|e| super::Refusal::Step(format!("generating the fetch credential ({e})")))
    }

    /// Revoke a fetch's credential: it stops working and its tunnels close.
    pub(crate) fn revoke(&self, credential: &Credential) {
        self.shared.revoke(credential);
    }
}

impl Drop for AllowlistProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        {
            let mut live = lock(&self.shared.live);
            if let Some(old) = live.take() {
                self.shared.finish(old);
            }
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

/// The most connections the proxy serves at once, tunnels included. A
/// preview's fetch opens a handful; the bound is generous, and exists so a
/// hostile local client cannot spend the gateway's descriptors and tasks
/// before any credential is checked.
const MAX_CONNECTIONS: usize = 64;

/// The proxy's time bounds; rows shorten them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// Admission.
    pub(crate) admit: Duration,
    /// The request head.
    pub(crate) head: Duration,
    /// Each dial.
    pub(crate) dial: Duration,
    /// A tunnel's life.
    pub(crate) splice: Duration,
}

/// The design's bounds.
pub(crate) const BOUNDS: Bounds = Bounds {
    admit: Duration::from_secs(30),
    head: Duration::from_secs(5),
    dial: Duration::from_secs(5),
    splice: Duration::from_secs(30),
};

/// Serve one accepted connection, or drop it (closing it) when the proxy
/// is already serving [`MAX_CONNECTIONS`].
fn serve_connection<S: Tunnel + 'static>(stream: S, shared: &Arc<Shared>) {
    let Ok(permit) = shared.permits.clone().try_acquire_owned() else {
        tracing::debug!("preview proxy at its connection bound; dropped a connection");
        return;
    };
    let shared = shared.clone();
    tokio::spawn(async move {
        let _permit = permit;
        handle(stream, shared).await;
    });
}

/// An accept error is usually transient (descriptors exhausted, a connection
/// aborted before it was accepted); the listener must outlive it.
async fn accept_failed(error: &io::Error) {
    tracing::debug!(%error, "preview proxy accept failed; carrying on");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

fn copy_bounds(m: &Mutex<Bounds>) -> Bounds {
    *m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A listener the accept loop can run over: a TCP or a Unix socket, or a
/// row's fake that fails on cue.
#[async_trait]
trait Accept: Send + Sync + 'static {
    type Stream: Tunnel + 'static;
    async fn accept(&self) -> io::Result<Self::Stream>;
}

#[async_trait]
impl Accept for UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept(&self) -> io::Result<tokio::net::UnixStream> {
        UnixListener::accept(self).await.map(|(stream, _)| stream)
    }
}

async fn serve<A: Accept>(listener: A, shared: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok(stream) => serve_connection(stream, &shared),
            Err(error) => accept_failed(&error).await,
        }
    }
}

/// Where a preview's private directory goes: `$XDG_RUNTIME_DIR` when it is
/// an absolute path, else the temp dir.
fn runtime_base(xdg: Option<std::ffi::OsString>) -> PathBuf {
    match xdg {
        Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
        _ => std::env::temp_dir(),
    }
}

/// A fresh owner-only directory under `$XDG_RUNTIME_DIR` when absolute, else
/// the temp dir, with a random name so another local user cannot pre-create
/// it; made exclusively, so an existing path is an error and a new name is
/// tried.
fn private_dir() -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut last = io::Error::other("no private directory name was free");
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        os_random(&mut bytes)?;
        let name = hex::encode(bytes);
        let dir =
            runtime_base(std::env::var_os("XDG_RUNTIME_DIR")).join(format!("mcp-gw-proxy-{name}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// The only authorities a CONNECT may name, compared after ASCII lowercasing:
/// no trailing dot, no percent-decoding, port 443 written plainly.
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

/// A tunnel's place in its fetch's registry, given up when this drops.
struct Registered {
    shared: Arc<Shared>,
    fetch: u64,
    tunnel: u64,
}

impl Drop for Registered {
    fn drop(&mut self) {
        if let Some(live) = lock(&self.shared.live)
            .as_mut()
            .filter(|l| l.id == self.fetch)
        {
            live.tunnels.remove(&self.tunnel);
        }
    }
}

async fn handle<S>(mut client: S, shared: Arc<Shared>)
where
    S: Tunnel,
{
    let bounds = copy_bounds(&shared.bounds);
    let admitted = tokio::time::timeout(bounds.admit, admit(&mut client, &shared, bounds))
        .await
        .unwrap_or(Err(Status::BadGateway));
    match admitted {
        Ok((mut upstream, fetch)) => {
            let (Ok(mine), Ok(theirs)) = (client.half(), upstream.half()) else {
                let _ = client.write_all(Status::BadGateway.head()).await;
                return;
            };
            let halves = [mine, theirs];
            // Registered before the 200 goes out: a fetch revoked meanwhile
            // never gets a tunnel it could use.
            let Some(tunnel) = register(&shared, &fetch, halves) else {
                let _ = client.write_all(Status::AuthRequired.head()).await;
                return;
            };
            // Leaves the registry however this task ends, a drop included.
            let _registered = Registered {
                shared: shared.clone(),
                fetch: fetch.id,
                tunnel,
            };
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_ok()
            {
                // A revoke shuts both sockets itself; the token is the
                // wake-up for this task. The tunnel's sockets close when
                // this task returns and `_registered` drops, which also
                // takes the tunnel out of the registry.
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                    () = fetch.closed.cancelled() => {}
                    () = tokio::time::sleep(bounds.splice) => {}
                }
            }
        }
        Err(status) => {
            tracing::debug!(?status, "preview proxy refused a request");
            let _ = client.write_all(status.head()).await;
        }
    }
}

/// Every check, in order; the tunnel's upstream and its fetch's close token
/// when all pass.
async fn admit<S>(
    client: &mut S,
    shared: &Shared,
    bounds: Bounds,
) -> Result<(TcpStream, Fetch), Status>
where
    S: AsyncRead + Unpin,
{
    let head = read_head(client, bounds.head)
        .await
        .ok_or(Status::BadRequest)?;
    let mut lines = head.split("\r\n");
    let parts: Vec<&str> = lines.next().unwrap_or_default().split(' ').collect();
    let [method, authority, version] = parts[..] else {
        return Err(Status::BadRequest);
    };
    let authority = authority.to_ascii_lowercase();
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
    if !ALLOWED.contains(&authority.as_str()) {
        return Err(Status::Forbidden);
    }
    // A Host header, when sent, names the same place (with or without port).
    let name = authority.trim_end_matches(":443");
    match host[..] {
        [] => {}
        [h] if h.to_ascii_lowercase() == authority || h.to_ascii_lowercase() == name => {}
        _ => return Err(Status::BadRequest),
    }
    let addrs = unless_revoked(&fetch.closed, shared.resolve.resolve(name))
        .await?
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
        let dialled = unless_revoked(
            &fetch.closed,
            tokio::time::timeout(
                bounds.dial,
                shared.connect.connect(SocketAddr::new(addr, 443)),
            ),
        )
        .await?;
        if let Ok(Ok(s)) = dialled {
            upstream = Some(s);
            break;
        }
    }
    // No liveness check after the dial: registering the tunnel is the one
    // check that counts there, made under the same lock a revoke takes.
    let upstream = upstream.ok_or(Status::BadGateway)?;
    Ok((upstream, fetch))
}

/// Runs `work` unless the fetch is revoked first, so a resolver or a dial that
/// never answers cannot keep a revoked fetch's connection alive.
async fn unless_revoked<T>(
    closed: &CancellationToken,
    work: impl std::future::Future<Output = T>,
) -> Result<T, Status> {
    tokio::select! {
        // Finished work wins a tie: the tunnel's registration is then the one
        // check that decides, and it refuses a revoked fetch.
        biased;
        out = work => Ok(out),
        () = closed.cancelled() => Err(Status::AuthRequired),
    }
}

/// The live fetch's close token when exactly one `Proxy-Authorization`
/// header carries its credential as `Basic base64(x:<secret>)`.
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
    let expected = format!("x:{}", live.credential.secret);
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
async fn read_head<S: AsyncRead + Unpin>(client: &mut S, bound: Duration) -> Option<String> {
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
    tokio::time::timeout(bound, read).await.ok()??;
    head.truncate(head.len() - 4);
    String::from_utf8(head).ok()
}

/// False only when the lookup failed with `NotFound`; true on success and every other error.
fn ipv6_tree_present(lookup: io::Result<()>) -> bool {
    lookup.is_ok()
}

/// `Ok(text)` is `Ok(Some(text))`; `NotFound` is `Ok(None)`; other errors are returned unchanged.
fn optional_text(read: io::Result<String>) -> io::Result<Option<String>> {
    read.map(Some)
}

/// The host's IPv4 addresses from `/proc/net/fib_trie`: every leaf with a
/// LOCAL route, in every table.
fn fib_trie_local(text: &str) -> io::Result<Vec<Ipv4Addr>> {
    let mut addresses = Vec::new();
    let mut current: Option<Ipv4Addr> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let line = line.trim();
        // A table header or an inner node: the next leaf starts afresh.
        if line.ends_with(':') || line.starts_with("+-- ") {
            current = None;
        } else if let Some(rest) = line.strip_prefix("|-- ") {
            current = Some(
                rest.parse()
                    .map_err(|_| io::Error::other(format!("bad fib_trie line: {line}")))?,
            );
        } else if line.starts_with('/') {
            let leaf =
                current.ok_or_else(|| io::Error::other(format!("bad fib_trie line: {line}")))?;
            if line.split_whitespace().next_back() == Some("LOCAL") && !addresses.contains(&leaf) {
                addresses.push(leaf);
            }
        } else {
            return Err(io::Error::other(format!("bad fib_trie line: {line}")));
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::other("no LOCAL entry in fib_trie"));
    }
    Ok(addresses)
}

/// The host's IPv6 addresses from `/proc/net/if_inet6`; a missing file means
/// no IPv6 only when the IPv6 sysctl tree is absent too.
fn if_inet6(text: Option<&str>, ipv6_sysctl_present: bool) -> io::Result<Vec<Ipv6Addr>> {
    let Some(text) = text else {
        return if ipv6_sysctl_present {
            Err(io::Error::other(
                "/proc/net/if_inet6 is missing while IPv6 is enabled",
            ))
        } else {
            Ok(Vec::new())
        };
    };
    let mut addresses = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let Some(field) = line.split_whitespace().next() else {
            return Err(io::Error::other(format!("bad if_inet6 line: {line}")));
        };
        if field.len() != 32 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::other(format!("bad if_inet6 line: {line}")));
        }
        let value = u128::from_str_radix(field, 16)
            .map_err(|_| io::Error::other(format!("bad if_inet6 line: {line}")))?;
        addresses.push(Ipv6Addr::from(value));
    }
    Ok(addresses)
}

/// The production parts on Linux: the system resolver (the proxy applies the
/// SSRF deny list to its answer itself and dials only what it checked), a
/// plain dial, and the host's own addresses read from /proc at each call.
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
        let v4 = fib_trie_local(&std::fs::read_to_string("/proc/net/fib_trie")?)?;
        let inet6 = match std::fs::read_to_string("/proc/net/if_inet6") {
            Ok(text) => Some(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        // Any error but a missing tree counts as present, so an unreadable
        // /proc refuses the read instead of reporting that IPv6 is off.
        let ipv6_sysctl_present = match std::fs::symlink_metadata("/proc/sys/net/ipv6") {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => true,
        };
        let v6 = if_inet6(inet6.as_deref(), ipv6_sysctl_present)?;
        Ok(v4
            .into_iter()
            .map(IpAddr::V4)
            .chain(v6.into_iter().map(IpAddr::V6))
            .collect())
    }
}

#[cfg(test)]
#[path = "proxy_tests/mod.rs"]
mod tests;
