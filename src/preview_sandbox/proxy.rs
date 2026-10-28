// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The allowlist proxy for a command preview's fetch phase (ADR-027, "The
//! allowlist proxy"): an HTTP CONNECT proxy on loopback that admits only the
//! package registries, behind a fresh credential per fetch.

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
    /// 32 bytes from the OS random source, URL-safe base64 without padding,
    /// so it sits in a proxy URL's user part with no escaping.
    fn fresh() -> Self {
        use base64::Engine as _;
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; 32];
        // The OS random source failing leaves no safe credential to issue.
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .unwrap_or_else(|_| panic!("the OS random source failed"));
        Self {
            secret: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        }
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

/// The fetch in progress: its credential, and the token that closes every
/// tunnel opened under it.
struct Live {
    credential: Credential,
    closed: CancellationToken,
}

struct Shared {
    live: Mutex<Option<Live>>,
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
}

impl AllowlistProxy {
    /// Bind `127.0.0.1:0`, the same port on `::1` if available, and a Unix
    /// socket in a fresh owner-only temp directory. The listeners stay bound
    /// for the proxy's life; outside a fetch they answer 407 to everything.
    pub(crate) async fn bind(
        resolve: Arc<dyn Resolve>,
        connect: Arc<dyn Connect>,
        interfaces: Arc<dyn Interfaces>,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            live: Mutex::new(None),
            resolve,
            connect,
            interfaces,
        });
        let v4 = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = v4.local_addr()?.port();
        let mut tasks = vec![tokio::spawn(serve_tcp(v4, shared.clone()))];
        if let Ok(v6) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await {
            tasks.push(tokio::spawn(serve_tcp(v6, shared.clone())));
        }
        let dir = std::env::temp_dir().join(format!("mcp-gw-proxy-{}-{port}", std::process::id()));
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        let unix_path = dir.join("proxy.sock");
        let unix = UnixListener::bind(&unix_path)?;
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
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn unix_path(&self) -> &Path {
        &self.unix_path
    }

    /// Start a fetch: a fresh credential, valid until [`Self::expire`]. Any
    /// earlier fetch's credential and tunnels end here too.
    pub(crate) fn begin_fetch(&self) -> Credential {
        let credential = Credential::fresh();
        let old = lock(&self.shared.live).replace(Live {
            credential: credential.clone(),
            closed: CancellationToken::new(),
        });
        if let Some(old) = old {
            old.closed.cancel();
        }
        credential
    }

    /// End a fetch: the credential stops working and its tunnels close.
    pub(crate) fn expire(&self, credential: &Credential) {
        let mut live = lock(&self.shared.live);
        if live
            .as_ref()
            .is_some_and(|l| l.credential.secret == credential.secret)
        {
            if let Some(old) = live.take() {
                old.closed.cancel();
            }
        }
    }
}

impl Drop for AllowlistProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Some(live) = lock(&self.shared.live).take() {
            live.closed.cancel();
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

async fn handle<S>(mut client: S, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match admit(&mut client, &shared).await {
        Ok((mut upstream, closed)) => {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            // Expiry drops both ends, so a tunnel never outlives its fetch.
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                () = closed.cancelled() => {}
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
async fn admit<S>(client: &mut S, shared: &Shared) -> Result<(TcpStream, CancellationToken), Status>
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
    let closed = authorized(&auth, shared).ok_or(Status::AuthRequired)?;
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
    if closed.is_cancelled() {
        return Err(Status::AuthRequired);
    }
    // One denied address refuses the whole answer, so a mixed answer cannot
    // fall through to its bad half on a retry.
    let own = shared.interfaces.addresses();
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
    if closed.is_cancelled() {
        return Err(Status::AuthRequired);
    }
    Ok((upstream, closed))
}

/// The live fetch's close token when exactly one `Proxy-Authorization`
/// header carries its credential as `Basic base64(<secret>:)`.
fn authorized(auth: &[&str], shared: &Shared) -> Option<CancellationToken> {
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
    bool::from(decoded.ct_eq(expected.as_bytes())).then(|| live.closed.clone())
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

#[cfg(test)]
#[path = "proxy_deny_vectors.rs"]
mod deny_vectors;

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
