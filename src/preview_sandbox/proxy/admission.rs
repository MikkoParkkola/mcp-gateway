// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether one CONNECT request is let through: its head, the credential, the
//! allowlist and the address checks, up to the dialled upstream.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::{Bounds, Fetch, Owned, Shared, lock, within};

/// The only authorities a CONNECT may name, compared after ASCII lowercasing:
/// no trailing dot, no percent-decoding, port 443 written plainly.
pub(super) const ALLOWED: [&str; 3] = [
    "registry.npmjs.org:443",
    "pypi.org:443",
    "files.pythonhosted.org:443",
];

/// The longest request head read; npm and uv send a few hundred bytes.
const MAX_HEAD: usize = 8 * 1024;

/// A refusal's status line. The text is fixed, so nothing a client sent
/// (the credential included) is ever echoed back.
#[derive(Clone, Copy, Debug)]
pub(super) enum Status {
    BadRequest,
    AuthRequired,
    Forbidden,
    BadMethod,
    BadGateway,
}

impl Status {
    pub(super) fn head(self) -> &'static [u8] {
        match self {
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::AuthRequired => b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"preview\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::BadMethod => b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        }
    }
}

/// Every check, in order; the tunnel's upstream and its fetch's close token
/// when all pass.
pub(super) async fn admit<S>(
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
    if !lock(&shared.allowed).contains(&authority.as_str()) {
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

/// The SSRF deny list, or inside one of the host's own networks. Mapped and
/// compatible IPv6 forms are unwrapped first (`is_private_or_reserved`
/// already unwraps them for its own ranges).
fn denied(addr: IpAddr, own: &[Owned]) -> bool {
    crate::security::ssrf::is_private_or_reserved(addr)
        || own.iter().any(|&(net, len)| within(addr, net, len))
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
