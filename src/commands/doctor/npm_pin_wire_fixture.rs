// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 network fixtures: an HTTPS fake registry on 127.0.0.1 with its
//! own test CA, and a recording CONNECT proxy. Used by `npm_pin_wire_tests.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use mcp_gateway::config::Config;

use super::super::super::{BUDGET, ClientCfg, Lookup, ProxyEnv, check, fetch_doc};
use crate::commands::doctor::CheckResult;

/// A request bound far past the budget and the rows' hang guard: with it, a
/// stalled lookup outlives every bound but the budget, so only the budget
/// can end the check.
pub(super) const STALL_OUTLASTS_BUDGET: Duration = Duration::from_secs(120);

/// How long a budget row waits for the check before failing. The rows prove
/// the budget by its effect, not by the clock: their lookups outlast every
/// bound but the budget, so a check that returns at all was ended by it. This
/// guard only turns a check that ignores the budget into a failure instead of
/// a hung job, so it sits far past the budget, where no slow host reaches.
/// The rows prove that some bound under this guard ended the check; that the
/// bound is [`BUDGET`] at 4 s is pinned separately, by
/// `the_bounds_nest_budget_hang_guard_stall` and
/// `the_check_is_bounded_by_the_budget_constant`.
pub(super) const HANG_GUARD: Duration = Duration::from_secs(60);

/// The check under [`HANG_GUARD`], and how long it took.
pub(super) async fn check_within_guard(
    config: &Config,
    cfg: &ClientCfg,
) -> (Vec<CheckResult>, Duration) {
    let started = Instant::now();
    let rows = tokio::time::timeout(HANG_GUARD, check(config, cfg, Lookup::On))
        .await
        .unwrap_or_else(|_| panic!("the check outlived its budget: it ignores BUDGET"));
    (rows, started.elapsed())
}

/// One lookup under [`HANG_GUARD`].
pub(super) async fn lookup_within_guard(
    http: &reqwest::Client,
    cfg: &ClientCfg,
    name: &str,
) -> Option<Vec<u8>> {
    tokio::time::timeout(HANG_GUARD, fetch_doc(http, cfg, name))
        .await
        .unwrap_or_else(|_| panic!("the lookup outlived its request bound"))
}

/// The budget, not an early error, ended the check. A lower bound only, so a
/// slow host cannot fail it.
pub(super) fn assert_budget_ended(took: Duration) {
    // Each row prints its time, so CI runs record the spread.
    eprintln!("the check took {took:?}");
    assert!(
        took >= BUDGET.saturating_sub(Duration::from_millis(200)),
        "the check ended before its budget: {took:?}"
    );
}

/// The client let go of every stalled lookup. The fake sees a close a moment
/// after the client drops it: wait for that, under the guard.
pub(super) async fn assert_all_released(fake: &Fake) {
    let deadline = Instant::now() + HANG_GUARD;
    while fake.in_flight() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fake.in_flight(), 0, "a stalled lookup was left open");
}

/// How the fake answers one path.
#[derive(Clone)]
pub(super) enum Reply {
    /// 200 with this JSON body.
    Json(Vec<u8>),
    /// 200 with this body gzip-compressed (`Content-Encoding: gzip`).
    Gzip(Vec<u8>),
    /// Accept the request and never answer; ends when the client goes away,
    /// so the in-flight count drops when the client gives up.
    Stall,
    /// 200 with this JSON body after this delay.
    Delay(Duration, Vec<u8>),
    /// This status with this JSON body (a valid document under a non-200).
    Status(u16, Vec<u8>),
    /// 302 to this location.
    Redirect(String),
    /// 200, chunked, `chunk` bytes at a time for `total` bytes, recording how
    /// many were written before the client went away.
    Drip { chunk: usize, total: usize },
}

#[derive(Clone, Debug)]
pub(super) struct Seen {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: HashMap<String, String>,
}

/// Which certificate the fake presents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cert {
    /// A leaf for 127.0.0.1 signed by the CA the client trusts.
    Trusted,
    /// A leaf for another name, signed by the trusted CA.
    WrongName,
    /// A leaf for 127.0.0.1 signed by a CA the client does not trust.
    UntrustedCa,
}

pub(super) struct Fake {
    pub(super) addr: SocketAddr,
    /// The CA the client should trust (always the "trusted" one).
    pub(super) roots: rustls::RootCertStore,
    /// That CA's DER, for a child process to trust it too.
    pub(super) ca_der: Vec<u8>,
    pub(super) seen: Arc<Mutex<Vec<Seen>>>,
    /// Requests in flight now, and the most at once.
    active: Arc<AtomicUsize>,
    pub(super) peak: Arc<AtomicUsize>,
    /// Bytes a `Drip` reply wrote before the client went away.
    pub(super) dripped: Arc<AtomicUsize>,
    /// TLS handshakes that failed (wrong name, untrusted CA).
    pub(super) handshakes_failed: Arc<AtomicUsize>,
}

impl Fake {
    pub(super) async fn start(replies: &[(&str, Reply)]) -> Self {
        Self::start_with(Cert::Trusted, replies).await
    }

    pub(super) async fn start_with(cert: Cert, replies: &[(&str, Reply)]) -> Self {
        let pki = Pki::new();
        let (chain, key) = match cert {
            Cert::Trusted => Pki::leaf(&pki.ca, "127.0.0.1"),
            Cert::WrongName => Pki::leaf(&pki.ca, "other.example"),
            Cert::UntrustedCa => Pki::leaf(&pki.stranger, "127.0.0.1"),
        };
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the fake accepts the crate's TLS provider")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the fake leaf matches its key");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let replies: Arc<HashMap<String, Reply>> = Arc::new(
            replies
                .iter()
                .map(|(path, reply)| ((*path).to_string(), reply.clone()))
                .collect(),
        );
        let fake = Self {
            addr,
            roots: pki.roots(),
            ca_der: pki.ca.0.der().to_vec(),
            seen: Arc::default(),
            active: Arc::default(),
            peak: Arc::default(),
            dripped: Arc::default(),
            handshakes_failed: Arc::default(),
        };
        let (seen, active, peak, dripped, failed) = (
            Arc::clone(&fake.seen),
            Arc::clone(&fake.active),
            Arc::clone(&fake.peak),
            Arc::clone(&fake.dripped),
            Arc::clone(&fake.handshakes_failed),
        );
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, replies) = (acceptor.clone(), Arc::clone(&replies));
                let (seen, active, peak, dripped, failed) = (
                    Arc::clone(&seen),
                    Arc::clone(&active),
                    Arc::clone(&peak),
                    Arc::clone(&dripped),
                    Arc::clone(&failed),
                );
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        failed.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    let Some(request) = read_head(&mut tls).await else {
                        return;
                    };
                    let path = request.target.clone();
                    seen.lock().expect("the log locks").push(request);
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let reply = replies.get(&path).cloned();
                    answer(&mut tls, reply, &dripped).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        fake
    }

    /// The base URL a client is pointed at.
    pub(super) fn base(&self) -> Url {
        Url::parse(&format!("https://{}/", self.addr)).expect("the fake base parses")
    }

    /// A client config for this fake through the production builder.
    pub(super) fn cfg(&self, proxy: &[(&str, &str)]) -> ClientCfg {
        ClientCfg {
            base: self.base(),
            roots: self.roots.clone(),
            proxy: ProxyEnv::from_pairs(proxy),
            bounds_override: None,
        }
    }

    /// [`Fake::cfg`] with both request bounds at [`STALL_OUTLASTS_BUDGET`], for
    /// the rows that prove the budget ends the check.
    pub(super) fn cfg_outlasting_budget(&self) -> ClientCfg {
        ClientCfg {
            bounds_override: Some(STALL_OUTLASTS_BUDGET),
            ..self.cfg(&[])
        }
    }

    /// Requests the fake is still holding open.
    pub(super) fn in_flight(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    pub(super) fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("the log locks").clone()
    }
}

/// Read one request head (no body: the lookup is a GET).
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 64 * 1024 || stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let text = String::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some(Seen {
        method,
        target,
        headers,
    })
}

async fn answer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    reply: Option<Reply>,
    dripped: &AtomicUsize,
) {
    let head = |status: &str, extra: &str, len: usize| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {len}\r\nConnection: close\r\n\r\n"
        )
    };
    match reply {
        None => {
            let _ = stream
                .write_all(head("404 Not Found", "", 0).as_bytes())
                .await;
        }
        Some(Reply::Json(body)) => {
            let _ = stream
                .write_all(head("200 OK", "", body.len()).as_bytes())
                .await;
            let _ = stream.write_all(&body).await;
        }
        Some(Reply::Gzip(body)) => {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            encoder.write_all(&body).expect("gzip writes");
            let packed = encoder.finish().expect("gzip finishes");
            let extra = "Content-Encoding: gzip\r\n";
            let _ = stream
                .write_all(head("200 OK", extra, packed.len()).as_bytes())
                .await;
            let _ = stream.write_all(&packed).await;
        }
        Some(Reply::Stall) => {
            // Read until the client closes: EOF or an error both mean gone.
            let mut sink = [0u8; 256];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
            return;
        }
        Some(Reply::Delay(wait, body)) => {
            tokio::time::sleep(wait).await;
            let _ = stream
                .write_all(head("200 OK", "", body.len()).as_bytes())
                .await;
            let _ = stream.write_all(&body).await;
        }
        Some(Reply::Status(code, body)) => {
            let status = format!("{code} Status");
            let _ = stream
                .write_all(head(&status, "", body.len()).as_bytes())
                .await;
            let _ = stream.write_all(&body).await;
        }
        Some(Reply::Redirect(location)) => {
            let extra = format!("Location: {location}\r\n");
            let _ = stream
                .write_all(head("302 Found", &extra, 0).as_bytes())
                .await;
        }
        Some(Reply::Drip { chunk, total }) => {
            let start = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
            if stream.write_all(start.as_bytes()).await.is_err() {
                return;
            }
            let piece = vec![b' '; chunk];
            let mut sent = 0;
            while sent < total {
                let frame = [format!("{chunk:x}\r\n").as_bytes(), &piece, b"\r\n"].concat();
                if stream.write_all(&frame).await.is_err() || stream.flush().await.is_err() {
                    break;
                }
                sent += chunk;
                dripped.store(sent, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
    let _ = stream.shutdown().await;
}

/// The trusted CA and a stranger CA the client never trusts.
pub(super) struct Pki {
    ca: (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>),
    stranger: (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>),
}

impl Pki {
    fn new() -> Self {
        Self {
            ca: Self::authority("npm fake CA"),
            stranger: Self::authority("stranger CA"),
        }
    }

    fn authority(name: &str) -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let key = KeyPair::generate().expect("a CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params.clone().self_signed(&key).expect("the CA self-signs");
        (cert, Issuer::new(params, key))
    }

    fn leaf(
        authority: &(rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>),
        name: &str,
    ) -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let key = rcgen::KeyPair::generate().expect("a leaf key");
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let leaf = params.signed_by(&key, &authority.1).expect("the CA signs");
        let chain = vec![
            rustls::pki_types::CertificateDer::from(leaf.der().to_vec()),
            rustls::pki_types::CertificateDer::from(authority.0.der().to_vec()),
        ];
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        (chain, key)
    }

    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                self.ca.0.der().to_vec(),
            ))
            .expect("the fake CA is a valid root");
        roots
    }
}

/// A recording CONNECT proxy: logs each CONNECT target, then tunnels.
pub(super) struct Proxy {
    pub(super) addr: SocketAddr,
    connects: Arc<Mutex<Vec<String>>>,
}

impl Proxy {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
        let addr = listener.local_addr().expect("has an address");
        let connects = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&connects);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let Some(head) = read_head(&mut inbound).await else {
                        return;
                    };
                    log.lock()
                        .expect("the log locks")
                        .push(format!("{} {}", head.method, head.target));
                    if head.method != "CONNECT" {
                        return;
                    }
                    let Ok(mut outbound) = TcpStream::connect(&head.target).await else {
                        return;
                    };
                    if inbound
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        Self { addr, connects }
    }

    pub(super) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(super) fn connects(&self) -> Vec<String> {
        self.connects.lock().expect("the log locks").clone()
    }
}
