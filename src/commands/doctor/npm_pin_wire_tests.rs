// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 red tests, network rows: an HTTPS fake registry on 127.0.0.1
//! with a test CA, and a recording CONNECT proxy. No row reaches the
//! internet. Every client is built by the production `client`, with only data
//! (base URL, roots, proxy snapshot) swapped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcp_gateway::config::{BackendConfig, Config};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::super::*;
use super::stdio;
use crate::commands::doctor::CheckStatus;

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
    ca_der: Vec<u8>,
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
            Cert::Trusted => pki.leaf(&pki.ca, "127.0.0.1"),
            Cert::WrongName => pki.leaf(&pki.ca, "other.example"),
            Cert::UntrustedCa => pki.leaf(&pki.stranger, "127.0.0.1"),
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
        }
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
struct Pki {
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
        &self,
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
struct Proxy {
    addr: SocketAddr,
    connects: Arc<Mutex<Vec<String>>>,
}

impl Proxy {
    async fn start() -> Self {
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

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn connects(&self) -> Vec<String> {
        self.connects.lock().expect("the log locks").clone()
    }
}

// ── fixtures ────────────────────────────────────────────────────────────────

const MEMORY_PATH: &str = "/@modelcontextprotocol%2Fserver-memory";
const FILESYSTEM_PATH: &str = "/@modelcontextprotocol%2Fserver-filesystem";
const DEPRECATED: &str = "Date-based versions are no longer published";

/// The memory document: `2026.8.31` deprecated, `1.0.0` current.
fn memory_doc() -> Vec<u8> {
    super::doc(&[("2026.8.31", Some(DEPRECATED)), ("1.0.0", None)])
}

fn config_of(backends: &[(&str, BackendConfig)]) -> Config {
    let mut config = Config::default();
    for (name, backend) in backends {
        config.backends.insert((*name).to_string(), backend.clone());
    }
    config
}

fn memory_on(version: &str) -> BackendConfig {
    stdio(
        &format!("npx -y @modelcontextprotocol/server-memory@{version}"),
        &[],
    )
}

fn warns(rows: &[CheckResult]) -> Vec<&CheckResult> {
    rows.iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .collect()
}

// ── DOCTOR.2: the falsifier ─────────────────────────────────────────────────

#[tokio::test]
async fn a_deprecated_memory_pin_warns_and_the_current_one_does_not() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let config = config_of(&[
        ("memory", memory_on("2026.8.31")),
        ("fresh", memory_on("1.0.0")),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    let warned = warns(&rows);
    assert_eq!(warned.len(), 1, "only the deprecated pin warns: {rows:?}");
    let row = warned[0];
    assert_eq!(row.label, "memory: npm pin");
    assert_eq!(row.category, "backend_stdio");
    assert!(
        row.detail
            .contains("@modelcontextprotocol/server-memory@2026.8.31"),
        "{}",
        row.detail
    );
    assert!(
        row.detail.contains(&format!("npm says: \"{DEPRECATED}\"")),
        "{}",
        row.detail
    );
    assert!(
        row.hint
            .as_deref()
            .is_some_and(|h| h.contains("MEMORY_FILE_PATH"))
    );
    assert!(
        rows.iter().all(|r| r.status != CheckStatus::Fail),
        "never Fail"
    );
    assert_eq!(fake.requests().len(), 1, "one request per distinct package");
}

// ── the request: what is sent, and only that ───────────────────────────────

#[tokio::test]
async fn the_request_carries_only_the_package_name_and_fixed_headers() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let mut backend = memory_on("2026.8.31");
    backend
        .env
        .insert("API_TOKEN".into(), "secret-value-canary".into());
    let config = config_of(&[("private-backend-name", backend)]);
    let _ = check(&config, &fake.cfg(&[]), Lookup::On).await;
    let seen = fake.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, MEMORY_PATH, "the version stays local");
    assert_eq!(
        request.headers.get("user-agent").map(String::as_str),
        Some(USER_AGENT)
    );
    assert_eq!(
        request.headers.get("accept").map(String::as_str),
        Some(ACCEPT)
    );
    for forbidden in ["authorization", "cookie", "proxy-authorization"] {
        assert!(!request.headers.contains_key(forbidden), "{forbidden} sent");
    }
    let wire = format!("{request:?}");
    for leak in ["secret-value-canary", "private-backend-name", "2026.8.31"] {
        assert!(!wire.contains(leak), "{leak} left the machine: {wire}");
    }
}

// ── scope: the allowlist and dedup ──────────────────────────────────────────

#[tokio::test]
async fn a_package_outside_the_registry_is_never_sent() {
    let fake = Fake::start(&[]).await;
    let config = config_of(&[
        (
            "internal",
            stdio("npx -y @company/internal-tool@1.2.3", &[]),
        ),
        (
            "ranged",
            stdio("npx -y @modelcontextprotocol/server-memory@latest", &[]),
        ),
        (
            "other-runner",
            stdio("pnpm dlx @modelcontextprotocol/server-memory@1.0.0", &[]),
        ),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    assert!(warns(&rows).is_empty());
    assert_eq!(
        fake.requests().len(),
        0,
        "nothing outside the allowlist is sent"
    );
}

#[tokio::test]
async fn one_request_per_package_with_a_row_per_backend() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let config = config_of(&[
        ("b-old", memory_on("2026.8.31")),
        ("a-old", memory_on("2026.8.31")),
        ("c-new", memory_on("1.0.0")),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    assert_eq!(fake.requests().len(), 1, "one request for three backends");
    let labels: Vec<&str> = warns(&rows).iter().map(|r| r.label.as_str()).collect();
    assert_eq!(
        labels,
        ["a-old: npm pin", "b-old: npm pin"],
        "sorted backend order"
    );
}

#[tokio::test]
async fn a_disabled_backend_is_not_checked() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let mut off = memory_on("2026.8.31");
    off.enabled = false;
    let rows = check(&config_of(&[("off", off)]), &fake.cfg(&[]), Lookup::On).await;
    assert!(warns(&rows).is_empty());
    assert_eq!(fake.requests().len(), 0);
}

// ── the off switch ──────────────────────────────────────────────────────────

#[tokio::test]
async fn every_off_reason_sends_nothing_and_prints_one_skipped_pass() {
    for lookup in [Lookup::OffByFlag, Lookup::OffByPosture] {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            lookup,
        )
        .await;
        assert_eq!(fake.requests().len(), 0, "{lookup:?}");
        assert_eq!(rows.len(), 1, "{lookup:?}: {rows:?}");
        assert_eq!(rows[0].status, CheckStatus::Pass);
        assert_eq!(rows[0].label, SKIPPED_LABEL);
        assert!(rows[0].detail.contains("skipped"), "{}", rows[0].detail);
    }
}

// ── fail-soft: every failure is silence, inside the budget ─────────────────

/// A margin for scheduling on a loaded CI runner.
const SLACK: Duration = Duration::from_secs(1);

#[tokio::test]
async fn offline_is_silent_and_quick() {
    let closed = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
    let port = closed.local_addr().expect("has an address").port();
    drop(closed);
    let cfg = ClientCfg {
        base: Url::parse(&format!("https://127.0.0.1:{port}/")).expect("parses"),
        roots: rustls::RootCertStore::empty(),
        proxy: ProxyEnv::default(),
    };
    let started = Instant::now();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &cfg,
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    // A refused connection answers at once; well under the connect bound.
    assert!(
        started.elapsed() < CONNECT_TIMEOUT,
        "{:?}",
        started.elapsed()
    );
}

/// Five stalled packages need two waves at four in flight; without the
/// aggregate budget the second wave alone would end past it.
#[tokio::test]
async fn stalls_end_inside_the_budget_and_never_exceed_the_concurrency() {
    let packages = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        ("@modelcontextprotocol/server-memory", MEMORY_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let replies: Vec<(&str, Reply)> = packages
        .iter()
        .map(|(_, path)| (*path, Reply::Stall))
        .collect();
    let fake = Fake::start(&replies).await;
    let backends: Vec<(String, BackendConfig)> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("b{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let started = Instant::now();
    let rows = check(&config_of(&named), &fake.cfg(&[]), Lookup::On).await;
    let took = started.elapsed();
    assert!(rows.is_empty(), "{rows:?}");
    assert!(
        took < BUDGET + SLACK,
        "the budget bounds the whole check: {took:?}"
    );
    assert!(
        took >= REQUEST_TIMEOUT,
        "the stall was waited on, not skipped: {took:?}"
    );
}

/// Eight packages that each answer after 300 ms: never more than four in
/// flight, and four at once (the pool is used, not run one by one).
#[tokio::test]
async fn at_most_four_requests_are_in_flight() {
    let packages = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        ("@modelcontextprotocol/server-memory", MEMORY_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("airtable-mcp-server", "/airtable-mcp-server"),
        ("exa-mcp-server", "/exa-mcp-server"),
        ("slack-mcp-server", "/slack-mcp-server"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let slow = Duration::from_millis(300);
    let replies: Vec<(&str, Reply)> = packages
        .iter()
        .map(|(_, path)| (*path, Reply::Delay(slow, br#"{"versions":{}}"#.to_vec())))
        .collect();
    let fake = Fake::start(&replies).await;
    let backends: Vec<(String, BackendConfig)> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("b{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let _ = check(&config_of(&named), &fake.cfg(&[]), Lookup::On).await;
    assert_eq!(
        fake.requests().len(),
        packages.len(),
        "every package asked once"
    );
    assert_eq!(fake.peak.load(Ordering::SeqCst), CONCURRENCY);
}

/// The memory warning finishes at once; seven stalled packages keep the
/// pool busy past one request bound, so the second wave is still running
/// when the aggregate budget ends. The finished row must survive that.
#[tokio::test]
async fn a_finished_warning_survives_the_budget_running_out() {
    let stalled = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("airtable-mcp-server", "/airtable-mcp-server"),
        ("exa-mcp-server", "/exa-mcp-server"),
        ("slack-mcp-server", "/slack-mcp-server"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let mut replies: Vec<(&str, Reply)> = stalled
        .iter()
        .map(|(_, path)| (*path, Reply::Stall))
        .collect();
    replies.push((MEMORY_PATH, Reply::Json(memory_doc())));
    let fake = Fake::start(&replies).await;
    let mut backends: Vec<(String, BackendConfig)> = stalled
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("s{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    backends.push(("memory".to_string(), memory_on("2026.8.31")));
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let started = Instant::now();
    let rows = check(&config_of(&named), &fake.cfg(&[]), Lookup::On).await;
    let took = started.elapsed();
    assert!(
        took >= BUDGET - Duration::from_millis(200),
        "the budget ran out: {took:?}"
    );
    assert!(took < BUDGET + SLACK, "{took:?}");
    let labels: Vec<&str> = warns(&rows).iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["memory: npm pin"], "{rows:?}");
}

#[tokio::test]
async fn a_non_200_answer_is_silent_even_with_a_valid_document() {
    for code in [404u16, 500, 203] {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Status(code, memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "HTTP {code}: {rows:?}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let fake = Fake::start(&[
        (MEMORY_PATH, Reply::Redirect("/elsewhere".to_string())),
        ("/elsewhere", Reply::Json(memory_doc())),
    ])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let targets: Vec<String> = fake.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(
        targets,
        [MEMORY_PATH],
        "the redirect target was never asked"
    );
}

#[tokio::test]
async fn an_endless_body_is_cut_early_and_silent() {
    let fake = Fake::start(&[(
        MEMORY_PATH,
        Reply::Drip {
            chunk: 64 * 1024,
            total: 8 * MAX_DOC_BYTES,
        },
    )])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let written = fake.dripped.load(Ordering::SeqCst);
    assert!(
        written < 4 * MAX_DOC_BYTES,
        "the client kept reading: {written} bytes"
    );
}

#[tokio::test]
async fn a_compressed_body_counts_its_decoded_size() {
    // A deprecated pin padded past the cap once decoded, tiny on the wire.
    let mut body = memory_doc();
    body.pop(); // the closing brace
    body.extend_from_slice(br#","padding":""#);
    body.extend(std::iter::repeat_n(b'a', 2 * MAX_DOC_BYTES));
    body.extend_from_slice(br#""}"#);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(
        rows.is_empty(),
        "the decoded size is over the cap: {rows:?}"
    );

    // The same document under the cap, compressed, is read.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(memory_doc()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
}

#[tokio::test]
async fn invalid_json_is_silent() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(b"{not json".to_vec()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn hostile_text_prints_sanitized() {
    let hostile = "\u{1b}[2J\u{1b}[31mPWNED\u{1b}[0m\nfake\u{202e}line";
    let body = super::doc(&[("2026.8.31", Some(hostile))]);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    let detail = &warns(&rows)[0].detail;
    assert!(detail.contains("npm says: \"PWNED fakeline\""), "{detail}");
    assert!(
        !detail.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{detail:?}"
    );
}

// ── TLS: the injected roots are the only roots ─────────────────────────────

#[tokio::test]
async fn a_wrong_name_or_an_untrusted_ca_is_silent() {
    for cert in [Cert::WrongName, Cert::UntrustedCa] {
        let fake = Fake::start_with(cert, &[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "{rows:?}");
        assert_eq!(
            fake.requests().len(),
            0,
            "no request over a refused handshake"
        );
        // The server sees the client's rejection a moment after the client
        // gives up: wait for it, bounded.
        let deadline = Instant::now() + Duration::from_secs(5);
        while fake.handshakes_failed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            fake.handshakes_failed.load(Ordering::SeqCst) >= 1,
            "the handshake was refused"
        );
    }
}

// ── proxy: through the production builder, never bypassed ──────────────────

#[tokio::test]
async fn https_proxy_carries_the_lookup_through_connect() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("REQUEST_METHOD", "GET")]),
        Lookup::On,
    )
    .await;
    assert_eq!(
        warns(&rows).len(),
        1,
        "the lookup went through the proxy: {rows:?}"
    );
    assert_eq!(proxy.connects(), [format!("CONNECT {}", fake.addr)]);
}

#[tokio::test]
async fn no_proxy_covering_the_host_goes_direct() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "127.0.0.1")]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());

    // A NO_PROXY that does not cover the host keeps the proxy.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let _ = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "other.example")]),
        Lookup::On,
    )
    .await;
    assert_eq!(proxy.connects().len(), 1);
}

#[tokio::test]
async fn an_unusable_proxy_sends_nothing_anywhere() {
    let proxy = Proxy::start().await;
    let with_userinfo = format!("http://user:pass@{}", proxy.addr);
    let socks = format!("socks5://{}", proxy.addr);
    let broken = format!("http://proxy{{typo}}:{}", proxy.addr.port());
    let cases: [&[(&str, &str)]; 4] = [
        &[("HTTPS_PROXY", with_userinfo.as_str())],
        &[("ALL_PROXY", socks.as_str())],
        &[("HTTPS_PROXY", broken.as_str())],
        &[("HTTPS_PROXY", "::not a url::")],
    ];
    for pairs in cases {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(pairs),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "{pairs:?}: {rows:?}");
        assert_eq!(fake.requests().len(), 0, "{pairs:?}: went direct");
        assert_eq!(
            fake.handshakes_failed.load(Ordering::SeqCst),
            0,
            "{pairs:?}: reached the fake"
        );
    }
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());
}

// ── the process environment: reached only through the snapshot ─────────────
//
// Setting the environment in-process is unsafe in edition 2024, so these rows
// run this test binary again as a child with a controlled environment. The
// child half is inert unless the parent marks it.

const CHILD_TEST: &str = "commands::doctor::npm_pin::tests::wire::child_runs_one_lookup";

/// The child half: one lookup against the parent's fake, with either an empty
/// snapshot or the process snapshot; prints how many rows warned.
#[tokio::test]
async fn child_runs_one_lookup() {
    let Ok(mode) = std::env::var("NPM_PIN_CHILD") else {
        return;
    };
    let base = Url::parse(&std::env::var("NPM_PIN_BASE").expect("a base")).expect("parses");
    let hex = std::env::var("NPM_PIN_CA").expect("a CA");
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der))
        .expect("the CA is a root");
    let proxy = match mode.as_str() {
        "empty" => ProxyEnv::default(),
        "process" => ProxyEnv::from_process(),
        other => panic!("unexpected child mode {other}"),
    };
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &ClientCfg { base, roots, proxy },
        Lookup::On,
    )
    .await;
    println!("CHILD-WARNS {}", warns(&rows).len());
}

/// Run the child half with `mode` and `env`; its stdout.
async fn child(fake: &Fake, mode: &str, env: &[(&str, &str)]) -> String {
    let hex: String = fake.ca_der.iter().map(|b| format!("{b:02x}")).collect();
    let exe = std::env::current_exe().expect("the test binary");
    let mut command = tokio::process::Command::new(exe);
    command
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("NPM_PIN_CHILD", mode)
        .env("NPM_PIN_BASE", fake.base().as_str())
        .env("NPM_PIN_CA", hex);
    if let Ok(root) = std::env::var("SystemRoot") {
        command.env("SystemRoot", root);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("the child ends")
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// The builder never reads the environment itself (`no_proxy()`): with an
/// empty snapshot, a process `HTTPS_PROXY` is not used.
#[tokio::test]
async fn an_empty_snapshot_ignores_the_process_proxy() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let out = child(
        &fake,
        "empty",
        &[("HTTPS_PROXY", url.as_str()), ("ALL_PROXY", url.as_str())],
    )
    .await;
    assert!(out.contains("CHILD-WARNS 1"), "{out}");
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());
    assert_eq!(fake.requests().len(), 1);
}

/// `from_process` reads the real environment, and `REQUEST_METHOD` changes
/// nothing: the lookup goes through the process proxy.
#[tokio::test]
async fn the_process_snapshot_uses_the_process_proxy() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let out = child(
        &fake,
        "process",
        &[("HTTPS_PROXY", url.as_str()), ("REQUEST_METHOD", "GET")],
    )
    .await;
    assert!(out.contains("CHILD-WARNS 1"), "{out}");
    assert_eq!(proxy.connects(), [format!("CONNECT {}", fake.addr)]);
}
