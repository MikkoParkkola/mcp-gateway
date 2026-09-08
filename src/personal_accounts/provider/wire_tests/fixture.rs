// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The recording TLS fixture the wire tests run against, wired by
//! `mod fixture;` in `wire_tests.rs`. Beyond recording it offers two SERVER-SIDE
//! synchronisation points, so no test guesses when the server got there: a PAUSE
//! BARRIER and an awaitable failed-handshake count.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::super::{GatewayProviderHttp, HttpError, HttpResponse, TerminalFailure};

/// A public-FORM name that resolves nowhere, reached only via the DNS override.
pub(super) const HOST: &str = "accounts.wire-fixture.example";

/// Synthetic markers. Not credentials for anything.
pub(super) const SENTINEL_REFRESH: &str = "synthetic-wire-refresh-not-a-real-token-9d2e";
pub(super) const SENTINEL_SECRET: &str = "synthetic-wire-client-secret-not-a-real-secret-7a63";
pub(super) const CLIENT_ID: &str = "synthetic-wire-client";

/// The production bound, restated ONLY as the number the fixture must straddle.
pub(super) const MAX_BODY_BYTES: usize = 256 * 1024;

/// Bound on any fixture wait. Below the client's own 10s request timeout, so a
/// hang fails as a test rather than as a transport retry.
pub(super) const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(super) struct RecordedRequest {
    pub(super) method: String,
    /// Request target exactly as it arrived, path and query together.
    pub(super) target: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
    /// Head plus body, for absence assertions that must not depend on parsing.
    pub(super) raw: String,
}

impl RecordedRequest {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The form as the server decoded it; hand-parsing = a second encoder.
    pub(super) fn form(&self) -> std::collections::BTreeMap<String, String> {
        serde_urlencoded::from_str(&self.body).expect("the token POST body is form-encoded")
    }
}

#[derive(Default)]
pub(super) struct Log {
    /// TCP connections accepted, counted BEFORE the handshake.
    pub(super) connections: usize,
    pub(super) handshakes_ok: usize,
    pub(super) handshakes_failed: usize,
    pub(super) requests: Vec<RecordedRequest>,
}

/// Produces the raw response bytes for a recorded request.
pub(super) type Responder = Arc<dyn Fn(&RecordedRequest) -> Vec<u8> + Send + Sync>;

/// One-shot suspension of the FIRST request served: read and RECORDED, then
/// announced, then held — the holder knows the request arrived AND is
/// unanswered. `opened` = released, not merely fired: an abandoned, dropped or
/// timed-out barrier answers NOTHING.
struct Gate {
    entered: Mutex<Option<oneshot::Sender<RecordedRequest>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
    opened: AtomicBool,
}

pub(super) struct Pause {
    entered: Option<oneshot::Receiver<RecordedRequest>>,
    release: Option<oneshot::Sender<()>>,
}

impl Pause {
    /// Await the barrier, return the held request. ASYNC: blocking would stall
    /// the task trying to arrive. Bounded, so a client that never dialled fails.
    pub(super) async fn wait_entered(&mut self) -> RecordedRequest {
        let entered = self.entered.take().expect("wait_entered is called once");
        timeout(FIXTURE_TIMEOUT, entered)
            .await
            .expect("a real request reached the fixture barrier within the bound")
            .expect("the parked request kept its announcement channel")
    }

    /// Answer the held request. Dropping a `Pause` instead is a REFUSAL.
    pub(super) fn release(mut self) {
        drop(self.release.take().map(|tx| tx.send(())));
    }
}

pub(super) struct Fixture {
    pub(super) addr: SocketAddr,
    /// The CA that signed the fixture leaf, PEM. An ADDITIONAL client root.
    ca_pem: String,
    log: Arc<Mutex<Log>>,
    /// Latest `Log::handshakes_failed`, retained even before a waiter subscribes.
    failed: Arc<watch::Sender<usize>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    pub(super) async fn start(responder: Responder) -> Self {
        let (fixture, _) = Self::start_inner(responder, false).await;
        fixture
    }

    /// Records, announces and WITHHOLDS the first response until [`Pause`] says.
    pub(super) async fn start_paused(responder: Responder) -> (Self, Pause) {
        let (fixture, pause) = Self::start_inner(responder, true).await;
        (
            fixture,
            pause.expect("a paused fixture returns its barrier"),
        )
    }

    async fn start_inner(responder: Responder, paused: bool) -> (Self, Option<Pause>) {
        let (chain, key, ca_pem) = certificates();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the fixture accepts the crate's own TLS provider")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the fixture leaf matches its key");
        // http/1.1 pinned: this file parses the wire instead of running a server.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("a loopback listener binds");
        let addr = listener.local_addr().expect("the listener has an address");
        let log = Arc::new(Mutex::new(Log::default()));
        let failed = Arc::new(watch::channel(0usize).0);
        let (shutdown, mut stop) = oneshot::channel();

        let (gate, pause) = if paused {
            let (entered_tx, entered_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            (
                Some(Arc::new(Gate {
                    entered: Mutex::new(Some(entered_tx)),
                    release: Mutex::new(Some(release_rx)),
                    opened: AtomicBool::new(false),
                })),
                Some(Pause {
                    entered: Some(entered_rx),
                    release: Some(release_tx),
                }),
            )
        } else {
            (None, None)
        };

        let task = tokio::spawn({
            let log = Arc::clone(&log);
            let failed = Arc::clone(&failed);
            async move {
                loop {
                    let stream = tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        accepted = listener.accept() => match accepted {
                            Ok((stream, _)) => stream,
                            Err(_) => return,
                        },
                    };
                    log.lock().expect("fixture log").connections += 1;
                    serve(stream, &acceptor, &responder, &log, &failed, gate.as_ref()).await;
                }
            }
        });

        (
            Self {
                addr,
                ca_pem,
                log,
                failed,
                shutdown: Some(shutdown),
                task,
            },
            pause,
        )
    }

    pub(super) fn log(&self) -> MutexGuard<'_, Log> {
        self.log.lock().expect("fixture log")
    }

    /// Await the fixture's OWN observation of `count` failed handshakes: a
    /// client's terminal error only says the CLIENT gave up. The watch RETAINS
    /// the count, so an earlier observation is seen on the first borrow — the
    /// signal is awaited, never missed, and never slept on.
    pub(super) async fn failed_handshakes_reached(&self, count: usize) {
        let mut seen = self.failed.subscribe();
        timeout(FIXTURE_TIMEOUT, async {
            while *seen.borrow_and_update() < count {
                seen.changed()
                    .await
                    .expect("fixture completion channel stays open");
            }
        })
        .await
        .expect("the fixture recorded the failed handshake within the bound");
    }

    pub(super) fn requests(&self) -> Vec<RecordedRequest> {
        self.log().requests.clone()
    }

    /// `https://HOST:PORT`; the port is in the URL as `resolve` carries none.
    pub(super) fn origin(&self) -> String {
        format!("https://{HOST}:{}", self.addr.port())
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    /// Stop accepting and join; aborted past the bound so cleanup cannot hang.
    pub(super) async fn stop(mut self) {
        drop(self.shutdown.take().map(|tx| tx.send(())));
        let mut task = self.task;
        if timeout(FIXTURE_TIMEOUT, &mut task).await.is_err() {
            task.abort();
        }
    }
}

/// Handshake, read one request, record it, hold it if armed, answer it, close.
async fn serve(
    stream: tokio::net::TcpStream,
    acceptor: &TlsAcceptor,
    responder: &Responder,
    log: &Arc<Mutex<Log>>,
    failed: &watch::Sender<usize>,
    gate: Option<&Arc<Gate>>,
) {
    let accepted = timeout(FIXTURE_TIMEOUT, acceptor.accept(stream)).await;
    let mut tls = match accepted {
        Ok(Ok(tls)) => {
            log.lock().expect("fixture log").handshakes_ok += 1;
            tls
        }
        // Refused cert, refused name, torn-down connection: one counter, and the
        // only server-side fact the untrusted-certificate test can wait on.
        Ok(Err(_)) | Err(_) => {
            let observed = {
                let mut log = log.lock().expect("fixture log");
                log.handshakes_failed += 1;
                log.handshakes_failed
            };
            // Published AFTER the guard drops: a woken waiter wants that lock.
            failed.send_replace(observed);
            return;
        }
    };

    let Ok(Some(request)) = timeout(FIXTURE_TIMEOUT, read_request(&mut tls)).await else {
        return;
    };
    // RECORDED BEFORE THE BARRIER: a waiting test asserts "arrived, unanswered".
    log.lock()
        .expect("fixture log")
        .requests
        .push(request.clone());
    if !hold(gate, &request).await {
        // Refused: the responder is NEVER called, so nothing looks released.
        let _ = timeout(FIXTURE_TIMEOUT, tls.shutdown()).await;
        return;
    }
    let response = responder(&request);
    // A write error is ordinary: the oversize response is refused mid-stream.
    let _ = timeout(FIXTURE_TIMEOUT, tls.write_all(&response)).await;
    let _ = timeout(FIXTURE_TIMEOUT, tls.shutdown()).await;
}

/// Announce this request and wait. `true` = this connection may be ANSWERED:
/// ungated, or armed, announced and EXPLICITLY released. Both channel halves are
/// TAKEN out of their mutexes before the await: no lock across a suspension.
async fn hold(gate: Option<&Arc<Gate>>, request: &RecordedRequest) -> bool {
    let Some(gate) = gate else {
        return true;
    };
    let Some(entered) = gate.entered.lock().expect("fixture gate").take() else {
        // Barrier already fired. A later request rides on the earlier verdict —
        // an unreleased gate does not auto-release for a fallback request.
        return gate.opened.load(Ordering::SeqCst);
    };
    let Some(release) = gate.release.lock().expect("fixture gate").take() else {
        return false;
    };
    // A send error means the test dropped the barrier before it fired.
    if entered.send(request.clone()).is_err() {
        return false;
    }
    // Ok(Ok(())) ONLY: dropped sender is Ok(Err(_)), lapsed bound is Err(_).
    if !matches!(timeout(FIXTURE_TIMEOUT, release).await, Ok(Ok(()))) {
        return false;
    }
    gate.opened.store(true, Ordering::SeqCst);
    true
}

/// Minimal HTTP/1.1 request read: head to CRLFCRLF, then `content-length` bytes.
async fn read_request<S>(stream: &mut S) -> Option<RecordedRequest>
where
    S: tokio::io::AsyncRead + Unpin,
{
    /// A head bound, so a malformed stream cannot grow a Vec unboundedly.
    const MAX_HEAD: usize = 64 * 1024;

    let mut buffer = Vec::new();
    let head_end = loop {
        if let Some(index) = find(&buffer, b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > MAX_HEAD {
            return None;
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };

    let head = String::from_utf8(buffer[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    let method = start.next()?.to_string();
    let target = start.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }

    let body = String::from_utf8_lossy(&body).into_owned();
    Some(RecordedRequest {
        method,
        target,
        headers,
        raw: format!("{head}\r\n\r\n{body}"),
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A CA and a leaf for [`HOST`], per fixture. Nothing touches disk.
fn certificates() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
    String,
) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    let ca_key = KeyPair::generate().expect("fixture CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("fixture CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_certificate = ca_params
        .clone()
        .self_signed(&ca_key)
        .expect("fixture CA self-signs");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("fixture leaf key");
    let leaf = CertificateParams::new(vec![HOST.to_string()])
        .expect("fixture leaf params")
        .signed_by(&leaf_key, &issuer)
        .expect("the fixture CA signs the leaf");

    let chain = vec![
        rustls::pki_types::CertificateDer::from(leaf.der().to_vec()),
        rustls::pki_types::CertificateDer::from(ca_certificate.der().to_vec()),
    ];
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        leaf_key.serialize_der(),
    ));
    (chain, key, ca_certificate.pem())
}

/// The production client, trusting the fixture CA IN ADDITION to the default
/// roots, [`HOST`] mapped to the fixture. The closure COULD remove a setting
/// (last-call-wins, seam S1) and deliberately does not.
pub(super) fn trusting_client(fixture: &Fixture) -> GatewayProviderHttp {
    let ca =
        reqwest::Certificate::from_pem(fixture.ca_pem.as_bytes()).expect("the fixture CA is PEM");
    GatewayProviderHttp::for_test(|builder| {
        builder.add_root_certificate(ca).resolve(HOST, fixture.addr)
    })
    .expect("the strict production builder accepts an extra root and a name override")
}

/// The same client WITHOUT the fixture CA: an untrusted signing authority.
pub(super) fn untrusting_client(fixture: &Fixture) -> GatewayProviderHttp {
    GatewayProviderHttp::for_test(|builder| builder.resolve(HOST, fixture.addr))
        .expect("the strict production builder accepts a name override")
}

pub(super) fn responder(
    f: impl Fn(&RecordedRequest) -> Vec<u8> + Send + Sync + 'static,
) -> Responder {
    Arc::new(f)
}

pub(super) fn response(
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn json_200(body: &str) -> Vec<u8> {
    response(
        200,
        "OK",
        &[("content-type", "application/json")],
        body.as_bytes(),
    )
}

/// A metadata document binding `issuer` to endpoints on `origin`.
pub(super) fn metadata(origin: &str, issuer: &str) -> String {
    format!(
        r#"{{"issuer":"{issuer}","authorization_endpoint":"{origin}/authorize","token_endpoint":"{origin}/token"}}"#
    )
}

pub(super) fn token_form() -> Vec<(String, String)> {
    vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), SENTINEL_REFRESH.to_string()),
        ("client_id".to_string(), CLIENT_ID.to_string()),
        ("client_secret".to_string(), SENTINEL_SECRET.to_string()),
    ]
}

#[track_caller]
pub(super) fn expect_terminal(
    result: Result<HttpResponse, HttpError>,
    what: &str,
) -> TerminalFailure {
    match result {
        Err(HttpError::Terminal(failure)) => failure,
        // A retryable answer is the dangerous one: it lets discovery advance.
        other => panic!("{what}: expected a terminal refusal, got {other:?}"),
    }
}
