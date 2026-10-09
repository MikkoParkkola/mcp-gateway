// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTPS callback receiver with its own CA, and a bare TCP listener that
//! counts connections. The receiver checks Standard Webhooks signatures with
//! its own HMAC code, not the gateway's.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
use serde_json::Value;
use sha2::Sha256;

/// How the receiver answers a verification POST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// 200 with `{"challenge": <the challenge>}`.
    Echo,
    /// 200 with a different challenge.
    WrongEcho,
    /// 200 with an empty body.
    Empty,
    /// 200 echoing the challenge of the previous request.
    Replay,
    /// A bare status, no body.
    Status(u16),
    /// [`Reply::Echo`] after holding the request this long.
    SlowEcho(Duration),
}

/// How the receiver answers an event delivery (any POST that is not a
/// verification). Scripted replies are used first, in order; then the default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventReply {
    /// A bare status, no body.
    Status(u16),
    /// The status with a canary body and an `X-Canary` header carrying it.
    Canary(u16, String),
    /// `307` with `Location` set to the given URL.
    Redirect(String),
    /// Hold the request open this long, then answer with the status.
    Hold(Duration, u16),
}

/// One request the receiver got.
#[derive(Clone, Debug)]
pub struct Received {
    pub at: Instant,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("receiver body is JSON")
    }

    /// Whether `webhook-signature` carries a `v1,` signature valid under the
    /// key inside `secret` (`whsec_` + base64).
    pub fn signed_by(&self, secret: &str) -> bool {
        let key = base64::engine::general_purpose::STANDARD
            .decode(secret.trim_start_matches("whsec_"))
            .expect("test secret decodes");
        let id = self.header("webhook-id").unwrap_or_default();
        let ts = self.header("webhook-timestamp").unwrap_or_default();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("any key length");
        mac.update(format!("{id}.{ts}.").as_bytes());
        mac.update(&self.body);
        let want = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        self.header("webhook-signature")
            .unwrap_or_default()
            .split(' ')
            .any(|sig| sig == format!("v1,{want}"))
    }
}

struct Shared {
    reply: Mutex<Reply>,
    event_script: Mutex<VecDeque<EventReply>>,
    event_default: Mutex<EventReply>,
    log: Mutex<Vec<Received>>,
}

/// A running HTTPS receiver at `https://127.0.0.1:<port>/hook`.
pub struct Receiver {
    pub url: String,
    pub ca_file: PathBuf,
    shared: Arc<Shared>,
    handle: axum_server::Handle<SocketAddr>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

async fn hook(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let verification =
        serde_json::from_slice::<Value>(&body).is_ok_and(|v| v["type"] == "verification");
    if !verification {
        shared.log.lock().expect("log").push(Received {
            at: Instant::now(),
            headers,
            body: body.to_vec(),
        });
        let next = shared.event_script.lock().expect("script").pop_front();
        let reply = next.unwrap_or_else(|| shared.event_default.lock().expect("default").clone());
        return match reply {
            EventReply::Status(code) => StatusCode::from_u16(code).expect("status").into_response(),
            EventReply::Canary(code, canary) => (
                StatusCode::from_u16(code).expect("status"),
                [("x-canary", canary.clone())],
                canary,
            )
                .into_response(),
            EventReply::Redirect(to) => {
                (StatusCode::TEMPORARY_REDIRECT, [("location", to)]).into_response()
            }
            EventReply::Hold(hold, code) => {
                tokio::time::sleep(hold).await;
                StatusCode::from_u16(code).expect("status").into_response()
            }
        };
    }
    let reply = *shared.reply.lock().expect("reply");
    if let Reply::SlowEcho(hold) = reply {
        tokio::time::sleep(hold).await;
    }
    verification_reply(&shared, headers, &body).into_response()
}

fn verification_reply(shared: &Shared, headers: HeaderMap, body: &Bytes) -> (StatusCode, String) {
    let reply = *shared.reply.lock().expect("reply");
    let mut log = shared.log.lock().expect("log");
    let previous = log
        .last()
        .and_then(|r| serde_json::from_slice::<Value>(&r.body).ok())
        .and_then(|v| v["challenge"].as_str().map(str::to_owned));
    let challenge = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["challenge"].as_str().map(str::to_owned))
        .unwrap_or_default();
    log.push(Received {
        at: Instant::now(),
        headers,
        body: body.to_vec(),
    });
    let echo = |c: &str| serde_json::json!({ "challenge": c }).to_string();
    match reply {
        Reply::Echo | Reply::SlowEcho(_) => (StatusCode::OK, echo(&challenge)),
        Reply::WrongEcho => (StatusCode::OK, echo("not-the-challenge")),
        Reply::Empty => (StatusCode::OK, String::new()),
        Reply::Replay => (StatusCode::OK, echo(&previous.unwrap_or_default())),
        Reply::Status(code) => (StatusCode::from_u16(code).expect("status"), String::new()),
    }
}

/// The debug-only variable naming extra test roots the gateway trusts on
/// every platform (MIK-8188); `src/test_trust.rs` reads it.
pub const TRUST_CA: &str = "MCP_GATEWAY_TEST_TRUST_CA";

impl Receiver {
    /// Generate a CA and a `127.0.0.1` / `localhost` leaf, serve, and write the CA to
    /// `root/receiver-ca.pem` for the gateway child's `SSL_CERT_FILE`.
    pub async fn start(root: &Path) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = mcp_gateway::mtls::CertGenerator::init_ca(&mcp_gateway::mtls::CaParams {
            cn: "events receiver temporary CA",
            validity_days: 1,
        })
        .expect("temporary CA");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind receiver");
        listener.set_nonblocking(true).expect("non-blocking");
        let addr = listener.local_addr().expect("receiver address");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "127.0.0.1");
        leaf.distinguished_name = dn;
        leaf.subject_alt_names = vec![
            SanType::IpAddress(addr.ip()),
            SanType::DnsName("localhost".try_into().expect("DNS SAN")),
        ];
        let ca_key = KeyPair::from_pem(&ca.key_pem).expect("CA key");
        let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("CA cert");
        let leaf_pem = leaf.signed_by(&leaf_key, &issuer).expect("leaf").pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf_pem.into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        )
        .await
        .expect("rustls config");
        let shared = Arc::new(Shared {
            reply: Mutex::new(Reply::Echo),
            event_script: Mutex::new(VecDeque::new()),
            event_default: Mutex::new(EventReply::Status(200)),
            log: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/hook", axum::routing::post(hook))
            .route("/hook2", axum::routing::post(hook))
            .with_state(Arc::clone(&shared));
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls)
                .expect("TLS listener")
                .handle(server_handle)
                .serve(app.into_make_service())
                .await;
        });
        let ca_file = root.join("receiver-ca.pem");
        std::fs::write(&ca_file, &ca.cert_pem).expect("write CA");
        Self {
            url: format!("https://{addr}/hook"),
            ca_file,
            shared,
            handle,
        }
    }

    pub fn reply(&self, reply: Reply) {
        *self.shared.reply.lock().expect("reply") = reply;
    }

    /// Answer the next event deliveries with `replies`, in order.
    pub fn script(&self, replies: impl IntoIterator<Item = EventReply>) {
        self.shared
            .event_script
            .lock()
            .expect("script")
            .extend(replies);
    }

    /// How event deliveries are answered once the script is used up.
    pub fn event_default(&self, reply: EventReply) {
        *self.shared.event_default.lock().expect("default") = reply;
    }

    /// The same receiver reached by name: `https://localhost:<port>/hook`.
    pub fn localhost_url(&self) -> String {
        self.url.replace("127.0.0.1", "localhost")
    }

    /// Event deliveries received so far (every POST but verifications).
    pub fn events(&self) -> Vec<Received> {
        self.received()
            .into_iter()
            .filter(|r| {
                !serde_json::from_slice::<Value>(&r.body).is_ok_and(|v| v["type"] == "verification")
            })
            .collect()
    }

    pub fn received(&self) -> Vec<Received> {
        self.shared.log.lock().expect("log").clone()
    }

    /// Verification POSTs received so far.
    pub fn challenges(&self) -> Vec<Received> {
        self.received()
            .into_iter()
            .filter(|r| r.json()["type"] == "verification")
            .collect()
    }

    /// The environment for a gateway child that must trust this receiver:
    /// `SSL_CERT_FILE`, which the verifier reads on Linux, and the debug-only
    /// `MCP_GATEWAY_TEST_TRUST_CA`, which it honours everywhere (macOS reads
    /// its keychain, not `SSL_CERT_FILE`; MIK-8188).
    pub fn trust_env(&self) -> [(&'static str, String); 2] {
        let file = self.ca_file.to_string_lossy().into_owned();
        [("SSL_CERT_FILE", file.clone()), (TRUST_CA, file)]
    }
}

/// A plain TCP listener on loopback that counts accepted connections.
pub struct ConnCounter {
    pub port: u16,
    count: Arc<AtomicUsize>,
}

impl ConnCounter {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind counter");
        let port = listener.local_addr().expect("addr").port();
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { port, count }
    }

    pub fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

/// A random `whsec_` secret of `bytes` decoded bytes.
pub fn whsec(bytes: usize) -> String {
    let raw: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}
