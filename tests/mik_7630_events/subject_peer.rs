// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A legacy-era HTTP MCP backend that tells its callers apart.
//!
//! Each request names its caller by the subject of the bearer it carries: the
//! `sub` claim of a JWT (a gateway-signed assertion), or the part after `at.`
//! (an opaque token issued for that subject). A request with no
//! `Authorization` header is the gateway's own, subject `""`; one whose
//! header names no subject is `"<unreadable>"`. Every subject has its own
//! session, its own catalogue (one tool and one resource named after it), its
//! own legacy subscriptions and its own GET streams, and a test pushes a
//! notification to one subject's streams only. The peer records which subject every request
//! carried, so a test can assert that no request for one user ever went out
//! as anyone else.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// One request the peer saw: the subject it carried and what it was.
#[derive(Debug, Clone)]
pub struct Request {
    pub subject: String,
    /// The JSON-RPC method, or `GET` for a stream.
    pub method: String,
    /// The `Mcp-Session-Id` it carried (`session-<subject>` as issued), or `""`.
    pub session: String,
    /// Whether it carried the [`STATIC_HEADER`]: a backend's static
    /// credential, which a per-user send must never present.
    pub static_header: bool,
}

/// The name of the static credential header a row configures on a backend.
pub const STATIC_HEADER: &str = "x-api-key";

#[derive(Default)]
struct Inner {
    seen: Vec<Request>,
    streams: Vec<(String, mpsc::UnboundedSender<String>)>,
    subscribed: BTreeMap<String, Vec<String>>,
    /// Subjects whose session the peer dropped: their next request that
    /// carries a session id is answered 404, as a backend that lost it.
    expired: std::collections::BTreeSet<String>,
}

#[derive(Clone, Default)]
struct State(Arc<Mutex<Inner>>);

impl State {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.0.lock().expect("subject peer"))
    }
}

/// The subject a bearer names: `""` with no `Authorization` header at all,
/// `"<unreadable>"` for one that names no subject, an empty one included.
pub fn subject_of(headers: &HeaderMap) -> String {
    let Some(header) = headers.get("authorization") else {
        return String::new();
    };
    let subject = named_subject(header);
    if subject.is_empty() {
        "<unreadable>".to_owned()
    } else {
        subject
    }
}

/// The subject a present `Authorization` header's bearer names, if any.
fn named_subject(header: &axum::http::HeaderValue) -> String {
    let Some(token) = header.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) else {
        return "<unreadable>".to_owned();
    };
    if let Some(subject) = token.strip_prefix("at.") {
        return subject.to_owned();
    }
    token
        .split('.')
        .nth(1)
        .and_then(|claims| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| claims["sub"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unreadable>".to_owned())
}

/// The URI of the one resource `subject` sees.
pub fn resource_of(subject: &str) -> String {
    format!("file:///{subject}")
}

/// A per-subject legacy HTTP MCP backend.
pub struct SubjectPeer {
    pub url: String,
    state: State,
}

impl SubjectPeer {
    pub async fn start() -> Self {
        let state = State::default();
        let (post_state, get_state) = (state.clone(), state.clone());
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(
                move |headers: HeaderMap, axum::Json(frame): axum::Json<Value>| {
                    let state = post_state.clone();
                    async move {
                        let subject = subject_of(&headers);
                        let method = frame["method"].as_str().unwrap_or_default();
                        record(&state, &subject, method, &headers);
                        if lost_session(&state, &subject, &headers) {
                            return axum::http::StatusCode::NOT_FOUND.into_response();
                        }
                        answer(&state, &subject, &frame)
                    }
                },
            )
            .get(move |headers: HeaderMap| {
                let state = get_state.clone();
                async move {
                    let subject = subject_of(&headers);
                    record(&state, &subject, "GET", &headers);
                    if lost_session(&state, &subject, &headers) {
                        return axum::http::StatusCode::NOT_FOUND.into_response();
                    }
                    stream(&state, subject)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind subject peer");
        let url = format!("http://{}/", listener.local_addr().expect("peer address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state }
    }

    /// Every request so far, in arrival order.
    pub fn seen(&self) -> Vec<Request> {
        self.state.with(|s| s.seen.clone())
    }

    /// GET streams `subject` holds open.
    pub fn open_streams(&self, subject: &str) -> usize {
        self.state.with(|s| {
            s.streams.retain(|(_, tx)| !tx.is_closed());
            s.streams.iter().filter(|(who, _)| who == subject).count()
        })
    }

    /// Whether `subject` holds a registered subscription to `uri`, the state a
    /// pushed resource update is routed by.
    pub fn subscribed_to(&self, subject: &str, uri: &str) -> bool {
        self.state.with(|s| {
            s.subscribed
                .get(subject)
                .is_some_and(|uris| uris.iter().any(|u| u == uri))
        })
    }

    /// Drop `subject`'s session as a restarted backend would: its open streams
    /// end, and its next request carrying a session id is answered 404, so a
    /// client must initialize again.
    pub fn expire_session(&self, subject: &str) {
        self.state.with(|s| {
            s.streams.retain(|(who, _)| who != subject);
            s.expired.insert(subject.to_owned());
        });
    }

    /// Send `method` to `subject`'s open streams only, as the backend would
    /// when that user's view changed. A resource update goes only where that
    /// subject subscribed to the URI.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "call sites build the value inline with json!"
    )]
    pub fn push_to(&self, subject: &str, method: &str, params: Value) {
        self.state.with(|s| {
            let subscribed = s.subscribed.get(subject).cloned().unwrap_or_default();
            if method == "notifications/resources/updated"
                && !subscribed.iter().any(|u| params["uri"] == *u)
            {
                return;
            }
            let frame = json!({"jsonrpc": "2.0", "method": method, "params": params});
            for (who, tx) in &s.streams {
                if who == subject {
                    let _ = tx.send(frame.to_string());
                }
            }
        });
    }
}

/// Whether this request rides a session the peer dropped; it is refused once.
fn lost_session(state: &State, subject: &str, headers: &HeaderMap) -> bool {
    headers.contains_key("mcp-session-id") && state.with(|s| s.expired.remove(subject))
}

fn reply(id: &Value, result: &Value) -> Response {
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

/// Every request is recorded on arrival, the ones a dropped session refuses
/// included.
fn record(state: &State, subject: &str, method: &str, headers: &HeaderMap) {
    let session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let static_header = headers.contains_key(STATIC_HEADER);
    state.with(|s| {
        s.seen.push(Request {
            subject: subject.to_owned(),
            method: method.to_owned(),
            session,
            static_header,
        });
    });
}

fn answer(state: &State, subject: &str, frame: &Value) -> Response {
    let method = frame["method"].as_str().unwrap_or_default().to_owned();
    let Some(id) = frame.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    match method.as_str() {
        "initialize" => {
            let mut response = reply(
                &id,
                &json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "resources": {"subscribe": true, "listChanged": true},
                        "tools": {"listChanged": true},
                    },
                    "serverInfo": {"name": "subject-peer", "version": "0"},
                }),
            );
            let session = format!("session-{subject}");
            if let Ok(value) = session.parse() {
                response.headers_mut().insert("mcp-session-id", value);
            }
            response
        }
        "tools/list" => reply(
            &id,
            &json!({"tools": [{"name": format!("tool_{subject}"),
                               "inputSchema": {"type": "object"}}]}),
        ),
        "resources/list" => reply(
            &id,
            &json!({"resources": [{"uri": resource_of(subject), "name": subject}]}),
        ),
        "resources/subscribe" | "resources/unsubscribe" => {
            let uri = frame["params"]["uri"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            state.with(|s| {
                let mine = s.subscribed.entry(subject.to_owned()).or_default();
                mine.retain(|u| *u != uri);
                if method == "resources/subscribe" {
                    mine.push(uri);
                }
            });
            reply(&id, &json!({}))
        }
        "prompts/list" => reply(&id, &json!({"prompts": []})),
        "ping" => reply(&id, &json!({})),
        _ => axum::Json(json!({"jsonrpc": "2.0", "id": id,
                               "error": {"code": -32601, "message": "not found"}}))
        .into_response(),
    }
}

fn stream(state: &State, subject: String) -> Response {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    state.with(|s| s.streams.push((subject, tx)));
    let body = async_stream::stream! {
        while let Some(frame) = rx.recv().await {
            yield Ok::<_, std::io::Error>(format!("event: message\ndata: {frame}\n\n"));
        }
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

/// An HTTPS RFC 8693 token endpoint for the `token_exchange` strategy. It
/// answers each exchange with `at.<subject>`, the subject read from the
/// gateway's `subject_token`, so the peer can tell exchanged callers apart.
pub struct TokenEndpoint {
    pub url: String,
    /// The CA this endpoint's leaf chains to, for the gateway's trust file.
    pub ca_file: std::path::PathBuf,
    exchanged: Arc<Mutex<Vec<String>>>,
}

impl TokenEndpoint {
    pub async fn start(root: &std::path::Path) -> Self {
        use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = mcp_gateway::mtls::CertGenerator::init_ca(&mcp_gateway::mtls::CaParams {
            cn: "subject peer token endpoint temporary CA",
            validity_days: 1,
        })
        .expect("temporary CA");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
        listener.set_nonblocking(true).expect("non-blocking");
        let addr = listener.local_addr().expect("token endpoint address");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "127.0.0.1");
        leaf.distinguished_name = dn;
        leaf.subject_alt_names = vec![SanType::IpAddress(addr.ip())];
        let ca_key = KeyPair::from_pem(&ca.key_pem).expect("CA key");
        let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("CA cert");
        let leaf_pem = leaf.signed_by(&leaf_key, &issuer).expect("leaf").pem();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf_pem.into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        )
        .await
        .expect("rustls config");
        let exchanged: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = Arc::clone(&exchanged);
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(
                move |axum::Form(form): axum::Form<BTreeMap<String, String>>| {
                    let log = Arc::clone(&log);
                    async move {
                        let mut headers = HeaderMap::new();
                        let bearer = format!(
                            "Bearer {}",
                            form.get("subject_token").map_or("", String::as_str)
                        );
                        if let Ok(value) = bearer.parse() {
                            headers.insert("authorization", value);
                        }
                        let subject = subject_of(&headers);
                        log.lock().expect("exchanged").push(subject.clone());
                        axum::Json(json!({
                            "access_token": format!("at.{subject}"),
                            "token_type": "Bearer",
                            "issued_token_type":
                                "urn:ietf:params:oauth:token-type:access_token",
                            "expires_in": 300,
                        }))
                    }
                },
            ),
        );
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls)
                .expect("TLS listener")
                .serve(app.into_make_service())
                .await;
        });
        let ca_file = root.join("token-endpoint-ca.pem");
        std::fs::write(&ca_file, &ca.cert_pem).expect("write CA");
        Self {
            url: format!("https://{addr}/token"),
            ca_file,
            exchanged,
        }
    }

    /// The subject of every exchange so far.
    pub fn exchanged(&self) -> Vec<String> {
        self.exchanged.lock().expect("exchanged").clone()
    }
}
