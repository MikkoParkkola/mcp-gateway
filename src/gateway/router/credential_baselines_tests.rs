// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Baselines: how many copies of a caller's credential a dispatch keeps alive
//! at the send, and how many it frees unwiped. Each row writes one line to the
//! file named by `MCPGW_BASELINE_OUT` (when set), asserts its premises, and
//! holds its path to a [`Ceiling`]: today's counts, so any added copy or
//! unwiped free fails the row. Work that removes a copy lowers the ceiling.
//!
//! The peer is a real loopback HTTP server in this process; its handler takes
//! the live census while the gateway is mid-send. The HTTP client's own
//! buffers hold the credential too, so a client-only row sends the same header
//! through a bare client, and the gateway's share is the difference.

use std::io::Write as _;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::alloc_meter::{Census, Scanned, isolate_reporting, scan_dispatch, take_census};
use crate::gateway::server::signing_allocation_tests::fixed_token_mint::{
    FixedTokenMint, LONG, SHORT, token,
};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

const BACKEND: &str = "baseline";
const TOOL: &str = "lookup";

/// Run `name` in an isolated child; in the parent, echo the child's baseline
/// lines and return `true`.
fn in_child(name: &str) -> bool {
    match isolate_reporting(&test_path(name)) {
        Some(stdout) => {
            stdout
                .lines()
                // libtest prints `test <name> ... ` on the line the row's
                // output starts on, so the tag is found anywhere in a line.
                .filter_map(|line| line.find("BASELINE\t").map(|at| &line[at..]))
                .for_each(|line| println!("{line}"));
            true
        }
        None => false,
    }
}

fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// One baseline line: the path, the token length, what the scan and the
/// census saw, and how many requests reached the peer.
fn report(path: &str, len: usize, scanned: Scanned, census: Census, sends: usize) {
    let line = format!(
        "BASELINE\t{path}\t{len}\tunwiped_frees={}\tsearched={}\tlive_at_send={}\tcensuses={}\tsends={sends}\n",
        scanned.hits, scanned.searched, census.most_live_copies, census.taken
    );
    print!("{line}");
    if let Some(out) = std::env::var_os("MCPGW_BASELINE_OUT") {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .expect("the baseline file is writable");
    }
}

/// How the peer treats `tools/call`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Peer {
    /// Answers every call.
    Answers,
    /// Answers the first measured request, of any method, with HTTP 503,
    /// then answers.
    FailsOnce,
    /// Never answers a call: the gateway's call is dropped mid-send.
    Hangs,
}

/// What a `Hangs` peer reports: the hung call arrived, and its handler
/// ended because the gateway dropped the call.
#[derive(Default)]
struct Hang {
    arrived: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

/// Wakes `released` when the hung handler is dropped.
struct Released(Arc<Hang>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.released.notify_one();
    }
}

/// A streamable HTTP MCP peer on loopback that takes a census on every
/// request it serves, then answers as `behaviour` says. Returns its URL, a
/// send counter, the switch that arms `FailsOnce` and `Hangs` (off for the
/// warm-up), and what a hung call reports.
async fn peer(
    behaviour: Peer,
) -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<Hang>,
) {
    use axum::response::IntoResponse as _;
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hang = Arc::new(Hang::default());
    let counted = Arc::clone(&sends);
    let switch = Arc::clone(&armed);
    let hung = Arc::clone(&hang);
    let app = axum::Router::new().fallback(
        move |_headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let switch = Arc::clone(&switch);
            let hung = Arc::clone(&hung);
            async move {
                take_census();
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let method = message["method"].as_str().unwrap_or_default().to_owned();
                if switch.load(std::sync::atomic::Ordering::SeqCst) {
                    match behaviour {
                        Peer::FailsOnce => {
                            switch.store(false, std::sync::atomic::Ordering::SeqCst);
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        Peer::Hangs if method == "tools/call" => {
                            let _released = Released(Arc::clone(&hung));
                            hung.arrived.notify_one();
                            std::future::pending::<()>().await;
                        }
                        Peer::Answers | Peer::Hangs => {}
                    }
                }
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let result = match method.as_str() {
                    "server/discover" => json!({
                        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                        "capabilities": {"tools": {}}
                    }),
                    "tools/list" => json!({"tools": [{
                        "name": TOOL,
                        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                    }]}),
                    "tools/call" => json!({"content": [{"type": "text", "text": "ok"}]}),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, sends, armed, hang)
}

/// A router whose one backend, at `url`, has a required per-user binding
/// minted by the fixed-token strategy, so each caller's slot is lent-only.
async fn gateway(
    url: String,
    minted: &'static str,
) -> (axum::Router, (tempfile::TempDir, tempfile::TempDir)) {
    let backend = Arc::new(crate::backend::Backend::new(
        BACKEND,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://baseline.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(FixedTokenMint { token: minted }));
    // A required per-user mint is audited, and refused without a log.
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "baseline".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("the transparency log opens"),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    let auth = crate::config::AuthConfig::default();
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    (super::create_router(state), (log_dir, store))
}

fn caller() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// POST `body` to `uri` as the verified caller, with the modern protocol
/// headers a meta call needs; returns the status and the parsed answer.
async fn post(router: &axum::Router, uri: &str, body: &Value) -> (axum::http::StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    if let Some(method) = body["method"].as_str() {
        request = request.header("mcp-method", method);
    }
    if let Some(name) = body["params"]["name"].as_str() {
        request = request.header("mcp-name", name);
    }
    let mut request = request
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(caller());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The most a path may reach: unwiped frees, and live copies at the send.
/// Both counts were identical for 40 B and 600 B tokens on every measured
/// run, so a ceiling at today's count has no slack to absorb an added copy.
#[derive(Clone, Copy)]
struct Ceiling {
    unwiped_frees: u64,
    live_at_send: u64,
}

const fn ceiling(unwiped_frees: u64, live_at_send: u64) -> Ceiling {
    Ceiling {
        unwiped_frees,
        live_at_send,
    }
}

/// Fail when `scanned` or `census` passes `ceiling`.
fn hold(label: &str, len: usize, ceiling: Ceiling, scanned: Scanned, census: Census) {
    assert!(
        scanned.hits <= ceiling.unwiped_frees && census.most_live_copies <= ceiling.live_at_send,
        "{label} ({len} B): {} unwiped frees (ceiling {}), {} live at the send (ceiling {})",
        scanned.hits,
        ceiling.unwiped_frees,
        census.most_live_copies,
        ceiling.live_at_send
    );
}

/// What a baseline row does: its label, the request, and where it goes.
struct Row {
    label: &'static str,
    uri: String,
    body: Value,
    /// The minted value: the token itself, or a variant the mint must refuse.
    minted: fn(usize) -> &'static str,
    /// Whether the measured request is served (premise), or refused.
    served: bool,
    /// For a refused row, text its refusal must carry, so a refusal for some
    /// other reason (a malformed request) cannot stand in for it.
    because: Option<&'static str>,
    /// How the peer treats the measured call.
    peer: Peer,
    ceiling: Ceiling,
}

fn plain(len: usize) -> &'static str {
    token(len)
}

/// A minted value no header may carry: header validation refuses it after
/// the strategy produced it.
fn invalid(len: usize) -> &'static str {
    Box::leak(format!("{}\nx", token(len)).into_boxed_str())
}

async fn measure(row: Row, len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = (row.minted)(len);
    let marker = token(len).as_bytes();
    let (url, sends, armed, hang) = peer(row.peer).await;
    let (router, _dirs) = gateway(url, minted).await;
    // Warm: the slot starts and lists once outside the measurement. A row
    // whose mint is refused warms into the same refusal; the warm-up's
    // outcome is not a premise.
    let warm = direct("tools/call", json!({"name": TOOL, "arguments": {"q": "x"}}));
    let _ = post(&router, &format!("/mcp/{BACKEND}"), &warm).await;
    let before = sends.load(std::sync::atomic::Ordering::SeqCst);
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let ((status, answer), scanned, census) = scan_dispatch(marker, || async {
        if row.peer == Peer::Hangs {
            // Dropped once the peer holds it, then measured until the peer's
            // handler ends: the client has closed the connection by then.
            tokio::select! {
                answered = post(&router, &row.uri, &row.body) => {
                    panic!("premise: the hung call was dropped, not answered: {answered:?}")
                }
                () = hang.arrived.notified() => {}
            }
            // A guard against a hang, never expected to elapse.
            tokio::time::timeout(std::time::Duration::from_secs(30), hang.released.notified())
                .await
                .expect("the peer's handler ends once the call is dropped");
            (axum::http::StatusCode::REQUEST_TIMEOUT, Value::Null)
        } else {
            post(&router, &row.uri, &row.body).await
        }
    })
    .await;
    let served = status == axum::http::StatusCode::OK
        && answer.get("error").is_none()
        && answer["result"]["isError"] != json!(true);
    assert_eq!(
        served, row.served,
        "premise: {} served={served}: {status} {answer}",
        row.label
    );
    if let Some(because) = row.because {
        assert!(
            answer.to_string().contains(because),
            "premise: {} was refused for another reason: {answer}",
            row.label
        );
    }
    let requests = sends.load(std::sync::atomic::Ordering::SeqCst) - before;
    report(row.label, len, scanned, census, requests);
    hold(row.label, len, row.ceiling, scanned, census);
}

/// A modern request: the protocol header a call sends requires the same
/// version and the client's capabilities in the params' `_meta`.
fn direct(method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

fn call_row() -> Row {
    Row {
        label: "direct tools/call",
        uri: format!("/mcp/{BACKEND}"),
        body: direct("tools/call", json!({"name": TOOL, "arguments": {"q": "x"}})),
        minted: plain,
        served: true,
        because: None,
        peer: Peer::Answers,
        ceiling: ceiling(5, 5),
    }
}

fn list_row() -> Row {
    Row {
        label: "direct tools/list",
        uri: format!("/mcp/{BACKEND}"),
        body: direct("tools/list", json!({})),
        minted: plain,
        served: true,
        because: None,
        peer: Peer::Answers,
        ceiling: ceiling(6, 7),
    }
}

fn refused_row() -> Row {
    Row {
        label: "direct refused (tool not listed)",
        uri: format!("/mcp/{BACKEND}"),
        body: direct("tools/call", json!({"name": "not-listed", "arguments": {}})),
        minted: plain,
        served: false,
        because: Some("not-listed"),
        peer: Peer::Answers,
        ceiling: ceiling(1, 0),
    }
}

fn failed_mint_row() -> Row {
    Row {
        label: "failed mint (invalid header)",
        uri: format!("/mcp/{BACKEND}"),
        body: direct("tools/call", json!({"name": TOOL, "arguments": {"q": "x"}})),
        minted: invalid,
        served: false,
        because: Some("invalid"),
        peer: Peer::Answers,
        ceiling: ceiling(1, 0),
    }
}

fn meta_row() -> Row {
    Row {
        label: "meta gateway_invoke",
        uri: "/mcp".to_string(),
        body: direct(
            "tools/call",
            json!({"name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}}}),
        ),
        minted: plain,
        served: true,
        because: None,
        peer: Peer::Answers,
        ceiling: ceiling(5, 6),
    }
}

fn discovery_row() -> Row {
    Row {
        label: "meta gateway_search_tools",
        uri: "/mcp".to_string(),
        body: direct(
            "tools/call",
            json!({"name": "gateway_search_tools", "arguments": {"query": TOOL}}),
        ),
        minted: plain,
        served: true,
        because: None,
        peer: Peer::Answers,
        ceiling: ceiling(1, 0),
    }
}

/// A `tools/call` is never resent (it may not be idempotent), so a 503 on
/// one is answered as a transport error; the retry path is a `tools/list`.
fn retry_row() -> Row {
    Row {
        label: "direct tools/list, retried after a 503",
        peer: Peer::FailsOnce,
        ceiling: ceiling(10, 7),
        ..list_row()
    }
}

fn cancelled_row() -> Row {
    Row {
        label: "direct tools/call, dropped mid-send",
        served: false,
        peer: Peer::Hangs,
        ceiling: ceiling(7, 5),
        ..call_row()
    }
}

macro_rules! baseline {
    ($name:ident, $row:expr, $len:expr) => {
        #[tokio::test]
        async fn $name() {
            measure($row, $len, stringify!($name)).await;
        }
    };
}

baseline!(baseline_direct_call_long, call_row(), LONG);
baseline!(baseline_direct_call_short, call_row(), SHORT);
baseline!(baseline_direct_list_long, list_row(), LONG);
baseline!(baseline_direct_list_short, list_row(), SHORT);
baseline!(baseline_refused_long, refused_row(), LONG);
baseline!(baseline_refused_short, refused_row(), SHORT);
baseline!(baseline_failed_mint_long, failed_mint_row(), LONG);
baseline!(baseline_failed_mint_short, failed_mint_row(), SHORT);
baseline!(baseline_meta_call_long, meta_row(), LONG);
baseline!(baseline_meta_call_short, meta_row(), SHORT);
baseline!(baseline_discovery_long, discovery_row(), LONG);
baseline!(baseline_discovery_short, discovery_row(), SHORT);
baseline!(baseline_retry_long, retry_row(), LONG);
baseline!(baseline_retry_short, retry_row(), SHORT);
baseline!(baseline_cancelled_long, cancelled_row(), LONG);
baseline!(baseline_cancelled_short, cancelled_row(), SHORT);

/// The HTTP client alone: the same `Authorization` header sent by a bare
/// client to the same peer. Its frees and live copies are the client's share,
/// subtracted from each gateway path's numbers.
async fn client_only(len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = token(len);
    let (url, sends, _armed, _hang) = peer(Peer::Answers).await;
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    let send = || async {
        client
            .post(&url)
            .header("Authorization", format!("Bearer {minted}"))
            .json(&body)
            .send()
            .await
            .expect("sent")
            .bytes()
            .await
            .expect("read")
    };
    let _ = send().await;
    let (_, scanned, census) = scan_dispatch(minted.as_bytes(), send).await;
    let requests = sends.load(std::sync::atomic::Ordering::SeqCst) - 1;
    report("client only", len, scanned, census, requests);
    hold("client only", len, ceiling(1, 1), scanned, census);
}

#[tokio::test]
async fn baseline_client_only_long() {
    client_only(LONG, "baseline_client_only_long").await;
}

#[tokio::test]
async fn baseline_client_only_short() {
    client_only(SHORT, "baseline_client_only_short").await;
}
