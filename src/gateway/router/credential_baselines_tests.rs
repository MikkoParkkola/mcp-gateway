// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Baselines: how many copies of a caller's credential a dispatch keeps alive
//! at the send, and how many it frees unwiped. Each row writes one line to the
//! file named by `MCPGW_BASELINE_OUT` (when set), asserts its premises, and
//! holds its path to a [`Ceiling`]: today's counts, so any added copy or
//! unwiped free fails the row. Work that removes a copy lowers the ceiling.
//!
//! A ceiling is never raised to absorb a rise. A dependency or toolchain
//! change that moves a count is re-baselined only with a fresh attribution
//! trace naming every added block as the HTTP client's or the test peer's,
//! and the client-only rows must move by the same amount. A block the trace
//! attributes to the gateway is a regression, whatever caused it.
//!
//! The peer is a real loopback HTTP server in this process; its handler takes
//! the live census while the gateway is mid-send. The HTTP client's own
//! buffers hold the credential too, so a client-only row sends the same header
//! through a bare client, and the gateway's share is the difference.

use std::io::Write as _;
use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::alloc_meter::{Census, Scanned, isolate_reporting, scan_dispatch};
use crate::gateway::server::signing_allocation_tests::fixed_token_mint::{
    FixedTokenMint, LONG, SHORT, token,
};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

mod peer;

use peer::{Peer, peer};

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

/// Which part of a call's life the scan covers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// A call on a slot a first call has already started and listed.
    Warm,
    /// The first call: it starts the slot, inside the scan.
    Cold,
    /// A warm call, then the router and its backends dropped inside the
    /// scan, until every connection to the peer has closed.
    Teardown,
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
    /// Requests the measured call sends (premise), each carrying the token,
    /// and the censuses those requests take.
    sends: usize,
    phase: Phase,
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
    let wire = peer(row.peer, token(len)).await;
    let (sends, carried, armed, hang) = (&wire.sends, &wire.carried, &wire.armed, &wire.hang);
    // Held so a teardown row can drop the whole stack inside the scan.
    let held = std::sync::Mutex::new(Some(gateway(wire.url.clone(), minted).await));
    let router = || {
        held.lock()
            .expect("held")
            .as_ref()
            .expect("not torn down")
            .0
            .clone()
    };
    // Warm: the slot starts and lists once outside the measurement. A row
    // whose mint is refused warms into the same refusal; the warm-up's
    // outcome is not a premise.
    if row.phase != Phase::Cold {
        let warm = direct("tools/call", json!({"name": TOOL, "arguments": {"q": "x"}}));
        let _ = post(&router(), &format!("/mcp/{BACKEND}"), &warm).await;
    }
    let before = sends.load(std::sync::atomic::Ordering::SeqCst);
    let carried_before = carried.load(std::sync::atomic::Ordering::SeqCst);
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let ((status, answer), scanned, census) = scan_dispatch(marker, || async {
        if row.peer == Peer::Hangs {
            // Dropped once the peer holds it, then measured until the peer's
            // handler ends: the client has closed the connection by then.
            let sending = router();
            tokio::select! {
                answered = post(&sending, &row.uri, &row.body) => {
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
            let answered = post(&router(), &row.uri, &row.body).await;
            if row.phase == Phase::Teardown {
                drop(held.lock().expect("held").take());
                // A guard against a hang, never expected to elapse.
                tokio::time::timeout(std::time::Duration::from_secs(30), wire.all_closed())
                    .await
                    .expect("every connection to the peer closes once the router is dropped");
            }
            answered
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
    let authenticated = carried.load(std::sync::atomic::Ordering::SeqCst) - carried_before;
    report(row.label, len, scanned, census, requests);
    sent_as_premised(row.label, row.sends, (requests, authenticated), census);
    hold(row.label, len, row.ceiling, scanned, census);
}

/// The premise of every count: the call sent exactly `expected` requests,
/// each carried the token, and each took one census. A cached or
/// short-circuited dispatch, or one that dropped its credential, fails here
/// rather than passing its ceiling with fewer copies.
fn sent_as_premised(
    label: &str,
    expected: usize,
    (requests, authenticated): (usize, usize),
    census: Census,
) {
    assert_eq!(
        requests, expected,
        "premise: {label} sent {requests} requests"
    );
    assert_eq!(
        authenticated, requests,
        "premise: {label}: {authenticated} of {requests} requests carried the token"
    );
    assert_eq!(
        census.taken, expected as u64,
        "premise: {label} took {} censuses",
        census.taken
    );
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
        sends: 1,
        phase: Phase::Warm,
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
        sends: 1,
        phase: Phase::Warm,
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
        sends: 0,
        phase: Phase::Warm,
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
        sends: 0,
        phase: Phase::Warm,
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
        sends: 1,
        phase: Phase::Warm,
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
        sends: 0,
        phase: Phase::Warm,
        ceiling: ceiling(1, 0),
    }
}

/// A `tools/call` is never resent (it may not be idempotent), so a 503 on
/// one is answered as a transport error; the retry path is a `tools/list`.
fn retry_row() -> Row {
    Row {
        label: "direct tools/list, retried after a 503",
        peer: Peer::FailsOnce,
        sends: 2,
        phase: Phase::Warm,
        ceiling: ceiling(10, 7),
        ..list_row()
    }
}

/// The first call on a cold slot: its start's sends are inside the scan.
fn cold_row() -> Row {
    Row {
        label: "direct tools/call, cold slot",
        phase: Phase::Cold,
        // The start's discovery, the key check's list fill, the call.
        sends: 3,
        ceiling: ceiling(10, 7),
        ..call_row()
    }
}

/// A warm call, then everything that held the credential dropped.
fn teardown_row() -> Row {
    Row {
        label: "direct tools/call, then teardown",
        phase: Phase::Teardown,
        ceiling: ceiling(7, 5),
        ..call_row()
    }
}

fn cancelled_row() -> Row {
    Row {
        label: "direct tools/call, dropped mid-send",
        served: false,
        peer: Peer::Hangs,
        phase: Phase::Warm,
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
baseline!(baseline_cold_long, cold_row(), LONG);
baseline!(baseline_cold_short, cold_row(), SHORT);
baseline!(baseline_teardown_long, teardown_row(), LONG);
baseline!(baseline_teardown_short, teardown_row(), SHORT);

/// The HTTP client alone: the same `Authorization` header sent by a bare
/// client to the same peer. Its frees and live copies are the client's share,
/// subtracted from each gateway path's numbers.
async fn client_only(len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = token(len);
    let wire = peer(Peer::Answers, minted).await;
    let (url, sends) = (&wire.url, &wire.sends);
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    let send = || async {
        client
            .post(url.as_str())
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
    let carried_before = wire.carried.load(std::sync::atomic::Ordering::SeqCst);
    let (_, scanned, census) = scan_dispatch(minted.as_bytes(), send).await;
    let requests = sends.load(std::sync::atomic::Ordering::SeqCst) - 1;
    let authenticated = wire.carried.load(std::sync::atomic::Ordering::SeqCst) - carried_before;
    report("client only", len, scanned, census, requests);
    sent_as_premised("client only", 1, (requests, authenticated), census);
    hold("client only", len, ceiling(1, 1), scanned, census);
}

/// The HTTP client alone, its call dropped once the peer holds it: what a
/// dropped send frees and keeps of the client's own, for the gateway's
/// dropped-send row to be read against.
async fn client_only_dropped(len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = token(len);
    let wire = peer(Peer::Hangs, minted).await;
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    wire.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let carried_before = wire.carried.load(std::sync::atomic::Ordering::SeqCst);
    let (_, scanned, census) = scan_dispatch(minted.as_bytes(), || async {
        let send = client
            .post(wire.url.as_str())
            .header("Authorization", format!("Bearer {minted}"))
            .json(&body)
            .send();
        tokio::select! {
            answered = send => panic!("premise: the hung call was answered: {answered:?}"),
            () = wire.hang.arrived.notified() => {}
        }
        // A guard against a hang, never expected to elapse.
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            wire.hang.released.notified(),
        )
        .await
        .expect("the peer's handler ends once the call is dropped");
    })
    .await;
    let requests = wire.sends.load(std::sync::atomic::Ordering::SeqCst);
    let authenticated = wire.carried.load(std::sync::atomic::Ordering::SeqCst) - carried_before;
    report(
        "client only, dropped mid-send",
        len,
        scanned,
        census,
        requests,
    );
    sent_as_premised(
        "client only, dropped mid-send",
        1,
        (requests, authenticated),
        census,
    );
    hold(
        "client only, dropped mid-send",
        len,
        ceiling(3, 3),
        scanned,
        census,
    );
}

#[tokio::test]
async fn baseline_client_only_dropped_long() {
    client_only_dropped(LONG, "baseline_client_only_dropped_long").await;
}

#[tokio::test]
async fn baseline_client_only_dropped_short() {
    client_only_dropped(SHORT, "baseline_client_only_dropped_short").await;
}

#[tokio::test]
async fn baseline_client_only_long() {
    client_only(LONG, "baseline_client_only_long").await;
}

#[tokio::test]
async fn baseline_client_only_short() {
    client_only(SHORT, "baseline_client_only_short").await;
}
