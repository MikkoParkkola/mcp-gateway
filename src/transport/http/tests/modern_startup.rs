// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! RFC-0061 §2.4 — discover first; handshake only when the answer is not modern.
//!
//! Both cases drive the **production start path**
//! (`Backend::request_with_task_capability` -> `ensure_entry_started` ->
//! `start_entry`) against a local server. Nothing primes the era cache and
//! nothing calls a shaping helper directly: a fixture that planted a verdict
//! would pass against a lifecycle that still handshakes first, which is the
//! defect these cases exist to catch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::protocol::PROTOCOL_VERSION;
use crate::protocol::extensions::Extension;
use crate::protocol::headers::encode_header_value;
use crate::protocol::meta::{KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION, MODERN_VERSIONS};

/// The tool both cases call, and the handle the fixture answers with.
const TOOL: &str = "slow-echo";
const HANDLE: &str = "task-7061";
/// The tasks extension id, as a const so it can key a `json!` object and index
/// a captured body with the same spelling the transport emits.
const TASKS: &str = Extension::Tasks.id();

/// One request as it arrived: the assertions read the wire, never a helper's
/// return value, because the header and body halves are emitted from different
/// sites and only the wire sees both.
#[derive(Clone)]
struct Wire {
    method: String,
    headers: HeaderMap,
    body: Value,
}

type Recorder = Arc<Mutex<Vec<Wire>>>;

/// Which peer the fixture plays.
#[derive(Clone, Copy)]
enum Peer {
    /// 2026-07-28 only: answers discovery, and **rejects** the handshake the
    /// way a stateless server must. The rejection is what makes case (a) a
    /// claim about startup rather than about counters.
    ModernOnly,
    /// A 2025 server: `method not found` for discovery, handshake and session.
    Legacy,
}

/// Answer one request the way `peer` would.
fn answer(peer: Peer, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    match (peer, method) {
        (Peer::ModernOnly, "server/discover") => json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "supportedVersions": MODERN_VERSIONS,
                "capabilities": { "extensions": { TASKS: {} } },
            }
        }),
        (Peer::Legacy, "server/discover") => json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": "method not found" }
        }),
        // Deliberately NOT a version-mismatch message: the transport's
        // negotiation branch would turn one rejected handshake into two, and
        // the counter must fail on the handshake, not on how it was worded.
        (Peer::ModernOnly, "initialize") => json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32600, "message": "this server is stateless; the handshake was removed" }
        }),
        (Peer::Legacy, "initialize") => json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "fixture", "version": "0" }
            }
        }),
        // The upstream-tasks answer, in the pinned SDK's vocabulary.
        (_, "tools/call") => json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "resultType": "task",
                "taskId": HANDLE,
                "status": "working",
                "createdAt": "2026-09-08T00:00:00Z",
                "lastUpdatedAt": "2026-09-08T00:00:00Z",
                "ttlMs": 900_000,
                "pollIntervalMs": 5_000,
            }
        }),
        _ => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
    }
}

/// A recording peer that mints a session on **every** answer.
///
/// Minting on the probe too, deliberately: it is the only way to see whether
/// the pre-handshake probe binds a session the handshake never negotiated.
async fn spawn_peer(peer: Peer) -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorder);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                async move {
                    let method = request
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    sink.lock().expect("recorder poisoned").push(Wire {
                        method: method.clone(),
                        headers,
                        body: request.clone(),
                    });
                    let mut out = HeaderMap::new();
                    let minted = if method == "server/discover" {
                        "probe-session"
                    } else {
                        "s1"
                    };
                    out.insert("Mcp-Session-Id", minted.parse().expect("ascii"));
                    (out, axum::Json(answer(peer, &request)))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture peer must get a port");
    let url = format!("http://{}/", listener.local_addr().expect("bound address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, recorder)
}

/// A backend built the way production builds one. `Backend::new` mints the era
/// cache itself, so nothing here can hand the transport a verdict the
/// lifecycle would not have given it.
fn backend_at(url: &str) -> Backend {
    Backend::new(
        "modern-startup-fixture",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            headers: HashMap::new(),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// Everything the peer saw, once the call under test has returned.
fn recorded(recorder: &Recorder) -> Vec<Wire> {
    recorder.lock().expect("recorder poisoned").clone()
}

fn count(seen: &[Wire], method: &str) -> usize {
    seen.iter().filter(|wire| wire.method == method).count()
}

/// The first request with this method, or a failure naming what did arrive.
fn wire<'a>(seen: &'a [Wire], method: &str) -> &'a Wire {
    seen.iter()
        .find(|wire| wire.method == method)
        .unwrap_or_else(|| {
            panic!(
                "{method} never reached the peer; it saw [{}]",
                methods(seen)
            )
        })
}

fn position(seen: &[Wire], method: &str) -> usize {
    seen.iter()
        .position(|wire| wire.method == method)
        .unwrap_or_else(|| {
            panic!(
                "{method} never reached the peer; it saw [{}]",
                methods(seen)
            )
        })
}

fn methods(seen: &[Wire]) -> String {
    seen.iter()
        .map(|wire| wire.method.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn header(wire: &Wire, name: &str) -> String {
    wire.headers
        .get(name)
        .unwrap_or_else(|| panic!("{name} is absent; the peer received {:?}", wire.headers))
        .to_str()
        .expect("a header this design emits is ASCII")
        .to_string()
}

fn tool_call() -> Value {
    json!({ "name": TOOL, "arguments": {} })
}

/// (a) A modern-only peer: production startup asks, never handshakes, and the
/// typed task call goes through in the 2026 shape.
///
/// The counters are exact rather than lower bounds. `initialize == 0` is the
/// criterion — a peer that rejects the handshake would also fail this case
/// through the returned error, but the counter says *why*, and it keeps
/// holding if a future peer starts tolerating the handshake instead.
#[tokio::test]
async fn a_modern_only_peer_starts_without_a_handshake_and_takes_a_task_call() {
    let (url, recorder) = spawn_peer(Peer::ModernOnly).await;
    let backend = backend_at(&url);

    let response = backend
        .request_with_task_capability("tools/call", Some(tool_call()), &[], None)
        .await
        .expect("a modern peer must be startable and callable without a handshake");
    assert!(response.error.is_none(), "{:?}", response.error);
    assert_eq!(
        response.result.as_ref().and_then(|r| r["taskId"].as_str()),
        Some(HANDLE),
        "the task handle must survive the typed path"
    );

    let seen = recorded(&recorder);
    assert_eq!(
        count(&seen, "server/discover"),
        1,
        "saw [{}]",
        methods(&seen)
    );
    assert_eq!(
        count(&seen, "initialize"),
        0,
        "a 2026 peer must never be handshaken; saw [{}]",
        methods(&seen)
    );
    assert_eq!(
        count(&seen, "notifications/initialized"),
        0,
        "the handshake's second half must not be sent either; saw [{}]",
        methods(&seen)
    );
    assert_eq!(count(&seen, "tools/call"), 1, "saw [{}]", methods(&seen));

    // The probe is a valid 2026 request, sent before any verdict exists. A
    // legacy-shaped probe is not evidence about a modern peer — it is a
    // question the peer is entitled to refuse.
    let probe = wire(&seen, "server/discover");
    assert_eq!(header(probe, "mcp-protocol-version"), MODERN_VERSIONS[0]);
    assert_eq!(header(probe, "mcp-method"), "server/discover");
    assert_eq!(
        probe.body["params"]["_meta"][KEY_PROTOCOL_VERSION],
        json!(MODERN_VERSIONS[0]),
        "the probe carries the modern envelope: {}",
        probe.body
    );

    // The resolved verdict reaches the ordinary shaping and the typed
    // task-capability path alike, which is what "coherent startup" means here.
    let call = wire(&seen, "tools/call");
    assert_eq!(header(call, "mcp-protocol-version"), MODERN_VERSIONS[0]);
    assert_eq!(header(call, "mcp-method"), "tools/call");
    assert_eq!(header(call, "mcp-name"), encode_header_value(TOOL));
    assert!(
        call.headers.get("mcp-session-id").is_none(),
        "the modern shape is stateless; it sent {:?}",
        call.headers
    );
    assert!(
        call.body["params"]["_meta"][KEY_CLIENT_CAPABILITIES]["extensions"][TASKS].is_object(),
        "the tasks opt-in must be declared: {}",
        call.body
    );
}

/// (b) A legacy peer: the probe comes first and the handshake still happens,
/// with nothing fabricated on the strength of having asked.
#[tokio::test]
async fn a_legacy_peer_falls_back_to_the_handshake_and_is_refused_the_tasks_optin() {
    let (url, recorder) = spawn_peer(Peer::Legacy).await;
    let backend = backend_at(&url);

    let response = backend
        .request("tools/call", Some(tool_call()))
        .await
        .expect("a legacy peer must still start and answer");
    assert!(response.error.is_none(), "{:?}", response.error);

    let seen = recorded(&recorder);
    assert_eq!(
        count(&seen, "server/discover"),
        1,
        "saw [{}]",
        methods(&seen)
    );
    assert_eq!(count(&seen, "initialize"), 1, "saw [{}]", methods(&seen));
    assert_eq!(
        count(&seen, "notifications/initialized"),
        1,
        "the legacy handshake is both halves; saw [{}]",
        methods(&seen)
    );
    assert!(
        position(&seen, "server/discover") < position(&seen, "initialize"),
        "discovery must precede the handshake, or the handshake is what \
         selected the era; saw [{}]",
        methods(&seen)
    );

    // The handshake is unchanged: legacy-shaped, and carrying no session,
    // because the probe that ran before it must not bind one.
    let handshake = wire(&seen, "initialize");
    assert_eq!(header(handshake, "mcp-protocol-version"), PROTOCOL_VERSION);
    assert!(
        handshake.headers.get("mcp-session-id").is_none(),
        "the probe must not have bound a session the handshake never \
         negotiated; it sent {:?}",
        handshake.headers
    );

    // The ordinary call keeps the legacy shape and the handshake's session.
    let call = wire(&seen, "tools/call");
    assert_eq!(header(call, "mcp-protocol-version"), PROTOCOL_VERSION);
    assert_eq!(header(call, "mcp-session-id"), "s1");
    assert!(
        call.headers.get("mcp-method").is_none(),
        "a legacy call carries no 2026 routing headers; it sent {:?}",
        call.headers
    );
    assert!(
        call.body["params"].get("_meta").is_none(),
        "a legacy call carries no 2026 envelope: {}",
        call.body
    );

    // Having probed must not make the peer look modern. The typed path is
    // refused locally and nothing further reaches the wire.
    let refused = backend
        .request_with_task_capability("tools/call", Some(tool_call()), &[], None)
        .await;
    assert!(
        refused.is_err(),
        "a legacy peer cannot carry the tasks declaration"
    );
    assert_eq!(
        count(&recorded(&recorder), "tools/call"),
        1,
        "the refused call must never reach the peer"
    );
}
