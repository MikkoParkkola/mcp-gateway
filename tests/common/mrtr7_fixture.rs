// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The asking fixture backend and the client requests the MRTR.7a stdio rows
//! drive it with. Included by `#[path]` from `mik_7212_mrtr7_stdio_acs.rs`.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

/// The revision this suite's client speaks. Matches the fixture backend's.
pub const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";
/// Config name for the backend the child dials.
pub const BACKEND: &str = "fixture";
/// The fixture tool whose result asks a question instead of answering one.
pub const ASKING_TOOL: &str = "needs_input";
/// Bound on draining everything the child has to say. A row that expects a
/// frame and gets none spends this once and then asserts.
pub const COLLECT_WINDOW: Duration = Duration::from_secs(5);

/// Every JSON-RPC request the fixture backend was handed, in arrival order.
pub type Received = Arc<Mutex<Vec<Value>>>;

pub fn saw_method(received: &Received, method: &str) -> bool {
    received
        .lock()
        .expect("fixture sink poisoned")
        .iter()
        .any(|request| request.get("method").and_then(Value::as_str) == Some(method))
}

/// A question body large enough that one frame cannot be written atomically.
///
/// Row 324 asserts that concurrent outbound frames are not interleaved, and a
/// frame small enough to clear the pipe in one go never gives an unlocked
/// writer the chance to interleave: at the fixture's original ~100 bytes the
/// assertion could not fire whatever the writer did, so an unlocked writer
/// passed the row written to catch it. The size is the test. It is chosen
/// against the pipe's **capacity** (64 KiB on this platform) rather than
/// against `PIPE_BUF`, which `getconf` reports as 512 and which bounds only
/// the guaranteed-atomic write: past the capacity a write blocks partway and
/// must be resumed, and two unserialized writers resuming into one pipe
/// produce a line that does not parse.
pub const QUESTION_BYTES: usize = 96 * 1024;

/// The backend's delay before answering `initialize`.
///
/// Row 323 needs the client-visible handshake to still be outstanding when the
/// pipelined `tools/call` is processed. Without a delay the gateway answers
/// `initialize` in microseconds while the bridged question needs a backend
/// round-trip, so the ordering the row asserts holds by timing rather than by
/// design and the row passes against the interleaving it exists to catch.
pub const BACKEND_INITIALIZE_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// An HTTP MCP backend that answers `initialize` and `tools/list`, and whose
/// one tool returns the MRTR interim shape carrying an `elicitation/create`
/// the gateway is meant to relay to its own client.
pub async fn spawn_fixture_backend() -> (String, Received) {
    let sink: Received = Arc::new(Mutex::new(Vec::new()));
    let app_sink = Arc::clone(&sink);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let sink = Arc::clone(&app_sink);
            async move {
                if request.get("method").and_then(Value::as_str) == Some("initialize") {
                    tokio::time::sleep(BACKEND_INITIALIZE_DELAY).await;
                }
                axum::Json(fixture_answer(&request, &sink))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture backend address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}/"), sink)
}

pub fn fixture_answer(request: &Value, sink: &Received) -> Value {
    sink.lock()
        .expect("fixture sink poisoned")
        .push(request.clone());
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": BACKEND, "version": "0"},
        }),
        Some("tools/list") => json!({
            "tools": [{
                "name": ASKING_TOOL,
                "description": "asks its caller a question before answering",
                "inputSchema": {"type": "object"},
            }],
        }),
        Some("tools/call") => {
            // A retry carrying answers completes; a first call asks. The two
            // must be distinguishable in the child's output, or a row could
            // pass on the interim result it was supposed to have relayed.
            let responses = request
                .pointer("/params/arguments/inputResponses")
                .or_else(|| request.pointer("/params/inputResponses"));
            // A tagged call (row 324) is echoed with its own tag and the tag
            // the client's answer carried, so a reply routed to the wrong
            // exchange shows in the result. Untagged calls keep `answered`.
            let call_tag = request
                .pointer("/params/arguments/tag")
                .and_then(Value::as_str);
            if let Some(responses) = responses {
                let text = match call_tag {
                    Some(tag) => format!("answered:{tag}:{}", find_tag(responses).unwrap_or("-")),
                    None => "answered".to_owned(),
                };
                json!({"content": [{"type": "text", "text": text}]})
            } else {
                json!({
                    "resultType": "input_required",
                    "inputRequests": {
                        "branch": {
                            "method": "elicitation/create",
                            "params": {
                                "mode": "form",
                                "message": format!("Which branch? [{}] ", call_tag.unwrap_or(""))
                                    + &"x".repeat(QUESTION_BYTES),
                                "requestedSchema": {"type": "object", "properties": {}},
                            },
                        },
                    },
                    "requestState": "mrtr7-stdio-state",
                })
            }
        }
        _ => json!({}),
    };
    json!({"jsonrpc": "2.0", "id": request.get("id").cloned(), "result": result})
}

/// The first string under a `tag` key anywhere in `value`: where the client's
/// answer content lands inside the retry is the bridge's business, not the row's.
pub fn find_tag(value: &Value) -> Option<&str> {
    match value {
        Value::Object(map) => map
            .get("tag")
            .and_then(Value::as_str)
            .or_else(|| map.values().find_map(find_tag)),
        Value::Array(items) => items.iter().find_map(find_tag),
        _ => None,
    }
}

/// An [`asking_call`] whose backend arguments carry `call-<id>`, which the
/// fixture writes into its question and echoes in its final answer.
pub fn tagged_call(id: i64) -> Value {
    let mut call = asking_call(id);
    call["params"]["arguments"]["arguments"] = json!({"tag": format!("call-{id}")});
    call
}

/// Write the config the child will actually read.
///
/// The error budget is put out of reach. A 65-call burst can run past the
/// fixture backend's rate limiter (100 rps, burst 50). Before F23 each such
/// refusal was reported as "Circuit breaker open" and sampled as a failure;
/// the refusals landed before any slow asking dispatch returned, so the
/// capability's first samples were all failures, its kill switch disabled the
/// fixture tool, and every later call was refused `-32000 … temporarily
/// disabled`: a cascade the rows misread as a regressed cap. F23 stopped
/// sampling those refusals, and ask expiries (`-32003` at the bridge's 30s
/// `per_prompt`) were never sampled. The budget is still not what these rows
/// are about, so it stays configured never to evaluate — `min_samples` equal
/// to the largest window, which no row comes near.
///
/// `Config::FALLBACK_PATHS` checks `gateway.yaml` relative to the working
/// directory before `~/.config/mcp-gateway/gateway.yaml`, and the session below
/// sets the child's working directory to this same temporary home — so a file
/// dropped here is found without depending on `HOME` layout at all.
pub fn write_config(home: &Path, backend_url: &str) {
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend_url}\"\n    streamable_http: true\n\
         error_budget:\n  window_size: 100000\n  min_samples: 100000\n  capability:\n    \
         window_size: 100000\n    min_samples: 100000\n"
    );
    // The top-level config ignores keys it does not know, so a misnested
    // budget would load silently and bring the cascade back. Fail here instead.
    let parsed: mcp_gateway::config::Config =
        serde_yaml::from_str(&yaml).expect("gateway.yaml parses");
    assert_eq!(
        (
            parsed.error_budget.min_samples,
            parsed.error_budget.capability.min_samples
        ),
        (Some(100_000), Some(100_000)),
        "the error budget did not bind where the child reads it"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(home.join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");
}

pub fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": CLIENT_PROTOCOL_VERSION,
            // The only place a legacy-shaped client can declare
            // `elicitation`: MRTR.9 reads per-request `_meta` for a modern
            // call, and a legacy call has none. See [`asking_call`] for why
            // these rows must be legacy-shaped.
            "capabilities": {"elicitation": {}},
            "clientInfo": {"name": "mrtr7-stdio-acs", "version": "0"},
        },
    })
}

/// A `tools/call` that reaches the fixture's asking tool through the meta tool.
///
/// Backend tools are not on `tools/call` by their own name unless an operator
/// pins them, so the invoke meta tool is the route a real client takes.
///
/// Deliberately carries no `params._meta`. The rows here assert an outbound
/// `elicitation/create` frame on the client's own channel, and that frame is
/// written only by the in-band bridge, which serves the legacy request shape;
/// a `_meta` carrying the modern fields classifies the call Modern and takes
/// the continuation route instead, which answers with an envelope and asks
/// nobody. The elicitation capability therefore has to come from the
/// `initialize` handshake -- see [`initialize_request`].
pub fn asking_call(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": BACKEND,
                "tool": ASKING_TOOL,
                "arguments": {},
            },
        },
    })
}
