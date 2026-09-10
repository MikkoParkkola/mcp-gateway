// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH #517 NEG.1-3 — streamable-HTTP protocol version negotiation.
//!
//! The client proposes and the server selects. The gateway currently proposes
//! and then ignores the selection, so a backend a few revisions behind is
//! addressed with a version it never agreed to.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::protocol::PROTOCOL_VERSION;

/// A version the gateway speaks that is deliberately NOT the one it proposes.
///
/// The whole point of these tests is that the gateway proposes one version and
/// the server picks another. If the gateway's own proposal ever moves onto this
/// value the tests would still pass while asserting nothing, so every test that
/// uses it goes through [`differs_from_our_proposal`] first.
const SERVER_SELECTS: &str = "2025-06-18";

/// A version no gateway release speaks.
const UNSUPPORTED: &str = "1999-01-01";

/// Guard against a silently vacuous test after a `PROTOCOL_VERSION` bump.
fn differs_from_our_proposal(version: &'static str) -> &'static str {
    assert_ne!(
        version, PROTOCOL_VERSION,
        "the mock must select a version the gateway did not propose, or the test asserts nothing"
    );
    version
}

/// How the mock backend answers `initialize`.
#[derive(Clone, Copy)]
enum Selects {
    /// Answer 200 selecting `version`, whatever the client proposed.
    Version(&'static str),
    /// Reject anything but `accepts` at the HTTP layer, the way several
    /// deployed servers do, listing the versions it speaks in the body.
    RejectingWith { accepts: &'static str },
}

struct Mock {
    selects: Selects,
    /// How many `initialize` requests arrived. NEG.3 asserts on this: a
    /// negotiation that never had to happen proves nothing about negotiation.
    initialize_attempts: usize,
    /// Method and headers of every request after the handshake, so an
    /// assertion can name the method rather than trusting arrival order.
    after_handshake: Vec<(String, HeaderMap)>,
}

async fn mcp_handler(
    State(mock): State<Arc<Mutex<Mock>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if method == "initialize" {
        let selects = {
            let mut slot = mock.lock().expect("mock mutex poisoned");
            slot.initialize_attempts += 1;
            slot.selects
        };
        let proposed = body["params"]["protocolVersion"].as_str().unwrap_or("");
        let selected = match selects {
            Selects::Version(version) => version,
            Selects::RejectingWith { accepts } if proposed == accepts => accepts,
            Selects::RejectingWith { accepts } => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {
                            "code": -32000,
                            "message": format!(
                                "Bad Request: Unsupported protocol version (supported versions: {accepts})"
                            )
                        }
                    })),
                )
                    .into_response();
            }
        };
        return Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": selected,
                "capabilities": {},
                "serverInfo": {"name": "mock", "version": "0"}
            }
        }))
        .into_response();
    }

    mock.lock()
        .expect("mock mutex poisoned")
        .after_handshake
        .push((method.clone(), headers));

    if method == "tools/list" {
        return Json(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})).into_response();
    }
    Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response()
}

async fn start_mock(selects: Selects) -> (String, Arc<Mutex<Mock>>) {
    let mock = Arc::new(Mutex::new(Mock {
        selects,
        initialize_attempts: 0,
        after_handshake: Vec::new(),
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&mock));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), mock)
}

fn backend_for(url: &str) -> Backend {
    let config = BackendConfig {
        description: "gh517 negotiation mock".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        stop_when_idle_for: None,
        timeout: Duration::from_secs(10),
        env: HashMap::default(),
        headers: HashMap::default(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: false,
        allow_cleartext_credentials: false,
        runtime_profile: None,
        identity_propagation: None,
    };
    Backend::new(
        "gh517-mock",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    )
}

/// Every distinct value of `name` seen on a post-handshake request, paired with
/// the method that carried it. A partial fix that stamps the version onto
/// `tools/list` but not onto the `initialized` notification shows up here.
fn headers_after_handshake(mock: &Arc<Mutex<Mock>>, name: &str) -> Vec<(String, Option<String>)> {
    let slot = mock.lock().expect("mock mutex poisoned");
    assert!(
        !slot.after_handshake.is_empty(),
        "no post-handshake request reached the mock"
    );
    slot.after_handshake
        .iter()
        .map(|(method, headers)| {
            (
                method.clone(),
                headers
                    .get(name)
                    .map(|value| value.to_str().expect("header not ASCII").to_string()),
            )
        })
        .collect()
}

fn assert_every_request_announces(mock: &Arc<Mutex<Mock>>, version: &str) {
    let seen = headers_after_handshake(mock, "MCP-Protocol-Version");
    assert!(
        seen.iter().any(|(method, _)| method == "tools/list"),
        "the tools/list request must be among those checked, got: {seen:?}"
    );
    for (method, value) in &seen {
        assert_eq!(
            value.as_deref(),
            Some(version),
            "{method} must announce the version the backend selected"
        );
    }
}

/// NEG.1 — the version the server selected governs every later request.
///
/// This is the assertion whose absence let the defect ship: the handshake
/// itself succeeds today, and only a request issued *after* it shows that the
/// selection was discarded.
#[tokio::test]
async fn server_selected_version_governs_later_requests() {
    let selected = differs_from_our_proposal(SERVER_SELECTS);
    let (url, mock) = start_mock(Selects::Version(selected)).await;
    let backend = backend_for(&url);

    backend
        .get_tools()
        .await
        .expect("a server-selected supported version must not fail the handshake");

    assert_every_request_announces(&mock, selected);
}

/// NEG.2 — a selection the gateway cannot speak fails the backend.
#[tokio::test]
async fn unsupported_server_selection_fails_the_backend() {
    let (url, _mock) = start_mock(Selects::Version(UNSUPPORTED)).await;
    let backend = backend_for(&url);

    let error = backend
        .get_tools()
        .await
        .expect_err("a version the gateway does not speak must not be accepted silently");

    // Kind as well as text: a transport blip that happened to echo the version
    // would satisfy a substring check alone.
    assert!(
        matches!(error, mcp_gateway::Error::Protocol(_)),
        "an unsupported selection is a protocol failure, not a transport one, got: {error:?}"
    );
    let error = error.to_string();
    assert!(
        error.contains(UNSUPPORTED),
        "the diagnostic must name the version the server selected, got: {error}"
    );
}

/// NEG.3 — negotiation covers a rejection delivered as an HTTP status.
#[tokio::test]
async fn http_status_rejection_negotiates_a_supported_version() {
    let accepts = differs_from_our_proposal(SERVER_SELECTS);
    let (url, mock) = start_mock(Selects::RejectingWith { accepts }).await;
    let backend = backend_for(&url);

    backend
        .get_tools()
        .await
        .expect("an HTTP-status version rejection must be negotiated, not fatal");

    // Without this the test would pass on a gateway that simply guessed right
    // on its first proposal, having negotiated nothing.
    assert!(
        mock.lock()
            .expect("mock mutex poisoned")
            .initialize_attempts
            >= 2,
        "the first initialize must have been rejected, or negotiation was never exercised"
    );
    assert_every_request_announces(&mock, accepts);
}
