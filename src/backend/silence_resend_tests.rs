// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-012 Silence rows (MIK-7272.SUB.4 rows 3, 3b and 9): a `tools/call`
//! that the backend never answers is resent only with explicit permission.
//!
//! Moved from `tests/mik_7272_sub4_adr012_acs.rs` (MIK-8360) so the rows can
//! keep their one short window, the silenced call's, off everything else:
//! - discovery is replaced by [`Backend::prefill_tools_for_test`], which runs
//!   the same `prepare_tool_metadata` a fill runs, so the resend set is the one
//!   a real `tools/list` would produce. The mock never answers `tools/list`,
//!   so a row that fills instead of prefilling fails rather than passing.
//! - the transport is started before the row ([`pre_start`]), so the
//!   handshake is not under the call's bound either.
//!
//! What is left under [`CALL_TIMEOUT`] is the silenced call alone, whose
//! outcome load cannot flip: the backend never answers, so the call fails
//! however late the timeout fires.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::header;
use axum::response::{IntoResponse as _, Response};
use serde_json::{Value, json};

use super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::protocol::{Tool, ToolAnnotations};

/// A mutation with no annotations: under amendment A1, deny.
const MUTATION: &str = "charge_card";
/// The backend states `readOnlyHint: true` explicitly: permitted.
const ANNOTATED_READ: &str = "read_ledger";
/// A name that reads like a query and is not one, with no annotations.
const READ_LOOKING_MUTATION: &str = "get_and_increment";

/// The backend's request timeout: the window the silenced call fails in, at
/// the timing gate's floor. Only that call runs under it.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Starts tried before a row gives up on its precondition.
const START_ATTEMPTS: usize = 10;
/// Real-time bound on all of them: only a hang reaches it.
const HANG_BOUND: Duration = Duration::from_secs(120);

/// An upstream that answers the handshake and never answers `tools/list` or
/// `tools/call`. Returns its URL and the tool name of every `tools/call` that
/// arrived: deliveries, not attempts.
async fn silent_upstream() -> (String, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let app = axum::Router::new().fallback(move |axum::Json(body): axum::Json<Value>| {
        let seen = Arc::clone(&seen);
        async move { answer(&seen, &body).await }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let url = format!("http://{}/mcp", listener.local_addr().expect("local addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, calls)
}

async fn answer(calls: &Mutex<Vec<String>>, body: &Value) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    match body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "initialize" => (
            [(
                header::HeaderName::from_static("mcp-session-id"),
                "sub4-session",
            )],
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "sub4-silent", "version": "0"}
                }
            })),
        )
            .into_response(),
        method @ ("tools/list" | "tools/call") => {
            if method == "tools/call" {
                calls.lock().expect("calls").push(
                    body["params"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            std::future::pending::<Response>().await
        }
        _ => axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response(),
    }
}

/// The catalogue the upstream would list, as protocol tools.
fn catalogue() -> Vec<Tool> {
    let tool = |name: &str, read_only: bool| Tool {
        name: name.to_string(),
        title: None,
        description: Some(name.to_string()),
        input_schema: json!({"type": "object", "properties": {}}),
        output_schema: None,
        annotations: read_only.then_some(ToolAnnotations {
            title: None,
            read_only_hint: Some(true),
            destructive_hint: None,
            idempotent_hint: None,
            open_world_hint: None,
        }),
        role: None,
        projection: None,
    };
    vec![
        tool(MUTATION, false),
        tool(ANNOTATED_READ, true),
        tool(READ_LOOKING_MUTATION, false),
    ]
}

/// The production failsafe shape with only the backoff shortened, as in the
/// integration suite.
fn failsafe() -> FailsafeConfig {
    let mut config = FailsafeConfig::default();
    assert!(
        config.retry.max_attempts > 1,
        "the rows need the shipped default to permit a resend"
    );
    config.retry.initial_backoff = Duration::from_millis(1);
    config.retry.max_backoff = Duration::from_millis(2);
    config
}

fn backend_for(url: &str) -> Backend {
    let config = BackendConfig {
        description: "ADR-012 silence mock".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        timeout: CALL_TIMEOUT,
        ..BackendConfig::default()
    };
    Backend::new("sub4-silent", config, &failsafe(), Duration::from_secs(300))
}

/// Start the backend before the row, retrying a start that timed out: the
/// handshake is not what these rows test. Bounded by [`START_ATTEMPTS`] and
/// [`HANG_BOUND`], and loud: a start that never completes fails the row as a
/// precondition rather than skipping it.
async fn pre_start(backend: &Backend) {
    let started = tokio::time::timeout(HANG_BOUND, async {
        let mut last = None;
        for _ in 0..START_ATTEMPTS {
            match backend.ensure_started().await {
                Ok(()) => return Ok(()),
                Err(error) => last = Some(error),
            }
        }
        Err(last)
    })
    .await;
    match started {
        Ok(Ok(())) => {}
        Ok(Err(last)) => panic!(
            "precondition: handshake never completed in {START_ATTEMPTS} starts; last: {last:?}"
        ),
        Err(elapsed) => {
            panic!("precondition: handshake never completed within {HANG_BOUND:?} ({elapsed})")
        }
    }
}

/// Deliveries of `name` for one silenced `tools/call`, with the transport
/// started and the catalogue prefilled before the call.
async fn deliveries(name: &str) -> usize {
    let (url, calls) = silent_upstream().await;
    let backend = backend_for(&url);
    pre_start(&backend).await;
    backend.prefill_tools_for_test(catalogue());
    let outcome = backend
        .request("tools/call", Some(json!({"name": name, "arguments": {}})))
        .await;
    assert!(
        outcome.is_err() || matches!(&outcome, Ok(response) if response.error.is_some()),
        "the silenced call must surface as a failure"
    );
    let calls = calls.lock().expect("calls").clone();
    assert!(
        calls.iter().all(|called| called == name),
        "only the tool under test may be called, got: {calls:?}"
    );
    calls.len()
}

/// Row 3: an unannotated `tools/call` that times out reaches the backend
/// exactly once. Pre-seated: the transport is started and the catalogue
/// prefilled before the call, so initialize and `tools/list` are not under
/// [`CALL_TIMEOUT`]; only the silenced call is.
#[tokio::test]
async fn unannotated_backend_timeout_reaches_the_backend_once() {
    let delivered = deliveries(MUTATION).await;
    assert_eq!(
        delivered, 1,
        "a `tools/call` carrying no explicit read-only or idempotent hint must \
         not be resent beneath the guard (ADR-012 consequence 2); the backend \
         received it {delivered} times inside one reservation"
    );
}

/// Row 3b: a call the backend annotates `readOnlyHint: true` is still
/// resent. Pre-seated as row 3: initialize and `tools/list` are not under
/// [`CALL_TIMEOUT`]. The resend set comes from the prefill's
/// `prepare_tool_metadata`, as a real fill's would.
#[tokio::test]
async fn an_explicitly_read_only_call_is_still_resent() {
    let delivered = deliveries(ANNOTATED_READ).await;
    assert!(
        delivered > 1,
        "a call the backend explicitly annotates `readOnlyHint: true` keeps its \
         resend permission (ADR-012 A1); it was delivered {delivered} time(s)"
    );
}

/// Row 9: a name that reads like a query grants no resend permission.
/// Pre-seated as row 3: initialize and `tools/list` are not under
/// [`CALL_TIMEOUT`].
#[tokio::test]
async fn a_resend_site_denies_by_default_without_an_annotation() {
    let delivered = deliveries(READ_LOOKING_MUTATION).await;
    assert_eq!(
        delivered, 1,
        "the resend default at every site is deny: `{READ_LOOKING_MUTATION}` \
         carries no explicit annotation and must be resent nowhere (ADR-012 A1, \
         A3); the backend received it {delivered} times"
    );
}
