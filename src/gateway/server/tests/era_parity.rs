// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8368: stdio refuses, from the body alone, the methods MCP 2026-07-28
//! removed, as `/mcp` does for a request that declares that revision. Wire
//! strings are written out, never taken from the constants. The unserved-revision
//! and undeclared-capability refusals stay HTTP-only (see the batch row).

use super::*;
use serde_json::{Value, json};

const REMOVED: [&str; 4] = [
    "ping",
    "logging/setLevel",
    "resources/subscribe",
    "resources/unsubscribe",
];

/// One stdio request through the real dispatch, as a client with
/// `server.modern_protocol` = `modern`.
async fn send(modern: bool, request: Value) -> Option<Value> {
    Gateway::dispatch_single_for_client(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        request,
        super::super::StdioClient {
            session_id: "era-parity",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern,
            sanitize: super::super::stdio_single::InputSanitizing::Off,
        },
    )
    .await
}

/// A request written against `version` with the `caps` the client declares.
fn modern_request(id: Option<i64>, method: &str, version: &str, caps: impl Into<Value>) -> Value {
    let caps: Value = caps.into();
    let mut request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": caps,
            "io.modelcontextprotocol/clientInfo": { "name": "era", "version": "1" }
        }}
    });
    if let Some(id) = id {
        request["id"] = json!(id);
    }
    request
}

fn legacy_request(id: Option<i64>, method: &str) -> Value {
    let mut request = json!({ "jsonrpc": "2.0", "method": method, "params": {} });
    if let Some(id) = id {
        request["id"] = json!(id);
    }
    request
}

fn removed_text(method: &str) -> String {
    format!("method '{method}' was removed in MCP 2026-07-28")
}

/// ERA.1a: every removed method answers -32601 with the revision's text.
/// Red on the base: ping and logging/setLevel are served, the subscribe pair
/// answers `Method not found`, and an id-bearing notification is dropped.
#[tokio::test]
async fn modern_stdio_refuses_every_removed_method() {
    for method in REMOVED
        .into_iter()
        .chain(["notifications/roots/list_changed"])
    {
        let answer = send(
            true,
            modern_request(Some(7), method, "2026-07-28", json!({})),
        )
        .await
        .unwrap_or_else(|| panic!("{method}: no answer"));
        assert_eq!(answer["error"]["code"], -32601, "{method}: {answer}");
        assert_eq!(
            answer["error"]["message"],
            removed_text(method),
            "{method}: {answer}"
        );
        assert_eq!(answer["id"], 7, "{method}: {answer}");
    }
}

/// ERA.1c: a notification without an id still gets no answer on stdio. HTTP
/// refuses it (404 with a null-id error); stdio has no channel to refuse on.
#[tokio::test]
async fn modern_stdio_removed_notification_without_id_stays_silent() {
    let request = modern_request(
        None,
        "notifications/roots/list_changed",
        "2026-07-28",
        json!({}),
    );
    assert!(send(true, request).await.is_none());
}

/// ERA.2: a legacy request keeps today's answers for the removed methods, and
/// every notification that is not refused stays silent, whatever its id, era or
/// revision.
#[tokio::test]
async fn legacy_and_other_notifications_keep_today_s_answers() {
    let ping = send(true, legacy_request(Some(1), "ping"))
        .await
        .expect("ping answers");
    assert_eq!(ping["result"], json!({}), "{ping}");
    for method in ["resources/subscribe", "resources/unsubscribe"] {
        let answer = send(true, legacy_request(Some(2), method))
            .await
            .expect("answers");
        assert_eq!(answer["error"]["code"], -32601, "{answer}");
        assert_eq!(
            answer["error"]["message"],
            format!("Method not found: {method}")
        );
    }
    let set_level = send(
        true,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "logging/setLevel",
            "params": { "level": "info" } }),
    )
    .await
    .expect("setLevel answers");
    assert!(set_level.get("error").is_none(), "{set_level}");
    assert!(set_level["result"].is_object(), "{set_level}");
    for (modern, request) in [
        (
            true,
            legacy_request(Some(4), "notifications/roots/list_changed"),
        ),
        (true, legacy_request(Some(5), "notifications/initialized")),
        // An id-bearing notification that is not removed is silent even when
        // its revision is unserved or modern serving is off.
        (
            true,
            modern_request(
                Some(6),
                "notifications/initialized",
                "1999-01-01",
                json!({}),
            ),
        ),
        (
            false,
            modern_request(
                Some(7),
                "notifications/initialized",
                "2026-07-28",
                json!({}),
            ),
        ),
    ] {
        assert!(send(modern, request.clone()).await.is_none(), "{request}");
    }
}

/// A modern call inside a batch is still served, and a removed method inside a
/// batch is still refused. Why stdio shares only the removed-method refusal: a
/// batch runs its items with `StdioClient::modern` off, so sharing the
/// unserved-revision refusal would refuse every modern call in a batch.
#[tokio::test]
async fn a_modern_batch_keeps_serving_and_still_refuses_removed_methods() {
    let answers = Gateway::dispatch_batch_for_client(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        json!([
            modern_request(Some(1), "tools/list", "2026-07-28", json!({})),
            modern_request(Some(2), "ping", "2026-07-28", json!({})),
        ]),
        "era-batch",
    )
    .await;
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert!(answers[0].get("error").is_none(), "{}", answers[0]);
    assert_eq!(answers[1]["error"]["code"], -32601, "{}", answers[1]);
    assert_eq!(answers[1]["error"]["message"], removed_text("ping"));
}

/// A request that declares the revision and omits a required field is
/// Malformed, not Modern: the shared refusals do not apply, as before.
#[tokio::test]
async fn a_malformed_non_tools_call_request_keeps_today_s_answer() {
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "ping",
        "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } }
    });
    let answer = send(true, request).await.expect("answers");
    assert_eq!(answer["result"], json!({}), "{answer}");
}
