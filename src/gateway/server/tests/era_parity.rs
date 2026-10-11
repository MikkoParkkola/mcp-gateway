// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8368: stdio refuses, from the body alone, what `/mcp` refuses for a
//! request that declares MCP 2026-07-28: methods the revision removed, a
//! revision this build does not serve, a method whose capability the client did
//! not declare. Wire strings are written out, never taken from the constants.

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
    Gateway::dispatch_single_with_sink(
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
        &super::super::StdioTelemetry::default(),
    )
    .await
}

/// A request written against `version` with the `caps` the client declares.
fn modern_request(id: Option<i64>, method: &str, version: &str, caps: Value) -> Value {
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
    let set_level = send(true, legacy_request(Some(3), "logging/setLevel"))
        .await
        .expect("setLevel answers");
    assert_ne!(
        set_level["error"]["message"],
        removed_text("logging/setLevel"),
        "{set_level}"
    );
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

/// ERA.3a: a revision this build does not serve, or serves with modern support
/// off, is refused -32022; the same revision with support on is served; the
/// version refusal comes first.
#[tokio::test]
async fn modern_stdio_refuses_an_unserved_revision() {
    let unserved = send(
        true,
        modern_request(Some(1), "tools/list", "1999-01-01", json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(unserved["error"]["code"], -32022, "{unserved}");
    assert_eq!(
        unserved["error"]["message"],
        "unsupported protocol version '1999-01-01'"
    );
    assert_eq!(
        unserved["error"]["data"]["supportedVersions"],
        json!(["2026-07-28"])
    );

    let disabled = send(
        false,
        modern_request(Some(2), "tools/list", "2026-07-28", json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(disabled["error"]["code"], -32022, "{disabled}");
    assert_eq!(disabled["error"]["data"]["supportedVersions"], json!([]));

    let served = send(
        true,
        modern_request(Some(3), "tools/list", "2026-07-28", json!({})),
    )
    .await
    .expect("answers");
    assert!(served.get("error").is_none(), "{served}");

    let first = send(
        true,
        modern_request(Some(4), "ping", "1999-01-01", json!({})),
    )
    .await
    .expect("answers");
    assert_eq!(
        first["error"]["code"], -32022,
        "version before removed: {first}"
    );
}

/// ERA.3b: a method that needs a capability the client did not declare is
/// refused -32021 naming it; declared, the request passes the check; legacy
/// keeps today's answer.
#[tokio::test]
async fn modern_stdio_refuses_an_undeclared_capability() {
    for (method, capability) in [
        ("sampling/createMessage", "sampling"),
        ("elicitation/create", "elicitation"),
        ("roots/list", "roots"),
    ] {
        let refused = send(
            true,
            modern_request(Some(1), method, "2026-07-28", json!({})),
        )
        .await
        .expect("answers");
        assert_eq!(refused["error"]["code"], -32021, "{method}: {refused}");
        assert_eq!(
            refused["error"]["message"],
            format!("client did not declare the '{capability}' capability")
        );
        assert_eq!(
            refused["error"]["data"]["requiredCapabilities"],
            json!([capability])
        );

        let declared = send(
            true,
            modern_request(Some(2), method, "2026-07-28", json!({ capability: {} })),
        )
        .await
        .expect("answers");
        assert_ne!(declared["error"]["code"], -32021, "{method}: {declared}");

        let legacy = send(true, legacy_request(Some(3), method))
            .await
            .expect("answers");
        assert_ne!(legacy["error"]["code"], -32021, "{method}: {legacy}");
    }
}

/// A batch item runs with modern serving off, so a modern item newly gets
/// -32022 with an empty list (stated in the PR).
#[tokio::test]
async fn a_modern_batch_item_is_refused_as_unserved() {
    let answer = Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &modern_request(Some(1), "tools/list", "2026-07-28", json!({})),
        "era-batch",
    )
    .await
    .expect("answers");
    assert_eq!(answer["error"]["code"], -32022, "{answer}");
    assert_eq!(answer["error"]["data"]["supportedVersions"], json!([]));
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
