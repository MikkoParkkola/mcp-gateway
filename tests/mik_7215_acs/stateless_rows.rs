// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[tokio::test]
async fn ac_stateless_3_a_modern_response_carries_no_session_header() {
    let (status, session, body) = post_mcp(modern_tools_list(1)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        session, None,
        "2026-07-28 removed protocol sessions and the Mcp-Session-Id header; \
         emitting one tells a modern client to carry state that no longer exists"
    );
}

#[tokio::test]
async fn ac_stateless_3_a_legacy_response_still_carries_the_session_header() {
    // The regression that matters. A change that strips the header
    // unconditionally satisfies the row above and breaks every 2025 client.
    let (status, session, body) = post_mcp(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list"
    }))
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        session.is_some(),
        "a 2025 client must keep the session header it has always received"
    );
}

#[tokio::test]
async fn ac_stateless_2_a_modern_result_identifies_the_server() {
    let (_, _, body) = post_mcp(modern_tools_list(3)).await;

    let info = &body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"];
    assert!(
        info["name"].is_string() && info["version"].is_string(),
        "a stateless client has no handshake to learn who it is talking to, \
         so every result identifies the server: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_2_a_legacy_result_is_unchanged() {
    // The mirror. Adding serverInfo to the shared result builder would
    // change the 2025 wire format for every existing client.
    let (_, _, body) = post_mcp(json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/list"
    }))
    .await;

    assert!(
        body["result"].get("_meta").is_none(),
        "a 2025 result gains no fields: {body}"
    );
}

#[tokio::test]
async fn a_well_formed_retry_naming_a_meta_tool_is_refused_before_dispatch() {
    // Adversarial review, 2026-08-30, confirmed at source: a malformed
    // retry was refused with -32602, but a well-formed one was logged at
    // debug and then dispatched as a fresh `tools/call`. For a destructive
    // tool that repeats whatever the first attempt already did — the exact
    // outcome the malformed branch exists to prevent, and the outcome the
    // comment above it claims cannot happen. `route_retry_to_origin_backend`
    // exempted the whole `gateway_` prefix, so a retry naming any meta-tool
    // bypassed the continuation guard; the exemption now covers only the two
    // tools that carry their own server and tool and open the envelope
    // themselves. Both shapes fail closed.
    let (status, _, body) = post_mcp(json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "gateway_list_servers",
            "arguments": {},
            "inputResponses": {
                "confirm": { "action": "accept", "content": { "ok": true } }
            },
            "requestState": "opaque-envelope"
        }
    }))
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an application denial rides in the JSON-RPC envelope: {body}"
    );
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert!(
        body.get("result").is_none(),
        "a refused retry must not serve the tool: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_9_a_malformed_modern_request_is_refused() {
    // Declared a version, omitted the capabilities. Refused, not served.
    let (status, _, body) = post_mcp(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/list",
        "params": {
            "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }
        }
    }))
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the specification requires 400 for a malformed request: {body}"
    );
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("clientCapabilities"),
        "the error names the field that was missing: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_4_an_unsupported_version_is_refused_with_its_own_error() {
    // A modern client naming a revision this gateway cannot serve gets a
    // recognised modern error listing what it can serve — which is what
    // lets the client retry on a shared version instead of guessing.
    let mut request = modern_tools_list(6);
    request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let (status, _, body) = post_mcp(request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"]["code"], -32022,
        "UnsupportedProtocolVersion, renumbered from -32004 by this revision: {body}"
    );
    let supported = &body["error"]["data"]["supportedVersions"];
    assert!(
        supported.is_array() && !supported.as_array().expect("array").is_empty(),
        "the error must list what the server does support: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_6_ping_is_refused_on_the_modern_path() {
    // `ping` was removed by this revision. A modern peer that can still
    // call it is not speaking this revision, whatever its version string
    // claims.
    let mut request = modern_tools_list(7);
    request["method"] = json!("ping");
    let (_, _, body) = post_mcp(request).await;

    assert!(
        body.get("error").is_some(),
        "ping is removed in 2026-07-28 and must be refused: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_6_every_removed_method_is_refused_on_the_modern_path() {
    // Total over the constant the handler consults, not over the three
    // methods the criterion happens to name: a test listing its own
    // methods goes quiet the moment a sixth is removed, and the guard it
    // is watching is the same `contains` either way.
    for (method, id) in mcp_gateway::protocol::meta::REMOVED_IN_2026_07_28
        .iter()
        .zip(900i64..)
    {
        let mut request = modern_tools_list(id);
        request["method"] = json!(method);
        let (status, _, body) = post_mcp(request).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{method}: {body}");
        assert_eq!(
            body["error"]["code"], -32601,
            "{method} is removed in 2026-07-28 and must be refused: {body}"
        );
    }
}

#[tokio::test]
async fn ac_stateless_6_ping_still_works_on_the_legacy_path() {
    // The regression. A version-blind removal satisfies the row above and
    // breaks every 2025 client's health check — and this gateway's own
    // backend health probe is a `ping`.
    let (status, _, body) = post_mcp(json!({
        "jsonrpc": "2.0", "id": 8, "method": "ping"
    }))
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("error").is_none(),
        "a 2025 client keeps the ping it has always had: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_8_one_endpoint_serves_both_eras() {
    // The dual-era claim, end to end: the same URL answers a 2025 client
    // and a 2026 client, and each gets its own era's treatment.
    let (legacy_status, legacy_session, legacy_body) = post_mcp(json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/list"
    }))
    .await;
    let (modern_status, modern_session, modern_body) = post_mcp(modern_tools_list(10)).await;

    assert_eq!(legacy_status, StatusCode::OK, "{legacy_body}");
    assert_eq!(modern_status, StatusCode::OK, "{modern_body}");
    assert!(
        legacy_session.is_some(),
        "the 2025 caller keeps its session"
    );
    assert_eq!(modern_session, None, "the 2026 caller is given none");
    assert!(
        legacy_body["result"]["tools"].is_array() && modern_body["result"]["tools"].is_array(),
        "both are served the tools, whatever era they speak"
    );
}

#[tokio::test]
async fn ac_stateless_8_modern_serving_is_off_unless_switched_on() {
    // The default an operator inherits on upgrade. Until the revision is
    // served completely, a client that asks for it is refused with an
    // answer it can act on — not served half a revision, where the working
    // half hides the missing one.
    let (state, _store_dir) = state_with_modern(false).await;
    let (status, _, body) = post_mcp_against(state, modern_tools_list(11)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32022, "{body}");
    assert_eq!(
        body["error"]["data"]["supportedVersions"],
        json!([]),
        "with the switch off the gateway claims no modern revision at all: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_8_a_legacy_client_is_unaffected_by_the_switch() {
    // The switch governs the modern path and nothing else. A 2025 client
    // sees the same gateway either way.
    for modern in [false, true] {
        let (state, _store_dir) = state_with_modern(modern).await;
        let (status, session, body) = post_mcp_against(
            state,
            json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/list" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "modern={modern}: {body}");
        assert!(session.is_some(), "modern={modern}: {body}");
    }
}

#[tokio::test]
async fn ac_stateless_5_an_unknown_method_is_404_with_a_json_rpc_body() {
    // The status distinguishes this from a legacy HTTP+SSE server that does
    // not host the modern endpoint at all: that 404 has no JSON-RPC body,
    // and a client uses the difference to decide whether to fall back.
    let mut request = modern_tools_list(13);
    request["method"] = json!("does/not/exist");
    let (status, _, body) = post_mcp(request).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], -32601, "{body}");
    assert_eq!(
        body["jsonrpc"], "2.0",
        "the body is what tells this apart from a transport-level 404: {body}"
    );
}

#[tokio::test]
async fn ac_stateless_10_an_undeclared_capability_is_named_in_the_refusal() {
    // The gateway must not rely on a capability the client did not declare.
    // When it needs one, the refusal says which — a client cannot fix what
    // it is not told.
    let mut request = modern_tools_list(14);
    request["method"] = json!("sampling/createMessage");
    let (status, _, body) = post_mcp(request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32021, "{body}");
    let required = &body["error"]["data"]["requiredCapabilities"];
    assert!(
        required
            .as_array()
            .is_some_and(|c| c.iter().any(|v| v == "sampling")),
        "the refusal must name the capability that was missing: {body}"
    );
}
