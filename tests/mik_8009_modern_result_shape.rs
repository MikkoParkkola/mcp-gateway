// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8009: a 2026-07-28 result carries the fields that revision requires.
//!
//! Claude Code 2.1.289 speaks 2026-07-28 over stdio. It sent `server/discover`,
//! then the lists, and ended with zero gateway tools: every reply it got was
//! invalid under the published schema, which requires `resultType` on every
//! result and `ttlMs` plus `cacheScope` on discovery and the cacheable lists.
//!
//! The required sets below are copied from `$defs` in
//! `modelcontextprotocol/modelcontextprotocol` `schema/2026-07-28/schema.json`
//! (commits b488c1662 and 271ecc9ac), not written from memory: a test that
//! asserts the names its own implementation invented passes on a wire nobody
//! else can read.

mod common;
#[path = "common/stdio_session.rs"]
mod stdio_session;

use common::{Fixture, Value, json};
use stdio_session::StdioSession;

const DISCOVER_RESULT: &[&str] = &[
    "cacheScope",
    "capabilities",
    "resultType",
    "supportedVersions",
    "ttlMs",
];
const LIST_TOOLS_RESULT: &[&str] = &["cacheScope", "resultType", "tools", "ttlMs"];
const LIST_PROMPTS_RESULT: &[&str] = &["cacheScope", "prompts", "resultType", "ttlMs"];
const LIST_RESOURCES_RESULT: &[&str] = &["cacheScope", "resources", "resultType", "ttlMs"];
const LIST_RESOURCE_TEMPLATES_RESULT: &[&str] =
    &["cacheScope", "resourceTemplates", "resultType", "ttlMs"];
const CALL_TOOL_RESULT: &[&str] = &["content", "resultType"];

/// The `_meta` Claude Code 2.1.289 sent on every request, as tapped.
fn claude_code_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
            "name": "claude-code",
            "title": "Claude Code",
            "version": "2.1.289",
        },
        "io.modelcontextprotocol/clientCapabilities": {
            "roots": {"listChanged": true},
            "elicitation": {"form": {}, "url": {}},
        },
    })
}

fn modern_request(id: i64, method: &str, mut params: Value) -> Value {
    params["_meta"] = claude_code_meta();
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// Every name in `required` that `result` lacks, plus a malformed cache hint.
fn violations(result: &Value, required: &[&str]) -> Vec<String> {
    let mut missing: Vec<String> = required
        .iter()
        .filter(|field| result.get(**field).is_none())
        .map(|field| format!("missing {field}"))
        .collect();
    if let Some(kind) = result.get("resultType")
        && !kind.is_string()
    {
        missing.push(format!("resultType {kind} is not a string"));
    }
    if let Some(scope) = result.get("cacheScope")
        && !matches!(scope.as_str(), Some("private" | "public"))
    {
        missing.push(format!("cacheScope {scope} is not private|public"));
    }
    if let Some(ttl) = result.get("ttlMs")
        && ttl.as_u64().is_none()
    {
        missing.push(format!("ttlMs {ttl} is not a non-negative integer"));
    }
    missing
}

fn spawn_gateway(home: &std::path::Path) -> StdioSession {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        "backends: {}\n",
    )
    .expect("write gateway.yaml");
    StdioSession::spawn(home)
}

#[tokio::test]
async fn stdio_modern_results_carry_the_fields_2026_07_28_requires() {
    let home = tempfile::tempdir().expect("home");
    let mut session = spawn_gateway(home.path());

    // The order the client used: discovery first, no handshake, then the lists.
    let rows: [(&str, Value, &[&str]); 6] = [
        ("server/discover", json!({}), DISCOVER_RESULT),
        ("prompts/list", json!({}), LIST_PROMPTS_RESULT),
        ("resources/list", json!({}), LIST_RESOURCES_RESULT),
        (
            "resources/templates/list",
            json!({}),
            LIST_RESOURCE_TEMPLATES_RESULT,
        ),
        ("tools/list", json!({}), LIST_TOOLS_RESULT),
        (
            "tools/call",
            json!({"name": "gateway_list_servers", "arguments": {}}),
            CALL_TOOL_RESULT,
        ),
    ];
    let mut failures = Vec::new();
    for (id, (method, params, required)) in (1_i64..).zip(rows) {
        session.send(&modern_request(id, method, params)).await;
        let (lines, reply) = session.read_until_id(id).await;
        let reply = reply.unwrap_or_else(|| panic!("no reply to {method}: {lines:?}"));
        let result = reply
            .get("result")
            .unwrap_or_else(|| panic!("{method} must answer with a result: {reply}"));
        let mut found = violations(result, required);
        // The other half of the modern contract the shaper writes.
        if result["_meta"][mcp_gateway::protocol::meta::KEY_SERVER_INFO].is_null() {
            found.push("missing _meta serverInfo".to_string());
        }
        if !found.is_empty() {
            failures.push(format!("{method}: {found:?}"));
        }
    }
    session.shutdown().await;

    assert!(
        failures.is_empty(),
        "a 2026-07-28 client rejects these results, so it loads no tools: {failures:#?}"
    );
}

#[tokio::test]
async fn http_modern_results_carry_the_fields_2026_07_28_requires() {
    let (state, _store_dir) = common::state(Fixture::default()).await;
    let rows: [(&str, &[&str]); 4] = [
        ("server/discover", DISCOVER_RESULT),
        ("prompts/list", LIST_PROMPTS_RESULT),
        ("resources/list", LIST_RESOURCES_RESULT),
        ("tools/list", LIST_TOOLS_RESULT),
    ];
    let mut failures = Vec::new();
    for (method, required) in rows {
        let (status, body) = common::post(&state, common::modern(method, json!({})), &[]).await;
        assert!(status.is_success(), "{method} must answer: {status} {body}");
        let found = violations(&body["result"], required);
        if !found.is_empty() {
            failures.push(format!("{method}: {found:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "HTTP results are invalid under 2026-07-28: {failures:#?}"
    );
}

/// The fix shapes modern results only. A 2025 session keeps the results it
/// gets today, which carry none of the 2026 fields.
#[tokio::test]
async fn stdio_legacy_results_stay_without_the_2026_fields() {
    let home = tempfile::tempdir().expect("home");
    let mut session = spawn_gateway(home.path());
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mik-8009-legacy", "version": "0"},
            }}),
        )
        .await;
    assert!(
        session.read_until_id(1).await.1.is_some(),
        "no initialize reply"
    );
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    session
        .send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    let reply = reply.unwrap_or_else(|| panic!("no tools/list reply: {lines:?}"));
    let result = &reply["result"];
    assert!(
        result["tools"].is_array(),
        "legacy tools/list must list: {reply}"
    );
    for field in ["resultType", "ttlMs", "cacheScope"] {
        assert!(
            result.get(field).is_none(),
            "a 2025 session must not gain the 2026 field {field}: {reply}"
        );
    }
}
