// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1441 refusal cells: a listed poisoned tool is refused by name on both
//! routes, whatever the argument-key enforcement mode; a warn-level
//! descriptor is still served.

use serde_json::{Value, json};

use super::super::issue_555_listing_scope::{call_tool, post};
use super::{CLEAN, POISONED, catalogue, env, env_with, names, tool};
use crate::config::{BackendConfig, InputSchemaEnforcement};

/// Call `name` on the direct route and through `gateway_invoke`.
async fn call_both(e: &super::Env, name: &str) -> (Value, Value) {
    let args = json!({ "name": name, "arguments": { "q": "x" } });
    let (_, direct) = post(&e.router, "/mcp/evil", None, "tools/call", args).await;
    let meta = call_tool(
        &e.router,
        None,
        "gateway_invoke",
        json!({ "server": "evil", "tool": name, "arguments": { "q": "x" } }),
    )
    .await;
    (direct, meta)
}

fn assert_withheld(e: &super::Env, direct: &Value, meta: &Value) {
    assert!(
        !e.calls().iter().any(|c| c == POISONED),
        "the backend received the poisoned call: {:?}",
        e.calls()
    );
    assert!(direct.to_string().contains("withheld"), "direct: {direct}");
    assert!(meta.to_string().contains("withheld"), "meta: {meta}");
}

/// T2: a listed poisoned tool is refused by name on both routes and the
/// backend never sees the call; the clean tool still goes through.
#[tokio::test]
async fn t2_a_listed_poisoned_tool_is_refused_by_name() {
    let e = env().await;
    let _ = call_both(&e, CLEAN).await;
    assert_eq!(
        e.calls().iter().filter(|c| *c == CLEAN).count(),
        2,
        "control: the clean tool must reach the backend on both routes"
    );
    let (direct, meta) = call_both(&e, POISONED).await;
    assert_withheld(&e, &direct, &meta);
}

/// T3: argument-key enforcement off does not switch the refusal off.
#[tokio::test]
async fn t3_refusal_holds_with_argument_key_enforcement_off() {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Off,
        ..BackendConfig::default()
    };
    let e = env_with(config, catalogue()).await;
    let (direct, meta) = call_both(&e, POISONED).await;
    assert_withheld(&e, &direct, &meta);
}

/// T6 (preservation): a descriptor the rule only warns about is served and
/// callable; withholding is for blocking findings alone.
#[tokio::test]
async fn t6_a_warn_level_descriptor_is_still_served() {
    let padded = format!("Echoes q.{}done", " ".repeat(60));
    let e = env_with(BackendConfig::default(), vec![tool("evil_padded", &padded)]).await;
    let (_, listed) = post(&e.router, "/mcp/evil", None, "tools/list", json!({})).await;
    assert!(
        names(&listed).iter().any(|n| n == "evil_padded"),
        "{listed}"
    );
    let _ = call_both(&e, "evil_padded").await;
    assert_eq!(e.calls().len(), 2, "{:?}", e.calls());
}

/// T12: a poisoned tool that also breaks an `x-mcp-header` rule is still
/// recorded as withheld, so dropping it for the header does not leave it
/// callable by name.
#[tokio::test]
async fn t12_a_poisoned_tool_with_a_bad_header_is_still_refused() {
    let mut both = tool(POISONED, super::PAYLOAD);
    both["inputSchema"]["properties"]["ratio"] =
        json!({ "type": "number", "x-mcp-header": "Ratio" });
    let e = env_with(BackendConfig::default(), vec![both]).await;
    let (direct, meta) = call_both(&e, POISONED).await;
    assert_withheld(&e, &direct, &meta);
}

/// #1441: an upstream error frame that also carries a `result` is forwarded
/// as an error only; its unjudged tool list never reaches the client.
#[tokio::test]
async fn an_error_frame_never_carries_an_unjudged_tool_list() {
    let e = env().await;
    e.upstream
        .error_frame
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (_, listed) = post(&e.router, "/mcp/evil", None, "tools/list", json!({})).await;
    assert!(
        listed.get("error").is_some(),
        "premise: an error frame: {listed}"
    );
    assert!(
        listed.get("result").is_none(),
        "an error frame carried an unjudged tool list: {listed}"
    );
}
