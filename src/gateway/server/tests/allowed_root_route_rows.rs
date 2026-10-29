// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end allowed-folder rows on the routes a client drives: each
//! outside path is refused with the root finding before the backend sees
//! it, and its inside twin reaches the backend as exactly the string
//! checked (I1-I3b). Batch 5b.

use serde_json::{Value, json};

use super::allowed_root_routes::Routes;

/// Whether a JSON-RPC answer is a refusal: an error, or an error result.
fn refused(answer: &Value) -> bool {
    answer.get("error").is_some() || answer["result"]["isError"] == json!(true)
}

/// The outside half: refused, recorded as the root finding (never a backend
/// lookup failure), and absent from what the backend received.
fn assert_outside(routes: &Routes, row: &str, answer: &Value, path: &str) {
    assert!(refused(answer), "{row}: refused: {answer}");
    let audit = routes.audited();
    assert!(
        audit.contains("path_outside_root"),
        "{row}: root finding: {audit}"
    );
    assert!(!audit.contains("unknown_backend"), "{row}: {audit}");
    assert!(
        !routes.received().contains(path),
        "{row}: the backend saw it"
    );
}

/// The inside half: answered, and received as exactly the checked string.
fn assert_inside(routes: &Routes, row: &str, answer: &Value, path: &str) {
    assert!(!refused(answer), "{row}: allowed: {answer}");
    let sent = serde_json::to_string(path).expect("a path serialises");
    assert!(
        routes.received().contains(&sent),
        "{row}: arrived as checked: {}",
        routes.received()
    );
}

fn call(path: &str) -> Value {
    json!({"name": "read_file", "arguments": {"path": path}})
}

/// I1: direct `tools/call` on `/mcp` (the surfaced tool) and on `/mcp/fs`.
#[tokio::test]
async fn i1_direct_routes_confine_the_path() {
    for uri in ["/mcp", "/mcp/fs"] {
        let routes = Routes::new().await;
        let (inside, outside) = (routes.path("safe/f"), routes.path("outside/f"));
        let answer = routes.post(uri, "tools/call", call(&outside)).await;
        assert_outside(&routes, uri, &answer, &outside);
        let answer = routes.post(uri, "tools/call", call(&inside)).await;
        assert_inside(&routes, uri, &answer, &inside);
    }
}

/// I2, I2b: `gateway_invoke` wrapping the call.
#[tokio::test]
async fn i2_gateway_invoke_confines_the_path() {
    let routes = Routes::new().await;
    let invoke = |path: &str| {
        json!({"name": "gateway_invoke", "arguments": {
            "server": "fs", "tool": "read_file", "arguments": {"path": path}}})
    };
    let (inside, outside) = (routes.path("safe/f"), routes.path("outside/f"));
    let answer = routes.post("/mcp", "tools/call", invoke(&outside)).await;
    assert_outside(&routes, "I2", &answer, &outside);
    let answer = routes.post("/mcp", "tools/call", invoke(&inside)).await;
    assert_inside(&routes, "I2b", &answer, &inside);
}

/// I3, I3b: a `gateway_execute` chain whose second step carries the path.
#[tokio::test]
async fn i3_execute_chain_second_step_confines_the_path() {
    let routes = Routes::new().await;
    let first = routes.path("safe/first");
    let chain = |path: &str| {
        json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": "fs:read_file", "arguments": {"path": first}},
            {"tool": "fs:read_file", "arguments": {"path": path}},
        ]}})
    };
    let (inside, outside) = (routes.path("safe/f"), routes.path("outside/f"));
    let answer = routes.post("/mcp", "tools/call", chain(&outside)).await;
    assert_outside(&routes, "I3", &answer, &outside);
    let answer = routes.post("/mcp", "tools/call", chain(&inside)).await;
    assert_inside(&routes, "I3b", &answer, &inside);
}

/// The stdio route stage: `gateway_invoke` over the stdio dispatch, through
/// the production meta-MCP firewall, confines the path the same way.
#[tokio::test]
async fn stdio_route_stage_confines_the_path() {
    let routes = Routes::new().await;
    let policy = std::sync::Arc::new(crate::security::ToolPolicy::default());
    let mtls = std::sync::Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let send = |path: String| {
        let request = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "fs", "tool": "read_file", "arguments": {"path": path}}}});
        let (meta, policy, mtls) = (&routes.meta, &policy, &mtls);
        async move {
            super::super::Gateway::dispatch_single(meta, policy, mtls, &request, "stdio-8939")
                .await
                .expect("a request is answered")
        }
    };
    let (inside, outside) = (routes.path("safe/f"), routes.path("outside/f"));
    let answer = send(outside.clone()).await;
    assert_outside(&routes, "stdio", &answer, &outside);
    let answer = send(inside.clone()).await;
    assert_inside(&routes, "stdio", &answer, &inside);
}
