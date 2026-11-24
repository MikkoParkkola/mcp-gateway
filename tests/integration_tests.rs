// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Integration tests for MCP Gateway new features
//!
//! These tests verify the following new features:
//! 1. Stats meta-tool (`gateway_get_stats`)
//! 2. Search tools with ranking (`gateway_search_tools`)
//! 3. Response caching (`gateway_invoke`)
//! 4. List servers (`gateway_list_servers`)
//! 5. CLI commands (cap registry-list)
//!
//! Note: These tests require the gateway to be running on localhost:39400
//! Run with: `cargo test --test integration_tests`
//! Or individually with: `cargo test --test integration_tests` `test_name`

use reqwest::Client;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/required.rs"]
mod required;

/// Gateway URL for testing
const GATEWAY_URL: &str = "http://localhost:39400/mcp";

/// JSON-RPC request helper
#[derive(serde::Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Value,
}

impl JsonRpcRequest {
    fn new(method: &str, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: method.to_string(),
            params,
        }
    }

    fn tools_call(tool_name: &str, arguments: &Value) -> Self {
        Self::new(
            "tools/call",
            json!({
                "name": tool_name,
                "arguments": arguments
            }),
        )
    }
}

/// The admin key a CI step generates for the gateway it starts (random per run, never a repo
/// secret). Read here only: `gateway_get_stats` is admin-only, so the rows that call it need an
/// admin caller.
fn admin_key() -> Option<String> {
    std::env::var("MCP_GATEWAY_TEST_ADMIN_KEY")
        .ok()
        .filter(|key| !key.is_empty())
}

/// What a stats row needs and names when it cannot run.
const ADMIN_KEY_NEEDED: &str = "MCP_GATEWAY_TEST_ADMIN_KEY (stats answer only an admin caller)";

/// A client that sends the admin key as a bearer when one is set. The gateway admits admin
/// meta-tools only for an authenticated caller with gateway admin standing; without a key the
/// rows talk to an auth-off gateway.
fn test_client() -> Client {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(key) = admin_key() {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
            .expect("an admin key is visible ASCII");
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    // A hang guard, well above any row's work: a stalled request fails as this row's error, not as the CI step's
    // 10-minute limit.
    Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("an HTTP client")
}

/// Check if gateway is running
async fn is_gateway_running() -> bool {
    let client = test_client();
    client
        .post(GATEWAY_URL)
        .json(&JsonRpcRequest::new("tools/list", json!({})))
        // A hang guard: a slow answer under load must not read as "not
        // running" and skip the test; a closed port still fails at once.
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .is_ok()
}

/// Parse MCP response content from tools/call
fn parse_tool_response(response: &Value) -> Result<Value, String> {
    // MCP wraps tool responses in result.content[0].text as JSON string
    let content_text = response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get(0))
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .ok_or("Missing content.text in response")?;

    serde_json::from_str(content_text).map_err(|e| format!("Failed to parse content JSON: {e}"))
}

#[tokio::test]
#[ignore = "requires a gateway on localhost:39400 and an admin key (MCP_GATEWAY_TEST_ADMIN_KEY)"]
async fn test_gateway_get_stats() {
    if !is_gateway_running().await {
        // No gateway: fail under TESTS_REQUIRE_ALL instead of passing unrun.
        required::skip_or_fail(&format!("a gateway answering on {GATEWAY_URL}"));
        return;
    }
    if admin_key().is_none() {
        required::skip_or_fail(ADMIN_KEY_NEEDED);
        return;
    }

    let client = test_client();

    // Call gateway_get_stats via MCP JSON-RPC
    let request = JsonRpcRequest::tools_call("gateway_get_stats", &json!({}));

    let response = client
        .post(GATEWAY_URL)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert!(response.status().is_success(), "HTTP request failed");

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify no JSON-RPC error
    assert!(
        body.get("error").is_none(),
        "JSON-RPC error: {:?}",
        body.get("error")
    );

    // Parse the actual tool response
    let stats = parse_tool_response(&body).expect("Failed to parse tool response");

    // Verify required fields are present
    assert!(
        stats.get("invocations").is_some(),
        "Missing 'invocations' field"
    );
    assert!(
        stats.get("cache_hits").is_some(),
        "Missing 'cache_hits' field"
    );
    assert!(
        stats.get("top_tools").is_some(),
        "Missing 'top_tools' field"
    );
    assert!(
        stats.get("cache_hit_rate").is_some(),
        "Missing 'cache_hit_rate' field"
    );
    assert!(
        stats.get("tools_discovered").is_some(),
        "Missing 'tools_discovered' field"
    );
    assert!(
        stats.get("tools_available").is_some(),
        "Missing 'tools_available' field"
    );
    assert!(stats.get("tokens_saved").is_none());
    assert!(stats.get("estimated_savings_usd").is_none());

    // Verify types
    assert!(
        stats["invocations"].is_number(),
        "invocations should be a number"
    );
    assert!(
        stats["cache_hits"].is_number(),
        "cache_hits should be a number"
    );
    assert!(
        stats["top_tools"].is_array(),
        "top_tools should be an array"
    );

    println!("✅ Stats test passed: {stats:?}");
}

#[tokio::test]
#[ignore = "requires gateway running on localhost:39400"]
async fn test_gateway_search_tools() {
    if !is_gateway_running().await {
        // No gateway: fail under TESTS_REQUIRE_ALL instead of passing unrun.
        required::skip_or_fail(&format!("a gateway answering on {GATEWAY_URL}"));
        return;
    }

    let client = test_client();

    // Search for "weather" tools
    let request = JsonRpcRequest::tools_call(
        "gateway_search_tools",
        &json!({
            "query": "weather",
            "limit": 5
        }),
    );

    let response = client
        .post(GATEWAY_URL)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert!(response.status().is_success(), "HTTP request failed");

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify no JSON-RPC error
    assert!(
        body.get("error").is_none(),
        "JSON-RPC error: {:?}",
        body.get("error")
    );

    // Parse the search results
    let results = parse_tool_response(&body).expect("Failed to parse tool response");

    // Verify result structure
    assert!(results.get("query").is_some(), "Missing 'query' field");
    assert!(results.get("matches").is_some(), "Missing 'matches' field");
    assert!(results.get("total").is_some(), "Missing 'total' field");

    assert_eq!(
        results["query"].as_str().unwrap(),
        "weather",
        "Query should be 'weather'"
    );

    // Verify matches array
    let matches = results["matches"]
        .as_array()
        .expect("matches should be array");
    // The repository ships weather_current (capabilities/knowledge/weather_current.yaml, the gateway's capability
    // directory in CI): an empty or wrongly loaded catalogue must not pass on structure alone.
    assert!(
        matches.iter().any(|m| m["tool"] == "weather_current"),
        "the shipped weather_current capability is not among the matches: {matches:?}"
    );

    // Each match should have server, tool, description
    for m in matches {
        assert!(
            m.get("server").is_some(),
            "Match missing 'server' field: {m:?}"
        );
        assert!(m.get("tool").is_some(), "Match missing 'tool' field: {m:?}");
        assert!(
            m.get("description").is_some(),
            "Match missing 'description' field: {m:?}"
        );

        // If ranking is enabled, score field should be present
        // (This is optional depending on configuration)
        if m.get("score").is_some() {
            assert!(
                m["score"].is_number(),
                "score should be a number if present"
            );
        }
    }

    println!("✅ Search test passed: found {} results", matches.len());
}

#[tokio::test]
#[ignore = "opt-in: calls the live Open-Meteo API through a gateway on :39400; run by hand"]
// Out of CI on purpose: an outside outage must not redden a pull request. The cache logic
// itself is covered in-crate through the client-swap seam; a stub cannot stand in here,
// because a spawned gateway refuses loopback egress and a loopback-relaxed fetch never enters
// the cache.
async fn test_invoke_caching() {
    if !is_gateway_running().await {
        // No gateway: fail under TESTS_REQUIRE_ALL instead of passing unrun.
        required::skip_or_fail(&format!("a gateway answering on {GATEWAY_URL}"));
        return;
    }
    if admin_key().is_none() {
        required::skip_or_fail(ADMIN_KEY_NEEDED);
        return;
    }

    let client = test_client();

    // First, get stats to establish baseline
    let stats_request = JsonRpcRequest::tools_call("gateway_get_stats", &json!({}));

    let initial_response = client
        .post(GATEWAY_URL)
        .json(&stats_request)
        .send()
        .await
        .expect("Failed to get initial stats");

    let initial_body: Value = initial_response
        .json()
        .await
        .expect("Failed to parse initial stats");
    let initial_stats = parse_tool_response(&initial_body).expect("Failed to parse initial stats");
    let initial_cache_hits = initial_stats["cache_hits"].as_u64().unwrap_or(0);

    // First invocation - should NOT be cached
    let invoke_request = JsonRpcRequest::tools_call(
        "gateway_invoke",
        &json!({
            "server": "capabilities",
            "tool": "weather_current",
            "arguments": {
                "latitude": 52.52,
                "longitude": 13.405
            }
        }),
    );

    // A response is cached only for a request whose protocol revision is known (docs/UPGRADING-4.0.md
    // section 6): this bare POST runs no initialize, so both invocations name the revision in the
    // header, or the second one never reaches the cache.
    let revision = (
        "MCP-Protocol-Version",
        mcp_gateway::protocol::PROTOCOL_VERSION,
    );
    let start1 = Instant::now();
    let response1 = client
        .post(GATEWAY_URL)
        .header(revision.0, revision.1)
        .json(&invoke_request)
        .send()
        .await
        .expect("Failed to send first request");
    let duration1 = start1.elapsed();

    assert!(response1.status().is_success(), "First request failed");
    let body1: Value = response1
        .json()
        .await
        .expect("Failed to parse first response");
    assert!(
        body1.get("error").is_none(),
        "First invocation error: {:?}",
        body1.get("error")
    );

    // No wait here: the gateway writes the cache before it answers (post_dispatch's set_read runs ahead of the
    // response), so the first answer arriving means the entry is in.
    // Second invocation - SHOULD be cached (same server, tool, arguments)
    let start2 = Instant::now();
    let response2 = client
        .post(GATEWAY_URL)
        .header(revision.0, revision.1)
        .json(&invoke_request)
        .send()
        .await
        .expect("Failed to send second request");
    let duration2 = start2.elapsed();

    assert!(response2.status().is_success(), "Second request failed");
    let body2: Value = response2
        .json()
        .await
        .expect("Failed to parse second response");
    assert!(
        body2.get("error").is_none(),
        "Second invocation error: {:?}",
        body2.get("error")
    );

    // Get final stats
    let final_response = client
        .post(GATEWAY_URL)
        .json(&stats_request)
        .send()
        .await
        .expect("Failed to get final stats");

    let final_body: Value = final_response
        .json()
        .await
        .expect("Failed to parse final stats");
    let final_stats = parse_tool_response(&final_body).expect("Failed to parse final stats");
    let final_cache_hits = final_stats["cache_hits"].as_u64().unwrap_or(0);

    // Verify cache hit occurred
    assert!(
        final_cache_hits > initial_cache_hits,
        "Cache hits should have increased. Initial: {initial_cache_hits}, Final: {final_cache_hits}"
    );

    // Cached response should typically be faster (though not guaranteed in all environments)
    println!(
        "✅ Caching test passed. First call: {:?}, Second call: {:?}, Cache hits increased by: {}",
        duration1,
        duration2,
        final_cache_hits - initial_cache_hits
    );
}

#[tokio::test]
#[ignore = "requires gateway running on localhost:39400"]
async fn test_gateway_list_servers() {
    if !is_gateway_running().await {
        // No gateway: fail under TESTS_REQUIRE_ALL instead of passing unrun.
        required::skip_or_fail(&format!("a gateway answering on {GATEWAY_URL}"));
        return;
    }

    let client = test_client();

    // Call gateway_list_servers
    let request = JsonRpcRequest::tools_call("gateway_list_servers", &json!({}));

    let response = client
        .post(GATEWAY_URL)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert!(response.status().is_success(), "HTTP request failed");

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify no JSON-RPC error
    assert!(
        body.get("error").is_none(),
        "JSON-RPC error: {:?}",
        body.get("error")
    );

    // Parse the servers list
    let servers_response = parse_tool_response(&body).expect("Failed to parse tool response");

    // Verify servers field exists and is an array
    assert!(
        servers_response.get("servers").is_some(),
        "Missing 'servers' field"
    );
    let servers = servers_response["servers"]
        .as_array()
        .expect("servers should be array");

    // Should have at least one server (capabilities backend always present)
    assert!(
        !servers.is_empty(),
        "Expected at least one server to be available"
    );

    // Verify each server has required fields
    for server in servers {
        assert!(
            server.get("name").is_some(),
            "Server missing 'name' field: {server:?}"
        );
        assert!(
            server.get("running").is_some(),
            "Server missing 'running' field: {server:?}"
        );
        assert!(
            server.get("transport").is_some(),
            "Server missing 'transport' field: {server:?}"
        );
        assert!(
            server.get("tools_count").is_some(),
            "Server missing 'tools_count' field: {server:?}"
        );
        assert!(
            server.get("circuit_breaker").is_some(),
            "Server missing 'circuit_breaker' field: {server:?}"
        );

        // Verify types
        assert!(server["name"].is_string(), "name should be string");
        assert!(server["running"].is_boolean(), "running should be boolean");
        assert!(
            server["transport"].is_string(),
            "transport should be string"
        );
        // MIK-8721: a count only for a backend whose tools are known; null
        // until then, so an unenumerated backend never reads as empty.
        let known = server["tools_known"]
            .as_bool()
            .unwrap_or_else(|| panic!("tools_known should be a boolean: {server:?}"));
        if known {
            assert!(
                server["tools_count"].as_u64().is_some(),
                "a known backend's tools_count should be a whole, non-negative number: {server:?}"
            );
        } else {
            assert_eq!(
                server.get("tools_count"),
                Some(&serde_json::Value::Null),
                "an unenumerated backend's tools_count should be null: {server:?}"
            );
        }
        assert!(
            server["circuit_breaker"].is_string(),
            "circuit_breaker should be string"
        );
    }

    println!(
        "✅ List servers test passed: found {} servers",
        servers.len()
    );
}

#[tokio::test]
async fn test_cap_registry_list() {
    // The binary cargo built for this test crate, so it always exists and the row needs no
    // skip; spawned through the shared helper so it runs with an isolated home, never the
    // developer's.
    let home = tempfile::tempdir().expect("temp home");
    let output = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["cap", "registry-list"])
        .output()
        .expect("Failed to execute mcp-gateway cap registry-list");

    // Should succeed
    assert!(
        output.status.success(),
        "cap registry-list command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output should contain capability names from the capabilities directory. wikipedia_search
    // left the list with the duplicate-YAML cleanup (0d66c80f88); the rest are still shipped.

    let expected_capabilities = [
        "stripe_list_charges",
        "yahoo_stock_quote",
        "ecb_exchange_rates",
        "gmail_send_email",
        "slack_post_message",
        "weather_current",
        "github_create_issue",
    ];

    for cap in &expected_capabilities {
        assert!(
            stdout.contains(cap),
            "Output should contain capability '{cap}', but got: {stdout}"
        );
    }

    println!("✅ CLI registry-list test passed");
}

#[tokio::test]
#[ignore = "requires a gateway on localhost:39400 and an admin key (MCP_GATEWAY_TEST_ADMIN_KEY)"]
async fn test_gateway_integration_flow() {
    if !is_gateway_running().await {
        // No gateway: fail under TESTS_REQUIRE_ALL instead of passing unrun.
        required::skip_or_fail(&format!("a gateway answering on {GATEWAY_URL}"));
        return;
    }
    if admin_key().is_none() {
        required::skip_or_fail(ADMIN_KEY_NEEDED);
        return;
    }

    let client = test_client();

    // 1. List servers
    let list_servers_req = JsonRpcRequest::tools_call("gateway_list_servers", &json!({}));
    let servers_response = client
        .post(GATEWAY_URL)
        .json(&list_servers_req)
        .send()
        .await
        .expect("Failed to list servers");
    let servers_body: Value = servers_response.json().await.expect("Failed to parse");
    let servers_data = parse_tool_response(&servers_body).expect("Failed to parse servers");
    let servers = servers_data["servers"].as_array().expect("servers array");

    assert!(!servers.is_empty(), "Should have at least one server");

    // 2. Search for tools
    let search_req = JsonRpcRequest::tools_call(
        "gateway_search_tools",
        &json!({
            "query": "weather",
            "limit": 10
        }),
    );
    let search_response = client
        .post(GATEWAY_URL)
        .json(&search_req)
        .send()
        .await
        .expect("Failed to search");
    let search_body: Value = search_response.json().await.expect("Failed to parse");
    let search_data = parse_tool_response(&search_body).expect("Failed to parse search");

    // 3. Get stats
    let stats_req = JsonRpcRequest::tools_call("gateway_get_stats", &json!({}));
    let stats_response = client
        .post(GATEWAY_URL)
        .json(&stats_req)
        .send()
        .await
        .expect("Failed to get stats");
    let stats_body: Value = stats_response.json().await.expect("Failed to parse");
    let stats_data = parse_tool_response(&stats_body).expect("Failed to parse stats");

    // Stats should show the search we just performed
    let searches_found = search_data["total"].as_u64().unwrap_or(0);
    assert!(
        stats_data["tools_discovered"].as_u64().unwrap_or(0) >= searches_found,
        "Stats should reflect discovered tools"
    );

    println!("✅ Integration flow test passed");
    println!("   Servers: {}", servers.len());
    println!("   Search results: {searches_found}");
    println!("   Total invocations: {}", stats_data["invocations"]);
}
