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
use serde_json::{json, Value};
use std::time::{Duration, Instant};

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

/// Check if gateway is running
async fn is_gateway_running() -> bool {
    let client = Client::new();
    client
        .post(GATEWAY_URL)
        .json(&JsonRpcRequest::new("tools/list", json!({})))
        .timeout(Duration::from_secs(2))
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

    serde_json::from_str(content_text)
        .map_err(|e| format!("Failed to parse content JSON: {e}"))
}

#[tokio::test]
#[ignore = "requires gateway running on localhost:39400"]
async fn test_gateway_get_stats() {
    if !is_gateway_running().await {
        eprintln!("⚠️  Gateway not running on {GATEWAY_URL}, skipping test");
        return;
    }

    let client = Client::new();

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
        stats.get("tokens_saved").is_some(),
        "Missing 'tokens_saved' field"
    );
    assert!(stats.get("top_tools").is_some(), "Missing 'top_tools' field");
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
    assert!(
        stats.get("estimated_savings_usd").is_some(),
        "Missing 'estimated_savings_usd' field"
    );

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
        stats["tokens_saved"].is_number(),
        "tokens_saved should be a number"
    );
    assert!(stats["top_tools"].is_array(), "top_tools should be an array");

    println!("✅ Stats test passed: {stats:?}");
}

#[tokio::test]
#[ignore = "requires gateway running on localhost:39400"]
async fn test_gateway_search_tools() {
    if !is_gateway_running().await {
        eprintln!("⚠️  Gateway not running on {GATEWAY_URL}, skipping test");
        return;
    }

    let client = Client::new();

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
    let matches = results["matches"].as_array().expect("matches should be array");

    // Each match should have server, tool, description
    for m in matches {
        assert!(m.get("server").is_some(), "Match missing 'server' field: {m:?}");
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
#[ignore = "requires gateway running on localhost:39400"]
async fn test_invoke_caching() {
    if !is_gateway_running().await {
        eprintln!("⚠️  Gateway not running on {GATEWAY_URL}, skipping test");
        return;
    }

    let client = Client::new();

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
    let initial_stats =
        parse_tool_response(&initial_body).expect("Failed to parse initial stats");
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

    let start1 = Instant::now();
    let response1 = client
        .post(GATEWAY_URL)
        .json(&invoke_request)
        .send()
        .await
        .expect("Failed to send first request");
    let duration1 = start1.elapsed();

    assert!(response1.status().is_success(), "First request failed");
    let body1: Value = response1.json().await.expect("Failed to parse first response");
    assert!(
        body1.get("error").is_none(),
        "First invocation error: {:?}",
        body1.get("error")
    );

    // Small delay to ensure cache is written
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second invocation - SHOULD be cached (same server, tool, arguments)
    let start2 = Instant::now();
    let response2 = client
        .post(GATEWAY_URL)
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
        eprintln!("⚠️  Gateway not running on {GATEWAY_URL}, skipping test");
        return;
    }

    let client = Client::new();

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
        assert!(server.get("name").is_some(), "Server missing 'name' field: {server:?}");
        assert!(server.get("running").is_some(), "Server missing 'running' field: {server:?}");
        assert!(
            server.get("transport").is_some(),
            "Server missing 'transport' field: {server:?}"
        );
        assert!(
            server.get("tools_count").is_some(),
            "Server missing 'tools_count' field: {server:?}"
        );
        assert!(
            server.get("circuit_state").is_some(),
            "Server missing 'circuit_state' field: {server:?}"
        );

        // Verify types
        assert!(server["name"].is_string(), "name should be string");
        assert!(server["running"].is_boolean(), "running should be boolean");
        assert!(server["transport"].is_string(), "transport should be string");
        assert!(
            server["tools_count"].is_number(),
            "tools_count should be number"
        );
        assert!(
            server["circuit_state"].is_string(),
            "circuit_state should be string"
        );
    }

    println!("✅ List servers test passed: found {} servers", servers.len());
}

#[tokio::test]
#[ignore = "requires mcp-gateway binary built in target/"]
async fn test_cap_registry_list() {
    // Check if mcp-gateway binary exists in target/debug or target/release
    let binary_path = if std::path::Path::new("target/release/mcp-gateway").exists() {
        "target/release/mcp-gateway"
    } else if std::path::Path::new("target/debug/mcp-gateway").exists() {
        "target/debug/mcp-gateway"
    } else {
        eprintln!("⚠️  mcp-gateway binary not found, skipping CLI test");
        eprintln!("   Build with: cargo build --release");
        return;
    };

    // Run: mcp-gateway cap registry-list
    let output = std::process::Command::new(binary_path)
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

    // Output should contain capability names from registry/index.json
    // Expected capabilities: stripe_list_charges, yahoo_stock_quote, ecb_exchange_rates,
    // gmail_send_email, slack_post_message, weather_current, wikipedia_search, github_create_issue

    let expected_capabilities = [
        "stripe_list_charges",
        "yahoo_stock_quote",
        "ecb_exchange_rates",
        "gmail_send_email",
        "slack_post_message",
        "weather_current",
        "wikipedia_search",
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
#[ignore = "requires gateway running on localhost:39400"]
async fn test_gateway_integration_flow() {
    if !is_gateway_running().await {
        eprintln!("⚠️  Gateway not running on {GATEWAY_URL}, skipping test");
        return;
    }

    let client = Client::new();

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
