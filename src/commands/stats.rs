//! Stats command handler for `mcp-gateway stats`.

use std::process::ExitCode;

/// Run the `stats` command against a running gateway.
pub async fn run_stats_command(url: &str, price: f64) -> ExitCode {
    use serde_json::json;

    let client = reqwest::Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_get_stats",
            "arguments": { "price_per_million": price }
        }
    });

    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));

    match client.post(&endpoint).json(&request_body).send().await {
        Ok(response) => handle_stats_response(response, &endpoint).await,
        Err(e) => {
            eprintln!("❌ Failed to connect to gateway: {e}");
            eprintln!("   Make sure the gateway is running at {url}");
            ExitCode::FAILURE
        }
    }
}

async fn handle_stats_response(response: reqwest::Response, url: &str) -> ExitCode {
    if !response.status().is_success() {
        eprintln!("❌ Gateway returned error: {}", response.status());
        return ExitCode::FAILURE;
    }
    match response.json::<serde_json::Value>().await {
        Ok(body) => print_stats_body(&body, url),
        Err(e) => {
            eprintln!("❌ Failed to parse response: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_stats_body(body: &serde_json::Value, _url: &str) -> ExitCode {
    if let Some(text) = extract_stats_text(body)
        && let Ok(stats) = serde_json::from_str::<serde_json::Value>(text)
    {
        println!("📊 Gateway Statistics\n");
        println!("Invocations:       {}", stats["invocations"]);
        println!("Cache Hits:        {}", stats["cache_hits"]);
        println!("Cache Hit Rate:    {}", stats["cache_hit_rate"]);
        println!("Tools Discovered:  {}", stats["tools_discovered"]);
        println!("Tools Available:   {}", stats["tools_available"]);
        println!(
            "Tokens Saved:      {}",
            stats["tokens_saved"].as_u64().unwrap_or(0)
        );
        println!("Estimated Savings: {}", stats["estimated_savings_usd"]);
        print_top_tools(&stats);
        return ExitCode::SUCCESS;
    }
    if let Some(error) = body.get("error") {
        eprintln!(
            "❌ Error: {}",
            error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
        );
        return ExitCode::FAILURE;
    }
    eprintln!("❌ Unexpected response format");
    ExitCode::FAILURE
}

fn extract_stats_text(body: &serde_json::Value) -> Option<&str> {
    body.get("result")?
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()
}

fn print_top_tools(stats: &serde_json::Value) {
    if let Some(top_tools) = stats["top_tools"].as_array()
        && !top_tools.is_empty()
    {
        println!("\n🏆 Top Tools:");
        for tool in top_tools {
            println!(
                "  • {}:{} - {} calls",
                tool["server"].as_str().unwrap_or(""),
                tool["tool"].as_str().unwrap_or(""),
                tool["count"]
            );
        }
    }
}
