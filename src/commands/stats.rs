// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stats command handler for `mcp-gateway stats`.

use std::process::ExitCode;

/// Build the default gateway base URL for the `stats` command from the
/// configured bind host/port.
///
/// `server.host` is a *bind* address (which interface to listen on), not
/// necessarily an address an HTTP client can dial — a wildcard bind
/// (`0.0.0.0`, `::`) means "all interfaces", not "connect to literally
/// `0.0.0.0`". This translates a wildcard bind to the loopback address so the
/// CLI can actually reach a locally-running gateway; a concrete host
/// (`127.0.0.1`, a real hostname/IP) passes through unchanged. IPv6 literals
/// are bracketed per RFC 3986 §3.2.2 so the result is a valid URL authority.
///
/// This exists because `stats` previously hardcoded `http://127.0.0.1:39400`
/// regardless of `--config`, so `mcp-gateway --config X stats` silently
/// talked to whatever else was listening on the default port instead of the
/// gateway `X` actually describes (MIK-6742).
pub fn default_stats_url(host: &str, port: u16) -> String {
    let client_host = if is_wildcard_bind(host) {
        "127.0.0.1"
    } else {
        host
    };
    if client_host.contains(':') && !client_host.starts_with('[') {
        format!("http://[{client_host}]:{port}")
    } else {
        format!("http://{client_host}:{port}")
    }
}

/// `true` when `host` is a wildcard bind address ("listen on all
/// interfaces") rather than a specific, client-dialable address.
fn is_wildcard_bind(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "0:0:0:0:0:0:0:0")
}

/// Plain HTTP client for the `stats` command. (MIK-8660 seam)
fn stats_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// `stats` output text for stdout (`Ok`) or stderr (`Err`). (MIK-8660 seam)
async fn stats_outcome(client: &reqwest::Client, url: &str) -> Result<String, String> {
    use serde_json::json;

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_get_stats",
            "arguments": {}
        }
    });

    let endpoint = format!("{}/mcp", url.trim_end_matches('/'));

    match client.post(&endpoint).json(&request_body).send().await {
        Ok(response) => handle_stats_response(response, &endpoint).await,
        Err(e) => Err(format!(
            "❌ Failed to connect to gateway: {e}\n   Make sure the gateway is running at {url}\n"
        )),
    }
}

/// Run the `stats` command against a running gateway.
pub async fn run_stats_command(url: &str) -> ExitCode {
    match stats_outcome(&stats_client(), url).await {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(text) => {
            eprint!("{text}");
            ExitCode::FAILURE
        }
    }
}

async fn handle_stats_response(response: reqwest::Response, url: &str) -> Result<String, String> {
    if !response.status().is_success() {
        return Err(format!("❌ Gateway returned error: {}\n", response.status()));
    }
    match response.json::<serde_json::Value>().await {
        Ok(body) => print_stats_body(&body, url),
        Err(e) => Err(format!("❌ Failed to parse response: {e}\n")),
    }
}

fn print_stats_body(body: &serde_json::Value, _url: &str) -> Result<String, String> {
    if let Some(text) = extract_stats_text(body)
        && let Ok(stats) = serde_json::from_str::<serde_json::Value>(text)
    {
        let mut out = format!(
            "📊 Gateway Statistics\n\nInvocations:       {}\nCache Hits:        {}\nCache Hit Rate:    {}\nTools Discovered:  {}\nTools Available:   {}\n",
            stats["invocations"],
            stats["cache_hits"],
            stats["cache_hit_rate"],
            stats["tools_discovered"],
            stats["tools_available"]
        );
        out.push_str(&print_top_tools(&stats));
        return Ok(out);
    }
    if let Some(error) = body.get("error") {
        return Err(format!(
            "❌ Error: {}\n",
            error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
        ));
    }
    Err("❌ Unexpected response format\n".to_string())
}

fn extract_stats_text(body: &serde_json::Value) -> Option<&str> {
    body.get("result")?
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()
}

fn print_top_tools(stats: &serde_json::Value) -> String {
    if let Some(top_tools) = stats["top_tools"].as_array()
        && !top_tools.is_empty()
    {
        let mut out = String::from("\n🏆 Top Tools:\n");
        for tool in top_tools {
            out.push_str(&format!(
                "  • {}:{} - {} calls\n",
                tool["server"].as_str().unwrap_or(""),
                tool["tool"].as_str().unwrap_or(""),
                tool["count"]
            ));
        }
        return out;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GIVEN the default gateway config's loopback host/port
    /// WHEN building the default stats URL
    /// THEN it matches the legacy hardcoded default exactly (no behavior
    /// change for the common case).
    #[test]
    fn default_stats_url_loopback_host_passes_through() {
        assert_eq!(
            default_stats_url("127.0.0.1", 39400),
            "http://127.0.0.1:39400"
        );
    }

    /// GIVEN a `serve` config bound to a non-default port (MIK-6742 repro:
    /// `serve` on a free port other than 39400)
    /// WHEN building the default stats URL
    /// THEN the resolved URL carries the configured port, not the old
    /// hardcoded 39400 — this is the exact scenario that produced the 406
    /// (stats silently talked to an unrelated service squatting on 39400).
    #[test]
    fn default_stats_url_tracks_configured_non_default_port() {
        assert_eq!(
            default_stats_url("127.0.0.1", 39477),
            "http://127.0.0.1:39477"
        );
    }

    /// GIVEN a wildcard IPv4 bind (`0.0.0.0`, "listen on every interface")
    /// WHEN building the default stats URL
    /// THEN the client target is translated to the loopback address, since a
    /// client cannot dial `0.0.0.0` as a destination.
    #[test]
    fn default_stats_url_translates_ipv4_wildcard_bind_to_loopback() {
        assert_eq!(
            default_stats_url("0.0.0.0", 39400),
            "http://127.0.0.1:39400"
        );
    }

    /// GIVEN a wildcard IPv6 bind (`::`)
    /// WHEN building the default stats URL
    /// THEN it is also translated to the (unbracketed) IPv4 loopback address.
    #[test]
    fn default_stats_url_translates_ipv6_wildcard_bind_to_loopback() {
        assert_eq!(default_stats_url("::", 39400), "http://127.0.0.1:39400");
    }

    /// GIVEN a concrete, non-wildcard IPv6 literal host
    /// WHEN building the default stats URL
    /// THEN it is bracketed per RFC 3986 §3.2.2 so the result is a valid URL.
    #[test]
    fn default_stats_url_brackets_non_wildcard_ipv6_host() {
        assert_eq!(default_stats_url("::1", 39400), "http://[::1]:39400");
    }

    /// GIVEN a concrete hostname (not an IP literal)
    /// WHEN building the default stats URL
    /// THEN the hostname passes through unchanged alongside its port.
    #[test]
    fn default_stats_url_passes_through_concrete_hostname() {
        assert_eq!(
            default_stats_url("gateway.internal", 8080),
            "http://gateway.internal:8080"
        );
    }
}
