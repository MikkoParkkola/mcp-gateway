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

/// Build the HTTP client for the `stats` command.
///
/// stats talks only to this gateway's own /mcp, so no redirect is legitimate and none is followed; no environment proxy either.
fn stats_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("❌ Failed to build HTTP client: {e}\n"))
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
    let client = match stats_client() {
        Ok(client) => client,
        Err(text) => {
            eprint!("{text}");
            return ExitCode::FAILURE;
        }
    };
    match stats_outcome(&client, url).await {
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
    if response.status().is_redirection() {
        if let Some(location) = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
        {
            return Err(format!(
                "❌ the gateway URL redirected to {location}; point stats at the final URL\n"
            ));
        }
        return Err("❌ the gateway URL redirected; point stats at the final URL\n".to_string());
    }
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

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

    /// A listener on loopback serving `app`; returns its base URL.
    async fn serve(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    /// The gateway stub: POST `/mcp` answers the stats payload.
    fn stats_stub() -> axum::Router {
        axum::Router::new().route(
            "/mcp",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "{\"invocations\":3,\"cache_hits\":1,\"cache_hit_rate\":0.5,\"tools_discovered\":2,\"tools_available\":2,\"top_tools\":[]}"
                        }]
                    }
                }))
            }),
        )
    }

    /// A counting listener; returns its base URL and hit count.
    async fn serve_counter() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        let base = serve(axum::Router::new().fallback(move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }))
        .await;
        (base, hits)
    }

    /// T7a (GUARD): stats renders the gateway's reported counters.
    #[tokio::test]
    async fn stats_outcome_renders_the_stubbed_gateway_statistics() {
        let base = serve(stats_stub()).await;
        let outcome = tokio::time::timeout(HANG_BOUND, stats_outcome(&stats_client(), &base))
            .await
            .expect("bounded");
        match outcome {
            Ok(text) => assert!(text.contains("Invocations:       3"), "text: {text}"),
            Err(msg) => panic!("expected Ok, got Err: {msg}"),
        }
    }

    /// T7b (GUARD): stats reaches the whole 127/8 loopback range.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stats_outcome_reaches_a_127_8_loopback_address() {
        // The only thing that could refuse a private host is an SSRF pin; stats has none, and a pin classifies 127.0.0.2 like an RFC1918 address.
        let listener = tokio::net::TcpListener::bind("127.0.0.2:0")
            .await
            .expect("bind 127.0.0.2");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, stats_stub()).await });
        let base = format!("http://{addr}");
        let outcome = tokio::time::timeout(HANG_BOUND, stats_outcome(&stats_client(), &base))
            .await
            .expect("bounded");
        match outcome {
            Ok(text) => assert!(text.contains("Invocations:       3"), "text: {text}"),
            Err(msg) => panic!("expected Ok, got Err: {msg}"),
        }
    }

    /// T7c (RED): a 301 from the gateway URL is reported, not followed.
    #[tokio::test]
    async fn stats_outcome_reports_a_redirect_without_following_it() {
        let (counter, hits) = serve_counter().await;
        let target = format!("{counter}/mcp");
        let expected =
            format!("the gateway URL redirected to {target}; point stats at the final URL");
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move || {
                let target = target.clone();
                async move {
                    (
                        axum::http::StatusCode::MOVED_PERMANENTLY,
                        [(axum::http::header::LOCATION, target)],
                    )
                }
            }),
        );
        let base = serve(app).await;
        let outcome = tokio::time::timeout(HANG_BOUND, stats_outcome(&stats_client(), &base))
            .await
            .expect("bounded");
        match outcome {
            Ok(text) => panic!("expected Err, got Ok: {text}"),
            Err(msg) => assert!(msg.contains(&expected), "msg: {msg}"),
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
