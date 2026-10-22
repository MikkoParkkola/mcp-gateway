// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::net::TcpListener;
use std::time::{Duration, Instant};

use mcp_gateway::config::Config;
use serde_json::{Value, json};

use super::CheckResult;

const RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// Gateway-runtime probe client with `RUNTIME_PROBE_TIMEOUT`.
fn runtime_probe_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(RUNTIME_PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

pub(super) async fn check_port_and_gateway_runtime(config: &Config) -> Vec<CheckResult> {
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    if TcpListener::bind(&bind_addr).is_ok() {
        return vec![
            CheckResult::pass("Port", format!("{bind_addr} available")).with_category("port"),
            CheckResult::warn("Gateway runtime", "not running on configured address")
                .with_category("runtime")
                .with_hint("Start the gateway, then rerun doctor to verify MCP runtime checks")
                .with_manual_fix("mcp-gateway -c gateway.yaml"),
        ];
    }

    let client = match runtime_probe_client() {
        Ok(client) => client,
        Err(e) => {
            return vec![
                CheckResult::fail("Port", format!("{bind_addr} already in use"))
                    .with_category("port")
                    .with_hint("Unable to construct HTTP client for runtime probe")
                    .with_manual_fix(format!(
                        "lsof -nP -iTCP:{} -sTCP:LISTEN",
                        config.server.port
                    )),
                CheckResult::fail("Gateway runtime", format!("probe setup failed: {e}"))
                    .with_category("runtime"),
            ];
        }
    };

    let base_url = runtime_base_url(config);
    let health = probe_gateway_health(&client, &base_url).await;
    if !health.gateway_detected {
        return vec![
            CheckResult::fail("Port", format!("{bind_addr} already in use"))
                .with_category("port")
                .with_hint("The configured port is occupied, but it did not look like mcp-gateway")
                .with_manual_fix(format!(
                    "lsof -nP -iTCP:{} -sTCP:LISTEN",
                    config.server.port
                )),
            health.result,
        ];
    }

    let mut results = vec![
        CheckResult::pass("Port", format!("{bind_addr} in use by reachable gateway"))
            .with_category("port"),
        health.result,
    ];
    results.extend(probe_mcp_runtime(&client, &base_url, config).await);
    results
}

struct GatewayHealthProbe {
    result: CheckResult,
    gateway_detected: bool,
}

async fn probe_gateway_health(client: &reqwest::Client, base_url: &str) -> GatewayHealthProbe {
    let url = format!("{base_url}/health");
    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let ms = start.elapsed().as_millis();
            let status = resp.status();
            if status.is_redirection() {
                let location =
                    mcp_gateway::security::http_diagnostics::redirect_target_phrase(&resp);
                return GatewayHealthProbe {
                    result: CheckResult::fail(
                        "Gateway runtime",
                        format!(
                            "HTTP {status} redirect to {location} (not followed; point doctor at the final URL)"
                        ),
                    )
                    .with_category("runtime"),
                    gateway_detected: false,
                };
            }
            match resp.json::<Value>().await {
                Ok(body) => {
                    let gateway_detected =
                        body.get("status").is_some() && body.get("version").is_some();
                    if !gateway_detected {
                        return GatewayHealthProbe {
                            result: CheckResult::fail(
                                "Gateway runtime",
                                format!(
                                    "HTTP {status} from /health was not a gateway health payload ({ms}ms)"
                                ),
                            )
                            .with_category("runtime"),
                            gateway_detected: false,
                        };
                    }

                    let health_status = body
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let version = body
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let detail = format!("{health_status} v{version} ({ms}ms)");
                    let result = if status.is_success() && health_status == "healthy" {
                        CheckResult::pass("Gateway runtime", detail)
                    } else {
                        CheckResult::warn("Gateway runtime", detail)
                            .with_hint("Gateway responded, but health is degraded")
                    }
                    .with_category("runtime");

                    GatewayHealthProbe {
                        result,
                        gateway_detected: true,
                    }
                }
                Err(e) => GatewayHealthProbe {
                    result: CheckResult::fail(
                        "Gateway runtime",
                        format!("invalid /health JSON from {url}: {e}"),
                    )
                    .with_category("runtime"),
                    gateway_detected: false,
                },
            }
        }
        Err(e) => GatewayHealthProbe {
            result: CheckResult::fail("Gateway runtime", format!("cannot reach {url}: {e}"))
                .with_category("runtime"),
            gateway_detected: false,
        },
    }
}

async fn probe_mcp_runtime(
    client: &reqwest::Client,
    base_url: &str,
    config: &Config,
) -> Vec<CheckResult> {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": mcp_gateway::MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-gateway-doctor",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    let init = post_mcp_probe(client, base_url, initialize, None).await;
    let init = match init {
        Ok(init) => init,
        Err(result) => return vec![*result],
    };

    if let Some(auth_result) = auth_blocked_result("MCP handshake", &init, config) {
        return vec![auth_result];
    }

    if let Some(error) = init.body.get("error") {
        return vec![
            CheckResult::fail(
                "MCP handshake",
                format!("initialize returned error: {error}"),
            )
            .with_category("mcp_handshake"),
        ];
    }

    if init.body.get("result").is_none() {
        return vec![
            CheckResult::fail("MCP handshake", "initialize response missing result")
                .with_category("mcp_handshake"),
        ];
    }

    let Some(session_id) = init.session_id else {
        return vec![
            CheckResult::fail(
                "MCP handshake",
                "initialize response missing mcp-session-id header",
            )
            .with_category("mcp_handshake"),
        ];
    };

    let mut results = vec![
        CheckResult::pass(
            "MCP handshake",
            "initialize accepted and session established",
        )
        .with_category("mcp_handshake"),
    ];

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ = post_mcp_probe(client, base_url, initialized, Some(session_id.as_str())).await;

    let tools_list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    match post_mcp_probe(client, base_url, tools_list, Some(session_id.as_str())).await {
        Ok(resp) => {
            if let Some(auth_result) = auth_blocked_result("Tool list", &resp, config) {
                results.push(auth_result);
            } else if let Some(error) = resp.body.get("error") {
                results.push(
                    CheckResult::fail("Tool list", format!("tools/list returned error: {error}"))
                        .with_category("tool_list"),
                );
            } else {
                let count = resp
                    .body
                    .get("result")
                    .and_then(|r| r.get("tools"))
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                results.push(
                    CheckResult::pass("Tool list", format!("{count} tool schema(s) returned"))
                        .with_category("tool_list"),
                );
            }
        }
        Err(result) => results.push(*result),
    }

    results
}

struct McpProbeResponse {
    status: reqwest::StatusCode,
    body: Value,
    session_id: Option<String>,
}

async fn post_mcp_probe(
    client: &reqwest::Client,
    base_url: &str,
    body: Value,
    session_id: Option<&str>,
) -> Result<McpProbeResponse, Box<CheckResult>> {
    let mut request = client.post(format!("{base_url}/mcp")).json(&body);
    if let Some(session_id) = session_id {
        request = request.header(MCP_SESSION_HEADER, session_id);
    }

    let response = request.send().await.map_err(|e| {
        Box::new(
            CheckResult::fail("MCP handshake", format!("cannot POST /mcp: {e}"))
                .with_category("mcp_handshake"),
        )
    })?;

    let status = response.status();
    if status.is_redirection() {
        let location =
            mcp_gateway::security::http_diagnostics::redirect_target_phrase(&response);
        return Err(Box::new(
            CheckResult::fail(
                "MCP handshake",
                format!(
                    "HTTP {status} redirect to {location} (not followed; point doctor at the final URL)"
                ),
            )
            .with_category("mcp_handshake"),
        ));
    }
    let session_id = response
        .headers()
        .get(MCP_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response.json::<Value>().await.map_err(|e| {
        Box::new(
            CheckResult::fail("MCP handshake", format!("invalid /mcp JSON response: {e}"))
                .with_category("mcp_handshake"),
        )
    })?;

    Ok(McpProbeResponse {
        status,
        body,
        session_id,
    })
}

fn auth_blocked_result(
    label: &'static str,
    response: &McpProbeResponse,
    config: &Config,
) -> Option<CheckResult> {
    if response.status != reqwest::StatusCode::UNAUTHORIZED
        && response.status != reqwest::StatusCode::FORBIDDEN
    {
        return None;
    }

    let mut result = if config.auth.enabled {
        CheckResult::warn(
            label,
            format!("HTTP {} requires gateway auth", response.status),
        )
    } else {
        CheckResult::fail(
            label,
            format!("HTTP {} rejected unauthenticated probe", response.status),
        )
    }
    .with_category("auth")
    .with_hint("MCP runtime is reachable but the probe lacks an accepted Authorization header")
    .with_manual_fix("configure client Authorization: Bearer <token>");

    if let Some(message) = response
        .body
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        result.detail = format!("{}: {message}", result.detail);
    }

    Some(result)
}

fn runtime_base_url(config: &Config) -> String {
    let host = match config.server.host.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1",
        host => host,
    };
    format!("http://{}:{}", host, config.server.port)
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

    /// A listener on loopback serving `app`; returns its base URL.
    async fn serve(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
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

    /// T13b (RED): a 301 from `/health` is reported, not followed.
    #[tokio::test]
    async fn gateway_health_probe_reports_a_redirect_without_following_it() {
        let (counter, hits) = serve_counter().await;
        let location = format!("{counter}/moved/here");
        let expected = counter.clone();
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let location = location.clone();
                async move {
                    (
                        axum::http::StatusCode::MOVED_PERMANENTLY,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        );
        let base = serve(app).await;
        let client = runtime_probe_client().expect("client");
        let probe = tokio::time::timeout(HANG_BOUND, probe_gateway_health(&client, &base))
            .await
            .expect("bounded");
        assert!(
            probe.result.detail.contains("301"),
            "detail: {}",
            probe.result.detail
        );
        assert!(
            probe.result.detail.contains(&expected),
            "detail: {}",
            probe.result.detail
        );
        assert!(
            !probe.result.detail.contains("/moved/here"),
            "detail: {}",
            probe.result.detail
        );
        assert!(
            !probe
                .result
                .detail
                .contains("was not a gateway health payload"),
            "detail: {}",
            probe.result.detail
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// T13c (RED): a 301 from POST `/mcp` is reported, not followed.
    #[tokio::test]
    async fn mcp_probe_reports_a_redirect_without_following_it() {
        let (counter, hits) = serve_counter().await;
        let location = format!("{counter}/moved/here");
        let expected = counter.clone();
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move || {
                let location = location.clone();
                async move {
                    (
                        axum::http::StatusCode::MOVED_PERMANENTLY,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        );
        let base = serve(app).await;
        let client = runtime_probe_client().expect("client");
        let outcome = tokio::time::timeout(
            HANG_BOUND,
            post_mcp_probe(&client, &base, serde_json::json!({}), None),
        )
        .await
        .expect("bounded");
        match outcome {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(result) => {
                assert!(result.detail.contains("301"), "detail: {}", result.detail);
                assert!(
                    result.detail.contains(&expected),
                    "detail: {}",
                    result.detail
                );
                assert!(
                    !result.detail.contains("/moved/here"),
                    "detail: {}",
                    result.detail
                );
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// A `/health` redirect Location carrying userinfo, a query token and a
    /// fragment is reported redacted, in the text detail and in the `--json`
    /// report alike.
    #[tokio::test]
    async fn gateway_health_probe_redacts_credentials_in_a_redirect_location() {
        let (counter, hits) = serve_counter().await;
        let location = counter.replacen("http://", "http://user:hunter2@", 1)
            + "/final/path?token=sekret-token-value#frag";
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let location = location.clone();
                async move {
                    (
                        axum::http::StatusCode::MOVED_PERMANENTLY,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        );
        let base = serve(app).await;
        let client = runtime_probe_client().expect("client");
        let probe = tokio::time::timeout(HANG_BOUND, probe_gateway_health(&client, &base))
            .await
            .expect("bounded");
        assert_redacted(&probe.result.detail, &counter);
        let report = super::super::check_result_json_value(&probe.result).to_string();
        assert_redacted(&report, &counter);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// A POST `/mcp` redirect Location carrying userinfo, a query token and a
    /// fragment is reported redacted, in the text detail and in the `--json`
    /// report alike.
    #[tokio::test]
    async fn mcp_probe_redacts_credentials_in_a_redirect_location() {
        let (counter, hits) = serve_counter().await;
        let location = counter.replacen("http://", "http://user:hunter2@", 1)
            + "/final/path?token=sekret-token-value#frag";
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move || {
                let location = location.clone();
                async move {
                    (
                        axum::http::StatusCode::MOVED_PERMANENTLY,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        );
        let base = serve(app).await;
        let client = runtime_probe_client().expect("client");
        let outcome = tokio::time::timeout(
            HANG_BOUND,
            post_mcp_probe(&client, &base, serde_json::json!({}), None),
        )
        .await
        .expect("bounded");
        match outcome {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(result) => {
                assert_redacted(&result.detail, &counter);
                let report = super::super::check_result_json_value(&result).to_string();
                assert_redacted(&report, &counter);
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// The redaction contract both doctor probes' redirect messages keep: no
    /// credential survives, only the target origin is shown.
    fn assert_redacted(text: &str, origin: &str) {
        assert!(!text.contains("hunter2"), "text: {text}");
        assert!(!text.contains("sekret-token-value"), "text: {text}");
        assert!(!text.contains("user:"), "text: {text}");
        assert!(!text.contains("/final/path"), "text: {text}");
        assert!(text.contains(origin), "text: {text}");
        assert!(text.contains("path hidden"), "text: {text}");
    }
}
