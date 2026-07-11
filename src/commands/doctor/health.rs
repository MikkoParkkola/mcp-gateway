// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::net::TcpListener;
use std::time::{Duration, Instant};

use mcp_gateway::config::Config;
use serde_json::{Value, json};

use super::CheckResult;

const RUNTIME_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const MCP_SESSION_HEADER: &str = "mcp-session-id";

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

    let client = match reqwest::Client::builder()
        .timeout(RUNTIME_PROBE_TIMEOUT)
        .build()
    {
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
        Err(result) => return vec![result],
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
        Err(result) => results.push(result),
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
) -> Result<McpProbeResponse, CheckResult> {
    let mut request = client.post(format!("{base_url}/mcp")).json(&body);
    if let Some(session_id) = session_id {
        request = request.header(MCP_SESSION_HEADER, session_id);
    }

    let response = request.send().await.map_err(|e| {
        CheckResult::fail("MCP handshake", format!("cannot POST /mcp: {e}"))
            .with_category("mcp_handshake")
    })?;

    let status = response.status();
    let session_id = response
        .headers()
        .get(MCP_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response.json::<Value>().await.map_err(|e| {
        CheckResult::fail("MCP handshake", format!("invalid /mcp JSON response: {e}"))
            .with_category("mcp_handshake")
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
