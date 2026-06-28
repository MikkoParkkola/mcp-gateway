use super::*;

fn assert_check(results: &[CheckResult], label: &str, status: &CheckStatus) {
    let result = results
        .iter()
        .find(|result| result.label == label)
        .unwrap_or_else(|| panic!("{label} result must be present"));
    assert_eq!(&result.status, status, "{label} status mismatch");
}

fn port_from_url(base_url: &str) -> u16 {
    reqwest::Url::parse(base_url)
        .unwrap()
        .port()
        .expect("test URL must include port")
}

#[allow(clippy::too_many_lines)]
async fn spawn_runtime_probe_server(require_auth: bool) -> String {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, HeaderValue, StatusCode, header::HeaderName},
        response::{IntoResponse, Response},
        routing::{get, post},
    };

    async fn health_handler() -> Json<Value> {
        Json(json!({
            "status": "healthy",
            "version": "test",
            "backends": {
                "count": 0,
                "all_healthy": true
            }
        }))
    }

    async fn mcp_handler(
        State(require_auth): State<bool>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        if require_auth && headers.get("authorization").is_none() {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32001,
                        "message": "Missing Authorization header"
                    }
                })),
            )
                .into_response();
        }

        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let response_body = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": mcp_gateway::MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "mcp-gateway-test",
                        "version": "test"
                    },
                    "capabilities": {}
                }
            }),
            "notifications/initialized" => {
                let mut response = (StatusCode::ACCEPTED, Json(json!({}))).into_response();
                response.headers_mut().insert(
                    HeaderName::from_static(MCP_SESSION_HEADER),
                    HeaderValue::from_static("test-session"),
                );
                return response;
            }
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "gateway_search",
                            "description": "Search tools",
                            "inputSchema": {
                                "type": "object"
                            }
                        }
                    ]
                }
            }),
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {other}")
                }
            }),
        };

        let mut response = (StatusCode::OK, Json(response_body)).into_response();
        response.headers_mut().insert(
            HeaderName::from_static(MCP_SESSION_HEADER),
            HeaderValue::from_static("test-session"),
        );
        response
    }

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler))
        .with_state(require_auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn runtime_probe_reports_gateway_health_handshake_and_tool_list() {
    let base_url = spawn_runtime_probe_server(false).await;
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = port_from_url(&base_url);

    let results = check_port_and_gateway_runtime(&config).await;

    assert_check(&results, "Port", &CheckStatus::Pass);
    assert_check(&results, "Gateway runtime", &CheckStatus::Pass);
    assert_check(&results, "MCP handshake", &CheckStatus::Pass);
    assert_check(&results, "Tool list", &CheckStatus::Pass);
}

#[tokio::test]
async fn runtime_probe_reports_auth_blocked_mcp_as_auth_warning() {
    let base_url = spawn_runtime_probe_server(true).await;
    let mut config = Config::default();
    config.auth.enabled = true;
    config.server.host = "127.0.0.1".to_string();
    config.server.port = port_from_url(&base_url);

    let results = check_port_and_gateway_runtime(&config).await;

    assert_check(&results, "Port", &CheckStatus::Pass);
    assert_check(&results, "Gateway runtime", &CheckStatus::Pass);
    let handshake = results
        .iter()
        .find(|result| result.label == "MCP handshake")
        .expect("MCP handshake result must be present");
    assert_eq!(handshake.status, CheckStatus::Warn);
    assert_eq!(handshake.category, "auth");
    assert!(
        handshake
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("Authorization")
    );
}
