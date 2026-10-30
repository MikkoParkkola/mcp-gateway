// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A preview injects nothing (MIK-9035, T1.17 scope): a backend with secret
//! rules and credential headers, previewed, sends no value of any of them,
//! so there is nothing its answers could echo.

use std::sync::Arc;

use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::{run_confirmed, scrub};
use crate::config::{BackendConfig, Config, TransportConfig};

const SECRET: &str = "preview-secret-4a8e1c";

/// Every request the server saw: its target, its body, then each header as
/// `name=value`.
type Seen = Arc<parking_lot::Mutex<Vec<String>>>;

/// A legacy MCP server on loopback that records each request whole.
async fn recording_server(seen: Seen) -> String {
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let seen = Arc::clone(&seen);
                async move {
                    let mut line = format!("{uri} {}", String::from_utf8_lossy(&body));
                    for (name, value) in &headers {
                        line.push_str(&format!(" {name}={}", value.to_str().unwrap_or("")));
                    }
                    seen.lock().push(line);
                    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let id = request["id"].clone();
                    if id.is_null() {
                        return axum::http::StatusCode::ACCEPTED.into_response();
                    }
                    let answer = match request["method"].as_str() {
                        Some("initialize") => json!({"result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": format!("previewed {SECRET}"), "version": "0"},
                            "instructions": format!("use key {SECRET}")}}),
                        Some("tools/list") => json!({"result": {"tools": [
                            {"name": "echo", "inputSchema": {"type": "object"}}]}}),
                        _ => json!({"error": {"code": -32601, "message": "not found"}}),
                    };
                    let mut answer = answer;
                    answer["jsonrpc"] = json!("2.0");
                    answer["id"] = id;
                    axum::Json(answer).into_response()
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

#[tokio::test]
async fn a_previewed_backend_with_secret_rules_receives_no_injected_value() {
    let seen = Seen::default();
    let url = recording_server(Arc::clone(&seen)).await;
    let rules = ["argument", "header", "query"].map(|target| {
        serde_json::from_value(json!({
            "name": format!("{target}-key"), "value": SECRET,
            "inject_as": target, "inject_key": "api_key"
        }))
        .expect("rule parses")
    });
    let mut backend = BackendConfig {
        transport: TransportConfig::Http {
            http_url: url,
            streamable_http: Some(true),
            protocol_version: None,
        },
        secrets: rules.to_vec(),
        headers: [("Authorization".to_owned(), format!("Bearer {SECRET}"))].into(),
        ..BackendConfig::default()
    };
    let withheld = scrub(&mut backend);
    assert_eq!(withheld.secrets, 3, "premise: the rules were present");
    let mut config = Config::default();
    config.security.ssrf_protection = false;
    let generation = crate::config_reload::Generation::prepare(config).expect("generation");
    let response = run_confirmed(&generation, "previewed", &backend, json!({})).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let seen = seen.lock().clone();
    assert!(
        seen.iter().any(|request| request.contains("tools/list")),
        "premise: the preview listed tools: {seen:?}"
    );
    for request in &seen {
        assert!(
            !request.contains(SECRET),
            "a value reached the backend: {request}"
        );
    }
}

/// T1.17: an initialize answer echoing a value the backend's set holds is
/// scrubbed by the transport, so the `serverInfo` it reports carries the
/// marker, not the value.
#[tokio::test]
async fn an_initialize_echo_is_scrubbed_by_the_transport() {
    let url = recording_server(Seen::default()).await;
    let transport = crate::transport::HttpTransport::new(
        &url,
        std::collections::HashMap::new(),
        std::time::Duration::from_secs(5),
        true,
    )
    .expect("transport");
    let needles =
        crate::security::needles::NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("previewed", SECRET);
    transport.attach_needles(Arc::new(needles));
    let reported = crate::backend::start_detached_http(
        &transport,
        "previewed",
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("the handshake completes");
    let text = serde_json::to_string(&reported).expect("serialises");
    assert!(
        text.contains("previewed"),
        "premise: serverInfo reported: {text}"
    );
    assert!(
        !text.contains(SECRET),
        "the echo reached serverInfo: {text}"
    );
}
