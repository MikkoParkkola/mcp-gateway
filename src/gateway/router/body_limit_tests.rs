// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.CONFIG.3 (C8): `server.max_body_size` caps every route's request body.
//!
//! `/mcp` and `/mcp/{name}` used to hard-code 10 MiB and every extractor route,
//! webhooks included, fell back to axum's 2 MiB default, so the knob did
//! nothing. Each row drives the full router, because layer placement is what
//! decides whether a merged route is covered.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use super::tests::test_router_app_state;
use super::{AppState, create_router_with};
use crate::gateway::webhooks::WebhookRegistry;

/// The shared fixture with `server.max_body_size` set to `cap`.
async fn state_with_cap(cap: Option<usize>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = test_router_app_state().await;
    if let Some(cap) = cap {
        let mut config = (*state.live_config.get()).clone();
        config.server.max_body_size = cap;
        state.live_config.set(config);
    }
    (state, store)
}

/// The production router with the dynamic webhook routes merged in, as
/// `gateway/server` builds it.
fn router_with_webhooks(state: &Arc<AppState>) -> axum::Router {
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        crate::config::WebhookConfig::default(),
    )));
    let webhooks = WebhookRegistry::create_dynamic_routes(registry, Arc::clone(&state.multiplexer));
    create_router_with(Arc::clone(state), Some(webhooks))
}

/// A valid JSON-RPC `ping` padded to at least `size` bytes, so only its size
/// can make it fail.
fn padded_ping(size: usize) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"_pad": "x".repeat(size)}})
        .to_string()
}

async fn post(router: axum::Router, uri: &str, body: String) -> StatusCode {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    router.oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn mcp_body_over_configured_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(router_with_webhooks(&state), "/mcp", padded_ping(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn direct_route_body_over_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(router_with_webhooks(&state), "/mcp/b", padded_ping(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn webhook_body_over_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(
        router_with_webhooks(&state),
        "/webhooks/x",
        padded_ping(2048),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Positive control: the default 10 MiB cap admits a 3 MiB webhook body that
/// axum's 2 MiB default refused. The registry is empty, so a buffered body
/// reaches the handler's 404; `Bytes` is its last extractor.
#[tokio::test]
async fn webhook_body_between_2_and_10_mib_accepted() {
    let (state, _store) = state_with_cap(None).await;
    let status = post(
        router_with_webhooks(&state),
        "/webhooks/x",
        padded_ping(3 * 1024 * 1024),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Positive control: a body under the cap is served on every route.
#[tokio::test]
async fn body_under_cap_accepted() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let router = router_with_webhooks(&state);
    assert_eq!(
        post(router.clone(), "/mcp", padded_ping(512)).await,
        StatusCode::OK
    );
    // The body is read before the backend lookup, so an unknown backend is 404.
    assert_eq!(
        post(router.clone(), "/mcp/b", padded_ping(512)).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(router, "/webhooks/x", padded_ping(512)).await,
        StatusCode::NOT_FOUND
    );
}

async fn send(
    router: axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> (StatusCode, serde_json::Value) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

/// A body with no `Content-Length` is only found oversize while it is read, so
/// this drives `read_body`'s own 413 mapping rather than an up-front length check.
#[tokio::test]
async fn mcp_streamed_body_without_content_length_over_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let body = padded_ping(2048).into_bytes();
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.chunks(512).map(|c| Ok(c.to_vec())).collect();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from_stream(futures::stream::iter(chunks)))
        .unwrap();
    assert!(request.headers().get("content-length").is_none());
    let (status, body) = send(router_with_webhooks(&state), request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "body: {body}");
    assert_eq!(body["error"]["code"], -32600, "body: {body}");
}

/// The cap is read once when the router is built: a later `live_config` edit
/// (a hot reload) must not lift it.
#[tokio::test]
async fn live_config_edit_after_build_does_not_lift_the_cap() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let router = router_with_webhooks(&state);
    let mut config = (*state.live_config.get()).clone();
    config.server.max_body_size = 10 * 1024 * 1024;
    state.live_config.set(config);
    let status = post(router, "/mcp", padded_ping(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// The key server's routes are merged outside `extra` and outside auth; the
/// cap must reach them too.
#[tokio::test]
async fn key_server_route_body_over_cap_is_rejected() {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let (state, _store) = super::tests::test_router_app_state_with_auth_and_key_server(
        &crate::config::AuthConfig::default(),
        Some(key_server),
    )
    .await;
    let mut config = (*state.live_config.get()).clone();
    config.server.max_body_size = 1024;
    state.live_config.set(config);
    let router = create_router_with(Arc::clone(&state), None);
    let form = |size: usize| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(format!("pad={}", "x".repeat(size))))
            .unwrap()
    };
    let (status, _) = send(router.clone(), form(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // Positive control: the route exists and a small body is parsed, not capped.
    let (status, _) = send(router, form(512)).await;
    assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_ne!(status, StatusCode::NOT_FOUND);
}

/// `DefaultBodyLimit::max(0)` refuses every body, so 0 is refused at load.
#[test]
fn zero_max_body_size_is_refused_at_load() {
    let mut config = crate::config::Config::default();
    config.validate().expect("the default config validates");
    config.server.max_body_size = 0;
    let error = config
        .validate()
        .expect_err("max_body_size 0 must be refused");
    assert!(
        error.to_string().contains("server.max_body_size"),
        "got: {error}"
    );
}

/// Source scan: request bodies are capped in one place. A hard-coded
/// `to_bytes(body, N)` or a second `DefaultBodyLimit` would bring back the
/// per-route caps C8 removed. `usize::MAX` reads are responses the gateway
/// built itself.
#[test]
fn no_hard_coded_body_limit_outside_the_configured_layer() {
    const CONFIGURED: &str = "DefaultBodyLimit::max(startup_config.server.max_body_size)";
    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    scan(&path, hits);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs")
                || name.contains("test")
                || name.contains("fixture")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for (at, _) in code.match_indices("to_bytes(") {
                let args = &code[at + "to_bytes(".len()..];
                let (mut depth, mut comma, mut end) = (0_i32, None, args.len());
                for (i, c) in args.char_indices() {
                    match c {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' if depth == 0 => {
                            end = i;
                            break;
                        }
                        ')' | ']' | '}' => depth -= 1,
                        ',' if depth == 0 && comma.is_none() => comma = Some(i),
                        _ => {}
                    }
                }
                if let Some(comma) = comma {
                    let limit = args[comma + 1..end].trim().trim_end_matches(',').trim();
                    if limit != "usize::MAX" {
                        hits.push(format!("{}: to_bytes(.., {limit})", path.display()));
                    }
                }
            }
            for (at, _) in code.match_indices("DefaultBodyLimit::") {
                if !code[at..].starts_with(CONFIGURED) {
                    hits.push(format!(
                        "{}: {}",
                        path.display(),
                        &code[at..at + 40.min(code.len() - at)]
                    ));
                }
            }
            if code.contains("RequestBodyLimitLayer") {
                hits.push(format!("{}: RequestBodyLimitLayer", path.display()));
            }
        }
    }
    let mut hits = Vec::new();
    scan(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut hits,
    );
    assert!(
        hits.is_empty(),
        "request bodies must be capped only by `{CONFIGURED}`: {hits:?}"
    );
}
