// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F6 (MIK 7570.GOVSTORE.1): a gateway serving governance read-only says why.
//!
//! `GET /ui/api/control-plane` carries `mutation_disabled_reason` and
//! `base_source`, and a mutation's 503 names the cause and the store path.
//! Startup resolves the store base once and carries it in `AppState`; these
//! cases drive the router with the state that startup leaves behind.

mod common;
use common::*;

use axum::http::Method;
use mcp_gateway::config_reload::LiveConfig;
use mcp_gateway::control_plane::role_mapping::{ControlPlaneBaseInfo, ControlPlaneBaseSource};

const TOKEN: &str = "f6-admin-token";

async fn send(
    app: &Arc<AppState>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let response = create_router(Arc::clone(app))
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn decision() -> Value {
    json!({
        "target_kind": "grant",
        "target_id": "grant-1",
        "decision": "approve",
        "reason": "MIK-1",
        "rollback": { "summary": "revert", "step": "revoke grant-1" },
    })
}

#[tokio::test]
async fn default_unwritable_store_reports_store_unavailable() {
    // What startup leaves when auth is on and the default base could not be
    // opened (the unit half, beside `build_control_plane_store`, forces that
    // with ENOTDIR): no store, and the base it tried.
    let base = std::path::PathBuf::from("/etc/mcp-gateway/gateway-control-plane");
    let (mut app, _tasks) = state(Fixture {
        auth: auth_with(Vec::new(), Some(TOKEN)),
        ..Fixture::default()
    })
    .await;
    Arc::get_mut(&mut app).unwrap().control_plane_base = Some(ControlPlaneBaseInfo {
        path: base.clone(),
        source: ControlPlaneBaseSource::Default,
    });

    let (status, body) = send(&app, Method::GET, "/ui/api/control-plane", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["route"]["read_only"], true);
    assert_eq!(
        body["mutation_disabled_reason"], "store_unavailable",
        "{body}"
    );
    assert_eq!(body["base_source"], "default", "{body}");

    let (status, body) = send(
        &app,
        Method::POST,
        "/ui/api/control-plane/decisions",
        Some(decision()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reason_code"], "CONTROL_STORE_UNAVAILABLE");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(&*base.to_string_lossy()),
        "the 503 reason must name the store path: {reason}"
    );
    assert!(
        reason.contains("control_plane.store_dir"),
        "the 503 reason must say how to fix it: {reason}"
    );
}

#[tokio::test]
async fn auth_off_reports_auth_off() {
    let (mut app, _tasks) = state(Fixture {
        auth: auth_with(Vec::new(), Some(TOKEN)),
        ..Fixture::default()
    })
    .await;
    // The running config has auth off, which is why startup opened no store.
    Arc::get_mut(&mut app).unwrap().live_config = Arc::new(LiveConfig::new(Config::default()));

    let (status, body) = send(&app, Method::GET, "/ui/api/control-plane", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mutation_disabled_reason"], "auth_off", "{body}");

    let (status, body) = send(
        &app,
        Method::POST,
        "/ui/api/control-plane/decisions",
        Some(decision()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let reason = body["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("auth"),
        "the 503 reason must name auth: {reason}"
    );
}
