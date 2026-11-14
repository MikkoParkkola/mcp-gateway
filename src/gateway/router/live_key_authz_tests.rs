// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K5, the authorization fields a reload changes on a kept key, each seen on
//! the next call: `backends`, `allowed_tools` and `denied_tools` decide
//! whether a call reaches the backend, `admin` whether the admin-only UI call
//! route serves it, and `rate_limit` whether the next request is admitted.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::ui_tool_call_tests::{ADMIN, Fx, SERVER, fixture, invoke, post_mcp, sent};
use crate::config_reload::ReloadContext;

/// The settings `fixture` runs with that a loaded file would otherwise
/// change: it is built from `Config::default()` with the request-path
/// security flags off, and a reload applies those flags live (ADR-023). Kept
/// in every reload so the reload differs from the running config in the key
/// alone, and a refusal is the field's, not the flags'.
const FIXTURE_SETTINGS: &str =
    "default_routing_profile: \"\"\nsecurity:\n  sanitize_input: false\n  ssrf_protection: false\n";

/// The admin key `fixture` starts with, as a reload writes it, with `fields`
/// (each a line already indented under the entry) in place of its defaults.
fn admin_key_yaml(fields: &[&str]) -> String {
    let digest = crate::config::api_key_digest_spec(ADMIN.as_bytes());
    let mut text = format!(
        "{FIXTURE_SETTINGS}auth:\n  enabled: true\n  api_keys:\n    - name: {ADMIN}\n      key_sha256: \"{digest}\"\n"
    );
    let has = |name: &str| fields.iter().any(|f| f.trim_start().starts_with(name));
    if !has("backends:") {
        text.push_str("      backends: [\"*\"]\n");
    }
    if !has("admin:") {
        text.push_str("      admin: true\n");
    }
    for field in fields {
        text.push_str(field);
        text.push('\n');
    }
    text
}

/// Reload `text` into the gateway of `state`.
async fn reload(state: &Arc<super::AppState>, dir: &std::path::Path, text: String) {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write");
    ReloadContext::new(
        path,
        Arc::clone(&state.live_config),
        Arc::clone(&state.backends),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .reload_outcome()
    .await
    .expect("the key edit applies");
}

/// Whether one `gateway_invoke` of `read` with the admin key reached the
/// backend.
async fn reached(fx: &Fx) -> bool {
    let before = sent(fx);
    let _ = post_mcp(fx, ADMIN, invoke("read"), None).await;
    sent(fx) > before
}

/// The status the admin-only UI call route gives the admin key.
async fn ui_call_status(fx: &Fx) -> StatusCode {
    let body = json!({"server": SERVER, "tool": "read", "arguments": {}, "confirm_write": false});
    let request = axum::http::Request::post("/ui/api/tools/call")
        .header("authorization", format!("Bearer {ADMIN}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("a response")
        .status()
}

/// K5 `backends` (MIK-9256.AUTHZ.2): a backend a reload takes off a kept
/// key's list is refused on the next call, and nothing reaches it.
#[tokio::test]
async fn k5_a_backend_removed_from_a_key_by_reload_is_refused_on_the_next_call() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    assert!(reached(&fx).await, "premise: the key reaches the backend");

    reload(
        &fx.state,
        dir.path(),
        admin_key_yaml(&["      backends: [\"elsewhere\"]"]),
    )
    .await;
    assert!(
        !reached(&fx).await,
        "a backend removed by reload was still reached"
    );

    reload(&fx.state, dir.path(), admin_key_yaml(&[])).await;
    assert!(
        reached(&fx).await,
        "the backend restored by reload is not reached"
    );
}

/// K5 `allowed_tools` (MIK-9256.AUTHZ.3): a tool a reload leaves out of a kept
/// key's allow list is refused on the next call.
#[tokio::test]
async fn k5_a_tool_left_out_of_allowed_tools_by_reload_is_refused() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    assert!(reached(&fx).await, "premise: the key reaches the tool");

    reload(
        &fx.state,
        dir.path(),
        admin_key_yaml(&["      allowed_tools: [\"write\"]"]),
    )
    .await;
    assert!(
        !reached(&fx).await,
        "a tool left out of allowed_tools by reload ran"
    );

    reload(
        &fx.state,
        dir.path(),
        admin_key_yaml(&["      allowed_tools: [\"read\"]"]),
    )
    .await;
    assert!(
        reached(&fx).await,
        "a tool allowed again by reload is refused"
    );
}

/// K5 `denied_tools` (MIK-9256.AUTHZ.4): a tool a reload adds to a kept key's
/// deny list is refused on the next call.
#[tokio::test]
async fn k5_a_tool_denied_by_reload_is_refused() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    assert!(reached(&fx).await, "premise: the key reaches the tool");

    reload(
        &fx.state,
        dir.path(),
        admin_key_yaml(&["      denied_tools: [\"read\"]"]),
    )
    .await;
    assert!(!reached(&fx).await, "a tool denied by reload ran");

    reload(&fx.state, dir.path(), admin_key_yaml(&[])).await;
    assert!(
        reached(&fx).await,
        "a tool no longer denied by reload is refused"
    );
}

/// K5 `admin` (MIK-9256.AUTHZ.5): the admin-only UI call route serves a kept
/// key while it is admin and refuses it once a reload takes admin away.
#[tokio::test]
async fn k5_admin_taken_away_by_reload_closes_the_admin_route() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    assert_eq!(
        ui_call_status(&fx).await,
        StatusCode::OK,
        "premise: the admin is served"
    );

    reload(
        &fx.state,
        dir.path(),
        admin_key_yaml(&["      admin: false"]),
    )
    .await;
    let before = sent(&fx);
    assert_eq!(
        ui_call_status(&fx).await,
        StatusCode::FORBIDDEN,
        "a key made non-admin by reload is still served the admin route"
    );
    assert_eq!(sent(&fx), before, "the refused admin call was sent");

    reload(&fx.state, dir.path(), admin_key_yaml(&[])).await;
    assert_eq!(
        ui_call_status(&fx).await,
        StatusCode::OK,
        "a key made admin again by reload is refused"
    );
}

/// One `ping` with `secret` on `/mcp`; its status.
async fn ping(state: &Arc<super::AppState>, secret: &str) -> StatusCode {
    let body: Value = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let request = axum::http::Request::post("/mcp")
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("a response")
        .status()
}

/// K5 `rate_limit` (MIK-9256.AUTHZ.1): a kept key's rate changed by reload
/// applies on the next request, and the usage so far is kept: a reload that
/// leaves the rate alone does not hand back the spent request.
///
/// On a paused clock (the buckets read tokio's `Instant`), so the time the
/// reloads take spends no debt: at a wall-clock 1000/min the two raised-rate
/// requests owed only 120 ms, which a loaded runner paid off before the
/// lowering reload. The values follow `ClientBucket::check_at`, all at one
/// instant `T`: rate 1 leaves the debt at `T + 60 s`; raising to 1000/min
/// re-prices it to `T + 60 ms` with a 59.94 s burst, and two admits move it
/// to `T + 180 ms`; lowering to 1/min re-prices that to `T + 180 s` with no
/// burst, paid exactly 180 s later.
#[tokio::test(start_paused = true)]
async fn k5_a_rate_limit_changed_by_reload_applies_and_keeps_its_usage() {
    const SECRET: &str = "live-keys-rate-secret";
    let digest = crate::config::api_key_digest_spec(SECRET.as_bytes());
    let entry = |rate: u32, extra: &str| {
        format!(
            "auth:\n  enabled: true\n  api_keys:\n    - name: rate\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n      rate_limit: {rate}\n{extra}"
        )
    };
    let auth = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![crate::config::ApiKeyConfig {
            key_sha256: Some(digest.clone()),
            name: "rate".to_owned(),
            backends: vec!["*".to_owned()],
            rate_limit: 1,
            ..Default::default()
        }],
        ..crate::config::AuthConfig::default()
    };
    let (state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let dir = crate::test_dir_keep::kept_tempdir();
    // The running table as a reload writes it, before the spend.
    reload(&state, dir.path(), entry(1, "")).await;
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::OK,
        "premise: one request"
    );
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::TOO_MANY_REQUESTS,
        "premise: the rate of one is spent"
    );

    // Usage kept: an unrelated field changed, the rate left at one.
    reload(
        &state,
        dir.path(),
        entry(1, "      denied_tools: [\"other\"]\n"),
    )
    .await;
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a reload that kept the rate handed back the spent request"
    );

    // The new rate applies: admitted, not merely "not throttled".
    reload(&state, dir.path(), entry(1000, "")).await;
    for _ in 0..2 {
        assert_eq!(
            ping(&state, SECRET).await,
            StatusCode::OK,
            "the rate raised by reload still refuses"
        );
    }

    // And a rate lowered by reload throttles again, owing the raised-rate
    // requests at the new interval: 180 s, one second short still refused.
    reload(&state, dir.path(), entry(1, "")).await;
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the rate lowered by reload still admits"
    );
    tokio::time::advance(std::time::Duration::from_secs(179)).await;
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the requests owed at the raised rate were not re-priced to the lowered one"
    );
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        ping(&state, SECRET).await,
        StatusCode::OK,
        "the re-priced debt is paid at T + 180 s"
    );
}
