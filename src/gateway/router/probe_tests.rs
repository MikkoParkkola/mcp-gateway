// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `/health`, `/livez` and `/readyz` as an orchestrator sees them.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets.

use axum::http::StatusCode;
use tower::ServiceExt;

use super::create_router;
use super::tests::{
    http_backend_at, test_router_app_state, test_router_app_state_with_auth,
    test_router_app_state_with_backend,
};
use crate::config::AuthConfig;

const PROBES: [&str; 2] = ["/livez", "/readyz"];

async fn get(router: &axum::Router, uri: &str, header: Option<(&str, &str)>) -> StatusCode {
    let mut request = axum::http::Request::builder().method("GET").uri(uri);
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    let request = request.body(axum::body::Body::empty()).unwrap();
    router.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn health_is_reachable_by_a_probe_and_refused_cross_site() {
    // No exemption. A monitoring probe sends no Origin and passes on the
    // general rules; a web page sends one and is refused like anywhere else,
    // so the boundary is the whole port with no special cases to audit.
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);

    for path in ["/health", PROBES[0], PROBES[1]] {
        assert_eq!(get(&router, path, None).await, StatusCode::OK, "{path}");
        let page = Some(("origin", "http://attacker.example"));
        assert_eq!(
            get(&router, path, page).await,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
}

/// One upstream down must not restart or unready the gateway.
///
/// `/health` still reports it, because that is what it is for; a probe that
/// read it restarted every replica for one flapping backend, and a backend
/// down at deploy time kept every new pod from ever starting.
#[tokio::test]
async fn probes_stay_green_while_health_reports_a_backend_down() {
    let backend = http_backend_at("down", "http://127.0.0.1:9/mcp");
    backend.trip_circuit_breaker_for_test();
    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);

    assert_eq!(
        get(&router, "/health", None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "precondition: /health reports the open circuit"
    );
    for path in PROBES {
        assert_eq!(get(&router, path, None).await, StatusCode::OK, "{path}");
    }
}

/// The probes are exposed exactly when `/health` is.
///
/// Every shipped config and every operator copy of one lists only `/health`
/// under `public_paths`; a probe that needed its own entry would answer 401 to
/// the kubelet on upgrade, which is the outage this endpoint exists to end.
#[tokio::test]
async fn probes_share_the_exposure_of_health() {
    let auth = |public_paths: Vec<String>| AuthConfig {
        enabled: true,
        bearer_token: Some("probe-secret".to_string()),
        public_paths,
        ..AuthConfig::default()
    };

    let (state, _store) = test_router_app_state_with_auth(&auth(vec!["/health".into()])).await;
    let router = create_router(state);
    for path in PROBES {
        assert_eq!(get(&router, path, None).await, StatusCode::OK, "{path}");
    }

    let (state, _store) = test_router_app_state_with_auth(&auth(Vec::new())).await;
    let router = create_router(state);
    for path in ["/health", PROBES[0], PROBES[1]] {
        assert_eq!(
            get(&router, path, None).await,
            StatusCode::UNAUTHORIZED,
            "{path} must not be public when /health is not"
        );
        let bearer = Some(("authorization", "Bearer probe-secret"));
        assert_eq!(get(&router, path, bearer).await, StatusCode::OK, "{path}");
    }
}
