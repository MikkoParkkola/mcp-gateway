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
    // Through the health tracker; the breaker route is
    // `health_is_degraded_while_the_breaker_is_open`.
    backend.fail_requests_for_test();
    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);

    assert_eq!(
        get(&router, "/health", None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "precondition: /health reports the failing backend"
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

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// B6 (MIK-7570.BREAKER.1): an open breaker degrades `/health`.
///
/// Tripped through the breaker alone, so the health tracker stays healthy and
/// only `circuit_state` can explain the 503. The probes stay green (#761).
#[tokio::test]
async fn health_is_degraded_while_the_breaker_is_open() {
    let backend = http_backend_at("down", "http://127.0.0.1:9/mcp");
    backend.trip_circuit_breaker_for_test();
    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);

    let (status, body) = get_json(&router, "/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["status"], "degraded", "{body}");
    for path in PROBES {
        assert_eq!(get(&router, path, None).await, StatusCode::OK, "{path}");
    }
}

/// The control for the test above: the same unstarted backend with its
/// breaker closed is healthy, so the 503 there is the breaker's.
#[tokio::test]
async fn health_is_healthy_with_breaker_closed() {
    let backend = http_backend_at("up", "http://127.0.0.1:9/mcp");
    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);

    let (status, body) = get_json(&router, "/health").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "healthy", "{body}");
}

/// B6: the redacted `/ui/api/status` counts an open breaker as degraded, and
/// the same backend closed as healthy, so neither count is a constant.
#[cfg(feature = "webui")]
#[tokio::test]
async fn ui_redacted_status_counts_open_breaker_degraded() {
    let backend = http_backend_at("down", "http://127.0.0.1:9/mcp");
    let (state, _store) = test_router_app_state_with_backend(backend.clone()).await;
    let router = create_router(state);

    let (status, body) = get_json(&router, "/ui/api/status").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["healthy_count"], 1, "closed control: {body}");
    assert_eq!(body["degraded_count"], 0, "closed control: {body}");

    backend.trip_circuit_breaker_for_test();
    let (status, body) = get_json(&router, "/ui/api/status").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["degraded_count"], 1, "{body}");
    assert_eq!(body["healthy_count"], 0, "{body}");
}

/// B6: the wire value of `circuit_state` is the breaker's own lowercase label,
/// before and after the field became typed.
#[test]
fn backend_status_serialises_circuit_state_lowercase() {
    let backend = http_backend_at("wire", "http://127.0.0.1:9/mcp");
    let closed = serde_json::to_value(backend.status()).unwrap();
    assert_eq!(closed["circuit_state"], "closed");
    backend.trip_circuit_breaker_for_test();
    let open = serde_json::to_value(backend.status()).unwrap();
    assert_eq!(open["circuit_state"], "open");
}

/// Renders the `mcp_backend_circuit_state` gauge left by one request.
#[cfg(feature = "metrics")]
fn gauge_after_one_request(backend: &crate::backend::Backend) -> Option<String> {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let _ = rt.block_on(backend.request("tools/list", None));
    });
    let rendered = handle.render();
    rendered
        .lines()
        .find(|l| l.starts_with("mcp_backend_circuit_state{"))
        .map(|l| l.rsplit(' ').next().unwrap_or_default().to_owned())
}

/// B6: metrics agree with `/health`. A request refused by the open breaker
/// sets the gauge to 0; a request the closed breaker lets through sets it to 1.
#[cfg(feature = "metrics")]
#[test]
fn metrics_gauge_reads_zero_while_breaker_open() {
    let backend = http_backend_at("gauge", "http://127.0.0.1:9/mcp");
    assert_eq!(gauge_after_one_request(&backend).as_deref(), Some("1"));
    backend.trip_circuit_breaker_for_test();
    assert_eq!(gauge_after_one_request(&backend).as_deref(), Some("0"));
}

/// A backend whose own limiter holds one token (1 rps, burst 1). `admit` runs
/// once per request, outside `with_retry`, so retry cannot spend a token; it is
/// off so its backoff cannot open a refill window between back-to-back calls.
/// Nothing listens on port 9, so an admitted request fails fast after the
/// limiter has already decided. A stall of over a second between calls would
/// refill the bucket; T5 carries the same exposure.
#[cfg(feature = "metrics")]
fn limited_backend() -> crate::backend::Backend {
    let mut failsafe = crate::config::FailsafeConfig::default();
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 1;
    failsafe.retry.enabled = false;
    let config = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        enabled: true,
        ..crate::config::BackendConfig::default()
    };
    crate::backend::Backend::new(
        "limited",
        config,
        &failsafe,
        std::time::Duration::from_secs(60),
    )
}

/// F23: a request the backend's own rate limiter refuses is not an open
/// circuit, so the gauge stays 1 while the breaker is closed.
#[cfg(feature = "metrics")]
#[test]
fn metrics_gauge_stays_one_on_a_rate_limit_refusal() {
    let backend = limited_backend();
    // The burst token admits the first request; the second finds the bucket empty.
    assert_eq!(gauge_after_one_request(&backend).as_deref(), Some("1"));
    assert_eq!(gauge_after_one_request(&backend).as_deref(), Some("1"));
}

/// The value of `mcp_backend_rate_limited_total{backend="limited"}` after
/// `calls` run back to back on one runtime inside one recorder, so no refill
/// window opens between them. `None` when the series was never written.
#[cfg(feature = "metrics")]
fn rate_limited_total_after<F, Fut>(calls: F) -> Option<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(calls());
    });
    handle
        .render()
        .lines()
        .find(|l| {
            l.starts_with("mcp_backend_rate_limited_total{") && l.contains("backend=\"limited\"")
        })
        .map(|l| l.rsplit(' ').next().unwrap_or_default().to_owned())
}

/// F23b T6: every refusal by the backend's own limiter is counted, on the
/// request path, and nothing else is. One token, three requests: the first is
/// admitted, the next two meet the empty bucket.
#[cfg(feature = "metrics")]
#[test]
fn rate_limited_counter_counts_each_limiter_refusal() {
    let backend = limited_backend();
    let total = rate_limited_total_after(|| async {
        for _ in 0..3 {
            let _ = backend.request("tools/list", None).await;
        }
    });
    assert_eq!(total.as_deref(), Some("2"));
}

/// F23b T6b: the notification path is gated by the same `admit`, so its
/// limiter refusal is counted too.
#[cfg(feature = "metrics")]
#[test]
fn rate_limited_counter_counts_a_refused_notification() {
    let backend = limited_backend();
    let total = rate_limited_total_after(|| async {
        let _ = backend.request("tools/list", None).await;
        let refused = backend.notify("notifications/initialized", None).await;
        assert!(
            matches!(refused, Err(crate::Error::RateLimited(_))),
            "the notification must meet the empty bucket: {refused:?}"
        );
    });
    assert_eq!(total.as_deref(), Some("1"));
}

/// F23b T7: a breaker refusal is not a rate-limit refusal. With the breaker
/// open, requests are refused before the limiter is asked, and the counter
/// stays unwritten.
#[cfg(feature = "metrics")]
#[test]
fn rate_limited_counter_ignores_an_open_breaker() {
    let backend = limited_backend();
    backend.trip_circuit_breaker_for_test();
    let total = rate_limited_total_after(|| async {
        for _ in 0..2 {
            let refused = backend.request("tools/list", None).await;
            assert!(matches!(refused, Err(crate::Error::CircuitOpen(_))));
        }
    });
    assert_eq!(total, None);
}
