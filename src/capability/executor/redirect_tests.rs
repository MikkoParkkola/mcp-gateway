// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Egress-proxy routing and blocked-redirect transport behaviour (MIK-8660).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn a_capability_request_goes_through_its_egress_proxy() {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hits_route = Arc::clone(&hits);
    let seen_route = Arc::clone(&seen);
    let app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap| {
            let hits = Arc::clone(&hits_route);
            let seen = Arc::clone(&seen_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut guard = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.push(uri.to_string());
                if let Some(host) = headers
                    .get(axum::http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                {
                    guard.push(host.to_string());
                }
                (axum::http::StatusCode::OK, "ok")
            }
        },
    );
    let listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let proxy_url = format!("http://127.0.0.1:{port}/");
    let proxy = url::Url::parse(&proxy_url).expect("url");
    let client = super::client::build(Some(&proxy));
    let _sent = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        client.get("http://api.capability-fixture.test/x").send(),
    )
    .await
    .expect("bounded");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the proxy sees the request once"
    );
    let guard = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        guard
            .iter()
            .any(|s| s.contains("api.capability-fixture.test")),
        "the proxy must see the target host, got: {guard:?}"
    );
}

#[tokio::test]
async fn a_blocked_redirect_is_a_transport_failure_with_a_health_mark() {
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(
                    axum::http::header::LOCATION,
                    "http://10.255.255.1/".to_string(),
                )],
            )
        }),
    );
    let listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let client = super::client::build(None);
    let health = crate::failsafe::HealthTracker::new("test");
    let url = format!("http://127.0.0.1:{port}/");
    for _ in 0..3 {
        let outcome = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            super::send_with_retry(client.get(&url), "test", true, &health),
        )
        .await
        .expect("bounded");
        let err = outcome.expect_err("a blocked redirect fails");
        assert_ne!(
            err.to_rpc_code(),
            -32600,
            "a blocked redirect is transport, not policy: {err}"
        );
    }
    assert!(
        !health.is_healthy(),
        "three transport failures mark the backend"
    );
}
