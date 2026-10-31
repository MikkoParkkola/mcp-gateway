// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Egress-proxy routing, and a blocked redirect as the SSRF refusal.

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
                let mut guard = seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let guard = seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        guard
            .iter()
            .any(|s| s.contains("api.capability-fixture.test")),
        "the proxy must see the target host, got: {guard:?}"
    );
}

/// A blocked hop is the SSRF refusal, as on the spec-fetch, backend and
/// OAuth clients, and three in a row leave the capability healthy: a policy
/// refusal is not a sick upstream. Each refusal still reaches the refusal log
/// and the audit record of its call.
#[tokio::test]
async fn a_blocked_redirect_is_the_ssrf_refusal_and_leaves_health_alone() {
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
            super::send_with_retry(client.get(&url), &client.redirects, "test", true, &health),
        )
        .await
        .expect("bounded");
        let err = outcome.expect_err("a blocked redirect fails");
        assert!(
            crate::security::ssrf::is_ssrf_refusal(&err),
            "a blocked redirect is the SSRF refusal: {err}"
        );
        assert_eq!(err.to_rpc_code(), -32600, "{err}");
    }
    assert!(
        health.is_healthy(),
        "three refused redirects marked the capability unhealthy"
    );
}

/// Latency row 23c(b): a public hop answered 302 to a denied address. A
/// server did answer, so the refused redirect notes one send, Failed.
#[tokio::test]
async fn a_refused_redirect_hop_notes_a_failed_send() {
    use crate::counters::End;
    use crate::gateway::{send_timer_seam as seam, with_dispatch_scope};
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://10.255.255.1/")],
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
    let send = std::time::Duration::from_millis(7);
    seam::inject(send);
    let (outcome, notes) = with_dispatch_scope(tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        super::send_with_retry(client.get(&url), &client.redirects, "test", true, &health),
    ))
    .await;
    seam::clear();
    let err = outcome.expect("bounded").expect_err("a blocked redirect fails");
    assert!(crate::security::ssrf::is_ssrf_refusal(&err), "{err}");
    assert_eq!(notes.backend_sample(), Some((send, End::Failed)));
}
