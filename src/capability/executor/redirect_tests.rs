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
            super::send_with_retry(client.get(&url), "test", true, &health),
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

/// Serves `app` on a fresh loopback port and returns the port.
async fn serve(app: axum::Router) -> u16 {
    let listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    port
}

/// One capability send to a loopback listener that redirects to `location`,
/// in its own delivery cell: the error and the `response_effect` it records.
async fn redirected(location: &'static str) -> (crate::Error, Option<serde_json::Value>) {
    redirected_in(location, || {}).await
}

/// [`redirected`], with `before` run inside the delivery cell first (to make
/// it a composite step's cell, say).
async fn redirected_in(
    location: &'static str,
    before: impl FnOnce(),
) -> (crate::Error, Option<serde_json::Value>) {
    use crate::gateway::delivery_facts;
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move || async move {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, location.to_string())],
            )
        }),
    );
    let port = serve(app).await;
    let client = super::client::build(None);
    let health = crate::failsafe::HealthTracker::new("test");
    let url = format!("http://127.0.0.1:{port}/");
    let (outcome, facts) = delivery_facts::scope(async {
        before();
        let outcome = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            super::send_with_retry(client.get(&url), "test", true, &health),
        )
        .await
        .expect("bounded");
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    let error = outcome.expect_err("the redirect is refused");
    (error, fields.get("response_effect").cloned())
}

/// A hop the redirect decision rejects (a private address) is the gateway's
/// refusal: the call's record says `refused`.
#[tokio::test]
async fn a_rejected_redirect_hop_records_refused() {
    let (error, effect) = Box::pin(redirected("http://10.255.255.1/")).await;
    assert_eq!(effect, Some("refused".into()), "{error}");
}

/// A request that began on loopback, redirected to cleartext off this
/// machine, is refused, and its record says so.
#[tokio::test]
async fn a_redirect_to_cleartext_off_machine_records_refused() {
    let (error, effect) = Box::pin(redirected("http://93.184.215.14/")).await;
    assert_eq!(effect, Some("refused".into()), "{error}");
}

/// Recording the refusal does not change what the caller receives: a hop the
/// destination policy refuses answers the SSRF refusal, and a cleartext
/// downgrade answers the same transport error as before, word for word.
#[tokio::test]
async fn a_refused_redirect_answers_as_its_kind_does() {
    let (refused, _) = Box::pin(redirected("http://10.255.255.1/")).await;
    assert!(
        crate::security::ssrf::is_ssrf_refusal(&refused),
        "{refused:?}"
    );
    let (downgrade, _) = Box::pin(redirected("http://93.184.215.14/")).await;
    assert!(
        matches!(downgrade, crate::Error::Transport(_)),
        "{downgrade:?}"
    );
    assert_eq!(
        downgrade.to_string(),
        "Transport error: test failed: error following redirect"
    );
}

/// A composite's step runs in an unvouched cell: a refused redirect there
/// leaves the plan's record unrefused, for both refused hops.
#[tokio::test]
async fn a_refused_redirect_in_an_unvouched_cell_records_no_refusal() {
    for location in ["http://10.255.255.1/", "http://93.184.215.14/"] {
        let (error, effect) = Box::pin(redirected_in(
            location,
            crate::gateway::delivery_facts::unvouched,
        ))
        .await;
        assert_ne!(effect, Some("refused".into()), "{location}: {error}");
    }
}

/// A streaming body cannot be cloned for a retry, so the send takes its
/// single-attempt path; a hop the redirect decision rejects there records
/// `refused` too.
#[tokio::test]
async fn a_single_attempt_rejected_redirect_records_refused() {
    use crate::gateway::delivery_facts;
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://10.255.255.1/")],
            )
        }),
    );
    let port = serve(app).await;
    let client = super::client::build(None);
    let health = crate::failsafe::HealthTracker::new("test");
    let body = reqwest::Body::wrap_stream(futures::stream::once(async {
        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"streamed"))
    }));
    let request = client.post(format!("http://127.0.0.1:{port}/")).body(body);
    assert!(
        request.try_clone().is_none(),
        "premise: the body is not cloneable"
    );
    let (outcome, facts) = delivery_facts::scope(async {
        let outcome = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            super::send_with_retry(request, "test", true, &health),
        )
        .await
        .expect("bounded");
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let error = outcome.expect_err("the redirect is refused");
    assert!(crate::security::ssrf::is_ssrf_refusal(&error), "{error:?}");
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    assert_eq!(
        fields.get("response_effect"),
        Some(&"refused".into()),
        "{error}"
    );
}

/// The single-attempt path treats a refused redirect as the retry path does:
/// a policy refusal, so three of them leave the capability healthy.
#[tokio::test]
async fn a_single_attempt_rejected_redirect_leaves_health_alone() {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://10.255.255.1/")],
            )
        }),
    );
    let port = serve(app).await;
    let client = super::client::build(None);
    let health = crate::failsafe::HealthTracker::new("test");
    for _ in 0..3 {
        let body = reqwest::Body::wrap_stream(futures::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"streamed"))
        }));
        let request = client.post(format!("http://127.0.0.1:{port}/")).body(body);
        let outcome = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            super::send_with_retry(request, "test", true, &health),
        )
        .await
        .expect("bounded");
        outcome.expect_err("the redirect is refused");
    }
    assert!(
        health.is_healthy(),
        "three refused redirects marked the capability unhealthy"
    );
}

/// The `response_effect` a delivery cell holds after one send of `request`
/// through `client`, and whether the send succeeded.
async fn effect_of_send(request: reqwest::RequestBuilder) -> (bool, Option<serde_json::Value>) {
    use crate::gateway::delivery_facts;
    let health = crate::failsafe::HealthTracker::new("test");
    let (ok, facts) = delivery_facts::scope(async {
        let outcome = tokio::time::timeout(
            crate::test_wait::HANG_BOUND,
            super::send_with_retry(request, "test", true, &health),
        )
        .await
        .expect("bounded");
        (outcome.is_ok(), delivery_facts::snapshot())
    })
    .await;
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    (ok, fields.get("response_effect").cloned())
}

/// Negative control: a redirect the policy allows is followed, and nothing
/// is recorded as refused. The first request goes to a loopback literal,
/// which skips the proxy; its hop names a public-looking host, which passes
/// the hop check and goes through the proxy, standing in for the target.
#[tokio::test]
async fn an_allowed_redirect_is_followed_and_records_no_refusal() {
    let listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move || async move {
            (
                axum::http::StatusCode::FOUND,
                [(
                    axum::http::header::LOCATION,
                    "http://capability-fixture.test/ok".to_string(),
                )],
            )
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    // The proxy answers the hop as its target would.
    let proxy_listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let proxy_port = proxy_listener.local_addr().expect("addr").port();
    let answer = axum::Router::new().fallback(|| async { "ok" });
    tokio::spawn(async move { axum::serve(proxy_listener, answer).await });
    let proxy = url::Url::parse(&format!("http://127.0.0.1:{proxy_port}/")).expect("proxy url");
    let client = super::client::build(Some(&proxy));
    let (ok, effect) = Box::pin(effect_of_send(
        client.get(format!("http://127.0.0.1:{port}/")),
    ))
    .await;
    assert!(ok, "premise: the redirect is followed");
    assert_ne!(effect, Some("refused".into()));
}

/// Negative control: an ordinary transport failure (nothing listening) is
/// the backend's, not a gateway refusal, and records no refusal.
#[tokio::test]
async fn an_ordinary_transport_failure_records_no_refusal() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let client = super::client::build(None);
    let (ok, effect) = Box::pin(effect_of_send(
        client.get(format!("http://127.0.0.1:{port}/")),
    ))
    .await;
    assert!(!ok, "premise: the send fails");
    assert_ne!(effect, Some("refused".into()));
}
