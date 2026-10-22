// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660: the spec import's redirect handling. Kept out of import.rs so
//! the listener-route scan (gateway/routes_tests.rs), which reads that file
//! whole, does not count these fixtures' routes as gateway routes.

fn closed_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind closed-port probe");
    let port = probe.local_addr().expect("closed-port addr").port();
    drop(probe);
    port
}

#[tokio::test]
async fn fetch_error_message_names_an_ssrf_block() {
    let closed = closed_port();
    let target = format!("http://127.0.0.1:{closed}/");
    let app = axum::Router::new().route(
        "/spec",
        axum::routing::get(move || {
            let target = target.clone();
            async move {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, target)],
                )
            }
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
    let url = format!("http://127.0.0.1:{port}/spec");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(crate::security::ssrf::ssrf_redirect_policy())
        .build()
        .expect("client");
    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(&url).send())
        .await
        .expect("bounded");
    let error = outcome.expect_err("a redirect to loopback must be refused");
    let message = super::fetch_error_message(&url, &error);
    assert!(
        message.contains("SSRF blocked"),
        "the message must name the block, got: {message}"
    );
}

#[tokio::test]
async fn fetch_spec_stops_after_five_redirects() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/{n}",
        axum::routing::get(move |axum::extract::Path(n): axum::extract::Path<usize>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::response::Redirect::temporary(&format!("/{}", n + 1))
            }
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
    let url = format!("http://127.0.0.1:{port}/0");
    let outcome =
        tokio::time::timeout(crate::test_wait::HANG_BOUND, super::fetch_spec(&url, false))
            .await
            .expect("bounded");
    assert!(outcome.is_err(), "an endless redirect chain must fail");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        6,
        "the first request plus 5 followed redirects"
    );
}
