// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doctor's HTTP backend probe reports a redirect and never follows it.

use super::*;

// ── The HTTP probe reports a redirect, never follows it ───────────────────

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const HANG_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

/// A listener on loopback serving `app`; returns its base URL.
async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// A counting listener; returns its base URL and hit count.
async fn serve_counter() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let base = serve(axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::OK
        }
    }))
    .await;
    (base, hits)
}

/// T13a (RED): a 301 from an HTTP backend is reported, not followed.
#[tokio::test]
async fn http_backend_probe_reports_a_redirect_without_following_it() {
    let (counter, hits) = serve_counter().await;
    let location = format!("{counter}/moved/here");
    let expected = counter.clone();
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains("301"), "detail: {}", result.detail);
    assert!(
        result.detail.contains(&expected),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("would refuse"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("/moved/here"),
        "detail: {}",
        result.detail
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A redirect Location carrying userinfo, a query token and a fragment is
/// reported origin-only, in the text detail and in the `--json` report alike.
#[tokio::test]
async fn http_backend_probe_redacts_credentials_in_a_redirect_location() {
    let (counter, hits) = serve_counter().await;
    let location = counter.replacen("http://", "http://user:hunter2@", 1)
        + "/final/path?token=sekret-token-value#frag";
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert!(
        !result.detail.contains("hunter2"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("sekret-token-value"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("user:"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("/final/path"),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains(&counter),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("path hidden"),
        "detail: {}",
        result.detail
    );
    let report = check_result_json_value(&result).to_string();
    assert!(!report.contains("hunter2"), "report: {report}");
    assert!(!report.contains("sekret-token-value"), "report: {report}");
    assert!(!report.contains("user:"), "report: {report}");
    assert!(!report.contains("/final/path"), "report: {report}");
    assert!(report.contains(&counter), "report: {report}");
    assert!(report.contains("path hidden"), "report: {report}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A redirect Location whose path carries the secret (a webhook token) is
/// reported origin-only, in the text detail and in the `--json` report alike.
#[tokio::test]
async fn http_backend_probe_hides_a_secret_carrying_redirect_path() {
    let (counter, hits) = serve_counter().await;
    let location = format!("{counter}/hooks/sekret-path-token-77");
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert!(
        !result.detail.contains("sekret-path-token-77"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("/hooks/"),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("path hidden"),
        "detail: {}",
        result.detail
    );
    let report = check_result_json_value(&result).to_string();
    assert!(!report.contains("sekret-path-token-77"), "report: {report}");
    assert!(!report.contains("/hooks/"), "report: {report}");
    assert!(report.contains("path hidden"), "report: {report}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A relative redirect Location is resolved against the request URL, so the
/// detail names the request's origin, with the path hidden.
#[tokio::test]
async fn http_backend_probe_resolves_a_relative_redirect_location() {
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::MOVED_PERMANENTLY,
                [(axum::http::header::LOCATION, "/relative/target")],
            )
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    // Loopback under the default posture: the gateway refuses the hop.
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains(&stub), "detail: {}", result.detail);
    assert!(
        result.detail.contains("path hidden"),
        "detail: {}",
        result.detail
    );
    assert!(
        !result.detail.contains("/relative/target"),
        "detail: {}",
        result.detail
    );
}

/// The backend probe reports the gateway's own decision. A
/// same-origin redirect on loopback is refused under the default posture (the
/// SSRF check runs on every hop), and under `hardened` with the backend listed
/// in `private_backends` it is followed: FAIL, then WARN. The probe follows
/// neither.
async fn same_origin_loopback_redirect(config: &Config) -> (CheckResult, String, usize) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let app = axum::Router::new()
        .route(
            "/x",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, "/y")],
                )
            }),
        )
        .route(
            "/y",
            axum::routing::get(move || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(HANG_BOUND, check_http_backend(config, "b", &transport))
        .await
        .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    (result, stub, hits.load(Ordering::SeqCst))
}

#[tokio::test]
async fn http_backend_probe_fails_on_a_same_origin_loopback_redirect_by_default() {
    let (result, stub, hits) = same_origin_loopback_redirect(&Config::default()).await;
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains(&stub), "detail: {}", result.detail);
    assert!(
        result.detail.contains("would refuse"),
        "detail: {}",
        result.detail
    );
    assert_eq!(hits, 0);
}

#[tokio::test]
async fn http_backend_probe_warns_on_a_same_origin_redirect_to_a_listed_private_backend() {
    let mut config = Config::default();
    config.security.posture = mcp_gateway::security::SecurityPosture::Hardened;
    config.security.hardened.private_backends = vec!["b".to_string()];
    let (result, stub, hits) = same_origin_loopback_redirect(&config).await;
    assert_eq!(result.status, CheckStatus::Warn);
    assert!(result.detail.contains(&stub), "detail: {}", result.detail);
    assert!(
        result.detail.contains("first hop"),
        "detail: {}",
        result.detail
    );
    assert_eq!(hits, 0);
}

/// The Location is decoded as UTF-8, as reqwest does. A Location that
/// is not UTF-8 cannot be followed or shown: FAIL, naming it unreadable, and
/// never a WARN or a panic.
#[tokio::test]
async fn http_backend_probe_fails_on_a_location_that_is_not_utf8() {
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(|| async {
            let mut response = axum::response::Response::new(axum::body::Body::empty());
            *response.status_mut() = axum::http::StatusCode::MOVED_PERMANENTLY;
            // 0xFF is a legal header byte (obs-text) but never valid UTF-8.
            response.headers_mut().insert(
                axum::http::header::LOCATION,
                axum::http::HeaderValue::from_bytes(b"/y\xff").expect("obs-text header value"),
            );
            response
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    // Hardened with the backend listed: a readable same-origin Location here
    // would be followed (WARN), so only the decoding can make this a FAIL.
    let mut config = Config::default();
    config.security.posture = mcp_gateway::security::SecurityPosture::Hardened;
    config.security.hardened.private_backends = vec!["b".to_string()];
    let outcome = tokio::time::timeout(HANG_BOUND, check_http_backend(&config, "b", &transport))
        .await
        .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert_eq!(
        result.status,
        CheckStatus::Fail,
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("an unreadable Location"),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("not followed"),
        "detail: {}",
        result.detail
    );
}

/// reqwest does not follow a 300, so neither does the gateway.
#[tokio::test]
async fn http_backend_probe_fails_on_a_300_even_with_a_same_origin_location() {
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::MULTIPLE_CHOICES,
                [(axum::http::header::LOCATION, "/y")],
            )
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let mut config = Config::default();
    config.security.posture = mcp_gateway::security::SecurityPosture::Hardened;
    config.security.hardened.private_backends = vec!["b".to_string()];
    let outcome = tokio::time::timeout(HANG_BOUND, check_http_backend(&config, "b", &transport))
        .await
        .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains("300"), "detail: {}", result.detail);
    assert!(
        result.detail.contains("would refuse or not follow"),
        "detail: {}",
        result.detail
    );
}

/// A redirect to another loopback listener (another port, hence
/// another origin) is a FAIL — the gateway refuses it — and the probe still
/// does not follow it.
#[tokio::test]
async fn http_backend_probe_fails_on_a_cross_origin_redirect_without_following_it() {
    let (counter, hits) = serve_counter().await;
    let location = format!("{counter}/elsewhere");
    let expected = counter.clone();
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::MOVED_PERMANENTLY,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(
        result.detail.contains(&expected),
        "detail: {}",
        result.detail
    );
    assert!(
        result.detail.contains("would refuse"),
        "detail: {}",
        result.detail
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A redirect to an unreachable foreign origin is a FAIL.
#[tokio::test]
async fn http_backend_probe_fails_on_a_redirect_to_an_unreachable_origin() {
    let app = axum::Router::new().route(
        "/x",
        axum::routing::get(|| async {
            (
                axum::http::StatusCode::MOVED_PERMANENTLY,
                [(axum::http::header::LOCATION, "http://10.255.255.1/x")],
            )
        }),
    );
    let stub = serve(app).await;
    let transport = TransportConfig::Http {
        http_url: format!("{stub}/x"),
        streamable_http: None,
        protocol_version: None,
    };
    let outcome = tokio::time::timeout(
        HANG_BOUND,
        check_http_backend(&Config::default(), "b", &transport),
    )
    .await
    .expect("bounded");
    let Some(result) = outcome else {
        panic!("an Http transport must produce a result");
    };
    assert_eq!(result.status, CheckStatus::Fail);
    assert!(result.detail.contains("301"), "detail: {}", result.detail);
    assert!(
        result.detail.contains("would refuse"),
        "detail: {}",
        result.detail
    );
}
