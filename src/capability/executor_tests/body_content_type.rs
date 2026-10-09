// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request body encoding by declared content type.

use super::*;

// ── body_content_type tests ──────────────────────────────────────────────────

#[test]
fn body_content_type_text_plain_uses_raw_string_body() {
    // Verify that when body_content_type = "text/plain" and the body template
    // is a JSON string, attach_request_body builds a raw-string request (not
    // JSON-encoded).  We can't easily inspect the built request in a unit test
    // without a live HTTP server, so we at least verify that the RestConfig
    // deserialises correctly from YAML and that substitute_string works.
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        body: Some(serde_json::Value::String(
            "SELECT * FROM bus_msg WHERE topic = '{topic}' LIMIT {max_msg}".to_string(),
        )),
        body_content_type: "text/plain".to_string(),
        ..Default::default()
    };

    let params = serde_json::json!({"topic": "bus.demo.test", "max_msg": 50});

    // substitute_string is the path taken for plain-text bodies.
    let sql = executor
        .substitute_string(config.body.as_ref().unwrap().as_str().unwrap(), &params)
        .unwrap();

    assert!(
        sql.contains("bus.demo.test"),
        "SQL should contain topic: {sql}"
    );
    assert!(sql.contains("50"), "SQL should contain max_msg: {sql}");
    assert!(
        !sql.contains('{'),
        "All placeholders should be resolved: {sql}"
    );
}

#[tokio::test]
async fn handle_response_binary_returns_base64_payload() {
    async fn binary_handler() -> AxumResponse {
        AxumResponse::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "video/mp4")
            .body(Body::from(vec![0_u8, 1, 2, 3, 4, 5]))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/video", get(binary_handler)))
            .await
            .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .get(format!("http://{addr}/video"))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_format: "binary".to_string(),
        ..Default::default()
    };

    let body = executor.handle_response(response, &config).await.unwrap();
    assert_eq!(body["mime_type"], "video/mp4");
    assert_eq!(body["size"], 6);
    assert_eq!(body["data"], STANDARD.encode([0_u8, 1, 2, 3, 4, 5]));
}

#[tokio::test]
async fn handle_response_graphql_error_with_null_projection_returns_error() {
    async fn graphql_error_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "data": null,
            "errors": [
                { "message": "Field \"createAsUser\" is not defined by type \"IssueCreateInput\"." },
                { "message": "Field \"displayIconUrl\" is not defined by type \"IssueCreateInput\"." }
            ]
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", post(graphql_error_handler)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .post(format!("http://{addr}/graphql"))
        .json(&serde_json::json!({ "query": "mutation Broken { issueCreate { success } }" }))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_path: Some("data.issueCreate".to_string()),
        ..Default::default()
    };

    let err = executor
        .handle_response(response, &config)
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("GraphQL error"), "{message}");
    assert!(message.contains("createAsUser"), "{message}");
    assert!(message.contains("displayIconUrl"), "{message}");
}

#[tokio::test]
async fn handle_response_graphql_success_with_response_path_is_unchanged() {
    async fn graphql_success_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "data": {
                "issueCreate": {
                    "success": true,
                    "issue": {
                        "id": "lin-123",
                        "identifier": "MIK-3181"
                    }
                }
            }
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", post(graphql_success_handler)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .post(format!("http://{addr}/graphql"))
        .json(&serde_json::json!({ "query": "mutation Ok { issueCreate { success } }" }))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_path: Some("data.issueCreate".to_string()),
        ..Default::default()
    };

    let body = executor.handle_response(response, &config).await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["issue"]["identifier"], "MIK-3181");
}

#[test]
fn body_content_type_empty_defaults_to_json() {
    // Default behaviour: body_content_type is empty → use JSON body.
    // RestConfig::default() should produce empty body_content_type.
    let config = RestConfig::default();
    assert!(
        config.body_content_type.is_empty(),
        "Default body_content_type must be empty (→ JSON)"
    );
}

#[test]
fn body_content_type_deserialises_from_yaml() {
    let yaml = r#"
base_url: "http://127.0.0.1:8000"
path: "/sql"
method: "POST"
body_content_type: "text/plain"
body: "SELECT * FROM bus_msg LIMIT 10"
"#;
    let config: RestConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.body_content_type, "text/plain");
    assert_eq!(
        config.body.unwrap().as_str().unwrap(),
        "SELECT * FROM bus_msg LIMIT 10"
    );
}

#[tokio::test]
async fn send_with_retry_recovers_from_transient_timeouts() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Local server: the first two connections never answer, so each attempt
    // times out (a transient timeout -> retry); the third responds 200 at once.
    // Verifies MIK-5081: transient outbound failures are retried with backoff
    // instead of surfacing as an immediate BACKEND_ERROR.
    //
    // The per-attempt timeout also bounds the third, answering attempt: if
    // suite load delays that answer past it, the retry budget is spent and the
    // call fails with "error sending request" (MIK-8212). The timeout is
    // therefore wide, and an unanswered connection stays open until the client
    // gives up on it, so no answer can arrive late and none can close early.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_srv = Arc::clone(&counter);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let n = counter_srv.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                if n < 2 {
                    // Hold the connection until the client drops it (read
                    // returns 0 or errors); the cap only ends an orphaned thread.
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                    while matches!(stream.read(&mut buf), Ok(k) if k > 0) {}
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                    let _ = stream.flush();
                }
            });
        }
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let req = client.get(&url).timeout(std::time::Duration::from_secs(1));

    // Idempotent (retry_timeouts = true): timeouts are retried.
    let health = crate::failsafe::HealthTracker::new("test");
    let resp = send_with_retry(req, "test", true, &health).await;
    assert!(
        resp.is_ok(),
        "retry should recover from transient timeouts, got {resp:?}"
    );
    assert_eq!(resp.unwrap().status(), 200);
    // A fresh tracker is already healthy, so the counts carry the claim: one
    // success recorded, and the retried timeouts not counted as failures.
    let metrics = health.metrics();
    assert!(
        health.is_healthy() && metrics.success_count == 1 && metrics.failure_count == 0,
        "a recovered call records one transport success and no failure, got {metrics:?}"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "should have taken exactly 3 attempts (2 transient + 1 success)"
    );
}

#[tokio::test]
async fn send_with_retry_records_transport_failures() {
    // A refused port yields connection errors, which are always retried and
    // recorded as transport failures. After enough consecutive failures the
    // health tracker flips unhealthy (MIK-5080). The port stays bound for the
    // whole test but never listens: a connection is refused, and no parallel
    // test can bind it in between (MIK-7981; a dropped listener's port could
    // be taken, and the connect then succeeded).
    let reserved = tokio::net::TcpSocket::new_v4().expect("socket");
    reserved
        .bind("127.0.0.1:0".parse().unwrap())
        .expect("bind without listening");
    let addr = reserved.local_addr().unwrap();

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let health = crate::failsafe::HealthTracker::new("test");

    assert!(health.is_healthy(), "fresh tracker is healthy");
    for _ in 0..3 {
        let req = client
            .get(&url)
            .timeout(std::time::Duration::from_millis(200));
        let resp = send_with_retry(req, "test", false, &health).await;
        assert!(resp.is_err(), "connect to a refused port must fail");
    }
    assert!(
        !health.is_healthy(),
        "consecutive transport failures should flip the tracker unhealthy"
    );
    drop(reserved);
}

#[tokio::test]
async fn send_with_retry_does_not_retry_timeouts_when_not_idempotent() {
    // A server that always hangs past the client timeout. With retry_timeouts
    // = false (non-idempotent), the timeout is NOT retried: exactly one
    // connection attempt is made. Protects against duplicate side effects.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_srv = Arc::clone(&counter);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            counter_srv.fetch_add(1, Ordering::SeqCst);
            // Hold the connection open and never respond.
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                drop(stream);
            });
        }
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let health = crate::failsafe::HealthTracker::new("test");
    let req = client
        .post(&url)
        .timeout(std::time::Duration::from_millis(120));

    let resp = send_with_retry(req, "test", false, &health).await;
    assert!(resp.is_err(), "the hung request should time out");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a non-idempotent timeout must NOT be retried (single attempt)"
    );
}

/// A backend URL carrying a query-string credential must not survive into the
/// text of an outbound transport error.
///
/// Both assertions matter: the first pins what `reqwest` does on its own, so a
/// future release that starts redacting turns this test red rather than leaving
/// it passing vacuously; the second pins what `redact_url` adds.
#[tokio::test]
async fn redact_url_strips_a_credential_bearing_backend_url() {
    let url = "http://127.0.0.1:1/spec?api_key=SECRET-QUERY-VALUE";
    let raw = reqwest::Client::new().get(url).send().await.unwrap_err();

    assert!(
        raw.to_string().contains("SECRET-QUERY-VALUE"),
        "reqwest no longer embeds the URL; redact_url may be obsolete: {raw}"
    );
    let redacted = super::client::redact_url(raw);
    assert!(
        !redacted.to_string().contains("SECRET-QUERY-VALUE"),
        "credential survived redaction: {redacted}"
    );
}

/// GH475.RL.10 — the linkage between a capability backend's *real* HTTP 429
/// and the shared predicate that must exclude it from failure accounting.
///
/// PINNED OBSERVABLE: the circuit state after one dispatch failure. A real
/// throttled response leaves the circuit closed; a real server error opens it.
/// The two responses differ **only in the status line** — same body, same
/// route shape — so the thing being pinned is that the status reaches the
/// accounting at all, not that some word in the payload happened to.
///
/// WHICH ACCOUNTING, precisely: capability dispatch never reaches `Failsafe`.
/// Its `Err` goes to `BudgetOutcome::of` (`gateway/meta_mcp/invoke.rs:1384`),
/// whose recorder is private to that module. `Failsafe::record_dispatch_failure`
/// is the only *public* consumer of the same `is_rate_limited` predicate
/// (`gateway/recovery.rs:286`), so it is what this test drives. What is pinned
/// is the classification of a real capability error string by that predicate —
/// not the capability path's own budget accounting.
///
/// The error text is produced by the production formatter in
/// `executor/params.rs` (`handle_response`), not composed here: a test that
/// writes its own `"429 Too Many Requests"` string pins a copy of the format
/// and stays green when the format changes.
///
/// FALSIFIER: a mutation probe, not a pre-fix ref — the exclusion and this
/// test arrived together, so §P2's retrofit probe does not apply. Dropping the
/// status from the `"API returned {}: {}"` literal makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
///
/// PINNED SEPARATELY: the same format site in `executor/jsonrpc.rs` and
/// `executor/graphql.rs` — each formats its own status text, and each is driven
/// by its own sibling test below. STILL NOT PINNED here or there: the
/// meta-MCP error-budget effect — `record_error_budget` is private to
/// `gateway::meta_mcp::invoke`, where `error_budget_tests` pins it against the
/// same `is_rate_limited` predicate this path uses.
#[tokio::test]
async fn a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use crate::failsafe::Failsafe;
    use std::time::Duration;

    // Same body on both routes: the status line is the only discriminator.
    async fn throttled() -> AxumResponse {
        AxumResponse::builder()
            .status(429)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }
    async fn broken() -> AxumResponse {
        AxumResponse::builder()
            .status(500)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/throttled", get(throttled))
                .route("/broken", get(broken)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let config = RestConfig::default();
    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .get(format!("http://{addr}{route}"))
            .send()
            .await
            .unwrap();
        errors.push(
            executor
                .handle_response(response, &config)
                .await
                .unwrap_err()
                .to_string(),
        );
    }

    let failsafe_config = FailsafeConfig {
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let latency = Duration::from_millis(1);

    let throttled_backend = Failsafe::new("throttled-capability", &failsafe_config);
    throttled_backend.record_dispatch_failure(&errors[0], latency);
    assert!(
        throttled_backend.circuit_breaker.can_proceed(),
        "a real 429 must not trip the breaker; error text was: {}",
        errors[0]
    );

    let broken_backend = Failsafe::new("broken-capability", &failsafe_config);
    broken_backend.record_dispatch_failure(&errors[1], latency);
    assert!(
        !broken_backend.circuit_breaker.can_proceed(),
        "the control must still trip: same body, only the status differs; error text was: {}",
        errors[1]
    );
}
