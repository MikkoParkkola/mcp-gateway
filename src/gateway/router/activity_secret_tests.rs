// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X5 of the U2 test plan (API2.7): no credential a caller presents to the
//! Activity routes appears in a log line or in an audit record.
//!
//! Every request goes through `create_router`, so authentication, the E1-f
//! audit layer and the Activity guard all run. The capture is thread-scoped:
//! it holds what the handlers and the layers log on this current-thread
//! runtime. The readers themselves run on the blocking pool, out of its
//! sight; X4 (`ui::activity::security_tests`) captures them directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth_and_key_server;
use super::ui_access_matrix_tests::seed_log;
use crate::config::{ApiKeyConfig, ApiKeyKind, AuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
use crate::gateway::routes;

/// Each credential value is unique and appears nowhere else in the fixture:
/// no key is named after its value, so a hit can only be a leak.
const BEARER: &str = "x5-bearer-value-61c3a9";
const ADMIN_KEY: &str = "x5-admin-key-value-8d27f0";
const STANDARD_KEY: &str = "x5-standard-key-value-4f90be";
const WRONG_KEY: &str = "x5-wrong-key-value-2b5e17";

fn key(value: &str, name: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(value.as_bytes())),
        name: name.to_string(),
        backends: vec!["*".to_string()],
        admin,
        kind: ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn get(uri: &str, bearer: Option<&str>, session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))));
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    if let Some(handle) = session {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    builder.body(Body::empty()).expect("request builds")
}

/// Every Activity request, by every kind of caller, through the router: the
/// statuses it answered, the audit log's lines once it is done, and the
/// session handle it presented.
async fn run_all() -> (Vec<(String, StatusCode)>, Vec<String>, String) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![
            key(ADMIN_KEY, "x5-admin", true),
            key(STANDARD_KEY, "x5-standard", false),
        ],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, _dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    let (log_dir, receipt_id) = seed_log(&mut state);
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let handle = state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits);
    let router = create_router(Arc::clone(&state));
    let receipt = routes::UI_ACTIVITY_RECEIPT.replace("{id}", &receipt_id);
    let list = format!("{}?server=srv", routes::UI_ACTIVITY);
    let csv = format!("{}?format=csv&server=srv", routes::UI_ACTIVITY_EXPORT);
    let cases: Vec<(&str, Option<&str>, Option<&str>)> = vec![
        (list.as_str(), Some(ADMIN_KEY), None),
        (routes::UI_ACTIVITY_EXPORT, Some(ADMIN_KEY), None),
        (csv.as_str(), Some(ADMIN_KEY), None),
        (receipt.as_str(), Some(ADMIN_KEY), None),
        (list.as_str(), Some(BEARER), None),
        (list.as_str(), None, Some(handle.as_str())),
        (list.as_str(), Some(STANDARD_KEY), None),
        (list.as_str(), Some(WRONG_KEY), None),
    ];
    let mut statuses = Vec::new();
    for (uri, bearer, session) in cases {
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            router.clone().oneshot(get(uri, bearer, session)),
        )
        .await
        .expect("the request finished")
        .expect("the router is infallible");
        let status = response.status();
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        statuses.push((format!("{} {uri}", bearer.unwrap_or("session")), status));
    }
    let lines = std::fs::read_to_string(log_dir.path().join("audit.jsonl"))
        .expect("the audit log reads")
        .lines()
        .map(str::to_string)
        .collect();
    (statuses, lines, handle)
}

#[test]
fn x5_no_presented_credential_in_any_log_line_or_audit_record() {
    let ((statuses, lines, handle), logged) =
        crate::test_log_capture::capture_at(tracing::Level::TRACE, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_all())
        });
    let codes: Vec<u16> = statuses.iter().map(|(_, s)| s.as_u16()).collect();
    // The reads ran: admin key, bearer and session are served; the standard
    // key is refused by role, the wrong key by authentication.
    assert_eq!(
        codes,
        [200, 200, 200, 200, 200, 200, 403, 401],
        "{statuses:?}"
    );
    // The three seeded calls, then whatever the requests themselves recorded.
    assert!(lines.len() >= 3, "the seeded calls: {lines:?}");
    let recorded = &lines[3..];
    for secret in [BEARER, ADMIN_KEY, STANDARD_KEY, WRONG_KEY, handle.as_str()] {
        assert!(!logged.contains(secret), "{secret} in a log line: {logged}");
        for record in recorded {
            assert!(
                !record.contains(secret),
                "{secret} in an audit record: {record}"
            );
        }
    }
}
