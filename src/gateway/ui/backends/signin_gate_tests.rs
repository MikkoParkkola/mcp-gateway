// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway-host gate of the sign-in start route: the callback binds
//! loopback only, so a sign-in started from any other authority is refused.
//! Accept and refuse cases are separate rows so a mutant of either side turns
//! its own row red. The route is driven without the origin middleware: the
//! handler's own gate is the unit under test.

use std::sync::Arc;

use axum::Extension;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use super::super::backends_router;
use super::is_gateway_host_authority;
use crate::config::{AuthConfig, BackendConfig, FailsafeConfig, OAuthConfig};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;

const START: &str = "/ui/api/backends/oauthy/signin";
const FOREIGN: [&str; 4] = [
    "gw.example:39400",
    "localhost.evil.example:39400",
    "10.0.0.5:39400",
    "gw.example:127",
];
const LOOPBACK: [&str; 3] = ["localhost:39400", "127.0.0.1:39400", "[::1]:39400"];

/// How the authority reaches the handler.
#[derive(Clone, Copy)]
enum Wire {
    /// HTTP/1.1: the `Host` header.
    Http1Host,
    /// HTTP/2: the `:authority`, an absolute URI and no `Host`.
    Http2Authority,
}

const WIRES: [Wire; 2] = [Wire::Http1Host, Wire::Http2Authority];

fn admin() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "signin-gate-admin".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: true,
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

/// A gateway with one OAuth backend, `oauthy`, that has no HTTP endpoint to
/// sign in to: a start that passes the gate ends there.
async fn state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, dir) =
        crate::gateway::router::tests::audience_state(&AuthConfig::default(), (None, None), |m| m)
            .await;
    let config = BackendConfig {
        oauth: Some(OAuthConfig {
            enabled: true,
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: None,
            shared_account: false,
        }),
        ..BackendConfig::default()
    };
    let backend = crate::backend::Backend::new(
        "oauthy",
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(state.backends.register(Arc::new(backend)), "registration");
    (state, dir)
}

/// A JSON POST of `{}` to `path` from `authority`, as an admin.
async fn post(
    state: &Arc<AppState>,
    path: &str,
    authority: &str,
    wire: Wire,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method("POST")
        .header("content-type", "application/json")
        .header(
            "cookie",
            format!(
                "{}={}",
                crate::gateway::auth::SESSION_COOKIE,
                super::fixture::session_handle(state)
            ),
        )
        .header("origin", format!("http://{authority}"));
    let builder = match wire {
        Wire::Http1Host => builder.uri(path).header("host", authority),
        Wire::Http2Authority => builder.uri(format!("http://{authority}{path}")),
    };
    let request = builder.body(Body::from("{}")).expect("request builds");
    let response = backends_router()
        .with_state(Arc::clone(state))
        .layer(Extension(admin()))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn assert_refused(status: StatusCode, body: &Value, context: &str) {
    assert_eq!(status, StatusCode::CONFLICT, "{context}: {body}");
    assert_eq!(body["error"], "gateway_host_required", "{context}: {body}");
}

#[test]
fn loopback_authorities_with_a_port_are_the_gateway_host() {
    for authority in LOOPBACK {
        assert!(is_gateway_host_authority(authority), "{authority}");
    }
}

#[test]
fn a_non_loopback_authority_is_not_the_gateway_host() {
    for authority in FOREIGN {
        assert!(!is_gateway_host_authority(authority), "{authority}");
    }
}

// G1: past the gate the start meets the backend's missing HTTP endpoint (502
// `sign_in_unavailable`), never the gate's 409.
#[tokio::test]
async fn loopback_authorities_with_a_port_start_a_flow() {
    let (state, _dir) = state().await;
    for wire in WIRES {
        for authority in LOOPBACK {
            let (status, body) = post(&state, START, authority, wire).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{authority}: {body}");
            assert_eq!(body["error"], "sign_in_unavailable", "{authority}: {body}");
        }
    }
}

// G2
#[tokio::test]
async fn a_non_loopback_host_is_refused_whatever_its_port() {
    let (state, _dir) = state().await;
    for wire in WIRES {
        for authority in FOREIGN {
            let (status, body) = post(&state, START, authority, wire).await;
            assert_refused(status, &body, authority);
        }
    }
}

// G4
#[tokio::test]
async fn the_refusal_names_the_dashboard_address() {
    let (state, _dir) = state().await;
    let (status, body) = post(&state, START, "gw.example:39400", Wire::Http1Host).await;
    assert_refused(status, &body, "gw.example");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("open the dashboard at localhost or 127.0.0.1")
            && message.contains("forward the callback port too"),
        "{message}"
    );
}

// G5
#[tokio::test]
async fn a_start_for_a_backend_without_oauth_is_refused() {
    let (state, _dir) = state().await;
    let plain = Arc::new(crate::backend::Backend::new(
        "plain",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    assert!(state.backends.register(plain), "fixture registration");
    let path = "/ui/api/backends/plain/signin";
    let (status, body) = post(&state, path, "127.0.0.1:39400", Wire::Http1Host).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "not_oauth", "{body}");
}
