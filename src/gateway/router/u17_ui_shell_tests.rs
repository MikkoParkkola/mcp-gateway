// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8870 (U17): `/ui/*` deep links answer the shell document, hashed
//! assets are served immutable, and the classic page moves to `/ui/classic`
//! while `/ui` stays classic. Every request goes through `create_router`, so
//! the router's route priority and the real auth layer decide each row.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::AuthConfig;

/// The one asset U17 ships, by its content-hashed name.
const ASSET: &str = "/ui/assets/shell.59b6e0f80d81.css";
const SHELL: &[u8] = include_bytes!("../ui/shell/index.html");
const CLASSIC: &[u8] = include_bytes!("../ui/index.html");

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Auth on with a static bearer, so `/ui/api` answers its auth refusal.
async fn fixture() -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some("u17-bearer".to_string()),
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

async fn send(state: &Arc<AppState>, method: &str, uri: &str) -> Reply {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .body(Body::empty())
        .expect("request builds");
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("the request finished")
    .expect("the router is infallible");
    let (status, headers) = (response.status(), response.headers().clone());
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

#[tokio::test]
async fn t1_a_deep_link_answers_the_shell_document() {
    let (state, _dir) = fixture().await;
    for uri in [
        "/ui/servers/github/status",
        "/ui/keys",
        "/ui/settings?tab=auth",
    ] {
        let reply = send(&state, "GET", uri).await;
        assert_eq!(reply.status, StatusCode::OK, "{uri}");
        assert_eq!(reply.body, SHELL, "{uri}");
        assert!(
            reply
                .header(header::CONTENT_TYPE)
                .is_some_and(|v| v.starts_with("text/html")),
            "{uri}"
        );
        assert_eq!(
            reply.header(header::CACHE_CONTROL),
            Some("no-cache, no-store, must-revalidate"),
            "{uri}"
        );
        let csp = reply
            .header(header::CONTENT_SECURITY_POLICY)
            .unwrap_or_default();
        for directive in ["default-src 'none'", "script-src 'self'", "font-src 'self'"] {
            assert!(csp.contains(directive), "{uri}: {csp}");
        }
        assert_eq!(
            reply.header(header::X_CONTENT_TYPE_OPTIONS),
            Some("nosniff")
        );
    }
}

#[tokio::test]
async fn t2_the_classic_page_is_also_at_ui_classic() {
    let (state, _dir) = fixture().await;
    let (classic, root) = (
        send(&state, "GET", "/ui/classic").await,
        send(&state, "GET", "/ui").await,
    );
    assert_eq!(classic.status, StatusCode::OK);
    assert_eq!(classic.body, CLASSIC);
    assert_eq!(root.body, CLASSIC, "/ui stays classic until UI1");
    for reply in [&classic, &root] {
        assert_eq!(
            reply.header(header::CACHE_CONTROL),
            Some("no-cache, no-store, must-revalidate")
        );
        assert!(
            reply.header(header::CONTENT_SECURITY_POLICY).is_none(),
            "the classic page keeps today's headers"
        );
    }
}

#[tokio::test]
async fn t3_a_hashed_asset_is_served_immutable() {
    let (state, _dir) = fixture().await;
    let reply = send(&state, "GET", ASSET).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        include_bytes!("../ui/shell/shell.59b6e0f80d81.css")
    );
    assert_eq!(
        reply.header(header::CONTENT_TYPE),
        Some("text/css; charset=utf-8")
    );
    assert_eq!(
        reply.header(header::CACHE_CONTROL),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(
        reply.header(header::X_CONTENT_TYPE_OPTIONS),
        Some("nosniff")
    );
}

/// PIN: 404 on the base too. No asset path ever answers HTML.
#[tokio::test]
async fn t3b_an_unknown_or_nested_asset_path_is_not_found() {
    let (state, _dir) = fixture().await;
    for uri in [
        "/ui/assets/nope.css",
        "/ui/assets/..%2Findex.html",
        "/ui/assets/a/b",
        "/ui/assets/../index.html",
        "/ui/assets",
    ] {
        assert_eq!(
            send(&state, "GET", uri).await.status,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
}

/// PIN: true on the base; it keeps the catch-all out of `/ui/api`.
#[tokio::test]
async fn t4_the_api_subtree_never_reaches_the_shell() {
    let (state, _dir) = fixture().await;
    for (method, uri) in [
        ("GET", "/ui/api/nope"),
        ("POST", "/ui/api/nope"),
        ("GET", "/ui/api"),
        ("GET", "/ui/api/status/"),
        ("GET", "/ui//api/status"),
    ] {
        let reply = send(&state, method, uri).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
    for (method, uri) in [
        ("GET", "/ui/api/status"),
        ("POST", "/ui/api/reload"),
        ("GET", "/ui/api/backends/x"),
    ] {
        // Routed: the auth layer answers, never the shell.
        let reply = send(&state, method, uri).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_ne!(reply.body, SHELL, "{method} {uri}");
    }
}

/// PIN: the empty catch-all is not matched.
#[tokio::test]
async fn t9_a_trailing_slash_on_ui_is_not_found() {
    let (state, _dir) = fixture().await;
    assert_eq!(
        send(&state, "GET", "/ui/").await.status,
        StatusCode::NOT_FOUND
    );
}
