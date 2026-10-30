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
const SHELL: &[u8] = include_bytes!("../ui/shell/index.html");
const CLASSIC: &[u8] = include_bytes!("../ui/index.html");
/// The shell's policy as the design states it, written out here so the
/// served header is checked against the spec, not against its own constant.
const SHELL_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; \
     form-action 'self'; frame-ancestors 'none'";

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
async fn fixture() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
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
        assert_eq!(
            reply.header(header::CONTENT_SECURITY_POLICY),
            Some(SHELL_CSP),
            "{uri}"
        );
        assert_eq!(
            reply.header(header::REFERRER_POLICY),
            Some("no-referrer"),
            "{uri}"
        );
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

/// Every asset the shell names, and the fonts its stylesheet names, read
/// from the document rather than pinned, so a rehash cannot strand a test.
fn shell_asset_names() -> Vec<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/ui/shell");
    let mut texts = vec![String::from_utf8_lossy(SHELL).into_owned()];
    let mut names = Vec::new();
    while let Some(text) = texts.pop() {
        for reference in text.split("/ui/assets/").skip(1) {
            let name = reference
                .split(['"', '\'', ')', ' '])
                .next()
                .unwrap_or_default()
                .to_string();
            if std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("css"))
            {
                texts.push(std::fs::read_to_string(dir.join(&name)).expect("stylesheet"));
            }
            names.push(name);
        }
    }
    names
}

fn shell_asset_bytes(name: &str) -> Vec<u8> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/ui/shell");
    std::fs::read(dir.join(name))
        .or_else(|_| std::fs::read(dir.join("fonts").join(name)))
        .expect("asset file")
}

#[tokio::test]
async fn t3_a_hashed_asset_is_served_immutable() {
    let (state, _dir) = fixture().await;
    let names = shell_asset_names();
    for ext in [".css", ".js", ".woff2"] {
        assert!(
            names.iter().any(|n| n.ends_with(ext)),
            "the shell names a {ext}"
        );
    }
    for name in names {
        let reply = send(&state, "GET", &format!("/ui/assets/{name}")).await;
        assert_eq!(reply.status, StatusCode::OK, "{name}");
        assert_eq!(reply.body, shell_asset_bytes(&name), "{name}");
        let want = match name.rsplit('.').next() {
            Some("css") => "text/css; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            _ => "font/woff2",
        };
        assert_eq!(reply.header(header::CONTENT_TYPE), Some(want), "{name}");
        assert_eq!(
            reply.header(header::CACHE_CONTROL),
            Some("public, max-age=31536000, immutable"),
            "{name}"
        );
        assert_eq!(
            reply.header(header::X_CONTENT_TYPE_OPTIONS),
            Some("nosniff"),
            "{name}"
        );
    }
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
        let reply = send(&state, "GET", uri).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{uri}");
        assert_ne!(reply.body, SHELL, "{uri}");
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
        assert_ne!(reply.body, SHELL, "{method} {uri}");
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

/// The exclusion reads the decoded path, a HEAD answers like a GET without a
/// body, and any other method on a deep link stays 404.
#[tokio::test]
async fn t10_encodings_and_methods_on_deep_links() {
    let (state, _dir) = fixture().await;
    for uri in ["/ui/%61pi/nope", "/ui/%61ssets/x"] {
        let reply = send(&state, "GET", uri).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{uri}");
        assert_ne!(reply.body, SHELL, "{uri}");
    }
    let head = send(&state, "HEAD", "/ui/servers").await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty(), "a HEAD has no body");
    for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
        let reply = send(&state, method, "/ui/servers").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method}");
    }
}
