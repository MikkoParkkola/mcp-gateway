// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Issuer provenance through `initialize`: moved from `tests.rs` unchanged
//! (file-size ceiling, MIK-8320).

use super::*;

// =========================================================================
// Issuer provenance through `initialize`
// =========================================================================

/// What the protected-resource document says, which is what decides where
/// `initialize` gets its issuer string from. Three states because there are
/// three assignment sites, and an `Option` collapses two of them.
#[derive(Clone)]
enum ResourceDocument {
    /// No document at all: the endpoint answers 404.
    Absent,
    /// A valid document that names no authorization server.
    WithoutAuthorizationServer,
    /// A valid document advertising this authorization server identifier.
    Advertising(String),
}

/// Serve both well-known documents from one address: the protected-resource
/// document described by `resource_document`, and authorization-server
/// metadata claiming `issuer_claimed`.
///
/// Serving address and claimed identity are separate parameters so a test can
/// make them differ by exactly one character.
async fn serve_oauth_documents(
    listener: tokio::net::TcpListener,
    resource_document: ResourceDocument,
    issuer_claimed: &str,
) -> String {
    use axum::{Router, response::IntoResponse, routing::get};

    let base = format!("http://{}", listener.local_addr().unwrap());

    let as_body = serde_json::json!({
        "issuer": issuer_claimed,
        "authorization_endpoint": format!("{issuer_claimed}authorize"),
        "token_endpoint": format!("{issuer_claimed}token"),
    });
    // The configured resource (every client here is built for `{base}/mcp`):
    // an origin-named document is refused for a path resource (MIK-8320).
    let resource = format!("{base}/mcp");
    let prm_body = match resource_document {
        ResourceDocument::Absent => None,
        ResourceDocument::WithoutAuthorizationServer => {
            Some(serde_json::json!({ "resource": resource }))
        }
        ResourceDocument::Advertising(auth_server) => Some(
            serde_json::json!({ "resource": resource, "authorization_servers": [auth_server] }),
        ),
    };

    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = as_body.clone();
                async move { axum::Json(body) }
            }),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || {
                let body = prm_body.clone();
                async move {
                    // No document is the fallback path, not an empty one: an
                    // empty body would parse into metadata advertising nothing.
                    body.map_or_else(
                        || axum::http::StatusCode::NOT_FOUND.into_response(),
                        |b| axum::Json(b).into_response(),
                    )
                }
            }),
        );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

fn client_for(resource_url: &str, dir: &std::path::Path) -> OAuthClient {
    OAuthClient::new(
        Client::new(),
        "issuer-provenance".to_string(),
        resource_url.to_string(),
        vec![],
        Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap()),
        OAuthClientConfig::default(),
    )
}

/// Bind and keep an ephemeral port: no parallel test can take it (MIK-7984).
async fn bound_base() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (listener, base)
}

/// The comparison arm is only half the control: which arm runs is decided by
/// three assignments in `initialize`, and a mis-tagged advertised identifier
/// would leave every metadata test green. Driven end to end from the resource
/// URL so the classification itself is under test.
#[tokio::test]
async fn an_issuer_advertised_by_protected_resource_metadata_is_compared_exactly() {
    let (listener, base) = bound_base().await;
    let served = serve_oauth_documents(
        listener,
        ResourceDocument::Advertising(base.clone()),
        &format!("{base}/"),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut client = client_for(&format!("{served}/mcp"), dir.path());

    let err = client
        .initialize()
        .await
        .expect_err("an advertised identifier differing by a trailing slash must be refused");
    assert!(
        err.to_string().contains("issuer mismatch"),
        "unexpected error: {err}"
    );
}

/// Same documents, minus the advertisement. Nothing then reflects the server's
/// own spelling, so the synthesised origin tolerates the slash and an Auth0-
/// shaped server stays reachable.
#[tokio::test]
async fn an_issuer_reached_by_the_origin_fallback_tolerates_a_trailing_slash() {
    let (listener, base) = bound_base().await;
    let served =
        serve_oauth_documents(listener, ResourceDocument::Absent, &format!("{base}/")).await;
    let dir = tempfile::tempdir().unwrap();
    let mut client = client_for(&format!("{served}/mcp"), dir.path());

    client
        .initialize()
        .await
        .expect("the origin fallback tolerates a trailing slash");
}

/// The third assignment site: a valid protected-resource document that names no
/// authorization server. It reaches the same fallback as a missing document,
/// but by a different branch, and a mis-tag there would be invisible to both
/// tests above.
#[tokio::test]
async fn resource_metadata_naming_no_authorization_server_falls_back_to_the_origin() {
    let (listener, base) = bound_base().await;
    let served = serve_oauth_documents(
        listener,
        ResourceDocument::WithoutAuthorizationServer,
        &format!("{base}/"),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let mut client = client_for(&format!("{served}/mcp"), dir.path());

    client
        .initialize()
        .await
        .expect("a document naming no authorization server falls back to the origin");
}
