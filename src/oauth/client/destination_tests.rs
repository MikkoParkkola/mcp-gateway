// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T7 and T9 of the HARDEN 4b test plan.
//!
//! T7 is a setup production never builds: an UNPINNED client carrying the
//! `Public` policy. Under the real pinned client no loopback mock is reachable
//! at all, so this is the only way to get a document served and then see the
//! literal checks refuse what it advertises. `hardened_oauth_client_is_pinned`
//! covers the production client.

use std::sync::Arc;

use serde_json::json;

use super::{Hop, hop};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::DestinationPolicy;

/// URLs the mock advertises; `{port}` is replaced with the mock's port.
struct Advertised {
    authorization_server: &'static str,
    token: &'static str,
    registration: &'static str,
}

const REACHABLE: &str = "http://localhost:{port}";

/// Serve both discovery documents on loopback; return the mock's port.
async fn serve(advertised: &Advertised) -> u16 {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fill = |template: &str| template.replace("{port}", &port.to_string());
    let reachable = fill(REACHABLE);
    let resource = json!({
        "resource": format!("{reachable}/mcp"),
        "authorization_servers": [fill(advertised.authorization_server)],
    });
    let server = json!({
        "issuer": reachable,
        "authorization_endpoint": format!("{reachable}/authorize"),
        "token_endpoint": fill(advertised.token),
        "registration_endpoint": fill(advertised.registration),
    });
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || {
                let body = resource.clone();
                async move { axum::Json(body) }
            }),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = server.clone();
                async move { axum::Json(body) }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

async fn initialize(advertised: &Advertised) -> crate::Result<()> {
    let port = serve(advertised).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Public,
        reqwest::Client::new(),
        "hardened-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await
}

async fn assert_refused(advertised: Advertised, which: &str) {
    let error = initialize(&advertised).await.expect_err(which).to_string();
    assert!(error.contains("SSRF blocked"), "{which}: {error}");
}

#[tokio::test]
async fn hardened_oauth_accepts_public_advertised_urls() {
    initialize(&Advertised {
        authorization_server: REACHABLE,
        token: "http://localhost:{port}/token",
        registration: "http://localhost:{port}/register",
    })
    .await
    .expect("control: every advertised URL is a name");
}

#[tokio::test]
async fn hardened_oauth_refuses_private_authorization_server() {
    assert_refused(
        Advertised {
            authorization_server: "http://127.0.0.1:{port}",
            token: "http://localhost:{port}/token",
            registration: "http://localhost:{port}/register",
        },
        "authorization server",
    )
    .await;
}

#[tokio::test]
async fn hardened_oauth_refuses_private_registration() {
    assert_refused(
        Advertised {
            authorization_server: REACHABLE,
            token: "http://localhost:{port}/token",
            registration: "http://10.0.0.5/register",
        },
        "registration endpoint",
    )
    .await;
}

#[tokio::test]
async fn hardened_oauth_refuses_private_token_endpoint() {
    assert_refused(
        Advertised {
            authorization_server: REACHABLE,
            token: "http://[::ffff:169.254.169.254]/token",
            registration: "http://localhost:{port}/register",
        },
        "token endpoint",
    )
    .await;
}

fn target(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

#[test]
fn oauth_redirect_hop_policy() {
    let private = target("http://169.254.169.254/latest");
    let public = target("https://auth.example.com/next");
    assert!(matches!(
        hop(DestinationPolicy::Public, 0, &private),
        Hop::Refuse(reason) if reason.contains("SSRF blocked")
    ));
    assert_eq!(hop(DestinationPolicy::Public, 0, &public), Hop::Follow);
    assert_eq!(hop(DestinationPolicy::Public, 10, &public), Hop::Stop);
    assert_eq!(hop(DestinationPolicy::Configured, 9, &public), Hop::Follow);
    assert_eq!(hop(DestinationPolicy::Configured, 10, &public), Hop::Stop);
    assert_eq!(
        hop(DestinationPolicy::Configured, 0, &private),
        Hop::Follow,
        "standard keeps today's redirects"
    );
}

/// A loopback listener that counts connections and drops each at once.
async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn hardened_oauth_client_is_pinned() {
    for (destination, reaches) in [
        (DestinationPolicy::Public, false),
        (DestinationPolicy::Configured, true),
    ] {
        let (port, accepted) = counting_listener().await;
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let mut client = OAuthClient::with_destination(
            destination,
            super::http_client(destination).unwrap(),
            "backend".to_string(),
            format!("http://localhost:{port}/mcp"),
            vec![],
            storage,
            OAuthClientConfig::default(),
        );
        client
            .initialize()
            .await
            .expect_err("nothing serves discovery here");
        let seen = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(seen > 0, reaches, "{destination:?}: {seen} connections");
    }
}
