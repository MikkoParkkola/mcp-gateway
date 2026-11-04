// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A discovery double for the issuer-change rows: a resource server that
//! answers the unauthenticated probe and names its authorization server in a
//! protected-resource document (RFC 9728), and two authorization servers, A
//! and B, each serving its own metadata (RFC 8414). Which one the resource
//! server names can be switched, as a provider that moved issuers would.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::response::IntoResponse;

use super::HttpTransport;
use crate::oauth::client::sign_in::{SignIn, SignInStatus};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::DestinationPolicy;

pub(super) const BACKEND_NAME: &str = "issuer-change";

/// The three servers and the switch.
pub(super) struct Disco {
    pub(super) resource: String,
    pub(super) issuer_b: String,
    names_b: Arc<AtomicBool>,
}

impl Disco {
    /// The resource server names issuer B from now on.
    pub(super) fn name_b(&self) {
        self.names_b.store(true, Ordering::SeqCst);
    }

    /// The resource server names issuer A from now on.
    pub(super) fn name_a(&self) {
        self.names_b.store(false, Ordering::SeqCst);
    }
}

async fn bind() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (listener, base)
}

/// An authorization server whose issuer is its own base URL.
async fn authorization_server() -> String {
    let (listener, base) = bind().await;
    let issuer = base.clone();
    let app = axum::Router::new().route(
        "/.well-known/oauth-authorization-server",
        axum::routing::get(move || {
            let base = issuer.clone();
            async move {
                axum::Json(serde_json::json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                }))
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// The double: servers A and B, and a resource server naming one of them.
pub(super) async fn disco() -> Disco {
    let (issuer_a, issuer_b) = (authorization_server().await, authorization_server().await);
    let (listener, resource) = bind().await;
    let names_b = Arc::new(AtomicBool::new(false));
    let (base, flag) = (resource.clone(), Arc::clone(&names_b));
    let (a, b) = (issuer_a.clone(), issuer_b.clone());
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let (base, flag, a, b) = (base.clone(), Arc::clone(&flag), a.clone(), b.clone());
        async move {
            match (req.method().as_str(), req.uri().path()) {
                ("POST", "/mcp") => (
                    axum::http::StatusCode::UNAUTHORIZED,
                    [(
                        axum::http::header::WWW_AUTHENTICATE,
                        format!("Bearer resource_metadata=\"{base}/prm\""),
                    )],
                )
                    .into_response(),
                ("GET", "/prm") => {
                    let named = if flag.load(Ordering::SeqCst) { b } else { a };
                    axum::Json(serde_json::json!({
                        "resource": format!("{base}/mcp"),
                        "authorization_servers": [named],
                    }))
                    .into_response()
                }
                _ => axum::http::StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Disco {
        resource,
        issuer_b,
        names_b,
    }
}

/// A gateway-owned client of the double's resource, sharing `dir` and `cell`.
pub(super) fn client_of(
    disco: &Disco,
    dir: &std::path::Path,
    cell: &Arc<SignInStatus>,
) -> OAuthClient {
    OAuthClient::with_destination(
        DestinationPolicy::Private,
        reqwest::Client::new(),
        BACKEND_NAME.to_owned(),
        format!("{}/mcp", disco.resource),
        vec![],
        Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap()),
        OAuthClientConfig {
            client_id: Some("issuer-change-client".to_owned()),
            ..OAuthClientConfig::default()
        },
    )
    .with_sign_in_status(Arc::clone(cell))
    .with_open_browser(Arc::new(|_: &str| true))
}

/// A fresh status cell.
pub(super) fn cell() -> Arc<SignInStatus> {
    Arc::new(SignInStatus::new(SignIn::NeverSignedIn))
}

/// `client` served through the transport's own request path.
pub(super) fn serve(client: OAuthClient) -> Arc<HttpTransport> {
    HttpTransport::new_with_oauth(
        "http://127.0.0.1:9/mcp",
        HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(client),
        None,
    )
    .unwrap()
}
