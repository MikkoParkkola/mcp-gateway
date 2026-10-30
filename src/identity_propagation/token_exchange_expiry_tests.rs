// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An exchanged token's expiry says whether the issuer published it: a send
//! past a default one is refused for its own loan only (never evicting).

use axum::{Json, Router, routing::post};
use tokio::net::TcpListener;

use super::*;

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    }
}

/// An exchange endpoint answering `body`, and a strategy pointed at it.
async fn exchange_answering(body: serde_json::Value) -> (TokenExchangeStrategy, BackendDescriptor) {
    let app = Router::new().route(
        "/token",
        post(move || {
            let body = body.clone();
            async move { Json(body) }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    let strategy = TokenExchangeStrategy::with_http_client(
        Arc::new(GatewayKeyPair::generate().expect("keygen")),
        300,
        reqwest::Client::new(),
    );
    let backend = BackendDescriptor {
        id: "mail".to_string(),
        audience: "https://mail.internal".to_string(),
        token_exchange_endpoint: Some(format!("http://{addr}/token")),
        token_exchange_scope: None,
    };
    (strategy, backend)
}

#[tokio::test]
async fn an_omitted_expires_in_marks_the_expiry_synthetic_and_the_cache_keeps_it() {
    let (strategy, backend) = exchange_answering(serde_json::json!({"access_token": "t"})).await;
    let fresh = strategy
        .propagate(&identity(), &backend)
        .await
        .expect("exchange");
    let cached = strategy
        .propagate(&identity(), &backend)
        .await
        .expect("cache");
    assert!(
        fresh.expiry_synthetic,
        "the 300 s default is not the issuer's word"
    );
    assert!(cached.expiry_synthetic, "a cache hit keeps the mark");
}

#[tokio::test]
async fn a_published_expires_in_is_not_synthetic() {
    let body = serde_json::json!({"access_token": "t", "expires_in": 300});
    let (strategy, backend) = exchange_answering(body).await;
    let fresh = strategy
        .propagate(&identity(), &backend)
        .await
        .expect("exchange");
    assert!(!fresh.expiry_synthetic);
}
