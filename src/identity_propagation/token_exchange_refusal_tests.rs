// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the token-exchange strategy refuses from a hostile or broken STS, and
//! that it never serves an expired cache entry.

use axum::routing::post;
use axum::{Router, response::IntoResponse};
use tokio::net::TcpListener;

use super::*;

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_owned(),
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.invalid".to_owned(),
    }
}

fn strategy() -> TokenExchangeStrategy {
    TokenExchangeStrategy::with_http_client(
        Arc::new(GatewayKeyPair::generate().expect("keygen")),
        300,
        reqwest::Client::new(),
    )
}

/// An STS that answers every exchange with `body` and 200.
async fn sts(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new().route(
        "/token",
        post(move || async move {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("sts");
    });
    (format!("http://{addr}/token"), server)
}

async fn exchanged(body: &'static str) -> Result<PropagatedCredential, PropagationError> {
    let (endpoint, server) = sts(body).await;
    let backend = BackendDescriptor {
        id: "mail".to_owned(),
        audience: "https://mail.invalid".to_owned(),
        token_exchange_endpoint: Some(endpoint),
        token_exchange_scope: None,
    };
    let outcome = strategy().propagate(&identity(), &backend).await;
    server.abort();
    outcome
}

/// Mutant: an unparsable or token-less STS answer is turned into a credential.
#[tokio::test]
async fn an_unparsable_or_empty_sts_answer_is_refused_and_a_good_one_is_not() {
    for body in [
        "not json",
        r#"{"expires_in": 60}"#,
        r#"{"access_token": "  "}"#,
    ] {
        let refused = exchanged(body).await;
        assert!(
            matches!(refused, Err(PropagationError::Refuse(_))),
            "{body}: {refused:?}"
        );
    }
    let good = exchanged(r#"{"access_token": "downstream", "expires_in": 60}"#)
        .await
        .expect("a well-formed answer is accepted");
    assert_eq!(good.headers[0].1, "Bearer downstream");
}

/// Mutant: an expired cached exchange is served again.
#[test]
fn an_expired_cached_exchange_is_never_served() {
    let s = strategy();
    let now = SignedAssertionStrategy::now_secs().unwrap();
    let entry = |expires_at| CachedExchange {
        access_token: "t".to_owned(),
        expires_at,
        scopes: Vec::new(),
    };
    s.cache.insert("live".to_owned(), entry(now + 100));
    s.cache.insert("dead".to_owned(), entry(now - 1));
    assert!(s.cached("live").is_some());
    assert!(s.cached("dead").is_none());
}
