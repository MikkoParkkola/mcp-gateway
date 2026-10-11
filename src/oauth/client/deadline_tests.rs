// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339: the login stages with no window of their own still end at a
//! detached step's one deadline. Each row stalls one stage against a loopback
//! authorization server and gives the step a deadline a few seconds out; the
//! HTTP client here has no timeout, so a stage that ignores the deadline
//! stalls until the row's own 10-second bound fails it.
//!
//! In production: dynamic client registration runs when no `client_id` is
//! configured; a joiner is a per-user slot that shares its backend's gate.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use crate::oauth::login_gate::{Begin, LoginGate};

/// Requests each stalled endpoint received.
#[derive(Default)]
struct Seen {
    register: AtomicUsize,
    token: AtomicUsize,
}

/// An authorization server whose registration and token endpoints never
/// answer. Returns its origin.
async fn stalling_server() -> (String, Arc<Seen>) {
    use axum::{Router, routing::post};
    let seen = Arc::new(Seen::default());
    let (register, token) = (Arc::clone(&seen), Arc::clone(&seen));
    let app = Router::new()
        .route(
            "/register",
            post(move || async move {
                register.register.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }),
        )
        .route(
            "/token",
            post(move || async move {
                token.token.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (origin, seen)
}

/// A gated client of `issuer`, with `client_id` configured or (`None`) one to
/// register; the browser it opens is approved at once.
fn client(dir: &std::path::Path, issuer: &str, client_id: Option<&str>) -> OAuthClient {
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::new(
        Client::builder().no_proxy().build().unwrap(),
        "deadline-backend".to_string(),
        "https://backend.example.com/mcp".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            client_id: client_id.map(str::to_string),
            callback_host: Some("127.0.0.1".to_string()),
            ..OAuthClientConfig::default()
        },
    );
    client.auth_metadata = Some(
        serde_json::from_value(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "registration_endpoint": format!("{issuer}/register"),
        }))
        .unwrap(),
    );
    let iss = issuer.to_string();
    client.open_browser = Box::new(move |url| {
        let query: std::collections::HashMap<String, String> = Url::parse(url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let callback = Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("code", "approved"),
                ("state", query["state"].as_str()),
                ("iss", iss.as_str()),
            ],
        )
        .unwrap();
        tokio::spawn(async move {
            let _ = Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(callback)
                .send()
                .await;
        });
        true
    });
    client.with_login_gate(Arc::new(LoginGate::default()))
}

/// Run `step` under the row's 10-second bound.
async fn bounded<T>(what: &str, step: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), step)
        .await
        .unwrap_or_else(|_| panic!("{what} outlived the step's deadline"))
}

fn deadline_in(secs: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(secs)
}

/// LOGINDL.20: a dynamic client registration stalled past the step's
/// deadline ends `AuthorizationIncomplete` at that deadline.
#[tokio::test]
async fn a_registration_stalled_past_the_deadline_ends_incomplete() {
    let (issuer, seen) = stalling_server().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &issuer, None);

    let ended = bounded(
        "a stalled registration",
        client.authorize_shared_with(true, None, None, Some(deadline_in(2))),
    )
    .await;

    assert_eq!(
        seen.register.load(Ordering::SeqCst),
        1,
        "premise: the step reached registration"
    );
    let error = ended.expect_err("no token from a stalled registration");
    assert!(
        matches!(error, Error::AuthorizationIncomplete { .. }),
        "the deadline ended the registration stage: {error:?}"
    );
}

/// LOGINDL.21: an approved login whose code exchange stalls past the step's
/// deadline ends `AuthorizationIncomplete` at that deadline, not at the
/// exchange's own request timeout.
#[tokio::test]
async fn a_code_exchange_stalled_past_the_deadline_ends_incomplete() {
    let (issuer, seen) = stalling_server().await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &issuer, Some("configured-client"));

    let ended = bounded(
        "a stalled code exchange",
        client.authorize_shared_with(true, None, None, Some(deadline_in(3))),
    )
    .await;

    assert_eq!(
        seen.token.load(Ordering::SeqCst),
        1,
        "premise: the person approved and the step reached the exchange"
    );
    let error = ended.expect_err("no token from a stalled exchange");
    assert!(
        matches!(error, Error::AuthorizationIncomplete { .. }),
        "the deadline ended the exchange stage: {error:?}"
    );
}

/// LOGINDL.22: a joiner's own deadline ends its wait on a login another
/// caller leads, `AuthorizationIncomplete`; the lead's login runs on.
#[tokio::test]
async fn a_joiners_deadline_ends_its_wait_on_the_lead() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "http://127.0.0.1:9", Some("configured-client"));
    let gate = client.login_gate().expect("a gated client");
    let Begin::Lead(lead) = gate.begin(None, None) else {
        panic!("premise: the test leads the login");
    };

    let ended = bounded(
        "a joiner's wait",
        client.authorize_shared_with(true, None, None, Some(deadline_in(1))),
    )
    .await;

    assert!(gate.in_flight(), "the lead's login runs on");
    lead.end(None);
    let error = ended.expect_err("the joiner gets no token");
    assert!(
        matches!(error, Error::AuthorizationIncomplete { .. }),
        "the joiner's deadline ended its wait: {error:?}"
    );
}
