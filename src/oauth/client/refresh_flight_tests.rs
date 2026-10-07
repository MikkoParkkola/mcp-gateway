// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8018: every client holding one stored credential refreshes it at most
//! once at a time, never with a superseded or possibly consumed refresh token.
//!
//! The token server here rotates refresh tokens and revokes the grant on any
//! reuse, the way an authorization server following RFC 9700 section 4.14.2
//! may. Each test drives two clients of one credential (one storage directory,
//! one backend, one issuer) the way a replaced transport and its replacement,
//! or two config-reload generations, hold it in production.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

const RESOURCE: &str = "https://backend.example.com/mcp";
const BACKEND: &str = "flight-backend";
const CLIENT_ID: &str = "flight-client";

/// How the token server answers the next refresh request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Rotate and answer at once.
    Rotate,
    /// Rotate, then hold the answer until the test releases it.
    HoldThenRotate,
    /// Rotate, then answer 502 as a proxy in front of it would.
    RotateThen502,
    /// Rotate, then send a 200 whose body breaks off.
    RotateThenBrokenBody,
    /// Rotate, then redirect to a port nobody listens on.
    RotateThenRedirect,
}

/// A rotating token server that records every refresh it is sent.
struct TokenServer {
    base: String,
    /// The refresh token of every refresh request, in arrival order.
    sent: Mutex<Vec<String>>,
    /// The client id of every refresh request, in arrival order.
    client_ids: Mutex<Vec<String>>,
    /// Refresh tokens already consumed; a second use revokes the grant.
    consumed: Mutex<Vec<String>>,
    revoked: AtomicBool,
    generation: AtomicUsize,
    answers: Mutex<Vec<Answer>>,
    arrived: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl TokenServer {
    /// Start one; `answers` are used in order, then `Rotate`.
    async fn start(answers: &[Answer]) -> Arc<Self> {
        use axum::{Form, Router, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Arc::new(Self {
            base: format!("http://{}", listener.local_addr().unwrap()),
            sent: Mutex::default(),
            client_ids: Mutex::default(),
            consumed: Mutex::default(),
            revoked: AtomicBool::new(false),
            generation: AtomicUsize::new(1),
            answers: Mutex::new(answers.iter().rev().copied().collect()),
            arrived: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let handler = Arc::clone(&server);
        let app = Router::new().route(
            "/token",
            post(move |Form(form): Form<HashMap<String, String>>| {
                let server = Arc::clone(&handler);
                async move { server.answer(&form).await }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await });
        server
    }

    async fn answer(&self, form: &HashMap<String, String>) -> axum::response::Response {
        use axum::{Json, http::StatusCode, response::IntoResponse};
        let sent = form.get("refresh_token").cloned().unwrap_or_default();
        self.sent.lock().unwrap().push(sent.clone());
        let client_id = form.get("client_id").cloned().unwrap_or_default();
        self.client_ids.lock().unwrap().push(client_id);
        self.arrived.notify_waiters();
        let answer = self.answers.lock().unwrap().pop().unwrap_or(Answer::Rotate);
        let reused = {
            let mut consumed = self.consumed.lock().unwrap();
            let reused = consumed.contains(&sent);
            consumed.push(sent.clone());
            reused
        };
        if reused {
            self.revoked.store(true, Ordering::SeqCst);
        }
        if reused || self.revoked.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response();
        }
        let n = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let mut body = serde_json::json!({
            "access_token": format!("a{n}"),
            "token_type": "Bearer",
            "expires_in": 3600,
        });
        body["refresh_token"] = format!("r{n}").into();
        match answer {
            Answer::HoldThenRotate => self.release.notified().await,
            Answer::RotateThen502 => return StatusCode::BAD_GATEWAY.into_response(),
            Answer::RotateThenRedirect => {
                return (
                    StatusCode::TEMPORARY_REDIRECT,
                    [("location", "http://127.0.0.1:1/token")],
                )
                    .into_response();
            }
            Answer::RotateThenBrokenBody => {
                let broken = futures::stream::iter([
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"{\"access_token\":")),
                    Err(std::io::Error::other("connection lost")),
                ]);
                return axum::response::Response::builder()
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from_stream(broken))
                    .unwrap();
            }
            Answer::Rotate => {}
        }
        Json(body).into_response()
    }

    /// How many refresh requests carried `token`.
    fn uses(&self, token: &str) -> usize {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|t| *t == token)
            .count()
    }

    fn requests(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Wait until `n` refresh requests have arrived, or `within` passes.
    async fn arrivals(&self, n: usize, within: Duration) {
        let _ = tokio::time::timeout(within, async {
            while self.requests() < n {
                self.arrived.notified().await;
            }
        })
        .await;
    }
}

/// A client of the shared credential, whose storage is `dir`.
fn client(dir: &std::path::Path, server: &TokenServer) -> OAuthClient {
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::new(
        Client::builder().no_proxy().build().unwrap(),
        BACKEND.to_string(),
        RESOURCE.to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            client_id: Some(CLIENT_ID.to_string()),
            ..OAuthClientConfig::default()
        },
    );
    client.auth_metadata = Some(
        serde_json::from_value(serde_json::json!({
            "issuer": server.base,
            "authorization_endpoint": format!("{}/authorize", server.base),
            "token_endpoint": format!("{}/token", server.base),
        }))
        .unwrap(),
    );
    client
}

/// A token with `refresh`, already expired when `expired`.
fn token(access: &str, refresh: Option<&str>, expired: bool) -> TokenInfo {
    let mut token = TokenInfo::from_response(
        access.to_string(),
        Some("Bearer".to_string()),
        refresh.map(str::to_string),
        Some(3600),
        None,
    );
    if expired {
        token.expires_at = Some(1);
    }
    token
}

/// Store `token` as the shared credential and cache it in `client`.
fn hold(client: &OAuthClient, token: &TokenInfo) {
    let key = client.credential_key().unwrap();
    client.storage.save(&key, RESOURCE, token).unwrap();
    *client.current_token.write() = Some(token.clone());
}

/// The shared credential as stored.
fn stored(client: &OAuthClient) -> Option<TokenInfo> {
    let key = client.credential_key().unwrap();
    client.storage.load(&key, RESOURCE)
}

/// Run `client`'s `get_token` the way the health probe and renewal do: never
/// opening a login, so a refused refresh cannot reach a browser.
async fn headless(client: &OAuthClient) -> Result<String> {
    crate::oauth::login_gate::non_interactive(client.get_token()).await
}

/// Expire the stored credential and `client`'s cached copy, keeping every
/// other field of the stored record as the gateway last wrote it.
fn expire(client: &OAuthClient) {
    let mut token = stored(client).expect("a stored token");
    token.expires_at = Some(1);
    let key = client.credential_key().unwrap();
    client.storage.save(&key, RESOURCE, &token).unwrap();
    *client.current_token.write() = Some(token);
}

/// RENEWREPLAY.1: two live clients of one credential, both expired, refresh
/// while the first exchange is still in flight. The original refresh token is
/// sent once; the second client takes up what the first stored.
#[tokio::test]
async fn two_live_clients_refresh_a_rotating_token_once() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    let first = Arc::new(client(dir.path(), &server));
    let second = Arc::new(client(dir.path(), &server));
    hold(&first, &token("a1", Some("r1"), true));
    *second.current_token.write() = Some(token("a1", Some("r1"), true));

    let a = tokio::spawn({
        let first = Arc::clone(&first);
        async move { headless(&first).await }
    });
    server.arrivals(1, Duration::from_secs(5)).await;
    let b = tokio::spawn({
        let second = Arc::clone(&second);
        async move { headless(&second).await }
    });
    server.arrivals(2, Duration::from_secs(2)).await;
    server.release.notify_one();

    a.await.unwrap().expect("the first refresh succeeds");
    let _ = b.await.unwrap();
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(
        !server.revoked.load(Ordering::SeqCst),
        "the grant was revoked"
    );
}

/// RENEWREPLAY.2: the first refresh's caller is dropped while the server holds
/// the rotated answer; the exchange still completes and stores it, and the
/// second client takes it up instead of replaying the consumed token.
#[tokio::test]
async fn a_cancelled_refresh_still_stores_the_rotated_token() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    let first = Arc::new(client(dir.path(), &server));
    let second = client(dir.path(), &server);
    hold(&first, &token("a1", Some("r1"), true));
    *second.current_token.write() = Some(token("a1", Some("r1"), true));

    let caller = tokio::spawn({
        let first = Arc::clone(&first);
        async move { headless(&first).await }
    });
    server.arrivals(1, Duration::from_secs(5)).await;
    caller.abort();
    let _ = caller.await;
    server.release.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while stored(&first).and_then(|t| t.refresh_token).as_deref() != Some("r2") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let _ = headless(&second).await;
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(
        !server.revoked.load(Ordering::SeqCst),
        "the grant was revoked"
    );
}

/// RENEWREPLAY.3: once the server has been seen to rotate, an exchange whose
/// outcome is unknown spends the refresh token it sent: no client sends it
/// again. One case per way the outcome can be unknown.
async fn an_uncertain_refresh_is_not_replayed(uncertain: Answer) {
    let server = TokenServer::start(&[Answer::Rotate, uncertain]).await;
    let dir = tempfile::tempdir().unwrap();
    let first = client(dir.path(), &server);
    let second = client(dir.path(), &server);
    hold(&first, &token("a1", Some("r1"), true));
    headless(&first)
        .await
        .expect("a first rotation is observed");

    expire(&first);
    let _ = headless(&first).await;
    *second.current_token.write() = Some(token("a2", Some("r2"), true));
    let _ = headless(&second).await;
    assert_eq!(
        server.uses("r2"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(
        !server.revoked.load(Ordering::SeqCst),
        "the grant was revoked"
    );
}

#[tokio::test]
async fn a_lost_rotated_answer_is_not_replayed() {
    an_uncertain_refresh_is_not_replayed(Answer::RotateThenBrokenBody).await;
}

#[tokio::test]
async fn a_rotated_answer_behind_a_502_is_not_replayed() {
    an_uncertain_refresh_is_not_replayed(Answer::RotateThen502).await;
}

#[tokio::test]
async fn a_rotated_answer_behind_a_redirect_is_not_replayed() {
    an_uncertain_refresh_is_not_replayed(Answer::RotateThenRedirect).await;
}

/// ADOPT.1: a client whose cached token has expired, while storage holds a
/// fresh one another client wrote, takes the stored one without a request.
#[tokio::test]
async fn a_client_with_an_expired_token_adopts_a_fresh_stored_one() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    let key = late.credential_key().unwrap();
    late.storage
        .save(&key, RESOURCE, &token("a5", Some("r1"), false))
        .unwrap();
    *late.current_token.write() = Some(token("a1", Some("r1"), true));

    assert_eq!(headless(&late).await.unwrap(), "a5");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// FU-A.2: with no stored refresh token (spent, or never issued), a client
/// never falls back to the one it still holds in memory.
#[tokio::test]
async fn without_a_stored_refresh_token_nothing_is_sent() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    let key = late.credential_key().unwrap();
    late.storage
        .save(&key, RESOURCE, &token("a1", None, true))
        .unwrap();
    *late.current_token.write() = Some(token("a1", Some("r0"), true));

    assert!(headless(&late).await.is_err(), "a login is needed");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// REFRESHID.1: a client refreshing with the stored refresh token sends the
/// client id registered with it, not a stale one it cached.
#[tokio::test]
async fn a_reloaded_refresh_token_brings_its_client_id() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    *late.client_id.write() = Some("stale-registration".to_string());
    *late.client_id_source.write() = Some(ClientIdSource::Registered);
    let key = late.credential_key().unwrap();
    late.storage
        .save_client_id(&key, RESOURCE, "current-registration")
        .unwrap();
    late.storage
        .save(&key, RESOURCE, &token("a3", Some("r3"), true))
        .unwrap();
    *late.current_token.write() = Some(token("a1", Some("r1"), true));

    let _ = headless(&late).await;
    assert_eq!(
        *server.sent.lock().unwrap(),
        ["r3"],
        "the stored refresh token"
    );
    assert_eq!(*server.client_ids.lock().unwrap(), ["current-registration"]);
}

/// REVOKE.1 (a pin, green before and after): a grant the server revoked
/// surfaces as a need to log in, not as an opaque refresh error.
#[tokio::test]
async fn a_revoked_grant_surfaces_as_a_clean_relogin() {
    let server = TokenServer::start(&[]).await;
    server.consumed.lock().unwrap().push("r1".to_string());
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    hold(&late, &token("a1", Some("r1"), true));

    let error = headless(&late).await.expect_err("the grant is gone");
    assert!(
        matches!(error, Error::AuthorizationRequired { .. }),
        "a login prompt, not {error:?}"
    );
}

/// k8: the rotated token is saved before the flight is released, so the next
/// waiter re-reads it rather than the token it replaces.
#[tokio::test]
async fn the_flight_is_held_until_the_rotated_token_is_saved() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let first = Arc::new(client(dir.path(), &server));
    hold(&first, &token("a1", Some("r1"), true));
    let key = first.credential_key().unwrap();
    let flight = super::refresh_flight::Flight::of(&first.storage.token_path(&key, RESOURCE));
    let gate = Arc::new(super::refresh_flight::SaveGate::default());
    *flight.save_gate.lock() = Some(Arc::clone(&gate));

    let task = tokio::spawn({
        let first = Arc::clone(&first);
        async move { headless(&first).await }
    });
    gate.reached.notified().await;
    assert!(
        flight.lock.try_lock().is_err(),
        "the flight was released before the save"
    );
    gate.release.notify_one();
    assert_eq!(task.await.unwrap().expect("refreshed"), "a2");
    *flight.save_gate.lock() = None;
}

/// The refresh-state sidecar sits in the secrets directory and is written as
/// the token file is: owner-only from creation.
#[cfg(unix)]
#[tokio::test]
async fn the_refresh_state_is_owner_only_like_the_token() {
    use std::os::unix::fs::PermissionsExt;
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    hold(&late, &token("a1", Some("r1"), true));
    headless(&late).await.expect("refreshed");

    let key = late.credential_key().unwrap();
    let mode =
        |path: std::path::PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let sidecar = mode(late.storage.refresh_state_path(&key, RESOURCE));
    assert_eq!(sidecar, 0o600);
    assert_eq!(sidecar, mode(late.storage.token_path(&key, RESOURCE)));
}

/// FU-A.5: the no-redirect refresh client keeps the destination checks: a
/// cleartext token endpoint off this machine is refused before anything is
/// sent.
#[tokio::test]
async fn a_cleartext_off_host_refresh_is_refused_before_sending() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut late = client(dir.path(), &server);
    if let Some(meta) = late.auth_metadata.as_mut() {
        meta.token_endpoint = "http://192.0.2.10/token".to_string();
    }
    hold(&late, &token("a1", Some("r1"), true));

    let error = late.refresh_token().await.expect_err("refused");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
    assert_eq!(server.requests(), 0);
}

/// FU-A.6: a stored record that differs only in its refresh token (another
/// client's rotation kept the access token) is taken up, not refreshed again.
#[tokio::test]
async fn a_stored_rotation_that_kept_the_access_token_is_adopted() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let late = client(dir.path(), &server);
    let live = token("a1", Some("r1"), false);
    let mut rotated = live.clone();
    rotated.refresh_token = Some("r9".to_string());
    let key = late.credential_key().unwrap();
    late.storage.save(&key, RESOURCE, &rotated).unwrap();
    *late.current_token.write() = Some(live);

    assert_eq!(late.refresh_token().await.unwrap(), "a1");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    let cached = late.current_token.read().clone().unwrap();
    assert_eq!(cached.refresh_token.as_deref(), Some("r9"));
}
