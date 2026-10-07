// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8020: a capability's stored OAuth credential is refreshed at most once
//! at a time, never with a refresh token an earlier exchange may have
//! consumed, as MIK-8018 does for MCP backends.
//!
//! Each test drives executors sharing one token store against a server that
//! rotates refresh tokens and revokes the grant on any reuse.

use std::time::Duration;

use crate::oauth::client::token_server_fixture::{Answer, TokenServer};
use crate::oauth::storage::RefreshState;

use super::*;

const PROVIDER: &str = "rest-flight";

fn context() -> CapabilityExecutionContext {
    CapabilityExecutionContext::default().with_isolated_loopback_egress()
}

/// An executor on the token store in `dir`, as a config-reload generation
/// holds one: its own in-memory cache, the shared store.
fn executor(dir: &std::path::Path) -> Arc<CapabilityExecutor> {
    let mut executor = CapabilityExecutor::new();
    executor.token_storage = Some(Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap()));
    Arc::new(executor)
}

/// An expired stored token carrying `refresh_token`.
fn store_expired(dir: &std::path::Path, refresh_token: &str) {
    let storage = TokenStorage::new(dir.to_path_buf()).unwrap();
    let mut token = TokenInfo::from_response("a1".to_string(), None, None, None, None);
    token.expires_at = Some(0);
    token.refresh_token = Some(refresh_token.to_string());
    storage.save(PROVIDER, PROVIDER, &token).unwrap();
}

fn stored(dir: &std::path::Path) -> Option<TokenInfo> {
    TokenStorage::new(dir.to_path_buf())
        .unwrap()
        .load(PROVIDER, PROVIDER)
}

async fn fetch(executor: &CapabilityExecutor, server: &TokenServer) -> crate::Result<String> {
    let auth = oauth_auth(PROVIDER, &format!("{}/token", server.base));
    executor.fetch_credential(&auth, &context()).await
}

fn not_revoked(server: &TokenServer) {
    assert!(
        !server.revoked.load(Ordering::SeqCst),
        "the grant was revoked; sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// RESTREPLAY.1: two executors refresh one expired credential while the first
/// exchange is in flight. The stored refresh token is sent once and the grant
/// survives.
#[tokio::test]
async fn two_capability_calls_refresh_a_rotating_token_once() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let (first, second) = (executor(dir.path()), executor(dir.path()));

    let a = tokio::spawn({
        let server = Arc::clone(&server);
        async move { fetch(&first, &server).await }
    });
    server.arrivals(1, Duration::from_secs(5)).await;
    let b = tokio::spawn({
        let server = Arc::clone(&server);
        async move { fetch(&second, &server).await }
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
    not_revoked(&server);
}

/// RESTREPLAY.2: the waiting call takes up the token the first one stored and
/// sends nothing itself.
#[tokio::test]
async fn a_waiting_capability_call_adopts_the_refreshed_token() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let (first, second) = (executor(dir.path()), executor(dir.path()));

    let a = tokio::spawn({
        let server = Arc::clone(&server);
        async move { fetch(&first, &server).await }
    });
    server.arrivals(1, Duration::from_secs(5)).await;
    let b = tokio::spawn({
        let server = Arc::clone(&server);
        async move { fetch(&second, &server).await }
    });
    server.arrivals(2, Duration::from_secs(1)).await;
    server.release.notify_one();

    let issued = a.await.unwrap().expect("the first refresh succeeds");
    let adopted = b
        .await
        .unwrap()
        .expect("the second call takes up the stored token");
    assert_eq!(adopted, issued);
    assert_eq!(
        server.requests(),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// RESTREPLAY.3: the call is dropped while the server holds the rotated
/// answer; the exchange still completes and the rotated token is stored.
#[tokio::test]
async fn a_dropped_capability_call_still_stores_the_rotated_token() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let first = executor(dir.path());

    let call = tokio::spawn({
        let server = Arc::clone(&server);
        async move { fetch(&first, &server).await }
    });
    server.arrivals(1, Duration::from_secs(5)).await;
    call.abort();
    let _ = call.await;
    server.release.notify_one();

    let refresh_token = || stored(dir.path()).and_then(|t| t.refresh_token);
    let saved = tokio::time::timeout(Duration::from_secs(2), async {
        while refresh_token().as_deref() != Some("r2") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        saved.is_ok(),
        "the rotated token was lost: {:?}",
        refresh_token()
    );
}

/// RESTREPLAY.3: once the server is seen to rotate, a refresh whose outcome is
/// unknown is never sent again, by this executor or another.
async fn an_uncertain_capability_refresh_is_not_replayed(uncertain: Answer) {
    let server = TokenServer::start(&[Answer::Rotate, uncertain]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    fetch(&executor(dir.path()), &server)
        .await
        .expect("a first rotation is observed");
    let mut rotated = stored(dir.path()).expect("the rotated token is stored");
    rotated.expires_at = Some(0);
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    storage.save(PROVIDER, PROVIDER, &rotated).unwrap();

    let _ = fetch(&executor(dir.path()), &server).await;
    let _ = fetch(&executor(dir.path()), &server).await;
    assert_eq!(
        server.uses("r2"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    not_revoked(&server);
}

#[tokio::test]
async fn a_capability_refresh_answered_502_is_not_replayed() {
    an_uncertain_capability_refresh_is_not_replayed(Answer::RotateThen502).await;
}

/// RESTREDIRECT.1: the refresh does not follow a redirect, and the token it
/// sent is not sent again.
#[tokio::test]
async fn a_redirected_capability_refresh_is_not_replayed() {
    an_uncertain_capability_refresh_is_not_replayed(Answer::RotateThenRedirect).await;
}

/// RESTMARK.1: a process stopped mid-refresh left the in-flight marker of a
/// rotating server's token. The next call sends nothing and asks for a login.
#[tokio::test]
async fn a_capability_refresh_left_in_flight_is_not_resent() {
    use sha2::Digest as _;
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let mut state = storage.load_refresh_state(PROVIDER, PROVIDER);
    state.rotates = true;
    state.in_flight = Some(hex::encode(sha2::Sha256::digest(b"r1")));
    storage
        .save_refresh_state(PROVIDER, PROVIDER, &state)
        .unwrap();

    let result = fetch(&executor(dir.path()), &server).await;
    assert!(result.is_err(), "a possibly consumed token was used");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// RESTSAVE.1: the token directory turns read-only before the refresh. The
/// rotated token cannot be saved, and the refresh token it replaced is not
/// sent again.
#[cfg(unix)]
#[tokio::test]
async fn a_capability_refresh_that_cannot_be_saved_is_not_replayed() {
    use std::os::unix::fs::PermissionsExt as _;
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
    mode(0o500).unwrap();
    if std::fs::write(dir.path().join("probe"), b"").is_ok() {
        mode(0o700).unwrap();
        eprintln!("skipped: a privileged user can write a read-only directory");
        return;
    }

    let _ = fetch(&executor(dir.path()), &server).await;
    let _ = fetch(&executor(dir.path()), &server).await;
    mode(0o700).unwrap();
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    not_revoked(&server);
}

/// RESTFIELDS.1: the refreshed record keeps what the capability path stores
/// beside the token: the endpoint and the client id sent with the refresh.
#[tokio::test]
async fn a_refreshed_capability_token_keeps_its_endpoint_and_client_id() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    store_expired(dir.path(), "r1");
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let mut token = stored(dir.path()).unwrap();
    token.client_id = Some("rest-client".to_string());
    storage.save(PROVIDER, PROVIDER, &token).unwrap();

    fetch(&executor(dir.path()), &server)
        .await
        .expect("refreshed");
    let saved = stored(dir.path()).unwrap();
    assert_eq!(*server.client_ids.lock().unwrap(), ["rest-client"]);
    assert_eq!(saved.client_id.as_deref(), Some("rest-client"));
    let endpoint = format!("{}/token", server.base);
    assert_eq!(saved.token_endpoint.as_deref(), Some(endpoint.as_str()));
    assert_eq!(saved.refresh_token.as_deref(), Some("r2"));
}
