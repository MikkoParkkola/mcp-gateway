// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8018: how each way a refresh exchange can end decides the fate of the
//! refresh token it sent (`MIK-7324.COV.3` rows `refresh_token`, `send`).
//! Nothing sent keeps the token; an unsettled outcome on a rotating server
//! spends it; a token that could not be marked in flight is never sent.

use std::sync::Arc;

use super::*;
use crate::oauth::storage::RefreshState;

/// The flight of `client`'s stored credential.
fn flight_of(client: &OAuthClient) -> Arc<super::super::refresh_flight::Flight> {
    let key = client.credential_key().unwrap();
    super::super::refresh_flight::Flight::of(&client.storage.token_path(&key, RESOURCE))
}

/// Point `client`'s token endpoint at `endpoint`.
fn token_endpoint(client: &mut OAuthClient, endpoint: String) {
    client.auth_metadata.as_mut().unwrap().token_endpoint = endpoint;
}

/// Record that the credential's server rotates refresh tokens.
fn rotating(client: &OAuthClient) {
    let key = client.credential_key().unwrap();
    let state = RefreshState {
        rotates: true,
        in_flight: None,
    };
    client
        .storage
        .save_refresh_state(&key, RESOURCE, &state)
        .unwrap();
}

/// A token endpoint that answers every request with a 200 whose body is not
/// JSON.
async fn malformed_endpoint() -> String {
    use axum::{Router, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/token",
        post(|| async {
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .body(axum::body::Body::from("not a token response"))
                .unwrap()
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("{base}/token")
}

/// Set `dir`'s mode; `false` when a read-only directory still takes writes
/// (a privileged runner), so a storage fault cannot be staged.
#[cfg(unix)]
fn set_mode(dir: &std::path::Path, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    mode & 0o200 != 0 || std::fs::write(dir.join("probe"), b"").is_err()
}

/// An owned client that cannot connect sent nothing: the refresh token stays
/// stored and unspent, the in-flight marker is settled, and the next refresh
/// sends it.
#[tokio::test]
async fn a_refresh_that_never_connects_keeps_its_token() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut owned = client(dir.path(), &server);
    rotating(&owned);
    hold(&owned, &token("a1", Some("r1"), true));
    // Bound for the whole test and never listening: a connection is refused,
    // and no parallel test can take the port meanwhile (MIK-7981).
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let refused = reserved.local_addr().unwrap();
    token_endpoint(&mut owned, format!("http://{refused}/token"));

    assert!(headless(&owned).await.is_err(), "nothing answered");
    assert_eq!(
        stored(&owned).and_then(|t| t.refresh_token).as_deref(),
        Some("r1")
    );
    assert_eq!(marker(&owned), None, "the exchange settled");
    assert!(
        !flight_of(&owned).is_spent("r1"),
        "an unsent token is not spent"
    );

    token_endpoint(&mut owned, format!("{}/token", server.base));
    headless(&owned).await.expect("the kept token refreshes");
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// A 200 that does not parse may still have consumed the token on a server
/// that rotates: it is spent, cleared from storage and never sent again.
#[tokio::test]
async fn an_unparsable_answer_spends_a_rotating_servers_token() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut owned = client(dir.path(), &server);
    rotating(&owned);
    hold(&owned, &token("a1", Some("r1"), true));
    token_endpoint(&mut owned, malformed_endpoint().await);

    // The refresh fails; the client then falls back to a login, which the
    // headless caller refuses. The token's fate is the assertion.
    assert!(headless(&owned).await.is_err(), "the answer does not parse");
    assert!(flight_of(&owned).is_spent("r1"));
    assert_eq!(stored(&owned).and_then(|t| t.refresh_token), None);
    assert_eq!(
        marker(&owned),
        None,
        "the retired token's marker is settled"
    );

    token_endpoint(&mut owned, format!("{}/token", server.base));
    *owned.current_token.write() = Some(token("a1", Some("r1"), true));
    assert!(headless(&owned).await.is_err(), "a login is needed");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// The server rotated, but the new token could not be saved: the sent token
/// is spent in this process, and its in-flight marker stays on disk, so no
/// client sends it again.
#[cfg(unix)]
#[tokio::test]
async fn a_rotated_token_that_cannot_be_saved_is_not_resent() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let first = Arc::new(client(dir.path(), &server));
    let second = client(dir.path(), &server);
    hold(&first, &token("a1", Some("r1"), true));
    let flight = flight_of(&first);
    let gate = Arc::new(super::super::refresh_flight::SaveGate::default());
    *flight.save_gate.lock() = Some(Arc::clone(&gate));

    let task = tokio::spawn({
        let first = Arc::clone(&first);
        async move { headless(&first).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.reached.notified())
        .await
        .expect("the refresh reached its save");
    *flight.save_gate.lock() = None;
    if !set_mode(dir.path(), 0o500) {
        eprintln!("skipped: the storage directory stays writable (privileged runner)");
        set_mode(dir.path(), 0o700);
        gate.release.notify_one();
        return;
    }
    gate.release.notify_one();
    let first_result = task.await.unwrap();
    set_mode(dir.path(), 0o700);

    assert!(first_result.is_err(), "the rotated token was not saved");
    assert!(flight.is_spent("r1"));
    assert!(marker(&first).is_some(), "the unsettled marker stays");
    *second.current_token.write() = Some(token("a1", Some("r1"), true));
    assert!(headless(&second).await.is_err(), "a login is needed");
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// A refresh that cannot mark its token in flight sends nothing: a stop
/// mid-exchange would otherwise leave no record that the token may be spent.
#[cfg(unix)]
#[tokio::test]
async fn a_refresh_that_cannot_mark_its_token_sends_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    headless(&owned)
        .await
        .expect("a first refresh takes the lock file");
    expire(&owned);

    if !set_mode(dir.path(), 0o500) {
        eprintln!("skipped: the storage directory stays writable (privileged runner)");
        set_mode(dir.path(), 0o700);
        return;
    }
    let result = headless(&owned).await;
    set_mode(dir.path(), 0o700);

    assert!(result.is_err(), "the refresh state could not be written");
    assert_eq!(
        server.requests(),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert_eq!(
        stored(&owned).and_then(|t| t.refresh_token).as_deref(),
        Some("r2")
    );
    assert_eq!(marker(&owned), None);
}

/// A refresh-state sidecar that does not parse reads as rotating, never as
/// the non-rotating default, so an exchange that ends unsettled from here on
/// spends its token. (An in-flight marker the damage destroyed is not
/// recovered here; MIK-8091 tracks that case.)
#[test]
fn a_corrupt_refresh_state_reads_as_rotating() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    std::fs::write(storage.refresh_state_path(BACKEND, RESOURCE), "not json").unwrap();
    let state = storage.load_refresh_state(BACKEND, RESOURCE);
    assert!(state.rotates);
    assert_eq!(state.in_flight, None);
}

/// A refresh-state sidecar that exists but cannot be read reads as rotating
/// too; only an absent one is the default.
#[test]
fn an_unreadable_refresh_state_reads_as_rotating() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    assert_eq!(
        storage.load_refresh_state(BACKEND, RESOURCE),
        RefreshState::default()
    );
    std::fs::create_dir(storage.refresh_state_path(BACKEND, RESOURCE)).unwrap();
    let state = storage.load_refresh_state(BACKEND, RESOURCE);
    assert!(state.rotates);
    assert_eq!(state.in_flight, None);
}

/// A token marked in flight by an exchange that never settled is retired at
/// the next start, and nothing is sent even when storage refuses to clear
/// it: the token is spent in this process and both records are left as they
/// were. This does not tell a conditional marker clear from an unconditional
/// one (both writes share the refused directory); that needs a token-only
/// write fault, which the MIK-7324 follow-up adds.
#[cfg(unix)]
#[tokio::test]
async fn a_marked_token_that_cannot_be_cleared_is_not_sent() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    headless(&owned)
        .await
        .expect("a first refresh takes the lock file");
    expire(&owned);
    let fingerprint = super::super::refresh_flight::fingerprint_hex("r2");
    let key = owned.credential_key().unwrap();
    let state = RefreshState {
        rotates: true,
        in_flight: Some(fingerprint.clone()),
    };
    owned
        .storage
        .save_refresh_state(&key, RESOURCE, &state)
        .unwrap();

    if !set_mode(dir.path(), 0o500) {
        eprintln!("skipped: the storage directory stays writable (privileged runner)");
        set_mode(dir.path(), 0o700);
        return;
    }
    let result = headless(&owned).await;
    set_mode(dir.path(), 0o700);

    assert!(result.is_err(), "a login is needed");
    assert_eq!(
        server.requests(),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(flight_of(&owned).is_spent("r2"));
    assert_eq!(
        stored(&owned).and_then(|t| t.refresh_token).as_deref(),
        Some("r2")
    );
    assert_eq!(
        marker(&owned),
        Some(fingerprint),
        "the sidecar is as it was"
    );
}
