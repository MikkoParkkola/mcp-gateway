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
        ..RefreshState::default()
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

/// A refresh-state sidecar that does not parse reads as rotating and
/// damaged, never as the non-rotating default: the marker it may have held is
/// lost, so the stored token is retired rather than sent (MIK-8091).
#[test]
fn a_corrupt_refresh_state_reads_as_rotating() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    std::fs::write(storage.refresh_state_path(BACKEND, RESOURCE), "not json").unwrap();
    let state = storage.load_refresh_state(BACKEND, RESOURCE);
    assert!(state.rotates);
    assert!(state.damaged);
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
    assert!(state.damaged);
    assert_eq!(state.in_flight, None);
}

/// ROT3.4: a sidecar an earlier build wrote has no `keeps`. Its
/// `rotates: false` meant only "not seen to rotate", so it reads as not seen
/// either way, which may rotate; a recorded rotation still does; only a
/// settled refresh that kept its token clears it (MIK-8145).
#[test]
fn an_earlier_builds_refresh_state_reads_as_not_yet_seen() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let read = |json: &str| {
        std::fs::write(storage.refresh_state_path(BACKEND, RESOURCE), json).unwrap();
        storage.load_refresh_state(BACKEND, RESOURCE).may_rotate()
    };
    assert!(read(r#"{"rotates":false,"in_flight":null}"#));
    assert!(read(r#"{"rotates":true,"in_flight":null}"#));
    assert!(read(r#"{"rotates":true,"keeps":true}"#));
    assert!(!read(r#"{"rotates":false,"keeps":true}"#));
}

/// A token marked in flight by an exchange that never settled is retired at
/// the next start, and nothing is sent even when storage refuses to clear
/// it: the token is spent in this process and both records are left as they
/// were. This does not tell a conditional marker clear from an unconditional
/// one (both writes share the refused directory);
/// `a_marker_survives_a_clear_that_fails` does.
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
        ..RefreshState::default()
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

/// A refresh that cannot take the cross-process lock sends nothing: without
/// the lock another gateway process could send the same token at once.
#[tokio::test]
async fn a_refresh_that_cannot_take_the_cross_process_lock_sends_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    let key = owned.credential_key().unwrap();
    let lock = owned
        .storage
        .token_path(&key, RESOURCE)
        .with_extension("refresh.lock");
    std::fs::create_dir(&lock).unwrap();

    // The refresh fails and falls back to a login the headless caller
    // refuses; what matters is that nothing was sent.
    assert!(headless(&owned).await.is_err(), "the lock cannot be taken");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert_eq!(
        stored(&owned).and_then(|t| t.refresh_token).as_deref(),
        Some("r1")
    );

    std::fs::remove_dir(&lock).unwrap();
    headless(&owned).await.expect("the kept token refreshes");
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// `MIK-8091.FAILCLOSED.1`: on a server that rotates, a refresh-state sidecar
/// that cannot be read may have held an in-flight marker for the stored
/// token. The token is retired, not sent: spent, cleared from storage, and a
/// login is required.
#[tokio::test]
async fn a_damaged_refresh_state_retires_the_token_instead_of_sending_it() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    headless(&owned)
        .await
        .expect("a first refresh shows the server rotates");
    expire(&owned);
    let key = owned.credential_key().unwrap();
    std::fs::write(owned.storage.refresh_state_path(&key, RESOURCE), "not json").unwrap();

    assert!(headless(&owned).await.is_err(), "a login is needed");
    assert_eq!(
        server.uses("r2"),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(flight_of(&owned).is_spent("r2"));
    assert_eq!(stored(&owned).and_then(|t| t.refresh_token), None);
    // Retirement rewrites a clean sidecar, and a fresh login's token refreshes.
    let state = owned.storage.load_refresh_state(&key, RESOURCE);
    assert!(state.rotates && !state.damaged && state.in_flight.is_none());
    hold(&owned, &token("a9", Some("r9"), true));
    headless(&owned).await.expect("a fresh token refreshes");
    assert_eq!(
        server.uses("r9"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// `MIK-8091.FAILCLOSED.2`: an absent sidecar is no damage: the token is sent.
#[tokio::test]
async fn an_absent_refresh_state_still_sends_the_token() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    let key = owned.credential_key().unwrap();
    assert!(!owned.storage.refresh_state_path(&key, RESOURCE).exists());

    headless(&owned).await.expect("refreshed");
    assert_eq!(
        server.uses("r1"),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}

/// A sidecar that cannot even be opened (here a directory in its place) is
/// damage too: the token is retired and cleared, though the sidecar cannot
/// be rewritten, and nothing is sent.
#[tokio::test]
async fn an_unreadable_refresh_state_retires_the_token_it_cannot_rewrite() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let owned = client(dir.path(), &server);
    hold(&owned, &token("a1", Some("r1"), true));
    let key = owned.credential_key().unwrap();
    std::fs::create_dir(owned.storage.refresh_state_path(&key, RESOURCE)).unwrap();

    assert!(headless(&owned).await.is_err(), "a login is needed");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    assert!(flight_of(&owned).is_spent("r1"));
    assert_eq!(stored(&owned).and_then(|t| t.refresh_token), None);
}

/// A token whose clear fails keeps its in-flight marker: a stored record that
/// cannot be read may still hold the token, so the marker must survive for a
/// later start to retire it. The sidecar stays writable here, so a marker
/// cleared regardless of the clear would show.
#[test]
fn a_marker_survives_a_clear_that_fails() {
    use super::super::refresh_flight::{Flight, fingerprint_hex, retire_unsettled};
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let key = "flight-key";
    std::fs::write(storage.token_path(key, RESOURCE), "not a token record").unwrap();
    let state = RefreshState {
        rotates: true,
        in_flight: Some(fingerprint_hex("r1")),
        ..RefreshState::default()
    };
    storage.save_refresh_state(key, RESOURCE, &state).unwrap();
    let flight = Flight::of(&storage.token_path(key, RESOURCE));

    retire_unsettled(&flight, &storage, (key, RESOURCE), BACKEND, "r1", state);

    assert!(flight.is_spent("r1"), "spent in this process");
    assert_eq!(
        storage.load_refresh_state(key, RESOURCE).in_flight,
        Some(fingerprint_hex("r1")),
        "the marker stays until the token is known to be gone"
    );
}

/// A login repairs a damaged sidecar: the token it saves is new, so no lost
/// marker can have named it, and its first refresh sends it. Without the
/// repair every fresh token would be retired at its first refresh, and the
/// backend would ask for a login once per token lifetime.
#[tokio::test]
async fn a_login_repairs_a_damaged_refresh_state() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut owned = client(dir.path(), &server);
    if let Some(meta) = owned.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    let key = owned.credential_key().unwrap();
    std::fs::write(owned.storage.refresh_state_path(&key, RESOURCE), "not json").unwrap();

    owned.try_client_credentials().await.expect("logged in");
    let issued = stored(&owned)
        .and_then(|t| t.refresh_token)
        .expect("the login stored a refresh token");
    expire(&owned);
    headless(&owned).await.expect("the fresh token refreshes");

    assert_eq!(
        server.uses(&issued),
        1,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
    let state = owned.storage.load_refresh_state(&key, RESOURCE);
    assert!(!state.damaged, "the login rewrote the sidecar");
}

/// A login stands when the damaged sidecar cannot be rewritten (here a
/// directory in its place): the user keeps the token the login issued, and
/// its refresh still fails closed until the path is cleared.
#[tokio::test]
async fn a_login_stands_when_the_sidecar_cannot_be_repaired() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut owned = client(dir.path(), &server);
    if let Some(meta) = owned.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    let key = owned.credential_key().unwrap();
    std::fs::create_dir(owned.storage.refresh_state_path(&key, RESOURCE)).unwrap();

    let access = owned.try_client_credentials().await.expect("logged in");
    assert_eq!(stored(&owned).map(|t| t.access_token), Some(access));
    assert!(owned.storage.load_refresh_state(&key, RESOURCE).damaged);
}

/// A sidecar path holding a dangling symlink is damage, not absence: the
/// entry exists, and what it held may have been a marker for the stored token.
#[cfg(unix)]
#[test]
fn a_dangling_refresh_state_link_reads_as_damaged() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
    let path = storage.refresh_state_path(BACKEND, RESOURCE);
    std::os::unix::fs::symlink(dir.path().join("gone.json"), &path).unwrap();

    let state = storage.load_refresh_state(BACKEND, RESOURCE);
    assert!(state.rotates);
    assert!(state.damaged);
}
