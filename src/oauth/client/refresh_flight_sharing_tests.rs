// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8018: a credential shared beyond one client of this process: through a
//! client the caller supplies, and with another gateway process that keeps
//! its tokens in the same storage directory.

use std::sync::Arc;
use std::time::Duration;

use super::*;

/// A client supplied to `OAuthClient::new` carries the refresh, standing in
/// for one built with the caller's own roots, proxy or identity. `Private`
/// keeps this loopback endpoint off the unproxied loopback route `Configured`
/// would take.
#[tokio::test]
async fn a_supplied_client_carries_its_refreshes() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut supplied = supplied_client(dir.path(), &server);
    supplied.destination = DestinationPolicy::Private;
    hold(&supplied, &token("a1", Some("r1"), true));

    headless(&supplied).await.expect("refreshed");
    assert_eq!(*server.agents.lock().unwrap(), [SUPPLIED_AGENT]);
}

/// A token file that exists but cannot be read may still hold the spent
/// token: spending does not count it retired, so the in-flight marker stays.
#[tokio::test]
async fn an_unreadable_token_file_is_not_counted_retired() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &server);
    let key = client.credential_key().unwrap();
    let path = client.storage.token_path(&key, RESOURCE);
    std::fs::create_dir_all(&path).unwrap();
    let flight = super::super::refresh_flight::Flight::of(&path);

    let retired = super::super::refresh_flight::spend(
        &flight,
        &client.storage,
        (&key, RESOURCE),
        BACKEND,
        "r1",
    );
    assert!(!retired, "an unreadable record was counted retired");
}

/// Another gateway process sharing the storage directory holds the
/// credential's refresh lock (the test holds it as that process would). A
/// refresh here sends nothing until it is released, then takes up the token
/// that process stored instead of sending the refresh token it consumed.
#[tokio::test]
async fn a_refresh_waits_for_another_process_holding_the_credential() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let client = Arc::new(client(dir.path(), &server));
    hold(&client, &token("a1", Some("r1"), true));
    let key = client.credential_key().unwrap();
    let path = client.storage.token_path(&key, RESOURCE);
    let other = super::super::refresh_flight::hold_across_processes(&path)
        .await
        .unwrap();

    let refresh = tokio::spawn({
        let client = Arc::clone(&client);
        async move { headless(&client).await }
    });
    server.arrivals(1, Duration::from_secs(1)).await;
    assert_eq!(server.requests(), 0, "sent while another process held it");
    let rotated = token("a2", Some("r2"), false);
    client.storage.save(&key, RESOURCE, &rotated).unwrap();
    drop(other);

    let access = refresh
        .await
        .unwrap()
        .expect("the stored token is taken up");
    assert_eq!(access, "a2");
    assert_eq!(
        server.requests(),
        0,
        "sent: {:?}",
        server.sent.lock().unwrap()
    );
}
