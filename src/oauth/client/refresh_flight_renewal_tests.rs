// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 wave 1: every outcome of a background renewal, and what the
//! refresh task does with each one that is not a refusal.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::oauth::client::renewal::Renewal;

/// `client` whose token endpoint answers every grant with an OAuth refusal
/// that is not the destination policy's.
fn refusing(dir: &std::path::Path, server: &TokenServer) -> OAuthClient {
    let mut client = client(dir, server);
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.token_endpoint = format!("{}/refused", server.base);
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    client
}

#[tokio::test]
async fn a_refresh_that_succeeds_is_a_renewal() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), &server);
    hold(&client, &token("a1", Some("r1"), true));
    assert_eq!(client.attempt_background_renewal().await, Renewal::Renewed);
    assert_eq!(
        *server.sent.lock().unwrap(),
        ["r1"],
        "the stored refresh token was sent"
    );
}

/// No refresh token, so the headless `client_credentials` grant is the one
/// tried, and it renews.
#[tokio::test]
async fn a_client_credentials_grant_that_succeeds_is_a_renewal() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut client = client(dir.path(), &server);
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    hold(&client, &token("a1", None, true));
    assert_eq!(client.attempt_background_renewal().await, Renewal::Renewed);
    assert_eq!(server.requests(), 1);
}

/// A refresh the server refuses (not the destination policy) falls through
/// to `client_credentials`; when that is refused too, the person must
/// authorize again.
#[tokio::test]
async fn refused_grants_that_are_not_the_policy_exhaust_the_renewal() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let client = refusing(dir.path(), &server);
    hold(&client, &token("a1", Some("r1"), true));
    assert_eq!(
        client.attempt_background_renewal().await,
        Renewal::Exhausted
    );
}

/// How long the refresh task may take to reach what a test waits for. A
/// bound on a hung task, never a window the outcome is timed against: under
/// full-suite load a real HTTP round trip can take seconds (MIK-8235).
const REACHED: Duration = Duration::from_secs(10);

/// Run `client`'s refresh loop until `reached` holds, polling. Fails if the
/// loop returns first (the task must keep running) or `REACHED` passes.
async fn run_until(client: OAuthClient, what: &str, reached: impl Fn() -> bool) {
    let watch = async {
        while !reached() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        () = OAuthClient::refresh_loop(
            Arc::new(tokio::sync::Mutex::new(client)),
            BACKEND.to_string(),
            Duration::from_millis(10),
        ) => panic!("the refresh task ended before {what}"),
        waited = tokio::time::timeout(REACHED, watch) => {
            waited.unwrap_or_else(|_| panic!("the refresh task never reached {what}"));
        }
    }
}

/// The refresh task keeps running after a renewal, and after an exhausted
/// one it logs that the person must authorize again and keeps running.
///
/// Each half waits for the event it names, not for a fixed window: the old
/// 200 ms window read the log before a loaded runner wrote it (MIK-8235).
#[tokio::test]
async fn the_refresh_task_keeps_running_after_a_renewal_or_an_exhausted_one() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let mut renewing = client(dir.path(), &server);
    renewing.token_refresh_buffer_secs = 300;
    hold(&renewing, &token("a1", Some("r1"), true));
    // Renewed, then three more polls (30 ms or more) for the 10 ms loop to
    // ask again if the fresh token were not taken. Load only gives it fewer
    // turns: a weaker check, never a false failure.
    let polls_after = std::sync::atomic::AtomicUsize::new(0);
    run_until(renewing, "a renewal and three more polls", || {
        server.requests() >= 1 && polls_after.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 3
    })
    .await;
    assert_eq!(
        server.requests(),
        1,
        "renewed once, then the fresh token needs none"
    );

    let other = tempfile::tempdir().unwrap();
    let mut exhausted = refusing(other.path(), &server);
    exhausted.token_refresh_buffer_secs = 300;
    hold(&exhausted, &token("a1", Some("r1"), true));
    let (guard, buffer) = crate::oauth::callback::tests::capture();
    run_until(exhausted, "the re-authorization warning", || {
        String::from_utf8_lossy(&buffer.lock().unwrap())
            .contains("manual re-authorization required")
    })
    .await;
    drop(guard);
}
