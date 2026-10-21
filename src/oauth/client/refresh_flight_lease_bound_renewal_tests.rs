// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T3, T6 and T7, the background renewal
//! loop with the lease held. Each drives the real loop across its periods.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::lease_bound::{BOUND, POLL};
use super::*;
use crate::oauth::OAuthClient;
use crate::oauth::client::refresh_flight::hold_across_processes;

/// Wait until the loop holds the client (an attempt started), then until it
/// lets go (the attempt ended): the span the attempt held the mutex.
async fn attempt_span(client: &Arc<tokio::sync::Mutex<OAuthClient>>) -> Duration {
    while client.try_lock().is_ok() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let start = Instant::now();
    while client.try_lock().is_err() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    start.elapsed()
}

/// T3: with the lease held, the renewal loop's attempt still returns: the
/// client mutex is free afterwards and the loop keeps running.
#[tokio::test(start_paused = true)]
async fn t3_renewal_loop_lets_go_of_the_client() {
    let _server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let client = client(dir.path(), &_server);
    hold(&client, &token("a1", Some("r1"), true));
    let token_path = client.storage.token_path(
        &client
            .credential_key()
            .expect("a test client has a credential key"),
        RESOURCE,
    );
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let guarded = Arc::new(tokio::sync::Mutex::new(client));
    let looping = tokio::spawn({
        let guarded = Arc::clone(&guarded);
        async move {
            OAuthClient::refresh_loop(guarded, BACKEND.to_string(), Duration::from_secs(1)).await;
        }
    });

    tokio::time::timeout(BOUND * 2, attempt_span(&guarded))
        .await
        .expect("the attempt returns inside twice the bound");
    assert!(guarded.try_lock().is_ok(), "the client stayed locked");
    assert!(!looping.is_finished(), "the loop ended after one attempt");
    looping.abort();
}

/// T6: with the lease held, one renewal period is one bound, not two, and the
/// refresh never falls through to `client_credentials`. The outcome reads
/// through the loop: no request (not renewed), no policy (not refused), no
/// grant attempt and no re-authorization warning (not exhausted).
#[tokio::test(start_paused = true)]
async fn t6_renewal_defers_after_one_bound_without_client_credentials() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let mut client = client(dir.path(), &server);
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    hold(&client, &token("a1", Some("r1"), true));
    let token_path = client.storage.token_path(
        &client
            .credential_key()
            .expect("a test client has a credential key"),
        RESOURCE,
    );
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let guarded = Arc::new(tokio::sync::Mutex::new(client));
    let (log_guard, log_buffer) = crate::oauth::callback::tests::capture();
    let looping = tokio::spawn({
        let guarded = Arc::clone(&guarded);
        async move {
            OAuthClient::refresh_loop(guarded, BACKEND.to_string(), Duration::from_secs(1)).await;
        }
    });

    let span = tokio::time::timeout(BOUND * 2, attempt_span(&guarded))
        .await
        .expect("the attempt returns inside twice the bound");
    looping.abort();
    drop(log_guard);

    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&span),
        "one bound, not two: {span:?}"
    );
    assert!(span < BOUND * 2, "a second bound ran inside the period");
    assert_eq!(
        server.requests(),
        0,
        "`client_credentials` ran after the busy refresh"
    );
    let held = log_buffer.lock().expect("the log buffer reads");
    let log = String::from_utf8_lossy(&held);
    assert!(
        !log.contains("manual re-authorization required"),
        "warned as exhausted: {log}"
    );
}

/// T7: with the lease held across two renewal periods, each period is exactly
/// one bounded attempt: the attempt count equals the period count, one debug
/// line each, never a warning.
#[tokio::test(start_paused = true)]
async fn t7_two_periods_are_two_bounded_attempts() {
    let _server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let client = client(dir.path(), &_server);
    hold(&client, &token("a1", Some("r1"), true));
    let token_path = client.storage.token_path(
        &client
            .credential_key()
            .expect("a test client has a credential key"),
        RESOURCE,
    );
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let guarded = Arc::new(tokio::sync::Mutex::new(client));
    let (log_guard, log_buffer) = crate::oauth::callback::tests::capture();
    let looping = tokio::spawn({
        let guarded = Arc::clone(&guarded);
        async move {
            OAuthClient::refresh_loop(
                guarded,
                BACKEND.to_string(),
                OAuthClient::RENEWAL_CHECK_PERIOD,
            )
            .await;
        }
    });

    // Strictly past two full periods, so a correct run is never cut off.
    let outer = (OAuthClient::RENEWAL_CHECK_PERIOD + BOUND) * 2 + Duration::from_secs(10);
    let spans = tokio::time::timeout(outer, async {
        let mut spans = Vec::new();
        while spans.len() < 2 {
            spans.push(attempt_span(&guarded).await);
        }
        spans
    })
    .await
    .expect("two periods complete");
    looping.abort();
    drop(log_guard);

    assert_eq!(spans.len(), 2, "the attempt count equals the period count");
    for span in &spans {
        assert!(
            (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(span),
            "a period held more than one bound: {span:?}"
        );
    }
    let held = log_buffer.lock().expect("the log buffer reads");
    let log = String::from_utf8_lossy(&held);
    let debugs = log
        .lines()
        .filter(|line| line.contains("DEBUG") && line.contains(BACKEND))
        .count();
    assert_eq!(debugs, 2, "one debug line per period: {log}");
    assert!(
        !log.contains("WARN"),
        "a warning fired on a busy lock: {log}"
    );
}
