// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T3, T6 and T7, the background renewal
//! loop with the lease held. Each drives the real loop across its periods.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::lease_bound::{BOUND, POLL, is_deferred};
use super::*;
use crate::oauth::OAuthClient;
use crate::oauth::client::refresh_flight::hold_across_processes;

/// One observation tick (10 ms): the granularity `attempt_span` and the T7
/// hold poll see mutex holds at, so spans read up to one tick short.
const TICK: Duration = Duration::from_millis(10);

/// Wait until the loop holds the client (an attempt started), then until it
/// lets go (the attempt ended): the span the attempt held the mutex.
async fn attempt_span(client: &Arc<tokio::sync::Mutex<OAuthClient>>) -> Duration {
    while client.try_lock().is_ok() {
        tokio::time::sleep(TICK).await;
    }
    let start = Instant::now();
    while client.try_lock().is_err() {
        tokio::time::sleep(TICK).await;
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
        ((BOUND - TICK)..BOUND + POLL + Duration::from_secs(1)).contains(&span),
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
/// one bounded attempt. The full two-period window runs out (an in-period
/// retry would show as a third hold); then exactly two holds, the first at
/// least one period in and the gap at least one period, one debug line each.
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
    let period = OAuthClient::RENEWAL_CHECK_PERIOD;
    let t0 = Instant::now();
    let looping = tokio::spawn({
        let guarded = Arc::clone(&guarded);
        async move {
            OAuthClient::refresh_loop(guarded, BACKEND.to_string(), period).await;
        }
    });

    // Strictly past two full periods, so a correct run is never cut off. The
    // whole window runs out; holds are the mutex held at least one bound less
    // a tick (the loop's brief freshness check is not an attempt).
    let outer = (period + BOUND) * 2 + Duration::from_secs(10);
    let attempts = tokio::time::timeout(outer, async {
        let mut spans = Vec::new();
        let mut held_at: Option<Instant> = None;
        let end = t0 + outer;
        while Instant::now() < end {
            if guarded.try_lock().is_ok() {
                if let Some(held) = held_at.take() {
                    spans.push((held, held.elapsed()));
                }
            } else if held_at.is_none() {
                held_at = Some(Instant::now());
            }
            tokio::time::sleep(TICK).await;
        }
        if let Some(held) = held_at.take() {
            spans.push((held, held.elapsed()));
        }
        spans
            .into_iter()
            .filter(|(_, span)| *span >= BOUND - TICK)
            .collect::<Vec<_>>()
    })
    .await
    .expect("two periods complete");
    looping.abort();
    drop(log_guard);

    assert_eq!(
        attempts.len(),
        2,
        "the attempt count equals the period count"
    );
    assert!(
        attempts[0].0.duration_since(t0) >= period,
        "the first attempt ran before its period: {:?} in",
        attempts[0].0.duration_since(t0)
    );
    assert!(
        attempts[1].0.duration_since(attempts[0].0) >= period,
        "the attempts share a period: {:?} apart",
        attempts[1].0.duration_since(attempts[0].0)
    );
    for (_, span) in &attempts {
        assert!(
            ((BOUND - TICK)..BOUND + POLL + Duration::from_secs(1)).contains(span),
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

/// Renewal without a refresh token takes the `client_credentials`-only arm;
/// with the save lease held its save meets the bound, the attempt defers,
/// and neither the cache nor storage changes (the save fails first).
#[tokio::test(start_paused = true)]
async fn t6b_renewal_without_a_refresh_token_defers_leaving_cache_and_storage() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let mut client = client(dir.path(), &server);
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    hold(&client, &token("a1", None, true));
    let cached_before = client.current_token.read().clone().expect("a cached token");
    let stored_before = stored(&client).expect("a stored token");
    let token_path = client.storage.token_path(
        &client
            .credential_key()
            .expect("a test client has a credential key"),
        RESOURCE,
    );
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let outcome = tokio::time::timeout(BOUND * 2, client.attempt_background_renewal()).await;
    let elapsed = start.elapsed();
    let renewal = outcome.expect("a bounded attempt answers inside twice the bound");

    assert!(is_deferred(&renewal), "not deferred: {renewal:?}");
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert_eq!(
        server.requests(),
        1,
        "the client_credentials exchange did not run"
    );
    let cached_after = client
        .current_token
        .read()
        .clone()
        .expect("the cache keeps its token");
    assert_eq!(cached_after.access_token, cached_before.access_token);
    assert_eq!(cached_after.refresh_token, cached_before.refresh_token);
    assert_eq!(cached_after.expires_at, cached_before.expires_at);
    let stored_after = stored(&client).expect("storage keeps its token");
    assert_eq!(stored_after.access_token, stored_before.access_token);
    assert_eq!(stored_after.refresh_token, stored_before.refresh_token);
    assert_eq!(stored_after.expires_at, stored_before.expires_at);
}
