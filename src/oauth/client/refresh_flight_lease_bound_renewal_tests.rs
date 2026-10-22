// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T3, T6 and T7, the background renewal
//! loop with the lease held. Each drives the real loop across its periods.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;

use super::lease_bound::{POLL, is_deferred};
use super::*;
use crate::oauth::OAuthClient;
use crate::oauth::client::refresh_flight::{
    CREDENTIAL_LOCK_WAIT, Flight, SaveGate, hold_across_processes,
};

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
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let client = client(dir.path(), &server);
    hold(&client, &token("a1", Some("r1"), true));
    let token_path = client.storage.token_path(
        &client
            .credential_key()
            .expect("a test client has a credential key"),
        RESOURCE,
    );
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
        .await
        .expect("the other process holds the lease");
    let guarded = Arc::new(tokio::sync::Mutex::new(client));
    let looping = tokio::spawn({
        let guarded = Arc::clone(&guarded);
        async move {
            OAuthClient::refresh_loop(guarded, BACKEND.to_string(), Duration::from_secs(1)).await;
        }
    });

    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, attempt_span(&guarded))
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
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
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

    let span = tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, attempt_span(&guarded))
        .await
        .expect("the attempt returns inside twice the bound");
    looping.abort();
    drop(log_guard);

    assert!(
        ((CREDENTIAL_LOCK_WAIT.saturating_sub(TICK))
            ..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
            .contains(&span),
        "one bound, not two: {span:?}"
    );
    assert!(
        span < CREDENTIAL_LOCK_WAIT * 2,
        "a second bound ran inside the period"
    );
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
/// one bounded attempt. The full two-period window runs out; a hold still open
/// at the deadline counts as an attempt too, so an unbounded wait cannot hide
/// from the count. Then exactly two holds, the first at least one period in
/// and every gap at least one period plus one bound (a period sleep plus a
/// bound hold), so an extra in-period attempt can no longer pass as two; one
/// debug line each. The outer timeout covers setup and the window.
#[tokio::test(start_paused = true)]
async fn t7_two_periods_are_two_bounded_attempts() {
    let period = OAuthClient::RENEWAL_CHECK_PERIOD;
    // Strictly past two full periods, so a correct run is never cut off.
    let outer = (period + CREDENTIAL_LOCK_WAIT) * 2 + Duration::from_secs(10);
    tokio::time::timeout(outer, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let client = client(dir.path(), &server);
        hold(&client, &token("a1", Some("r1"), true));
        let token_path = client.storage.token_path(
            &client
                .credential_key()
                .expect("a test client has a credential key"),
            RESOURCE,
        );
        let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");
        let guarded = Arc::new(tokio::sync::Mutex::new(client));
        let (log_guard, log_buffer) = crate::oauth::callback::tests::capture();
        let t0 = Instant::now();
        let looping = tokio::spawn({
            let guarded = Arc::clone(&guarded);
            async move {
                OAuthClient::refresh_loop(guarded, BACKEND.to_string(), period).await;
            }
        });

        // The whole window runs out; holds are the mutex held at least one
        // bound less a tick (the loop's brief freshness check is not an
        // attempt), plus any hold still open at the deadline, kept without
        // the duration filter so a short in-period retry cannot hide either.
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
        let open_start = held_at.take();
        if let Some(held) = open_start {
            spans.push((held, held.elapsed()));
        }
        let attempts: Vec<_> = spans
            .into_iter()
            .filter(|(at, span)| {
                Some(*at) == open_start || *span >= CREDENTIAL_LOCK_WAIT.saturating_sub(TICK)
            })
            .collect();
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
            attempts[1].0.duration_since(attempts[0].0) >= period + CREDENTIAL_LOCK_WAIT,
            "the attempts share a period: {:?} apart",
            attempts[1].0.duration_since(attempts[0].0)
        );
        for (_, span) in &attempts {
            assert!(
                ((CREDENTIAL_LOCK_WAIT.saturating_sub(TICK))
                    ..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
                    .contains(span),
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
    })
    .await
    .expect("two periods complete");
}

/// Renewal without a refresh token takes the `client_credentials`-only arm;
/// with the save lease held its save meets the bound, the attempt defers,
/// and neither the cache nor storage changes (the save fails first). The
/// exchange runs with real time and the clock pauses only after its answer
/// was read (the save's gate), so no socket runs under the paused clock. The
/// outer timeout covers setup and the attempt.
#[tokio::test(start_paused = true)]
async fn t6b_renewal_without_a_refresh_token_defers_leaving_cache_and_storage() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let mut made = client(dir.path(), &server);
        if let Some(meta) = made.auth_metadata.as_mut() {
            meta.grant_types_supported = vec!["client_credentials".to_string()];
        }
        hold(&made, &token("a1", None, true));
        let client = Arc::new(made);
        let cached_before = client.current_token.read().clone().expect("a cached token");
        let stored_before = stored(client.as_ref()).expect("a stored token");
        let token_path = client.storage.token_path(
            &client
                .credential_key()
                .expect("a test client has a credential key"),
            RESOURCE,
        );
        let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");
        // Pause only at the issued-save gate: it is reached after the grant's
        // answer was read and before the save's budget starts, so no socket
        // exchange runs under the paused clock (MIK-8653). Waiting on
        // `arrivals` instead paused with the reply still in flight; the
        // server's yields keep that mistake failing every time.
        server.yields_before_reply.store(3, Ordering::SeqCst);
        let flight = Flight::of(&token_path);
        let gate = Arc::new(SaveGate::default());
        *flight.issued_gate.lock() = Some(Arc::clone(&gate));

        // The exchange with real time.
        tokio::time::resume();
        let attempting = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.attempt_background_renewal().await }
        });
        tokio::time::timeout(Duration::from_secs(5), gate.reached.notified())
            .await
            .expect("the save is reached after the exchange");
        assert_eq!(
            server.requests(),
            1,
            "the client_credentials exchange did not run"
        );
        tokio::time::pause();

        // The save now meets the held lease under the paused clock.
        let start = Instant::now();
        gate.release.notify_one();
        let renewal = attempting.await.expect("the attempt joins");
        let elapsed = start.elapsed();
        *flight.issued_gate.lock() = None;

        assert!(is_deferred(&renewal), "not deferred: {renewal:?}");
        assert!(
            (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "answered off the bound: {elapsed:?}"
        );
        let cached_after = client
            .current_token
            .read()
            .clone()
            .expect("the cache keeps its token");
        assert_eq!(cached_after.access_token, cached_before.access_token);
        assert_eq!(cached_after.refresh_token, cached_before.refresh_token);
        assert_eq!(cached_after.expires_at, cached_before.expires_at);
        let stored_after = stored(client.as_ref()).expect("storage keeps its token");
        assert_eq!(stored_after.access_token, stored_before.access_token);
        assert_eq!(stored_after.refresh_token, stored_before.refresh_token);
        assert_eq!(stored_after.expires_at, stored_before.expires_at);
    })
    .await
    .expect("a bounded attempt answers inside twice the bound");
}
