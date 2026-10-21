// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 r4.4: the contention class picks the budget. Long callers wait and
//! adopt; Short callers answer busy at the short wait.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::lease_bound::{POLL, credential_paths};
use super::*;
use crate::oauth::client::refresh_flight::{
    CREDENTIAL_LOCK_WAIT, Flight, SHORT_CONTENTION_WAIT, hold_across_processes,
};
use crate::transport::Transport;

/// T14: a Long waiter queued behind a same-process flight holder adopts the
/// token the holder stored, past the short wait. RED in phase 1, where a
/// non-interactive caller gets the 2 s budget and answers busy; green when
/// only the Short class gets 2 s.
#[tokio::test(start_paused = true)]
async fn t14_a_long_waiter_behind_a_same_process_holder_adopts_its_token() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let oauth = Arc::new(client(dir.path(), &server));
        hold(&oauth, &token("a1", Some("r1"), true));
        let (_, token_path, _) = credential_paths(&oauth);
        // The in-process holder: a spawned task, as a refresh blocked on the
        // lease would hold the flight, releasing at 3 s with a fresh token.
        // Not a held token exchange: a live socket on a paused clock lets
        // auto-advance fire the client's own timeouts. The network case, a
        // held exchange on the real clock, is
        // `two_live_clients_refresh_a_rotating_token_once`.
        let flight = Flight::of(&token_path);
        let acquired = Arc::new(tokio::sync::Notify::new());
        let holder = tokio::spawn({
            let flight = Arc::clone(&flight);
            let acquired = Arc::clone(&acquired);
            let oauth = Arc::clone(&oauth);
            async move {
                let guard = flight.lock.lock().await;
                acquired.notify_one();
                tokio::time::sleep(Duration::from_secs(3)).await;
                let key = oauth
                    .credential_key()
                    .expect("a test client has a credential key");
                oauth
                    .storage
                    .save(&key, RESOURCE, &token("a2", Some("r2"), false))
                    .expect("the holder stores afresh");
                drop(guard);
            }
        });
        acquired.notified().await;

        // A Long waiter: still queued past the short wait, then it takes up
        // what the holder stored.
        let start = Instant::now();
        let outcome = headless(&oauth).await;
        let elapsed = start.elapsed();
        holder.await.expect("the holder joins");

        assert_eq!(
            outcome.expect("a long waiter adopts the holder's token"),
            "a2"
        );
        assert!(
            (Duration::from_secs(3)..Duration::from_secs(3) + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "adopted off the release: {elapsed:?}"
        );
        assert_eq!(server.requests(), 0, "an adoption sends nothing");
    })
    .await
    .expect("a bounded wait answers inside twice the bound");
}

/// T14b: a Long waiter behind a cross-process lease adopts the token the
/// holder stored at its 3 s release. It pins the reversal of the r4.2 lease
/// regression for background Long callers (listener, task recovery). RED in
/// phase 1.
#[tokio::test(start_paused = true)]
async fn t14b_a_long_waiter_behind_a_cross_process_lease_adopts_its_token() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let client = Arc::new(client(dir.path(), &server));
        hold(&client, &token("a1", Some("r1"), true));
        let (_, token_path, lock_path) = credential_paths(&client);
        let holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");

        // The waiter reports its own elapsed: a Long waiter is still queued
        // past the short wait, then adopts what the release stored.
        let waiter = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                let start = Instant::now();
                let outcome = headless(&client).await;
                (outcome, start.elapsed())
            }
        });
        // The waiter's first poll failed: it is on the lock, and has sent nothing.
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.requests(), 0, "sent while another process held it");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let key = client
            .credential_key()
            .expect("a test client has a credential key");
        client
            .storage
            .save(&key, RESOURCE, &token("a2", Some("r2"), false))
            .expect("the holder stores afresh");
        drop(holder);

        let (outcome, elapsed) = waiter.await.expect("the waiter joins");
        assert_eq!(
            outcome.expect("a long waiter adopts across the lease"),
            "a2"
        );
        assert!(
            (Duration::from_secs(3)..Duration::from_secs(3) + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "adopted off the release: {elapsed:?}"
        );
        assert_eq!(server.requests(), 0, "an adoption sends nothing");
    })
    .await
    .expect("a 3 s wait ends inside twice the bound");
}

/// T15: a Short close behind a held lease still sends its session DELETE: a
/// busy header build falls back to a session-only DELETE inside the close
/// stage (bounded at 10 s by `close_stage`). Green in both phases; it pins
/// the Short class for close (mutant mC2, always Long, makes it time out).
#[tokio::test]
async fn t15_a_short_close_behind_a_held_lease_still_sends_its_session_delete() {
    tokio::time::timeout(Duration::from_secs(20), async {
        use axum::{
            Router,
            extract::State,
            http::{HeaderMap, StatusCode},
            routing::delete,
        };

        async fn capture_delete(
            State(seen): State<Arc<std::sync::Mutex<Vec<HeaderMap>>>>,
            headers: HeaderMap,
        ) -> StatusCode {
            seen.lock().expect("the capture lock").push(headers);
            StatusCode::NO_CONTENT
        }

        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let oauth = client(dir.path(), &server);
        hold(&oauth, &token("a1", Some("r1"), true));
        let (_, token_path, _) = credential_paths(&oauth);
        // The cross-process lease, held throughout the close.
        let _lease = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");

        let seen: Arc<std::sync::Mutex<Vec<HeaderMap>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a capture listener");
        let addr = listener.local_addr().expect("the capture address");
        let app = Router::new()
            .route("/messages", delete(capture_delete))
            .with_state(Arc::clone(&seen));
        let capture = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let transport = crate::transport::HttpTransport::new_with_oauth(
            &format!("http://{addr}/mcp"),
            std::collections::HashMap::new(),
            Duration::from_secs(30),
            true,
            Some(oauth),
            None,
        )
        .expect("a transport");
        transport.seed_session_for_test(format!("http://{addr}/messages"), "close-session");

        let start = Instant::now();
        transport.close().await.expect("close answers Ok");
        let elapsed = start.elapsed();
        capture.abort();

        assert!(
            (SHORT_CONTENTION_WAIT..SHORT_CONTENTION_WAIT + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "answered off the short wait: {elapsed:?}"
        );
        let seen = seen.lock().expect("the capture lock");
        assert_eq!(seen.len(), 1, "one session DELETE");
        assert_eq!(seen[0]["mcp-session-id"], "close-session");
        assert!(
            !seen[0].contains_key("authorization"),
            "a busy close sends no bearer"
        );
        assert_eq!(server.requests(), 0, "no exchange crossed the lease");
    })
    .await
    .expect("a short close ends inside its bound");
}
