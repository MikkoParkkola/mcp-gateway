// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T13h to T13j, the in-process flight lock
//! behind the same contention budget as the lease.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use super::lease_bound::{POLL, credential_paths};
use super::*;
use crate::Error;
use crate::oauth::client::refresh_flight::{
    CREDENTIAL_LOCK_WAIT, Flight, SHORT_CONTENTION_WAIT, is_credential_lock_busy,
};

/// A transport whose request runs the real token step before answering
/// health, as the HTTP transport does before its POST.
struct TokenStepTransport {
    client: Arc<crate::oauth::OAuthClient>,
}

#[async_trait]
impl crate::transport::Transport for TokenStepTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let _token = self.client.get_token().await?;
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            serde_json::json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// T13h: an interactive refresh queued behind the in-process flight lock keeps
/// the long wait: still pending past the short wait, then the marked busy
/// error inside the 90 s window. The holder is a spawned task, so the waiter
/// queues rather than deadlocks on its own hold. RED now: `refresh_stored`
/// waits the flight lock unbounded, so the outer timeout fires.
#[tokio::test(start_paused = true)]
async fn t13h_interactive_waiter_behind_the_flight_lock_keeps_the_long_wait() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let oauth = Arc::new(client(dir.path(), &server));
        hold(&oauth, &token("a1", Some("r1"), true));
        let (_, token_path, _) = credential_paths(&oauth);
        // The in-process holder: a spawned task, as a refresh blocked on the
        // lease would hold the flight, past the outer timeout.
        let flight = Flight::of(&token_path);
        let acquired = Arc::new(tokio::sync::Notify::new());
        let holder = tokio::spawn({
            let flight = Arc::clone(&flight);
            let acquired = Arc::clone(&acquired);
            async move {
                let _guard = flight.lock.lock().await;
                acquired.notify_one();
                tokio::time::sleep(CREDENTIAL_LOCK_WAIT * 2 + Duration::from_secs(10)).await;
            }
        });
        acquired.notified().await;

        // An interactive refresh: no non-interactive scope, so the long budget.
        let start = Instant::now();
        let waiter = tokio::spawn({
            let oauth = Arc::clone(&oauth);
            async move { oauth.get_token().await }
        });
        // Past the short wait the long waiter is still queued.
        tokio::time::sleep(SHORT_CONTENTION_WAIT + POLL).await;
        assert!(
            !waiter.is_finished(),
            "an interactive waiter answered inside the short wait"
        );
        assert_eq!(server.requests(), 0, "sent while the flight was held");

        let outcome = waiter.await.expect("the waiter joins");
        let elapsed = start.elapsed();
        holder.abort();
        let error = outcome.expect_err("no token crosses a held flight");
        assert!(
            is_credential_lock_busy(&error),
            "not the marked error: {error}"
        );
        assert!(
            matches!(error, Error::BackendUnavailable(_)),
            "not unwrapped: {error:?}"
        );
        assert!(error.is_pre_dispatch(), "a busy lock frees the key");
        assert!(
            (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "answered off the long wait: {elapsed:?}"
        );
        assert_eq!(server.requests(), 0, "sent while the flight was held");
    })
    .await
    .expect("a bounded wait answers inside twice the bound");
}

/// T13i: a Long `save_issued` queued behind the in-process flight lock is
/// still pending past the short wait, then saves once the holder releases,
/// inside the long budget. RED in phase 1, where a non-interactive save
/// answers busy at 2 s.
#[tokio::test(start_paused = true)]
async fn t13i_a_long_save_behind_the_flight_lock_waits_and_saves() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let oauth = Arc::new(client(dir.path(), &server));
        let (_, token_path, _) = credential_paths(&oauth);
        // The in-process holder: a spawned task, so the waiter queues behind
        // another task's hold rather than its own.
        let flight = Flight::of(&token_path);
        let acquired = Arc::new(tokio::sync::Notify::new());
        let holder = tokio::spawn({
            let flight = Arc::clone(&flight);
            let acquired = Arc::clone(&acquired);
            async move {
                let _guard = flight.lock.lock().await;
                acquired.notify_one();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        acquired.notified().await;

        let issued = token("issued", None, false);
        let waiter = tokio::spawn({
            let oauth = Arc::clone(&oauth);
            let issued = issued.clone();
            async move {
                let start = Instant::now();
                let outcome =
                    crate::oauth::login_gate::non_interactive(oauth.save_issued_for_test(&issued))
                        .await;
                (outcome, start.elapsed())
            }
        });
        // Past the short wait the Long save is still queued.
        tokio::time::sleep(SHORT_CONTENTION_WAIT + POLL).await;
        assert!(
            !waiter.is_finished(),
            "a long save answered inside the short wait"
        );

        let (outcome, elapsed) = waiter.await.expect("the waiter joins");
        holder.await.expect("the holder joins");
        outcome.expect("the long save saves after the release");
        assert!(
            (Duration::from_secs(5)..Duration::from_secs(5) + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "saved off the release: {elapsed:?}"
        );
        assert_eq!(
            stored(&oauth).expect("saved").access_token,
            issued.access_token
        );
        assert_eq!(server.requests(), 0, "the save sent");
    })
    .await
    .expect("a bounded save answers inside twice the bound");
}

/// T13j: one budget covers the flight lock and the lease: a non-interactive
/// probe that queued 1.5 s on the flight and meets a held lease answers busy
/// at about 2 s total, not 1.5 s plus a fresh 2 s. RED now: the lease wait
/// starts after the flight, so the answer lands at about 3.5 s.
#[tokio::test(start_paused = true)]
async fn t13j_one_budget_covers_the_flight_lock_and_the_lease() {
    tokio::time::timeout(
        Duration::from_secs(5) * 2,
        Box::pin(async {
            let server = TokenServer::start(&[]).await;
            let dir = tempfile::tempdir().expect("a scratch token store");
            let oauth = Arc::new(client(dir.path(), &server));
            hold(&oauth, &token("a1", Some("r1"), true));
            let (_, token_path, _) = credential_paths(&oauth);
            // The cross-process lease, held throughout the probe.
            let _lease = crate::oauth::client::refresh_flight::hold_across_processes(
                &token_path,
                Instant::now() + CREDENTIAL_LOCK_WAIT,
            )
            .await
            .expect("the other process holds the lease");
            // The in-process flight, held for 1.5 s, then released.
            let flight = Flight::of(&token_path);
            let acquired = Arc::new(tokio::sync::Notify::new());
            let holder = tokio::spawn({
                let flight = Arc::clone(&flight);
                let acquired = Arc::clone(&acquired);
                async move {
                    let _guard = flight.lock.lock().await;
                    acquired.notify_one();
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
            });
            acquired.notified().await;

            let backend = crate::backend::Backend::new(
                "t13j-probe",
                crate::config::BackendConfig::default(),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            backend.set_transport_for_test(Arc::new(TokenStepTransport {
                client: Arc::clone(&oauth),
            }) as Arc<dyn crate::transport::Transport>);
            let before = backend.circuit_breaker_stats().current_failures;

            let start = Instant::now();
            let outcome = backend.health_probe(Duration::from_secs(5)).await;
            let elapsed = start.elapsed();
            holder.abort();

            let error = outcome.expect_err("a busy lock is not health");
            assert!(
                is_credential_lock_busy(&error),
                "not the marked error: {error}"
            );
            assert!(
                matches!(error, Error::BackendUnavailable(_)),
                "not unwrapped: {error:?}"
            );
            assert!(
                (SHORT_CONTENTION_WAIT..SHORT_CONTENTION_WAIT + POLL + Duration::from_secs(1))
                    .contains(&elapsed),
                "answered off the single budget (about 3.5 s is two budgets): {elapsed:?}"
            );
            assert_eq!(
                backend.rebuilds_attempted.load(Ordering::SeqCst),
                0,
                "the probe rebuilt over a busy lock"
            );
            assert_eq!(
                backend.circuit_breaker_stats().current_failures,
                before,
                "a busy lock sampled as a backend failure"
            );
            assert!(
                !backend.is_circuit_tripped(),
                "the probe tripped the breaker on a busy lock"
            );
            assert_eq!(server.requests(), 0, "sent while the locks were held");
        }),
    )
    .await
    .expect("a probe answers inside twice its timeout");
}
