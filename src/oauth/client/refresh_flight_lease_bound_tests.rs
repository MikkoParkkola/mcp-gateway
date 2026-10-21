// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): the stored-credential lease wait is bounded.
//! Rows T1, T2, T4, T5, T5b and T8: the flight, the saves and the login paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::Error;
use crate::oauth::OAuthClient;
use crate::oauth::client::OAUTH_AUTHORIZATION_WINDOW;
use crate::oauth::client::refresh_flight::{
    CREDENTIAL_LOCK_WAIT, Flight, SHORT_CONTENTION_WAIT, hold_across_processes,
    is_credential_lock_busy,
};
use crate::oauth::client::renewal::Renewal;
use crate::oauth::client::{StoredCredential, refresh_stored};
use crate::oauth::login_gate::LoginGate;

// Shared with the sibling rows. `POLL` mirrors the private `LOCK_POLL`.
// Invariant: every row's outer timeout is twice its bound, so a regression is
// red, never hung.

/// One lock poll (50 ms), mirroring the private `LOCK_POLL`, which phase 2 keeps.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// Whether a renewal deferred on a busy lock.
pub(super) fn is_deferred(renewal: &Renewal) -> bool {
    matches!(renewal, Renewal::Deferred)
}

/// The credential's key and its token and lock paths for `client`.
pub(super) fn credential_paths(
    client: &OAuthClient,
) -> (String, std::path::PathBuf, std::path::PathBuf) {
    let key = client
        .credential_key()
        .expect("a test client has a credential key");
    let token_path = client.storage.token_path(&key, RESOURCE);
    let lock_path = token_path.with_extension("refresh.lock");
    (key, token_path, lock_path)
}

/// Count the browser opens of `client`; the rows below must open none.
pub(super) fn count_browsers(client: &mut OAuthClient) -> Arc<AtomicUsize> {
    let opened = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        true
    });
    opened
}

/// T1: `refresh_stored` with the lease held answers the lock-busy error at the
/// bound, and the flight lock is free afterwards.
#[tokio::test(start_paused = true)]
async fn t1_refresh_answers_busy_at_the_bound_and_frees_the_flight() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let client = client(dir.path(), &server);
    hold(&client, &token("a1", Some("r1"), true));
    let (key, token_path, _) = credential_paths(&client);
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
        .await
        .expect("the other process holds the lease");
    let flight = Flight::of(&token_path);

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        CREDENTIAL_LOCK_WAIT * 2,
        refresh_stored(
            &client,
            StoredCredential {
                storage: &client.storage,
                key: &key,
                resource_url: RESOURCE,
                label: BACKEND,
            },
        ),
    )
    .await;
    let elapsed = start.elapsed();

    // `Refreshed` is not `Debug`, so the error is taken by pattern, not `expect_err`.
    let Err(error) = outcome.expect("a bounded wait answers inside twice the bound") else {
        panic!("no token crosses a held lease");
    };
    assert!(
        is_credential_lock_busy(&error),
        "not the lock-busy error: {error}"
    );
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "a busy lock frees the key: {error:?}"
    );
    assert!(
        (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
            .contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert!(
        flight.lock.try_lock().is_ok(),
        "the flight lock stayed held"
    );
    assert_eq!(server.requests(), 0, "sent while another process held it");
}

/// T2: a client-credentials save with the lease held answers busy and stores
/// nothing. (`save_issued` is private to `grants`; the grant is its reachable
/// caller.)
#[tokio::test(start_paused = true)]
async fn t2_save_under_a_held_lease_fails_busy_and_stores_nothing() {
    // The save is driven directly: on a paused clock a real token exchange
    // first would time out on its socket before the lease wait is reached.
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let client = client(dir.path(), &server);
    let (_, token_path, _) = credential_paths(&client);
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let issued = token("issued", None, false);
    let outcome = tokio::time::timeout(
        CREDENTIAL_LOCK_WAIT * 2,
        client.save_issued_for_test(&issued),
    )
    .await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded save answers inside twice the bound")
        .expect_err("no token is issued past a held lease");
    assert!(
        is_credential_lock_busy(&error),
        "not the lock-busy error: {error}"
    );
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "a busy lock frees the key: {error:?}"
    );
    assert!(
        (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
            .contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert!(stored(&client).is_none(), "a failed save stored a token");
}

/// T4 (regression, green now): a holder that releases at 30 s is waited for
/// through the INTERACTIVE `get_token` path, so the 30 s release exercises
/// the 90 s budget (r4.2 gives non-interactive callers 2 s, so a headless
/// waiter would answer busy instead). The waiter adopts the fresh token the
/// holder stored and sends nothing. The outer timeout covers setup and
/// execution, so a stuck readiness poll fails red.
#[tokio::test(start_paused = true)]
async fn t4_waiter_adopts_what_a_releasing_holder_stored() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let client = Arc::new(client(dir.path(), &server));
        hold(&client, &token("a1", Some("r1"), true));
        let (_, token_path, lock_path) = credential_paths(&client);
        let holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");

        let waiter = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.get_token().await }
        });
        // The waiter's first poll failed: it is on the lock, and has sent nothing.
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.requests(), 0, "sent while another process held it");
        tokio::time::sleep(Duration::from_secs(30)).await;
        let key = client
            .credential_key()
            .expect("a test client has a credential key");
        client
            .storage
            .save(&key, RESOURCE, &token("a2", Some("r2"), false))
            .expect("the holder stores afresh");
        drop(holder);

        let access = waiter
            .await
            .expect("the waiter joins")
            .expect("the stored token is taken up");
        assert_eq!(access, "a2");
        assert_eq!(server.requests(), 0, "an adoption sends nothing");
    })
    .await
    .expect("a 30 s wait ends inside twice the bound");
}

/// T4b: the same 30 s holder, the waiter non-interactive: it answers the
/// marked error at the short wait instead of waiting for the release. RED on
/// the base, where the waiter waits the 30 s and adopts (the lease wait is
/// unbounded, so no short bound answers). No socket runs: the lease blocks
/// the exchange before any POST, and the adoption (on the base) sends none.
#[tokio::test(start_paused = true)]
async fn t4b_noninteractive_waiter_answers_busy_at_the_short_wait() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let client = Arc::new(client(dir.path(), &server));
        hold(&client, &token("a1", Some("r1"), true));
        let (_, token_path, lock_path) = credential_paths(&client);
        let holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");

        // The waiter reports its own elapsed: on the fixed code it answers at
        // the short wait while the holder still holds; on the base it waits
        // for the 30 s release below and adopts.
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
        tokio::time::sleep(Duration::from_secs(30)).await;
        let key = client
            .credential_key()
            .expect("a test client has a credential key");
        client
            .storage
            .save(&key, RESOURCE, &token("a2", Some("r2"), false))
            .expect("the holder stores afresh");
        drop(holder);

        let (outcome, elapsed) = waiter.await.expect("the waiter joins");
        let Err(error) = outcome else {
            panic!("waited past the short wait and adopted: the lease wait is unbounded");
        };
        assert!(
            is_credential_lock_busy(&error),
            "not the lock-busy error: {error}"
        );
        assert!(
            matches!(error, Error::BackendUnavailable(_)),
            "the busy error rides BackendUnavailable: {error:?}"
        );
        assert!(
            error.is_pre_dispatch(),
            "a busy lock frees the key: {error:?}"
        );
        assert!(
            (SHORT_CONTENTION_WAIT..SHORT_CONTENTION_WAIT + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "answered off the short wait: {elapsed:?}"
        );
        assert_eq!(server.requests(), 0, "an adoption sends nothing");
    })
    .await
    .expect("a short wait ends inside twice the bound");
}

/// T5: an interactive detached step with the lease held answers busy at the
/// bound and never opens a browser. (No MIK-8617 row exists yet; the gate
/// setup mirrors `grants_tests`.)
#[tokio::test(start_paused = true)]
async fn t5_detached_step_answers_busy_without_a_login() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let gate = Arc::new(LoginGate::default());
    let mut client = client(dir.path(), &server).with_login_gate(Arc::clone(&gate));
    hold(&client, &token("a1", Some("r1"), true));
    let browsers = count_browsers(&mut client);
    let (_, token_path, _) = credential_paths(&client);
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
        .await
        .expect("the other process holds the lease");
    let cohort = gate.cohort();
    let deadline = Instant::now() + Duration::from_secs(600);

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        CREDENTIAL_LOCK_WAIT * 2,
        client.get_token_detached(true, gate.epoch(), &cohort, deadline),
    )
    .await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded step answers inside twice the bound")
        .expect_err("no token crosses a held lease");
    assert!(
        is_credential_lock_busy(&error),
        "not the lock-busy error: {error}"
    );
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
            .contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert_eq!(
        browsers.load(Ordering::SeqCst),
        0,
        "a login started on a busy lock"
    );
}

/// T5b: the same no-browser row on `get_token` (the non-detached arm).
#[tokio::test(start_paused = true)]
async fn t5b_get_token_answers_busy_without_a_login() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let gate = Arc::new(LoginGate::default());
    let mut client = client(dir.path(), &server).with_login_gate(Arc::clone(&gate));
    hold(&client, &token("a1", Some("r1"), true));
    let browsers = count_browsers(&mut client);
    let (_, token_path, _) = credential_paths(&client);
    let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let outcome = tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, client.get_token()).await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded step answers inside twice the bound")
        .expect_err("no token crosses a held lease");
    assert!(
        is_credential_lock_busy(&error),
        "not the lock-busy error: {error}"
    );
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        (CREDENTIAL_LOCK_WAIT..CREDENTIAL_LOCK_WAIT + POLL + Duration::from_secs(1))
            .contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert_eq!(
        browsers.load(Ordering::SeqCst),
        0,
        "a login started on a busy lock"
    );
}

/// T8 (green now): a login save keeps the authorization window. Released past
/// the contention budget but inside the window, it stores; held past the
/// window, it ends `AuthorizationIncomplete` at the window deadline, never
/// busy. The save runs through `save_issued_until_for_test` (no browser,
/// callback or exchange sockets); the lock-attempt seam shows it reached its
/// lease wait. The outer timeout covers setup and execution of both halves.
#[tokio::test(start_paused = true)]
async fn t8_login_save_keeps_the_authorization_window() {
    tokio::time::timeout(OAUTH_AUTHORIZATION_WINDOW * 2, async {
        // Released at 120 s: past the budget, inside the window. The save stores.
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let login = Arc::new(client(dir.path(), &server));
        let (_, token_path, lock_path) = credential_paths(&login);
        let holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");
        let start = Instant::now();
        let saving = tokio::spawn({
            let login = Arc::clone(&login);
            async move {
                login
                    .save_issued_until_for_test(&token("a2", Some("r2"), false))
                    .await
            }
        });
        // The save is on the lock, and no HTTP ran to get there.
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.requests(), 0, "the save sent before its lease wait");
        tokio::time::sleep(Duration::from_secs(120)).await;
        drop(holder);
        saving
            .await
            .expect("the save joins")
            .expect("the save stores");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(120),
            "stored before the release: {elapsed:?}"
        );
        assert!(
            elapsed < OAUTH_AUTHORIZATION_WINDOW,
            "waited past the window: {elapsed:?}"
        );
        let key = login
            .credential_key()
            .expect("a test client has a credential key");
        let saved = login
            .storage
            .load(&key, RESOURCE)
            .expect("the save stored its token");
        assert_eq!(saved.access_token, "a2");
        assert_eq!(server.requests(), 0, "the save sent");

        // Held past the window: `AuthorizationIncomplete` at the window deadline.
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let login = client(dir.path(), &server);
        let (_, token_path, lock_path) = credential_paths(&login);
        let _holder = hold_across_processes(&token_path, Instant::now() + CREDENTIAL_LOCK_WAIT)
            .await
            .expect("the other process holds the lease");
        let start = Instant::now();
        let saving = tokio::spawn({
            let issued = token("issued", Some("r9"), false);
            async move { login.save_issued_until_for_test(&issued).await }
        });
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.requests(), 0, "the save sent before its lease wait");
        let error = saving
            .await
            .expect("the save joins")
            .expect_err("no token crosses a held lease");
        let elapsed = start.elapsed();
        assert!(
            matches!(
                error,
                Error::AuthorizationIncomplete { window_secs, .. }
                    if window_secs == OAUTH_AUTHORIZATION_WINDOW.as_secs()
            ),
            "not the window expiry: {error}"
        );
        assert!(
            !is_credential_lock_busy(&error),
            "a window expiry is not busy: {error}"
        );
        assert!(
            (OAUTH_AUTHORIZATION_WINDOW
                ..OAUTH_AUTHORIZATION_WINDOW + POLL + Duration::from_secs(1))
                .contains(&elapsed),
            "expired off the window deadline: {elapsed:?}"
        );
        assert_eq!(server.requests(), 0, "the save sent");
    })
    .await
    .expect("both halves end inside twice the window");
}

/// The lease boundary: a lock released just before the deadline is still
/// taken, because the probe runs before every sleep.
#[tokio::test(start_paused = true)]
async fn lease_acquires_when_released_just_before_the_deadline() {
    tokio::time::timeout(Duration::from_secs(2) * 2, async {
        let dir = tempfile::tempdir().expect("a scratch lock dir");
        let lock_path = dir.path().join("boundary.lock");
        let holder = crate::fs_lock::ExclusiveFileLock::try_lease(&lock_path)
            .expect("a free lock leases")
            .expect("a free lock gives Some");
        let deadline = Instant::now() + Duration::from_secs(2);
        let waiter = tokio::spawn({
            let lock_path = lock_path.clone();
            async move { crate::fs_lock::ExclusiveFileLock::lease(&lock_path, POLL, deadline).await }
        });
        // The waiter is on the lock: its first probe failed.
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Released just before the deadline, with two polls to spare.
        tokio::time::sleep(Duration::from_millis(1900)).await;
        drop(holder);
        let acquired = waiter
            .await
            .expect("the waiter joins")
            .expect("a release just before the deadline is taken");
        drop(acquired);
    })
    .await
    .expect("a release before the deadline answers inside twice the bound");
}

/// The lease boundary: ongoing contention times out at the deadline.
#[tokio::test(start_paused = true)]
async fn lease_times_out_at_the_deadline_under_ongoing_contention() {
    let bound = Duration::from_secs(2);
    let dir = tempfile::tempdir().expect("a scratch lock dir");
    let lock_path = dir.path().join("contention.lock");
    let _holder = crate::fs_lock::ExclusiveFileLock::try_lease(&lock_path)
        .expect("a free lock leases")
        .expect("a free lock gives Some");
    let deadline = Instant::now() + bound;
    let start = Instant::now();
    let outcome = tokio::time::timeout(
        bound * 2,
        crate::fs_lock::ExclusiveFileLock::lease(&lock_path, POLL, deadline),
    )
    .await;
    let elapsed = start.elapsed();
    let Err(error) = outcome.expect("a bounded wait answers inside twice the bound") else {
        panic!("no lock crosses a held lease");
    };
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::TimedOut,
        "not a timeout: {error}"
    );
    assert!(
        (bound..bound + POLL + Duration::from_secs(1)).contains(&elapsed),
        "timed out off the deadline: {elapsed:?}"
    );
}
