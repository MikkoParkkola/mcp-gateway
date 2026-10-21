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
use crate::oauth::client::refresh_flight::{Flight, hold_across_processes};
use crate::oauth::client::renewal::Renewal;
use crate::oauth::client::{StoredCredential, refresh_stored};
use crate::oauth::login_gate::LoginGate;

// Phase-2 stand-ins, shared with the sibling rows. Phase 2 deletes them and
// uses `CREDENTIAL_LOCK_WAIT`, `CREDENTIAL_LOCK_BUSY` and
// `is_credential_lock_busy` from `refresh_flight`, plus `Renewal::Deferred`.
// Invariant: every row's outer timeout is twice its bound, so a regression is
// red, never hung.

/// The contention budget (90 s): phase 2 replaces with `CREDENTIAL_LOCK_WAIT`.
pub(super) const BOUND: Duration = Duration::from_secs(90);

/// The non-interactive contention budget (2 s): phase 2 replaces with NONINTERACTIVE_LEASE_WAIT.
pub(super) const SHORT_WAIT: Duration = Duration::from_secs(2);

/// One lock poll (50 ms), mirroring the private `LOCK_POLL`, which phase 2 keeps.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// The busy marker text, the exact value phase 2 gives `refresh_flight::CREDENTIAL_LOCK_BUSY`;
/// phase 2 replaces this stand-in with that const.
pub(super) const BUSY_MARKER: &str = "credential lock busy";

/// Whether `error` carries the busy marker: phase 2 replaces with
/// `is_credential_lock_busy`. `BackendUnavailable` carries it as a prefix;
/// joiners get it inside `OAuth` text (`Failed(error.to_string())`, r4.1), so
/// that arm matches the marker with its colon anywhere in the text.
pub(super) fn is_busy(error: &Error) -> bool {
    match error {
        Error::BackendUnavailable(text) => text.starts_with(BUSY_MARKER),
        Error::OAuth(text) => text.contains(&format!("{BUSY_MARKER}:")),
        _ => false,
    }
}

/// Whether a renewal deferred on a busy lock: phase 2 replaces with
/// `matches!(renewal, Renewal::Deferred)`. Until then no renewal is one, so
/// the negation of today's three variants reads the same either way.
pub(super) fn is_deferred(renewal: &Renewal) -> bool {
    !matches!(
        renewal,
        Renewal::Renewed | Renewal::Refused | Renewal::Exhausted
    )
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
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let flight = Flight::of(&token_path);

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        BOUND * 2,
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
    assert!(is_busy(&error), "not the lock-busy error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "a busy lock frees the key: {error:?}"
    );
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
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
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let issued = token("issued", None, false);
    let outcome = tokio::time::timeout(BOUND * 2, client.save_issued_for_test(&issued)).await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded save answers inside twice the bound")
        .expect_err("no token is issued past a held lease");
    assert!(is_busy(&error), "not the lock-busy error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "a busy lock frees the key: {error:?}"
    );
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert!(stored(&client).is_none(), "a failed save stored a token");
}

/// T4 (regression, green now): a holder that releases at 30 s is waited for;
/// the waiter adopts the fresh token it stored and sends nothing. The outer
/// timeout covers setup and execution, so a stuck readiness poll fails red.
#[tokio::test(start_paused = true)]
async fn t4_waiter_adopts_what_a_releasing_holder_stored() {
    tokio::time::timeout(BOUND * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let client = Arc::new(client(dir.path(), &server));
        hold(&client, &token("a1", Some("r1"), true));
        let (_, token_path, lock_path) = credential_paths(&client);
        let holder = hold_across_processes(&token_path)
            .await
            .expect("the other process holds the lease");

        let waiter = tokio::spawn({
            let client = Arc::clone(&client);
            async move { headless(&client).await }
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
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let cohort = gate.cohort();
    let deadline = Instant::now() + Duration::from_secs(600);

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        BOUND * 2,
        client.get_token_detached(true, gate.epoch(), &cohort, deadline),
    )
    .await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded step answers inside twice the bound")
        .expect_err("no token crosses a held lease");
    assert!(is_busy(&error), "not the lock-busy error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
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
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let outcome = tokio::time::timeout(BOUND * 2, client.get_token()).await;
    let elapsed = start.elapsed();

    let error = outcome
        .expect("a bounded step answers inside twice the bound")
        .expect_err("no token crosses a held lease");
    assert!(is_busy(&error), "not the lock-busy error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
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
        let holder = hold_across_processes(&token_path)
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
        let _holder = hold_across_processes(&token_path)
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
        assert!(!is_busy(&error), "a window expiry is not busy: {error}");
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
