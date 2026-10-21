// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): the stored-credential lease wait is bounded.
//! Rows T1, T2, T4, T5, T5b and T8: the flight, the saves and the login paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

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

/// One lock poll (50 ms), mirroring the private `LOCK_POLL`, which phase 2 keeps.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// The busy marker text, the exact value phase 2 gives `refresh_flight::CREDENTIAL_LOCK_BUSY`;
/// phase 2 replaces this stand-in with that const.
pub(super) const BUSY_MARKER: &str = "credential lock busy";

/// Whether `error` carries the busy marker: phase 2 replaces with
/// `is_credential_lock_busy`. The marker rides as a prefix on either variant:
/// `BackendUnavailable` everywhere, the `OAuth` text form for joiners (r4.1).
pub(super) fn is_busy(error: &Error) -> bool {
    match error {
        Error::BackendUnavailable(text) | Error::OAuth(text) => text.starts_with(BUSY_MARKER),
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
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let mut client = client(dir.path(), &server);
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    let (_, token_path, _) = credential_paths(&client);
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");

    let start = Instant::now();
    let outcome = tokio::time::timeout(BOUND * 2, client.try_client_credentials()).await;
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
/// the waiter adopts the fresh token it stored and sends nothing.
#[tokio::test(start_paused = true)]
async fn t4_waiter_adopts_what_a_releasing_holder_stored() {
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

    let access = tokio::time::timeout(BOUND * 2, waiter)
        .await
        .expect("a 30 s wait ends inside twice the bound")
        .expect("the waiter joins")
        .expect("the stored token is taken up");
    assert_eq!(access, "a2");
    assert_eq!(server.requests(), 0, "an adoption sends nothing");
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

/// A client whose browser approves at once against `server`, for a login that
/// must reach its save. (The sibling approval helpers are private to their
/// modules; this is the same shape, minimal for the save rows.)
fn approving_client(dir: &std::path::Path, server: &TokenServer) -> OAuthClient {
    let mut approved = client(dir, server);
    approved.callback_host = Some("127.0.0.1".to_string());
    let iss = server.base.clone();
    approved.open_browser = Box::new(move |url| {
        let query: std::collections::HashMap<String, String> = url::Url::parse(url)
            .expect("the authorization url parses")
            .query_pairs()
            .into_owned()
            .collect();
        let callback = url::Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("code", "t8-approved"),
                ("state", query["state"].as_str()),
                ("iss", iss.as_str()),
            ],
        )
        .expect("the callback url builds");
        tokio::spawn(async move {
            let _ = reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("the approval client builds")
                .get(callback)
                .send()
                .await;
        });
        true
    });
    approved
}

/// T8 (green now): a login save keeps the authorization window. Released past
/// the contention budget but inside the window, it stores; held past the
/// window, it ends `AuthorizationIncomplete`, never busy. (`save_issued_until`
/// is private to `grants`; the login is its reachable caller.)
#[tokio::test(start_paused = true)]
async fn t8_login_save_keeps_the_authorization_window() {
    // Released at 120 s: past the budget, inside the window. The login stores.
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let login = Arc::new(approving_client(dir.path(), &server));
    let (_, token_path, lock_path) = credential_paths(&login);
    let holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let saving = tokio::spawn({
        let login = Arc::clone(&login);
        async move {
            login
                .authorize_until_by(&CancellationToken::new(), None, None)
                .await
        }
    });
    // The exchange landed and the save is on the lock.
    while server.requests() < 1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    while crate::fs_lock::lock_attempts(&lock_path) < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_secs(120)).await;
    drop(holder);
    let access = tokio::time::timeout(OAUTH_AUTHORIZATION_WINDOW * 2, saving)
        .await
        .expect("a save released inside the window ends")
        .expect("the login joins")
        .expect("the login stores");
    assert_eq!(access, "a2");
    let key = login
        .credential_key()
        .expect("a test client has a credential key");
    let saved = login
        .storage
        .load(&key, RESOURCE)
        .expect("the login stored its token");
    assert_eq!(saved.access_token, "a2");

    // Held past the window: `AuthorizationIncomplete`, never busy.
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let login = Arc::new(approving_client(dir.path(), &server));
    let (_, token_path, _) = credential_paths(&login);
    let _holder = hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let cancel = CancellationToken::new();
    let outcome = tokio::time::timeout(
        OAUTH_AUTHORIZATION_WINDOW * 2,
        login.authorize_until_by(&cancel, None, None),
    )
    .await;
    let error = outcome
        .expect("a save held past the window ends at the window")
        .expect_err("no token crosses a held lease");
    assert!(
        matches!(
            error,
            Error::AuthorizationIncomplete { window_secs, .. }
                if window_secs == OAUTH_AUTHORIZATION_WINDOW.as_secs()
        ),
        "not the window expiry: {error}"
    );
    assert!(!is_busy(&error), "a window expiry is not busy: {error}");
}
