// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T10 to T13, the capability path, the
//! shared login, a lock io error and the health probe under a busy lock.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use super::lease_bound::{
    BOUND, BUSY_MARKER, POLL, count_browsers, credential_paths, is_busy, is_deferred,
};
use super::*;
use crate::Error;
use crate::oauth::login_gate::{Begin, LoginGate};

/// A provider whose stored token lapsed with a refresh token to renew with.
const PROVIDER: &str = "t10-provider";

/// T10: a capability refresh with the lease held answers the marked error
/// unwrapped, without the re-authentication warning. (The executor's refresh
/// entry points are `pub(super)` to it; the public `execute` is the caller.)
#[tokio::test(start_paused = true)]
async fn t10_capability_refresh_answers_busy_without_reauth_noise() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");
    let storage =
        Arc::new(crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("token storage"));
    let mut seed = crate::oauth::TokenInfo::from_response(
        "old-access".to_string(),
        Some("Bearer".to_string()),
        Some("t10-refresh".to_string()),
        Some(3600),
        None,
    );
    seed.expires_at = Some(0);
    storage
        .save(PROVIDER, PROVIDER, &seed)
        .expect("the lapsed seed");
    let executor = crate::capability::CapabilityExecutor::with_token_storage(Arc::clone(&storage));
    let token_path = storage.token_path(PROVIDER, PROVIDER);
    let _holder = crate::oauth::client::refresh_flight::hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");
    let yaml = format!(
        "name: t10_cap\ndescription: lease-bound probe\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: {base}\n      path: /k\nauth:\n  required: true\n  type: oauth\n  key: \"oauth:{PROVIDER}\"\n  token_endpoint: \"{base}/token\"\n",
        base = server.base,
    );
    let capability =
        crate::capability::parse_capability(&yaml).expect("the probe capability parses");
    let context =
        crate::capability::CapabilityExecutionContext::default().with_isolated_loopback_egress();
    let (log_guard, log_buffer) = crate::oauth::callback::tests::capture();

    let start = Instant::now();
    let outcome = tokio::time::timeout(
        BOUND * 2,
        executor.execute_with_context(&capability, serde_json::json!({}), context),
    )
    .await;
    let elapsed = start.elapsed();
    drop(log_guard);

    let error = outcome
        .expect("a busy lock answers inside twice the bound")
        .expect_err("no credential crosses a held lease");
    assert!(is_busy(&error), "not the marked error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "not unwrapped: {error:?}"
    );
    assert!(error.is_pre_dispatch(), "a busy lock frees the key");
    assert!(
        (BOUND..BOUND + POLL + Duration::from_secs(1)).contains(&elapsed),
        "answered off the bound: {elapsed:?}"
    );
    assert_eq!(server.requests(), 0, "sent while another process held it");
    let held = log_buffer.lock().expect("the log buffer reads");
    let log = String::from_utf8_lossy(&held);
    assert!(
        !log.contains("manual re-authentication required"),
        "warned as re-auth: {log}"
    );
}

/// T11: a joiner of a login whose save hit a lock io error shares the marked
/// failure as `OAuth` text, which still reads busy. (`LoginOutcome::of` is
/// private; the lead records it exactly as `authorize_shared_with` does.)
#[tokio::test(start_paused = true)]
async fn t11_joiner_shares_the_marked_save_failure() {
    let dir = tempfile::tempdir().expect("a scratch token store");
    let storage = crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("token storage");
    let token_path = storage.token_path("t11-credential", "https://t11.example/mcp");
    std::fs::create_dir_all(token_path.with_extension("refresh.lock"))
        .expect("a directory stands where the lock goes");

    let gate = Arc::new(LoginGate::default());
    let cohort = gate.cohort();
    let Begin::Lead(lead) = gate.begin(None, None) else {
        panic!("no login in flight, so the test leads");
    };
    let outcome = tokio::time::timeout(
        BOUND * 2,
        crate::oauth::client::refresh_flight::hold_across_processes(&token_path),
    )
    .await
    .expect("an io error answers at once");
    // `ExclusiveFileLock` is not `Debug`, so the error is taken by pattern.
    let Err(save_error) = outcome else {
        panic!("a directory is not a lock file");
    };
    assert!(
        matches!(save_error, Error::BackendUnavailable(_)),
        "the lead's lock failure rides BackendUnavailable: {save_error:?}"
    );
    lead.end(Some(&save_error));

    let Begin::Ended(shared) = gate.begin(None, Some(&cohort)) else {
        panic!("the cohort ended with the lead");
    };
    let joined = shared.to_error("t11-backend");
    assert!(
        is_busy(&joined),
        "the marker did not reach the joiner: {joined}"
    );
    assert!(
        matches!(joined, Error::OAuth(_)),
        "not the text form: {joined:?}"
    );
    assert!(
        !joined.is_pre_dispatch(),
        "r4.1: joiners lose the pre-dispatch class on this rare path"
    );
}

/// A marked `BackendUnavailable` through the same lead-end path still reads
/// busy to the joiner (green now: the text round-trips, and `is_busy` matches
/// the marker inside the joiner's `OAuth` text).
#[tokio::test(start_paused = true)]
async fn t11b_marked_error_round_trips_busy_to_the_joiner() {
    tokio::time::timeout(BOUND * 2, async {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("no login in flight, so the test leads");
        };
        let marked = Error::BackendUnavailable(format!("{BUSY_MARKER}: x"));
        lead.end(Some(&marked));

        let Begin::Ended(shared) = gate.begin(None, Some(&cohort)) else {
            panic!("the cohort ended with the lead");
        };
        let joined = shared.to_error("t11b-backend");
        assert!(
            matches!(joined, Error::OAuth(_)),
            "not the text form: {joined:?}"
        );
        assert!(is_busy(&joined), "the marker did not round-trip: {joined}");
    })
    .await
    .expect("a cohort end answers at once");
}

/// T12: a lock io error that is not a timeout (a directory where the lock file
/// belongs) passes through at once, with no login, on `get_token` and renewal.
#[tokio::test(start_paused = true)]
async fn t12_lock_io_error_passes_through_at_once() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().expect("a scratch token store");

    // `get_token`: busy at once, and the browser stays shut.
    let mut gated = client(dir.path(), &server).with_login_gate(Arc::new(LoginGate::default()));
    hold(&gated, &token("a1", Some("r1"), true));
    let browsers = count_browsers(&mut gated);
    let (_, _, lock_path) = credential_paths(&gated);
    std::fs::create_dir_all(&lock_path).expect("a directory stands where the lock goes");
    let start = Instant::now();
    let outcome = tokio::time::timeout(BOUND * 2, gated.get_token()).await;
    let elapsed = start.elapsed();
    // On a timeout, the browser count says where the wait went: a login.
    let Ok(result) = outcome else {
        panic!(
            "an io error did not answer at once; browsers opened: {}",
            browsers.load(Ordering::SeqCst)
        );
    };
    let error = result.expect_err("no token crosses a broken lock");
    assert!(is_busy(&error), "not the lock-busy error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "the busy error rides BackendUnavailable: {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "a busy lock frees the key: {error:?}"
    );
    assert!(elapsed < Duration::from_secs(5), "not at once: {elapsed:?}");
    assert_eq!(
        browsers.load(Ordering::SeqCst),
        0,
        "a login started on a broken lock"
    );

    // Renewal: deferred at once, without trying `client_credentials`.
    let mut renewing = client(dir.path(), &server);
    if let Some(meta) = renewing.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    hold(&renewing, &token("a1", Some("r1"), true));
    let start = Instant::now();
    let outcome = tokio::time::timeout(BOUND * 2, renewing.attempt_background_renewal()).await;
    let elapsed = start.elapsed();
    let renewal = outcome.expect("an io error answers at once");
    assert!(is_deferred(&renewal), "not deferred: {renewal:?}");
    assert!(elapsed < Duration::from_secs(5), "not at once: {elapsed:?}");
    assert_eq!(
        server.requests(),
        0,
        "`client_credentials` ran after the busy refresh"
    );
}

/// A transport whose token step met a busy credential lock, as one does while
/// another process holds the lease past the budget.
struct BusyTransport;

#[async_trait]
impl crate::transport::Transport for BusyTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Err(crate::Error::BackendUnavailable(format!(
            "{BUSY_MARKER}: the token step holds the lease"
        )))
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

/// T13: a probe whose request meets a busy lock neither rebuilds nor trips the
/// breaker. (The OAuth-wired variant needs `Backend::oauth_test_seam`, which
/// is private to `backend`; the mock surfaces what the token step returns.)
#[tokio::test(start_paused = true)]
async fn t13_probe_skips_rebuild_and_breaker_on_busy() {
    let dir = tempfile::tempdir().expect("a scratch token store");
    let storage = crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("token storage");
    let token_path = storage.token_path("t13-credential", "https://t13.example/mcp");
    let _holder = crate::oauth::client::refresh_flight::hold_across_processes(&token_path)
        .await
        .expect("the other process holds the lease");

    let backend = crate::backend::Backend::new(
        "t13-probe",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    backend.set_transport_for_test(Arc::new(BusyTransport) as Arc<dyn crate::transport::Transport>);

    let outcome = tokio::time::timeout(BOUND * 2, backend.health_probe(Duration::from_secs(5)))
        .await
        .expect("a probe answers");
    let error = outcome.expect_err("a busy lock is not health");
    assert!(is_busy(&error), "not the marked error: {error}");
    assert!(
        matches!(error, Error::BackendUnavailable(_)),
        "not unwrapped: {error:?}"
    );
    assert_eq!(
        backend.rebuilds_attempted.load(Ordering::SeqCst),
        0,
        "the probe rebuilt over a busy lock"
    );
    assert!(
        !backend.is_circuit_tripped(),
        "the probe tripped the breaker on a busy lock"
    );
    assert_eq!(
        backend.circuit_breaker_stats().current_failures,
        0,
        "a busy lock sampled as a backend failure"
    );
}

/// T13d: a dispatch through `Backend::request` whose token step meets a busy
/// lock leaves the breaker's failure count unchanged. The probe never calls
/// `record_dispatch_error`, so only this path pins the exclusion; on the base
/// the marked error counts and the row is red.
#[tokio::test(start_paused = true)]
async fn t13d_dispatch_skips_breaker_on_busy() {
    tokio::time::timeout(BOUND * 2, async {
        let backend = crate::backend::Backend::new(
            "t13d-dispatch",
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        backend.set_transport_for_test(
            Arc::new(BusyTransport) as Arc<dyn crate::transport::Transport>
        );
        let before = backend.circuit_breaker_stats().current_failures;

        let error = backend
            .request("tools/list", None)
            .await
            .expect_err("a busy lock answers no tools");
        assert!(is_busy(&error), "not the marked error: {error}");
        assert!(
            matches!(error, Error::BackendUnavailable(_)),
            "not unwrapped: {error:?}"
        );
        assert_eq!(
            backend.circuit_breaker_stats().current_failures,
            before,
            "a busy lock sampled as a backend failure"
        );
        assert!(
            !backend.is_circuit_tripped(),
            "the dispatch tripped the breaker on a busy lock"
        );
    })
    .await
    .expect("a dispatch answers at once");
}
