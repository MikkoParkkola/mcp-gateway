// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8619 phase 1 (red first): rows T10 to T13, the capability path, the
//! shared login, a lock io error and the health probe under a busy lock.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use super::lease_bound::{POLL, count_browsers, credential_paths, is_deferred};
use super::*;
use crate::Error;
use crate::oauth::client::refresh_flight::{
    CREDENTIAL_LOCK_BUSY, CREDENTIAL_LOCK_WAIT, Flight, SHORT_CONTENTION_WAIT,
    is_credential_lock_busy,
};
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
    let _holder = crate::oauth::client::refresh_flight::hold_across_processes(
        &token_path,
        Instant::now() + CREDENTIAL_LOCK_WAIT,
    )
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
        CREDENTIAL_LOCK_WAIT * 2,
        executor.execute_with_context(&capability, serde_json::json!({}), context),
    )
    .await;
    let elapsed = start.elapsed();
    drop(log_guard);

    let error = outcome
        .expect("a busy lock answers inside twice the bound")
        .expect_err("no credential crosses a held lease");
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

/// T11: a joiner of a login whose save hit a lock io error gets the typed busy
/// (`BackendUnavailable` with the marker), as the lead does (MIK-8658).
/// (`LoginOutcome::of` is private; the lead records it exactly as
/// `authorize_shared_with` does.)
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
        CREDENTIAL_LOCK_WAIT * 2,
        crate::oauth::client::refresh_flight::hold_across_processes(
            &token_path,
            Instant::now() + CREDENTIAL_LOCK_WAIT,
        ),
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
        is_credential_lock_busy(&joined),
        "the marker did not reach the joiner: {joined}"
    );
    assert!(
        matches!(joined, Error::BackendUnavailable(_)),
        "not the typed busy: {joined:?}"
    );
    assert!(
        joined.is_pre_dispatch(),
        "D2: the joiner sent nothing, so its busy is pre-dispatch (supersedes #4031 r4.1)"
    );
    assert_eq!(
        joined.to_rpc_code(),
        -32000,
        "D1: the lead's code for the same busy"
    );
    assert!(
        joined
            .to_string()
            .starts_with("Backend unavailable: credential lock busy:"),
        "{joined}"
    );
}

/// A marked `BackendUnavailable` through the same lead-end path reaches the
/// joiner as the same typed busy: same text, code and pre-dispatch class as
/// the lead's (MIK-8658).
#[tokio::test(start_paused = true)]
async fn t11b_marked_error_round_trips_busy_to_the_joiner() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("no login in flight, so the test leads");
        };
        let marked = Error::BackendUnavailable(format!("{CREDENTIAL_LOCK_BUSY}: x"));
        lead.end(Some(&marked));

        let Begin::Ended(shared) = gate.begin(None, Some(&cohort)) else {
            panic!("the cohort ended with the lead");
        };
        let joined = shared.to_error("t11b-backend");
        assert!(
            matches!(joined, Error::BackendUnavailable(_)),
            "not the typed busy: {joined:?}"
        );
        assert!(
            is_credential_lock_busy(&joined),
            "the marker did not round-trip: {joined}"
        );
        assert_eq!(
            joined.to_string(),
            format!("Backend unavailable: {CREDENTIAL_LOCK_BUSY}: x")
        );
        assert!(joined.is_pre_dispatch(), "{joined:?}");
        assert_eq!(joined.to_rpc_code(), -32000);
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
    let outcome = tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, gated.get_token()).await;
    let elapsed = start.elapsed();
    // On a timeout, the browser count says where the wait went: a login.
    let Ok(result) = outcome else {
        panic!(
            "an io error did not answer at once; browsers opened: {}",
            browsers.load(Ordering::SeqCst)
        );
    };
    let error = result.expect_err("no token crosses a broken lock");
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
    // Well under the short wait: an io error does not wait, not even 2 s.
    assert!(
        elapsed < POLL + Duration::from_millis(500),
        "not at once: {elapsed:?}"
    );
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
    let outcome = tokio::time::timeout(
        CREDENTIAL_LOCK_WAIT * 2,
        renewing.attempt_background_renewal(),
    )
    .await;
    let elapsed = start.elapsed();
    let renewal = outcome.expect("an io error answers at once");
    assert!(is_deferred(&renewal), "not deferred: {renewal:?}");
    // Well under the short wait: an io error does not wait, not even 2 s.
    assert!(
        elapsed < POLL + Duration::from_millis(500),
        "not at once: {elapsed:?}"
    );
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
            "{CREDENTIAL_LOCK_BUSY}: the token step holds the lease"
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

/// A transport whose request fails unmarked: the same `BackendUnavailable`
/// variant without the busy text, so a blanket skip of every such error fails.
struct UnmarkedTransport;

#[async_trait]
impl crate::transport::Transport for UnmarkedTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Err(crate::Error::BackendUnavailable("x".to_string()))
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

/// T13: a probe whose request meets a busy lock neither rebuilds nor trips the
/// breaker. (The OAuth-wired variant needs `Backend::oauth_test_seam`, which
/// is private to `backend`; the mock surfaces what the token step returns.)
/// An unmarked `BackendUnavailable` still rebuilds, so skipping every such
/// error fails. The outer timeout covers setup and both probes.
#[tokio::test(start_paused = true)]
async fn t13_probe_skips_rebuild_and_breaker_on_busy() {
    tokio::time::timeout(
        CREDENTIAL_LOCK_WAIT * 2,
        Box::pin(async {
            let dir = tempfile::tempdir().expect("a scratch token store");
            let storage =
                crate::oauth::TokenStorage::new(dir.path().to_path_buf()).expect("token storage");
            let token_path = storage.token_path("t13-credential", "https://t13.example/mcp");
            let _holder = crate::oauth::client::refresh_flight::hold_across_processes(
                &token_path,
                Instant::now() + CREDENTIAL_LOCK_WAIT,
            )
            .await
            .expect("the other process holds the lease");

            let backend = crate::backend::Backend::new(
                "t13-probe",
                crate::config::BackendConfig::default(),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            backend.set_transport_for_test(
                Arc::new(BusyTransport) as Arc<dyn crate::transport::Transport>
            );

            let error = backend
                .health_probe(Duration::from_secs(5))
                .await
                .expect_err("a busy lock is not health");
            assert!(
                is_credential_lock_busy(&error),
                "not the marked error: {error}"
            );
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

            // Unmarked: the same variant without the busy text still rebuilds.
            let plain = crate::backend::Backend::new(
                "t13-plain",
                crate::config::BackendConfig::default(),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            plain.set_transport_for_test(
                Arc::new(UnmarkedTransport) as Arc<dyn crate::transport::Transport>
            );
            let error = plain
                .health_probe(Duration::from_secs(5))
                .await
                .expect_err("an unmarked failure is not health");
            assert!(
                !is_credential_lock_busy(&error),
                "an unmarked error reads busy: {error}"
            );
            assert!(
                matches!(error, Error::BackendUnavailable(_)),
                "not the variant: {error:?}"
            );
            assert!(
                plain.rebuilds_attempted.load(Ordering::SeqCst) > 0,
                "the probe did not rebuild over an unmarked failure"
            );
        }),
    )
    .await
    .expect("both probes answer inside twice the bound");
}

/// T13b: a probe whose transport runs the real held-lease token step answers
/// the marked error at the short wait, without a rebuild or a breaker sample.
#[tokio::test(start_paused = true)]
async fn t13b_probe_answers_busy_at_the_short_wait() {
    tokio::time::timeout(
        Duration::from_secs(5) * 2,
        Box::pin(async {
            let server = TokenServer::start(&[]).await;
            let dir = tempfile::tempdir().expect("a scratch token store");
            let oauth = client(dir.path(), &server);
            hold(&oauth, &token("a1", Some("r1"), true));
            let (_, token_path, _) = credential_paths(&oauth);
            let _holder = crate::oauth::client::refresh_flight::hold_across_processes(
                &token_path,
                Instant::now() + CREDENTIAL_LOCK_WAIT,
            )
            .await
            .expect("the other process holds the lease");
            let backend = crate::backend::Backend::new(
                "t13b-probe",
                crate::config::BackendConfig::default(),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            backend.set_transport_for_test(Arc::new(TokenStepTransport {
                client: Arc::new(oauth),
            }) as Arc<dyn crate::transport::Transport>);
            let before = backend.circuit_breaker_stats().current_failures;

            let start = Instant::now();
            let outcome = backend.health_probe(Duration::from_secs(5)).await;
            let elapsed = start.elapsed();

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
                "answered off the short wait: {elapsed:?}"
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
            assert_eq!(server.requests(), 0, "sent while another process held it");
        }),
    )
    .await
    .expect("a probe answers inside twice its timeout");
}

/// T13g: a probe queued behind an in-process holder answers the marked busy
/// error at the short wait, with no rebuild and no breaker sample. The holder
/// is a spawned task holding the flight lock, as an interactive refresh
/// blocked on the lease would hold it. RED now: `refresh_stored` waits the
/// flight lock unbounded, so the probe times out at 5 s and rebuilds.
#[tokio::test(start_paused = true)]
async fn t13g_probe_behind_an_in_process_holder_answers_busy_at_the_short_wait() {
    tokio::time::timeout(
        Duration::from_secs(5) * 2,
        Box::pin(async {
            let server = TokenServer::start(&[]).await;
            let dir = tempfile::tempdir().expect("a scratch token store");
            let oauth = client(dir.path(), &server);
            hold(&oauth, &token("a1", Some("r1"), true));
            let (_, token_path, _) = credential_paths(&oauth);
            // The in-process holder: a spawned task, so the probe queues behind
            // another task's hold rather than its own.
            let flight = Flight::of(&token_path);
            let acquired = Arc::new(tokio::sync::Notify::new());
            let holder = tokio::spawn({
                let flight = Arc::clone(&flight);
                let acquired = Arc::clone(&acquired);
                async move {
                    let _guard = flight.lock.lock().await;
                    acquired.notify_one();
                    tokio::time::sleep(CREDENTIAL_LOCK_WAIT * 2).await;
                }
            });
            acquired.notified().await;
            let backend = crate::backend::Backend::new(
                "t13g-probe",
                crate::config::BackendConfig::default(),
                &crate::config::FailsafeConfig::default(),
                Duration::from_secs(60),
            );
            backend.set_transport_for_test(Arc::new(TokenStepTransport {
                client: Arc::new(oauth),
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
                "answered off the short wait: {elapsed:?}"
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
            assert_eq!(server.requests(), 0, "sent while the flight was held");
        }),
    )
    .await
    .expect("a probe answers inside twice its timeout");
}

/// T13c: the same probe succeeds when the holder stores afresh and releases
/// within the short wait; the token step adopts without sending.
#[tokio::test(start_paused = true)]
async fn t13c_probe_succeeds_when_the_lease_frees_in_time() {
    tokio::time::timeout(Duration::from_secs(5) * 2, async {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().expect("a scratch token store");
        let oauth = client(dir.path(), &server);
        hold(&oauth, &token("a1", Some("r1"), true));
        let (key, token_path, lock_path) = credential_paths(&oauth);
        let holder = crate::oauth::client::refresh_flight::hold_across_processes(
            &token_path,
            Instant::now() + CREDENTIAL_LOCK_WAIT,
        )
        .await
        .expect("the other process holds the lease");
        let oauth = Arc::new(oauth);
        let backend = Arc::new(crate::backend::Backend::new(
            "t13c-probe",
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(Arc::new(TokenStepTransport {
            client: Arc::clone(&oauth),
        }) as Arc<dyn crate::transport::Transport>);
        let before = backend.circuit_breaker_stats().current_failures;
        let probing = tokio::spawn({
            let backend = Arc::clone(&backend);
            async move { backend.health_probe(Duration::from_secs(5)).await }
        });
        // The probe's token step is on the lock, and has sent nothing.
        while crate::fs_lock::lock_attempts(&lock_path) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.requests(), 0, "sent while another process held it");
        tokio::time::sleep(Duration::from_secs(1)).await;
        oauth
            .storage
            .save(&key, RESOURCE, &token("a2", Some("r2"), false))
            .expect("the holder stores afresh");
        drop(holder);

        probing
            .await
            .expect("the probe joins")
            .expect("the probe succeeds when the lease frees in time");
        // The token step adopted the fresh token the holder stored.
        let cached = oauth
            .current_token
            .read()
            .clone()
            .expect("the probe cached its token");
        assert_eq!(
            cached.access_token, "a2",
            "the probe did not adopt the fresh token"
        );
        assert_eq!(
            backend.rebuilds_attempted.load(Ordering::SeqCst),
            0,
            "the probe rebuilt over a freed lease"
        );
        assert_eq!(
            backend.circuit_breaker_stats().current_failures,
            before,
            "a freed lease sampled as a backend failure"
        );
        assert!(
            !backend.is_circuit_tripped(),
            "the probe tripped the breaker on a freed lease"
        );
        assert_eq!(server.requests(), 0, "an adoption sends nothing");
    })
    .await
    .expect("a freed lease answers inside twice the probe timeout");
}

/// T13d: a dispatch through `Backend::request` whose token step meets a busy
/// lock leaves the breaker's failure count unchanged. The probe never calls
/// `record_dispatch_error`, so only this path pins the exclusion; on the base
/// the marked error counts and the row is red. An unmarked
/// `BackendUnavailable` is still sampled, so skipping every such error fails.
#[tokio::test(start_paused = true)]
async fn t13d_dispatch_skips_breaker_on_busy() {
    tokio::time::timeout(CREDENTIAL_LOCK_WAIT * 2, async {
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
        assert!(
            is_credential_lock_busy(&error),
            "not the marked error: {error}"
        );
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

        // Unmarked: the same variant without the busy text still samples.
        let plain = crate::backend::Backend::new(
            "t13d-plain",
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        plain.set_transport_for_test(
            Arc::new(UnmarkedTransport) as Arc<dyn crate::transport::Transport>
        );
        let before = plain.circuit_breaker_stats().current_failures;
        let error = plain
            .request("tools/list", None)
            .await
            .expect_err("an unmarked failure answers no tools");
        assert!(
            !is_credential_lock_busy(&error),
            "an unmarked error reads busy: {error}"
        );
        assert!(
            matches!(error, Error::BackendUnavailable(_)),
            "not the variant: {error:?}"
        );
        assert!(
            plain.circuit_breaker_stats().current_failures > before,
            "an unmarked failure was not sampled"
        );
    })
    .await
    .expect("both dispatches answer at once");
}
