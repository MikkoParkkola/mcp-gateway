// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.2 conjunct 3: live holders across a revoke and a re-consent.
//!
//! A refresh task that is still RUNNING and a credential whose cache entry is
//! still WARM are the two holders the criterion names. Both are held live at the
//! same instant, the grant is revoked and re-consented under a new generation,
//! and neither may use or reinstate the old grant afterwards. Same real custody,
//! registry, executor and response cache as `account_rest_tests.rs`; only the
//! refresh provider is scripted, so it can park one call.

use std::sync::Arc;

use serde_json::json;

use crate::personal_accounts::AccountCustody;

use super::super::account_resolver_fixture::{ALICE_WORK_TOKEN, WORK, account_key, grant};
use super::super::account_rest_fixture::{
    cacheable_base_url, cacheable_capability, caching_executor, capture_endpoint,
    installed_gateway, managed, prepared_caching_context,
};

/// A valid gateway-held `oauth:google` login, seeded as a trap: a refusal that
/// leaves it unused chose to fail closed with a working fallback in hand.
const LEGACY_TRAP_TOKEN: &str = "synthetic-operator-legacy-trap-token-3d0a";

/// Refresh provider for the live-holder case. Call 1 answers at once with a
/// rotation that is STILL expired, so the next refresh must go to the provider
/// again. Call 2 announces itself, then parks until the test releases it, and
/// only then answers with a rotation that must never land.
struct ParkingProvider {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

const FIRST_ROTATION_TOKEN: &str = "synthetic-alice-work-first-rotation-1a7c09";
const STALE_ROTATION_TOKEN: &str = "synthetic-alice-work-stale-rotation-9e04b3";
const RECONSENTED_TOKEN: &str = "synthetic-alice-work-reconsented-5d82f1";

impl crate::personal_accounts::RefreshProvider for ParkingProvider {
    fn refresh(
        &self,
        _account: &crate::personal_accounts::AccountKey,
        current: &crate::personal_accounts::GrantRecord,
    ) -> impl std::future::Future<
        Output = Result<
            crate::personal_accounts::TokenRefresh,
            crate::personal_accounts::ProviderRefreshError,
        >,
    > + Send {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let scopes = Some(current.scopes.clone());
        let parked = if call == 2 {
            let entered = self.entered.lock().unwrap().take();
            let release = self.release.lock().unwrap().take();
            Some((entered, release))
        } else {
            None
        };
        async move {
            let (access_token, expires_at) = match parked {
                None => (FIRST_ROTATION_TOKEN, 0),
                Some((entered, release)) => {
                    if let Some(entered) = entered {
                        let _ = entered.send(());
                    }
                    if let Some(release) = release {
                        let _ = release.await;
                    }
                    (STALE_ROTATION_TOKEN, u64::MAX)
                }
            };
            Ok(crate::personal_accounts::TokenRefresh {
                access_token: access_token.to_string(),
                refresh_token: None,
                scopes,
                token_type: "Bearer".into(),
                expires_at,
            })
        }
    }
}

/// STORE.2 CONJUNCT 3: A LIVE REFRESH TASK AND A WARM CACHED CREDENTIAL, BOTH
/// HELD ACROSS A REVOKE AND A RE-CONSENT, ARE RETIRED — NEITHER CAN USE NOR
/// REINSTATE THE OLD GRANT UNDER THE NEW GENERATION.
///
/// The neighbours each leave one holder out: the held-refresh service tests
/// revoke without re-consent (the stale rotation meets a tombstone) or
/// re-consent without a revoke; the warm-cache tests here have no refresh in
/// flight. Here both holders are live at once, and the stale rotation meets a
/// CONNECTED successor that differs from the version it expects ONLY in
/// generation — revision, epoch and descriptor revision are identical — so a
/// generation-blind compare-and-swap would let it land.
///
/// Two positive controls bracket the refusals: the cache is proven warm before
/// the revoke, and the successor is proven served on the wire after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered scenario: both holders must be live at the same instant across the \
              revoke and re-consent, so the steps cannot be split into separate tests"
)]
async fn a_live_refresh_and_a_warm_cached_credential_cannot_survive_revoke_and_reconsent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::personal_accounts::{
        ConsentExpectation, CustodyHandle, GrantVersion, PersonalAccountStore,
    };

    use super::super::account_resolver_fixture::{
        RECONNECT_GENERATION, RecordingObserver, store_config,
    };

    const BOUND: Duration = Duration::from_secs(10);

    let (port, captured) = capture_endpoint().await;
    let alice = account_key("alice", WORK);

    // G1, already expired: every refresh of it goes to the provider.
    let root = tempfile::TempDir::new().expect("tempdir");
    let config = store_config(root.path());
    let store = PersonalAccountStore::initialize(config.clone()).expect("store initialize");
    store
        .commit_grant(&alice, &grant(ALICE_WORK_TOKEN, 0))
        .expect("seed G1");
    drop(store);

    let calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let handle = Arc::new(
        CustodyHandle::start(
            config,
            ParkingProvider {
                calls: Arc::clone(&calls),
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(Some(release_rx)),
            },
            Arc::new(RecordingObserver::default()),
            4,
        )
        .expect("custody starts over the seeded store"),
    );
    let installed: Arc<dyn AccountCustody> = Arc::clone(&handle) as Arc<dyn AccountCustody>;
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let dir = tempfile::tempdir().expect("tempdir");
    let executor = caching_executor(&registry, Some((LEGACY_TRAP_TOKEN, &dir)));
    let capability = cacheable_capability(&cacheable_base_url(port), "oauth:google", Some(WORK));

    // HOLDER 2, populated: a credential prepared under G1 (refresh call 1) warms
    // the response cache.
    let prepared = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "G1 was expired, so prepare refreshed it"
    );
    let warm = executor
        .execute_with_context(&capability, json!({}), prepared.clone())
        .await
        .expect("the prepared G1 credential dispatches while G1 is current");
    assert_eq!(captured.count(), 1, "the cache must actually be warm");
    assert_eq!(
        warm["authorization"],
        json!(format!("Bearer {FIRST_ROTATION_TOKEN}")),
        "the warm entry is G1's rotated credential"
    );
    // The entry is USABLE, not merely written: the identical request is a hit.
    let hit = executor
        .execute_with_context(&capability, json!({}), prepared.clone())
        .await
        .expect("the identical G1 request is served while G1 is current");
    assert_eq!(hit, warm, "a warm hit returns the stored body verbatim");
    assert_eq!(captured.count(), 1, "the hit did not reach the wire");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the hit did not refresh");

    // The version both holders were issued under.
    let g1 = handle.resolve(&alice).await.expect("G1 is connected");
    assert_eq!(g1.token_revision, 2, "call 1 committed revision 2");

    // HOLDER 1, live: a refresh task parked inside the provider, holding G1's
    // expected version and the per-key flight lock.
    let held = {
        let handle = Arc::clone(&handle);
        let alice = alice.clone();
        tokio::spawn(async move { handle.refresh_if_expired(&alice).await })
    };
    tokio::time::timeout(BOUND, entered_rx)
        .await
        .expect("the refresh task must reach the provider")
        .expect("entered signal");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the held refresh is the second provider call"
    );
    assert!(
        !held.is_finished(),
        "the refresh task is live across the revoke"
    );

    // Revoke, then re-consent under a NEW generation that matches G1's version
    // in every other field.
    handle
        .invalidate(&alice)
        .await
        .expect("revoke through real custody");
    let version = GrantVersion {
        generation: g1.generation.clone(),
        token_revision: g1.token_revision,
        authorization_epoch: g1.authorization_epoch,
        descriptor_revision: g1.descriptor_revision.clone(),
    };
    let mut g2 = grant(RECONSENTED_TOKEN, u64::MAX);
    g2.generation = RECONNECT_GENERATION.to_string();
    g2.token_revision = g1.token_revision;
    g2.authorization_epoch = g1.authorization_epoch;
    g2.descriptor_revision = g1.descriptor_revision.clone();
    assert_ne!(
        g2.generation, g1.generation,
        "a re-consent boundary, not a bump"
    );
    handle
        .commit_grant_if(&alice, &ConsentExpectation::Revoked(version), &g2)
        .await
        .expect("re-consent publishes G2 through live custody");

    // HOLDER 1 retired: the stale rotation is refused as a retired lease.
    release_tx.send(()).expect("the provider is still parked");
    let stale = tokio::time::timeout(BOUND, held)
        .await
        .expect("the held refresh must finish once released")
        .expect("held refresh task");
    assert_eq!(
        format!(
            "{:?}",
            stale.expect_err("the stale rotation must not succeed")
        ),
        "Account(LeaseRetired)",
        "the refresh of G1 must be refused because G1 is no longer the grant"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "no further provider call");

    // Nothing reinstated: the live grant is exactly G2.
    let current = handle.resolve(&alice).await.expect("G2 is connected");
    assert_eq!(
        current.generation, g2.generation,
        "the live generation is G2"
    );
    assert_eq!(
        current.token_revision, g2.token_revision,
        "the stale rotation must not have advanced the revision"
    );
    let released = handle.release(&current).await.expect("G2 releases");
    assert!(
        released.access_token == RECONSENTED_TOKEN,
        "G2's own token is live, not the stale rotation"
    );

    // HOLDER 2 retired: the byte-identical request with the G1 credential is
    // refused before the warm entry and before the wire.
    let error = executor
        .execute_with_context(&capability, json!({}), prepared)
        .await
        .expect_err("a credential prepared under G1 must not be served under G2");
    let text = error.to_string();
    for token in [
        ALICE_WORK_TOKEN,
        FIRST_ROTATION_TOKEN,
        STALE_ROTATION_TOKEN,
        RECONSENTED_TOKEN,
        LEGACY_TRAP_TOKEN,
    ] {
        assert!(
            !text.contains(token),
            "the refusal must carry no token: {text}"
        );
    }
    assert_eq!(
        captured.count(),
        1,
        "neither the cache nor the wire answered"
    );

    // Positive control: a fresh resolve under G2 reaches the wire with G2.
    let fresh = prepared_caching_context(&registry, "alice", WORK, "oauth:google").await;
    let served = tokio::time::timeout(
        BOUND,
        executor.execute_with_context(&capability, json!({}), fresh),
    )
    .await
    .expect("the G2 dispatch must not hang")
    .expect("G2 dispatches");
    assert_eq!(
        served["authorization"],
        json!(format!("Bearer {RECONSENTED_TOKEN}")),
        "the successor's credential is served"
    );
    assert_eq!(
        captured.count(),
        2,
        "and it reached the real wire, not the G1 entry"
    );
    let authorizations = captured.authorizations();
    assert!(
        authorizations
            .iter()
            .flatten()
            .all(|value| !value.contains(STALE_ROTATION_TOKEN)),
        "the stale rotation never reached the wire: {authorizations:?}"
    );
    assert!(
        authorizations
            .iter()
            .skip(1)
            .flatten()
            .all(|value| !value.contains(FIRST_ROTATION_TOKEN)),
        "G1's credential never reached the wire after re-consent: {authorizations:?}"
    );
}
