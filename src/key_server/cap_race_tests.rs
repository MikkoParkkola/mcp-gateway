// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The per-identity token cap holds under concurrent mints. A store that
//! holds every mint at its count until all of them have counted would show
//! a check-then-insert gap (each sees room, and each inserts); reservation
//! counts and claims in one step, so the held count never decides.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::sync::Barrier;

use super::InMemoryTokenStore;
use super::oidc_test_harness::{Harness, ISS_A, config_yaml};
use super::store::{
    ActivateError, ReservationId, ReservationRequest, ReserveError, TemporaryToken, TokenStore,
};

const CAP: usize = 2;
const MINTS: usize = 5;
const SUBJECT: &str = "cap-race-subject";
/// The config default token lifetime, which the harness config keeps.
const TTL: u64 = 3600;

/// The real store, with each of the first [`MINTS`] counts held until all of
/// them have counted. The wait is bounded, so a mint path that no longer
/// counts cannot hang the row.
struct HeldAtCount {
    inner: InMemoryTokenStore,
    barrier: Barrier,
    counts: AtomicUsize,
}

#[async_trait::async_trait]
impl TokenStore for HeldAtCount {
    fn reserve(
        &self,
        request: ReservationRequest,
        now: u64,
    ) -> Result<ReservationId, ReserveError> {
        self.inner.reserve(request, now)
    }
    fn activate(
        &self,
        id: &ReservationId,
        token: TemporaryToken,
        now: u64,
    ) -> Result<(), ActivateError> {
        self.inner.activate(id, token, now)
    }
    fn abort(&self, id: &ReservationId) {
        self.inner.abort(id);
    }
    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        self.inner.get(bearer).await
    }
    async fn revoke_by_jti(&self, jti: &str) -> bool {
        self.inner.revoke_by_jti(jti).await
    }
    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        self.inner.live_jti(jti, now).await
    }
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.revoke_by_subject(issuer, subject).await
    }
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        let seen = self.inner.count_for_subject(issuer, subject).await;
        if self.counts.fetch_add(1, Ordering::SeqCst) < MINTS {
            let _ = tokio::time::timeout(Duration::from_secs(2), self.barrier.wait()).await;
        }
        seen
    }
    async fn reap_expired(&self) -> usize {
        self.inner.reap_expired().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mints_never_pass_the_identity_cap() {
    let store = Arc::new(HeldAtCount {
        inner: InMemoryTokenStore::new(CAP, TTL),
        barrier: Barrier::new(MINTS),
        counts: AtomicUsize::new(0),
    });
    let yaml = config_yaml(
        "[]",
        &format!(
            "max_tokens_per_identity: {CAP}\npolicies:\n  - match: {{ issuer: \"{ISS_A}\" }}\n    \
             scopes: {{ backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }}\n"
        ),
    );
    let h = Arc::new(
        Harness::start_with_store(&yaml, |_| -> Arc<dyn TokenStore> { store.clone() }).await,
    );
    let mut mints = Vec::new();
    for _ in 0..MINTS {
        let h = Arc::clone(&h);
        mints.push(tokio::spawn(async move {
            h.exchange(&h.mint(ISS_A, SUBJECT, &json!({}))).await.0
        }));
    }
    let mut statuses = Vec::new();
    for mint in mints {
        statuses.push(
            tokio::time::timeout(Duration::from_secs(10), mint)
                .await
                .expect("a mint finished")
                .expect("a mint task"),
        );
    }
    statuses.sort_unstable();
    let active = store.inner.count_for_subject(ISS_A, SUBJECT).await;
    assert!(
        active <= CAP,
        "{active} active tokens for one identity under a cap of {CAP}; answers {statuses:?}"
    );
    assert_eq!(
        statuses,
        [[200_u16].repeat(CAP), [429_u16].repeat(MINTS - CAP)].concat(),
        "exactly the cap is minted and the rest refused without eviction"
    );
}
