// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The propagation entry and the 401 fallthrough of the vault strategy
//! (MIK-8195 W5), split from `vault_tests.rs` to keep it under the file-size
//! ceiling. A child of that module, so its fixtures are shared, not copied.

use super::*;

/// MIK-8195 W5: the `IdentityPropagation` entry mints exactly what
/// [`VaultStrategy::prepare`] mints for the same verified identity: same
/// headers, binding and expiry. The MCP route reaches custody only through
/// this entry, so a mistake here would change every routed credential.
#[test]
fn the_propagation_entry_mints_what_prepare_mints_for_a_verified_identity() {
    let alice = identity();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(
        tmp.path(),
        &[(
            key_for(Principal::Verified(&alice)),
            unexpired_grant(ALICE_TOKEN),
        )],
    );
    block_on(async {
        let (vault, _) = strategy(tmp.path(), false);
        let (prepared, _) = vault
            .prepare(Principal::Verified(&alice), &backend())
            .await
            .expect("the seeded grant leases");
        let propagated = IdentityPropagation::propagate(&vault, &alice, &backend())
            .await
            .expect("the trait entry leases the same grant");
        assert_eq!(propagated.headers, prepared.headers);
        assert_eq!(propagated.cache_binding, prepared.cache_binding);
        assert_eq!(propagated.expires_at, prepared.expires_at);
    });
}

/// Real custody, except that the forced refresh after a 401 is refused for a
/// reason connecting cannot fix.
struct BusyOnRejection {
    inner: Arc<dyn AccountCustody>,
    error: fn() -> CustodyError,
}

#[async_trait::async_trait]
impl AccountCustody for BusyOnRejection {
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError> {
        self.inner.resolve(account).await
    }

    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        self.inner.refresh_if_expired(account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        self.inner.release(lease).await
    }

    async fn refresh_after_rejection(
        &self,
        _lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        Err((self.error)())
    }
}

/// MIK-8195 W5: after a backend 401, a custody refusal that connecting cannot
/// fix (busy, shutting down) leaves the backend's refusal exactly as it was:
/// no reconnect offer, no rejection mark. Mutant: the fallthrough returns a
/// reconnect refusal, which would send the user to re-consent for a full
/// queue.
#[test]
fn a_custody_refusal_reconnecting_cannot_fix_leaves_the_401_as_it_was() {
    let alice = identity();
    for error in [(|| CustodyError::Busy) as fn() -> CustodyError, || {
        CustodyError::ShuttingDown
    }] {
        let tmp = tempfile::TempDir::new().expect("root");
        seed(
            tmp.path(),
            &[(
                key_for(Principal::Verified(&alice)),
                unexpired_grant(ALICE_TOKEN),
            )],
        );
        block_on(async {
            let (inner, _) = custody(tmp.path());
            let vault = Arc::new(VaultStrategy::new(
                Arc::new(BusyOnRejection { inner, error }) as Arc<dyn AccountCustody>,
                descriptor(),
                seeded_revision(),
                false,
            ));
            let (_credential, held) = vault
                .prepare_held(Principal::Verified(&alice), &backend())
                .await
                .expect("the seeded grant leases");
            let refused = crate::Error::Config("backend answered 401".into());
            let answered = held.after_upstream_401(refused).await;
            assert_eq!(
                answered.to_string(),
                "Configuration error: backend answered 401",
                "{answered}"
            );
        });
    }
}
