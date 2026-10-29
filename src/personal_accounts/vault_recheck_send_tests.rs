// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-send recheck of a managed lease: what says the grant is gone
//! (definitive: the slot is evicted) and what says nothing about it
//! (transient: this send fails, the slot stays). A child of `vault_tests`, so
//! its fixtures are shared, not copied.

use super::*;
use crate::transport::Refusal;

/// What the scripted custody answers a `release` with, set after the mint.
#[derive(Clone, Copy)]
enum Release {
    /// Release as the real custody does.
    Pass,
    /// Refuse with this custody error.
    Fail(fn() -> CustodyError),
    /// Release, but report the access token as already expired.
    Expired,
}

/// Real custody whose `release` can be scripted once the dispatch has minted.
struct ScriptedRelease {
    inner: Arc<dyn AccountCustody>,
    mode: parking_lot::Mutex<Release>,
}

#[async_trait::async_trait]
impl AccountCustody for ScriptedRelease {
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
        let mode = *self.mode.lock();
        match mode {
            Release::Pass => self.inner.release(lease).await,
            Release::Fail(error) => Err(error()),
            Release::Expired => {
                self.inner
                    .release(lease)
                    .await
                    .map(|released| ReleasedCredentials {
                        expires_at: 0,
                        ..released
                    })
            }
        }
    }

    async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        self.inner.refresh_after_rejection(lease).await
    }
}

/// A dispatch's managed lease over a store seeded with alice's live grant,
/// the vault that released it, and the handle that can still change the grant.
struct Leased {
    vault: Arc<VaultStrategy>,
    held: ManagedLease,
    script: Arc<ScriptedRelease>,
    handle: Arc<CustodyHandle<CountingProvider, SilentObserver>>,
    account: AccountKey,
    _tmp: tempfile::TempDir,
}

async fn lease_alice() -> Leased {
    let alice = identity();
    let account = key_for(Principal::Verified(&alice));
    let tmp = tempfile::TempDir::new().expect("root");
    seed(
        tmp.path(),
        &[(account.clone(), unexpired_grant(ALICE_TOKEN))],
    );
    let handle = Arc::new(
        CustodyHandle::start(
            store_config(tmp.path()),
            CountingProvider {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            SilentObserver,
            4,
        )
        .expect("custody starts against a seeded store"),
    );
    let script = Arc::new(ScriptedRelease {
        inner: Arc::clone(&handle) as Arc<dyn AccountCustody>,
        mode: parking_lot::Mutex::new(Release::Pass),
    });
    let vault = Arc::new(VaultStrategy::new(
        Arc::clone(&script) as Arc<dyn AccountCustody>,
        descriptor(),
        seeded_revision(),
        false,
    ));
    let (_credential, held) = vault
        .prepare_held_classified(Principal::Verified(&alice), &backend())
        .await
        .expect("the seeded grant leases");
    Leased {
        vault,
        held,
        script,
        handle,
        account,
        _tmp: tmp,
    }
}

#[test]
fn a_live_grant_passes_the_send_recheck() {
    block_on(async {
        let leased = lease_alice().await;
        assert_eq!(leased.held.recheck_send(&leased.vault).await, Ok(()));
    });
}

#[test]
fn a_revoked_grant_is_definitive() {
    block_on(async {
        let leased = lease_alice().await;
        leased
            .handle
            .invalidate(&leased.account)
            .await
            .expect("revocation applies");
        assert_eq!(
            leased.held.recheck_send(&leased.vault).await,
            Err(Refusal::Definitive),
            "a grant revoked after the mint must evict the slot"
        );
    });
}

#[test]
fn a_busy_or_stopping_custody_is_transient() {
    block_on(async {
        let leased = lease_alice().await;
        for error in [(|| CustodyError::Busy) as fn() -> CustodyError, || {
            CustodyError::ShuttingDown
        }] {
            *leased.script.mode.lock() = Release::Fail(error);
            assert_eq!(
                leased.held.recheck_send(&leased.vault).await,
                Err(Refusal::Transient),
                "a fault that says nothing about the grant must not evict"
            );
        }
    });
}

#[test]
fn a_store_fault_is_transient() {
    block_on(async {
        let leased = lease_alice().await;
        *leased.script.mode.lock() =
            Release::Fail(|| CustodyError::Account(AccountServiceError::ProviderUnavailable));
        assert_eq!(
            leased.held.recheck_send(&leased.vault).await,
            Err(Refusal::Transient)
        );
    });
}

#[test]
fn a_reconnect_requirement_is_definitive() {
    block_on(async {
        let leased = lease_alice().await;
        *leased.script.mode.lock() =
            Release::Fail(|| CustodyError::Account(AccountServiceError::ReconnectRequired));
        assert_eq!(
            leased.held.recheck_send(&leased.vault).await,
            Err(Refusal::Definitive)
        );
    });
}

#[test]
fn a_replaced_vault_is_definitive() {
    block_on(async {
        let leased = lease_alice().await;
        // Another install over the same custody: not the instance that released.
        let replacement = Arc::new(VaultStrategy::new(
            Arc::clone(&leased.script) as Arc<dyn AccountCustody>,
            descriptor(),
            seeded_revision(),
            false,
        ));
        assert_eq!(
            leased.held.recheck_send(&replacement).await,
            Err(Refusal::Definitive),
            "a lease cannot be rechecked by custody other than its own"
        );
    });
}

#[test]
fn a_token_past_its_durable_expiry_is_definitive() {
    block_on(async {
        let leased = lease_alice().await;
        *leased.script.mode.lock() = Release::Expired;
        assert_eq!(
            leased.held.recheck_send(&leased.vault).await,
            Err(Refusal::Definitive),
            "the lease still matches, but the token it releases has run out"
        );
    });
}

/// A lease retired while its account stays connected (a refreshed token, a
/// moved generation) refuses this loan only: the slot is not evicted, and the
/// user's next dispatch mints the new lease.
#[test]
fn a_retired_lease_on_a_connected_account_refuses_this_loan_only() {
    block_on(async {
        let leased = lease_alice().await;
        *leased.script.mode.lock() = Release::Fail(|| {
            CustodyError::Account(
                crate::personal_accounts::service::AccountServiceError::LeaseRetired,
            )
        });
        assert_eq!(
            leased.held.recheck_send(&leased.vault).await,
            Err(Refusal::ThisLoan),
            "the account is still connected: one refused send, no eviction"
        );
    });
}
