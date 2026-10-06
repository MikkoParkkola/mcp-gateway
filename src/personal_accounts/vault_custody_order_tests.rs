// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7843: `prepare` refuses a wrong audience and an unbindable principal
//! before custody is consulted, counted at the custody seam itself.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// The real custody, with every call counted.
struct CountedCustody {
    inner: Arc<dyn AccountCustody>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AccountCustody for CountedCustody {
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(account).await
    }

    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.refresh_if_expired(account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.release(lease).await
    }

    async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.refresh_after_rejection(lease).await
    }
}

/// Mutant: a backend expecting another audience is minted for, or a principal
/// whose key cannot be built is minted for, before custody is consulted.
#[test]
fn prepare_refuses_a_wrong_audience_and_an_unbindable_principal_before_custody() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed_sole_operator(tmp.path());

    block_on(async {
        let (inner, _refreshes) = custody(tmp.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::new(CountedCustody {
            inner,
            calls: Arc::clone(&calls),
        });
        let vault = VaultStrategy::new(counted, descriptor(), seeded_revision(), true);

        let mut elsewhere = backend();
        elsewhere.audience = "https://other.invalid/".into();
        let refused = vault.prepare(Principal::SoleOperator, &elsewhere).await;
        assert!(
            matches!(refused, Err(PropagationError::Misconfigured(_))),
            "{refused:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "wrong audience: custody asked"
        );

        let mut nameless = identity();
        nameless.subject = String::new();
        let refused = vault
            .prepare(Principal::Verified(&nameless), &backend())
            .await;
        // The identity-binding refusal specifically: custody also refuses an
        // invalid key, with the same variant but its own text.
        let Err(PropagationError::Refuse(why)) = refused else {
            panic!("an unbindable principal must be refused: {refused:?}");
        };
        assert!(why.starts_with("account identity binding refused"), "{why}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "unbindable: custody asked");

        // Positive control: the same strategy and backend mint for the
        // operator, and the counter sees custody consulted.
        vault
            .prepare(Principal::SoleOperator, &backend())
            .await
            .expect("control: the seeded grant leases");
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "control: custody was consulted"
        );
    });
}
