// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 rows O1 and O2 (s2-t0 section E): every custody answer a
//! mint-free view read can get maps to one exact account outcome, and
//! `view_binding` is `view_binding_checked(..).ok()` for each of them.
//! Custody is scripted at its trait seam; the vault and the mapping are the
//! production code.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::view_outcome;
use crate::gateway::meta_mcp::visible::AccountOutcome;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::identity::{AccountDescriptor, Principal};
use crate::personal_accounts::{
    AccountCustody, AccountError, AccountKey, AccountServiceError, CredentialLease, CustodyError,
    RejectionOutcome, ReleasedCredentials, VaultStrategy,
};

const REVISION: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What `resolve` answers, chosen per case.
#[derive(Clone, Copy, Debug)]
enum Answer {
    Lease { revision: &'static str },
    ConnectOffer,
    Revoked,
    ReconnectRequired,
    Busy,
    ShuttingDown,
    StoreError,
}

/// Custody that answers `resolve` as scripted and counts the reads. Nothing
/// else is reachable from a mint-free view.
struct Scripted {
    answer: Answer,
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl AccountCustody for Scripted {
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let refused = |error| Err(CustodyError::Account(error));
        match self.answer {
            Answer::Lease { revision } => Ok(CredentialLease {
                account: account.clone(),
                generation: "fedcba9876543210fedcba9876543210".into(),
                authorization_epoch: 1,
                scopes: Vec::new(),
                descriptor_revision: revision.into(),
                token_revision: 1,
            }),
            Answer::ConnectOffer => refused(AccountServiceError::ConnectOffer),
            Answer::Revoked => refused(AccountServiceError::Revoked),
            Answer::ReconnectRequired => refused(AccountServiceError::ReconnectRequired),
            Answer::Busy => Err(CustodyError::Busy),
            Answer::ShuttingDown => Err(CustodyError::ShuttingDown),
            Answer::StoreError => {
                refused(AccountServiceError::Store(AccountError::StorageUnavailable))
            }
        }
    }

    async fn refresh_if_expired(
        &self,
        _account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        unreachable!("a view read never refreshes")
    }

    async fn release(&self, _lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        unreachable!("a view read never releases")
    }

    async fn refresh_after_rejection(
        &self,
        _lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        unreachable!("a view read never forces a refresh")
    }
}

fn vault(answer: Answer) -> (VaultStrategy, Arc<Scripted>) {
    let custody = Arc::new(Scripted {
        answer,
        reads: AtomicUsize::new(0),
    });
    let descriptor = AccountDescriptor {
        descriptor_id: "work-gmail".into(),
        provider: "google".into(),
        resource: "https://gmail.googleapis.com".into(),
        issuer: "https://accounts.google.com".into(),
    };
    let strategy = VaultStrategy::new(
        Arc::clone(&custody) as Arc<dyn AccountCustody>,
        descriptor,
        REVISION.into(),
        true,
    );
    (strategy, custody)
}

/// The production mapping with no slot rule refusing (the slot rules are
/// T8/T10's, on a real backend).
fn outcome(view: Result<String, crate::identity_propagation::PropagationError>) -> AccountOutcome {
    view_outcome(view, |_| false)
}

/// O1 + O2, one case per custody answer; M7 (Unavailable read as NoView)
/// and M22 (a `view_binding` that is not `checked(..).ok()`) fail here.
#[tokio::test]
async fn o1_o2_each_custody_answer_maps_to_one_exact_outcome() {
    let cases = [
        (Answer::Lease { revision: REVISION }, AccountOutcome::Live),
        (Answer::ConnectOffer, AccountOutcome::NoView),
        (Answer::Revoked, AccountOutcome::NoView),
        (Answer::ReconnectRequired, AccountOutcome::NoView),
        // The descriptor fence: a grant stored under another revision.
        (
            Answer::Lease {
                revision: "1111111111111111111111111111111111111111111111111111111111111111",
            },
            AccountOutcome::NoView,
        ),
        (Answer::Busy, AccountOutcome::Unavailable),
        (Answer::ShuttingDown, AccountOutcome::Unavailable),
        (Answer::StoreError, AccountOutcome::Unavailable),
    ];
    for (answer, expected) in cases {
        let (strategy, custody) = vault(answer);
        let checked = strategy.view_binding_checked(Principal::SoleOperator).await;
        let plain = strategy.view_binding(Principal::SoleOperator).await;
        assert_eq!(plain, checked.as_ref().ok().cloned(), "O2 {answer:?}");
        assert_eq!(outcome(checked), expected, "O1 {answer:?}");
        assert_eq!(
            custody.reads.load(Ordering::SeqCst),
            2,
            "{answer:?}: one read each"
        );
    }
}

/// A slot rule refusing the binding the vault handed back is no view.
#[test]
fn a_binding_the_slot_rule_refuses_is_no_view() {
    assert_eq!(
        view_outcome(Ok("acct:v1:x".into()), |_| true),
        AccountOutcome::NoView
    );
}

/// A principal no account key can be built for is refused before custody,
/// as `Refuse`, and so reads as Unavailable (retryable). Pinned on purpose:
/// it is a permanent condition answered as a transient one, raised to the
/// lead with this row.
#[tokio::test]
async fn an_unbindable_principal_reads_unavailable_without_a_custody_read() {
    let (strategy, custody) = vault(Answer::Lease { revision: REVISION });
    let nameless = VerifiedIdentity {
        subject: String::new(),
        email: "nobody@example.invalid".into(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".into(),
    };
    let checked = strategy
        .view_binding_checked(Principal::Verified(&nameless))
        .await;
    assert_eq!(outcome(checked), AccountOutcome::Unavailable);
    assert_eq!(custody.reads.load(Ordering::SeqCst), 0);
}
