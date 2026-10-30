// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lent credential's per-send check at the backend: a definitive refusal
//! evicts exactly the refusing slot and ends the retries; a transient one
//! does neither. The transport here does what the HTTP transport does before
//! a lent send (find the loan by the call's headers, run its check, record a
//! refusal), so the rows judge the backend's side of it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::Value;

use super::Backend;
use super::slot_eviction_tests::{
    binding_and_prefix, per_user_backend, slot, subscriber_credential,
};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::{Lender, LentCredential, Refusal, ResendPermission, SendCheck, Transport};
use crate::{Error, Result};

/// A slot transport that runs the lent credential's check before each send.
struct CheckingUpstream {
    lender: Arc<Lender>,
    sends: AtomicUsize,
}

#[async_trait]
impl Transport for CheckingUpstream {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::BackendUnavailable("no loan, no send".to_string()))
    }

    async fn request_with_headers(
        &self,
        _method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: ResendPermission,
    ) -> Result<JsonRpcResponse> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        let loans = self.lender.matching_all(extra_headers);
        let refused = || Error::Transport("send refused".to_string());
        if loans.is_empty() {
            return Err(refused());
        }
        for loan in &loans {
            let Some(check) = loan.check.as_ref() else {
                return Err(refused());
            };
            if loan.refused.is_some() {
                return Err(refused());
            }
            if let Err(refusal) = check().await {
                self.lender.refuse(loan.id, refusal);
                return Err(refused());
            }
        }
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// A check that passes `passes` times, then refuses with `refusal`.
fn passes_then(passes: usize, refusal: Refusal) -> SendCheck {
    let left = Arc::new(AtomicUsize::new(passes));
    Arc::new(move || {
        let left = Arc::clone(&left);
        Box::pin(async move {
            let had = left
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if had { Ok(()) } else { Err(refusal) }
        })
    })
}

fn checked(binding: &str, check: SendCheck) -> LentCredential {
    LentCredential {
        headers: subscriber_credential(binding).into(),
        check: Some(check),
    }
}

/// A per-user slot over a `CheckingUpstream`, ready to dispatch on.
async fn checked_slot(name: &str) -> (Arc<Backend>, String, Arc<CheckingUpstream>) {
    let backend = per_user_backend(name);
    let (binding, _) = binding_and_prefix("alice", super::slot_eviction_tests::AUDIENCE).await;
    let entry = backend
        .pooled_entry(&slot(&binding))
        .expect("slot admitted");
    let upstream = Arc::new(CheckingUpstream {
        lender: Arc::clone(&entry.lender),
        sends: AtomicUsize::new(0),
    });
    backend.set_pooled_transport_for_test(
        &slot(&binding),
        Arc::clone(&upstream) as Arc<dyn Transport>,
    );
    (backend, binding, upstream)
}

async fn ping(backend: &Backend, binding: &str, credential: &LentCredential) -> Result<()> {
    backend
        .request_with_headers_lent("ping", None, credential.clone(), Some(binding))
        .await
        .map(|_| ())
}

#[tokio::test]
async fn a_grant_revoked_between_two_sends_refuses_the_second_and_evicts_the_slot() {
    let (backend, binding, upstream) = checked_slot("send_check_evict").await;
    let credential = checked(&binding, passes_then(1, Refusal::Definitive));

    ping(&backend, &binding, &credential)
        .await
        .expect("the first send passes its check");
    assert!(backend.pool_has_slot_for_test(&slot(&binding)), "premise");
    ping(&backend, &binding, &credential)
        .await
        .expect_err("the second send is refused");

    assert!(
        !backend.pool_has_slot_for_test(&slot(&binding)),
        "a definitive refusal evicts the refusing slot"
    );
    assert_eq!(
        upstream.sends.load(Ordering::SeqCst),
        2,
        "the refused send is not resent"
    );
}

#[tokio::test]
async fn a_transient_refusal_fails_the_send_and_keeps_the_slot() {
    let (backend, binding, _upstream) = checked_slot("send_check_transient").await;
    let credential = checked(&binding, passes_then(0, Refusal::Transient));

    ping(&backend, &binding, &credential)
        .await
        .expect_err("a transient refusal fails closed");

    assert!(
        backend.pool_has_slot_for_test(&slot(&binding)),
        "a fault that says nothing about the grant must not evict"
    );
}

#[tokio::test]
async fn a_this_loan_refusal_keeps_the_slot() {
    let (backend, binding, _upstream) = checked_slot("send_check_this_loan").await;
    let credential = checked(&binding, passes_then(0, Refusal::ThisLoan));

    ping(&backend, &binding, &credential)
        .await
        .expect_err("a dispatch-scoped credential past its exp is refused");

    assert!(backend.pool_has_slot_for_test(&slot(&binding)), "no evict");
}

#[tokio::test]
async fn a_retry_stops_when_its_own_loan_was_refused() {
    let (backend, binding, upstream) = checked_slot("send_check_retry").await;
    let credential = checked(&binding, passes_then(0, Refusal::ThisLoan));

    ping(&backend, &binding, &credential)
        .await
        .expect_err("refused");

    assert_eq!(
        upstream.sends.load(Ordering::SeqCst),
        1,
        "a refused credential repeats its refusal, so it is not resent"
    );
}

#[tokio::test]
async fn a_refusal_from_a_replaced_entry_does_not_evict_its_replacement() {
    let (backend, binding, _upstream) = checked_slot("send_check_replaced").await;
    let old = backend.pooled_entry(&slot(&binding)).expect("old entry");
    let (_, prefix) = binding_and_prefix("alice", super::slot_eviction_tests::AUDIENCE).await;
    backend.evict_identity_slots(&prefix);
    let replacement = backend.pooled_entry(&slot(&binding)).expect("readmitted");
    assert!(!Arc::ptr_eq(&old, &replacement), "premise: a new entry");

    let loan = old
        .lender
        .lend(checked(&binding, passes_then(0, Refusal::Definitive)));
    old.lender.refuse(loan.id(), Refusal::Definitive);

    assert!(
        backend.pool_has_slot_for_test(&slot(&binding)),
        "the replacement stays"
    );
}

/// A routine refresh costs one refused send, never a stuck user: after a
/// this-loan refusal, the same user's next dispatch, under its fresh
/// credential, is served by the slot.
#[tokio::test]
async fn the_next_dispatch_after_a_this_loan_refusal_is_served() {
    let (backend, binding, _upstream) = checked_slot("send_check_next").await;
    let stale = checked(&binding, passes_then(0, Refusal::ThisLoan));
    ping(&backend, &binding, &stale)
        .await
        .expect_err("the stale lease is refused");

    let fresh = LentCredential {
        headers: vec![("Authorization".to_owned(), "Bearer refreshed".to_owned())].into(),
        check: Some(passes_then(1, Refusal::Definitive)),
    };
    ping(&backend, &binding, &fresh)
        .await
        .expect("the next dispatch is served under its fresh credential");
}

/// Choosing the unchecked public entry for a minted credential fails closed
/// rather than skipping the check.
#[tokio::test]
async fn the_public_unchecked_entry_fails_closed_on_a_lent_only_slot() {
    let (backend, binding, _upstream) = checked_slot("send_check_public_entry").await;
    let plain = subscriber_credential(&binding);

    let outcome = backend
        .request_with_headers("ping", None, &plain, Some(&binding))
        .await;

    assert!(
        outcome.is_err(),
        "a lent-only slot refuses an unchecked loan"
    );
    // The upstream counts refused attempts too; what matters is that each was
    // refused, which `outcome` shows. The HTTP transport's own refusal of an
    // unchecked loan is pinned in lent_slot.
}
