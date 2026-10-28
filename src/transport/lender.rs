// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user pool slot's lender (ADR-007 IDP.7): the credentials
//! the dispatches now in flight on the slot lend to its transport. A
//! lent-only transport sends only what is lent here, so a send with no
//! dispatch in flight (a session DELETE on close, a reconnect between calls)
//! has nothing to send as and is not sent.
//!
//! Every loan on one slot is its one principal's (the slot is keyed by that
//! principal's binding), and none outlives the dispatch that made it: the
//! [`Loan`] ends it when dropped, zeroing its copy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future::BoxFuture;
use zeroize::Zeroizing;

/// Why a lent credential's per-send check refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Revoked, unreleasable or past its published expiry: the slot is
    /// evicted, and no later send under this loan is tried.
    Definitive,
    /// Refused for this send only (a dispatch-scoped credential whose own
    /// `exp` passed): no later send under this loan is tried, the slot stays.
    ThisLoan,
    /// A fault that says nothing about the credential (a busy custody, a
    /// network or storage error): this send fails, the loan is not marked.
    Transient,
}

/// Whether a lent credential may be sent now; run before every send.
pub(crate) type SendCheck = Arc<dyn Fn() -> BoxFuture<'static, Result<(), Refusal>> + Send + Sync>;

/// A dispatch's credential and the check every send of it runs first. Only
/// the mint core attaches a check; headers from anywhere else carry none,
/// and a lent-only slot refuses a loan without one.
#[derive(Clone, Default)]
pub(crate) struct LentCredential {
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) check: Option<SendCheck>,
}

impl From<&[(String, String)]> for LentCredential {
    fn from(headers: &[(String, String)]) -> Self {
        Self {
            headers: headers.to_vec(),
            check: None,
        }
    }
}

/// One loan: its zeroed-on-drop headers, its check, and whether a check
/// refused it.
struct Lent {
    id: u64,
    headers: Zeroizing<Vec<(String, String)>>,
    check: Option<SendCheck>,
    refused: Option<Refusal>,
}

/// What a send needs of one loan, cloned out under the lock so nothing is
/// held across the check's await.
pub(crate) struct Snapshot {
    pub(crate) id: u64,
    pub(crate) headers: Zeroizing<Vec<(String, String)>>,
    pub(crate) check: Option<SendCheck>,
    pub(crate) refused: Option<Refusal>,
}

/// The loans of one slot, newest last.
#[derive(Default)]
pub(crate) struct Lender {
    loans: parking_lot::Mutex<Vec<Lent>>,
    next: AtomicU64,
    /// Run once a loan is refused definitively: the slot that owns this
    /// lender evicts itself, whether or not its dispatch is still awaited.
    evict: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl Lender {
    /// Lend `headers`, with no check, until the returned [`Loan`] drops.
    pub(crate) fn lend(self: &Arc<Self>, headers: &[(String, String)]) -> Loan {
        self.lend_credential(&LentCredential::from(headers))
    }

    /// Lend `credential` until the returned [`Loan`] drops.
    pub(crate) fn lend_credential(self: &Arc<Self>, credential: &LentCredential) -> Loan {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.loans.lock().push(Lent {
            id,
            headers: Zeroizing::new(credential.headers.clone()),
            check: credential.check.clone(),
            refused: None,
        });
        Loan {
            lender: Arc::clone(self),
            id,
        }
    }

    /// The credential of the newest dispatch in flight, if any lends one.
    pub(crate) fn now(&self) -> Option<Vec<(String, String)>> {
        self.loans.lock().last().map(|lent| lent.headers.to_vec())
    }

    /// The loan whose headers are exactly `headers`: the one the dispatch
    /// that sent them lent. Two live loans with identical headers carry one
    /// credential, so either one's check is a check on it.
    pub(crate) fn matching(&self, headers: &[(String, String)]) -> Option<Snapshot> {
        self.loans
            .lock()
            .iter()
            .find(|lent| lent.headers.as_slice() == headers)
            .map(Self::snapshot)
    }

    /// The live loan `id`, if its dispatch still runs.
    pub(crate) fn loan(&self, id: u64) -> Option<Snapshot> {
        self.loans
            .lock()
            .iter()
            .find(|lent| lent.id == id)
            .map(Self::snapshot)
    }

    fn snapshot(lent: &Lent) -> Snapshot {
        Snapshot {
            id: lent.id,
            headers: lent.headers.clone(),
            check: lent.check.clone(),
            refused: lent.refused,
        }
    }

    /// Record that loan `id`'s check refused. A definitive refusal runs the
    /// eviction hook once, at the refusal, so a dispatch dropped right after
    /// cannot skip it.
    pub(crate) fn refuse(&self, id: u64, refusal: Refusal) {
        if refusal == Refusal::Transient {
            return;
        }
        let first = {
            let mut loans = self.loans.lock();
            loans
                .iter_mut()
                .find(|lent| lent.id == id)
                .is_some_and(|lent| lent.refused.replace(refusal).is_none())
        };
        if first && refusal == Refusal::Definitive {
            if let Some(evict) = self.evict.lock().as_ref() {
                evict();
            }
        }
    }

    /// Set what a definitive refusal runs: the owning slot's eviction.
    pub(crate) fn on_definitive_refusal(&self, evict: Box<dyn Fn() + Send + Sync>) {
        *self.evict.lock() = Some(evict);
    }
}

/// One dispatch's loan; ends when dropped.
pub(crate) struct Loan {
    lender: Arc<Lender>,
    id: u64,
}

impl Loan {
    /// This loan's id within its lender.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Whether a check refused this loan, and how.
    pub(crate) fn refused(&self) -> Option<Refusal> {
        self.lender.loan(self.id).and_then(|lent| lent.refused)
    }
}

impl Drop for Loan {
    fn drop(&mut self) {
        self.lender.loans.lock().retain(|lent| lent.id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_owned(), value.to_owned())]
    }

    #[test]
    fn a_send_finds_its_own_loan_by_its_headers() {
        let lender = Arc::new(Lender::default());
        let first = lender.lend(&headers("one"));
        let _second = lender.lend(&headers("two"));
        let mine = lender.matching(&headers("one")).expect("its own loan");
        assert_eq!(mine.id, first.id(), "never the newest loan: its own");
        assert!(
            lender.matching(&headers("three")).is_none(),
            "no loan: nothing to send as"
        );
    }

    #[test]
    fn a_definitive_refusal_evicts_once_and_a_transient_one_marks_nothing() {
        let lender = Arc::new(Lender::default());
        let evicted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&evicted);
        lender.on_definitive_refusal(Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }));
        let loan = lender.lend(&headers("one"));
        lender.refuse(loan.id(), Refusal::Transient);
        assert_eq!(loan.refused(), None, "a transient fault marks nothing");
        lender.refuse(loan.id(), Refusal::Definitive);
        lender.refuse(loan.id(), Refusal::Definitive);
        assert_eq!(loan.refused(), Some(Refusal::Definitive));
        assert_eq!(
            evicted.load(Ordering::SeqCst),
            1,
            "evicted once, at the refusal"
        );
        let other = lender.lend(&headers("two"));
        lender.refuse(other.id(), Refusal::ThisLoan);
        assert_eq!(other.refused(), Some(Refusal::ThisLoan));
        assert_eq!(
            evicted.load(Ordering::SeqCst),
            1,
            "a this-loan refusal does not evict"
        );
    }

    #[test]
    fn a_loan_lends_only_while_held_and_the_newest_wins() {
        let lender = Arc::new(Lender::default());
        assert_eq!(lender.now(), None, "nothing lent: nothing to send as");
        let first = lender.lend(&headers("one"));
        assert_eq!(lender.now(), Some(headers("one")));
        let second = lender.lend(&headers("two"));
        assert_eq!(lender.now(), Some(headers("two")), "the newest dispatch's");
        drop(second);
        assert_eq!(lender.now(), Some(headers("one")), "the other still lends");
        drop(first);
        assert_eq!(lender.now(), None, "no dispatch in flight: nothing lent");
    }
}
