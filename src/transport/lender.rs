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

use zeroize::Zeroizing;

/// Each loan's id and its zeroed-on-drop copy of the lent headers.
type Loans = Vec<(u64, Zeroizing<Vec<(String, String)>>)>;

/// The loans of one slot, newest last.
#[derive(Default)]
pub(crate) struct Lender {
    loans: parking_lot::Mutex<Loans>,
    next: AtomicU64,
}

impl Lender {
    /// Lend `headers` until the returned [`Loan`] drops.
    pub(crate) fn lend(self: &Arc<Self>, headers: &[(String, String)]) -> Loan {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.loans
            .lock()
            .push((id, Zeroizing::new(headers.to_vec())));
        Loan {
            lender: Arc::clone(self),
            id,
        }
    }

    /// The credential of the newest dispatch in flight, if any lends one.
    pub(crate) fn now(&self) -> Option<Vec<(String, String)>> {
        self.loans
            .lock()
            .last()
            .map(|(_, headers)| headers.to_vec())
    }
}

/// One dispatch's loan; ends when dropped.
pub(crate) struct Loan {
    lender: Arc<Lender>,
    id: u64,
}

impl Drop for Loan {
    fn drop(&mut self) {
        self.lender.loans.lock().retain(|(id, _)| *id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> Vec<(String, String)> {
        vec![("Authorization".to_owned(), value.to_owned())]
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
