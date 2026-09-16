// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One deterministic barrier for the revocation race, and nothing else.
//!
//! The question the barrier answers is "does the RELEASE-time recheck refuse a
//! credential whose grant was revoked after the lease was taken?". Revoking
//! before the whole lookup cannot answer it: the resolve would refuse first and
//! the recheck would never run. So this wrapper stops the resolution exactly at
//! the entry to `release`, after the lease is held, hands control to the test,
//! and only resumes when the test says so.
//!
//! IT IS A DELEGATING WRAPPER, NOT A SERVICE. Both trait methods —
//! `refresh_if_expired` and `release`, which are the whole of `AccountCustody` —
//! forward to the real production `CustodyHandle`. It stores nothing, decides
//! nothing, and re-implements no recheck. Release stays MANDATORY: after the
//! barrier the real `release` runs and its result — success or refusal — is
//! returned verbatim. Invalidation is NOT wrapped: the test performs the real
//! revocation directly on the `CustodyHandle` it started.
//!
//! NO SILENT AUTO-RELEASE. There is no timer here and no drop-triggered pass.
//! If the resume channel is dropped without an explicit resume, that is a test
//! defect and it panics loudly rather than quietly delegating. The bounded wait
//! belongs to the TEST (`tokio::time::timeout`), which is where a stall must be
//! reported as a failure.
//!
//! Only the FIRST release is gated. A test that drives one resolution through
//! the barrier and then continues gets ordinary custody behavior afterwards.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::personal_accounts::CustodyError;
use crate::personal_accounts::{AccountCustody, AccountKey};
use crate::personal_accounts::{CredentialLease, ReleasedCredentials};

/// The two ends the test drives the barrier with.
pub(super) struct ReleaseBarrier {
    /// Resolves once the resolution has reached the release entry with a lease
    /// in hand. Await it before mutating the store.
    pub(super) entered: oneshot::Receiver<()>,
    /// Send to let the real release proceed. Mandatory: nothing releases
    /// without it.
    pub(super) resume: oneshot::Sender<()>,
}

/// Delegating custody that pauses at the first `release`.
pub(super) struct GatedCustody {
    inner: Arc<dyn AccountCustody>,
    entered: Mutex<Option<oneshot::Sender<()>>>,
    resume: Mutex<Option<oneshot::Receiver<()>>>,
}

/// Wrap real custody in the barrier. The returned custody is what gets
/// installed on the gateway, so the resolution under test runs through the
/// production consumer with the production custody underneath it.
pub(super) fn gated(inner: Arc<dyn AccountCustody>) -> (Arc<GatedCustody>, ReleaseBarrier) {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    (
        Arc::new(GatedCustody {
            inner,
            entered: Mutex::new(Some(entered_tx)),
            resume: Mutex::new(Some(resume_rx)),
        }),
        ReleaseBarrier {
            entered: entered_rx,
            resume: resume_tx,
        },
    )
}

#[async_trait::async_trait]
impl AccountCustody for GatedCustody {
    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        self.inner.refresh_if_expired(account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        // Take both ends first: the barrier is armed once, and a later release
        // must not block on an already-consumed channel.
        let entered = self.entered.lock().take();
        let resume = self.resume.lock().take();
        if let (Some(entered), Some(resume)) = (entered, resume) {
            // The lease is held at this point; the test may now revoke.
            //
            // The receiver is dropped only when the test itself is gone, which
            // is a test failure that has already been reported — proceeding is
            // the honest behavior there, since release must still happen.
            let _ = entered.send(());
            resume
                .await
                .expect("the release barrier must be resumed explicitly; never on timeout or drop");
        }
        // Release is MANDATORY and unmodified: whatever the real recheck decides
        // is the answer the consumer sees.
        self.inner.release(lease).await
    }
}
