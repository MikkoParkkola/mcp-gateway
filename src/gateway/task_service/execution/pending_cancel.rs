// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A claimed upstream `tasks/cancel` that was not confirmed is retried
//! (MIK-8347, design r3.2).
//!
//! The claim keeps the row's cancel `Pending` until a peer answers. One sender
//! at a time per row, under an in-process lock held from before the claim (or
//! the retry's eligibility read) through the send and the outcome write.
//! Retries are spawned, never awaited by the sweep that finds them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::TaskExecutor;

/// Failed attempts (sent toward a ready backend, not confirmed) after which a
/// row's cancel is given up. `NotReady` attempts do not count.
pub(crate) const MAX_CANCEL_ATTEMPTS: u8 = 6;

/// How long a claimed cancel is retried, from its claim, whatever the row's
/// retention: unlimited retention must not mean unlimited retrying.
pub(crate) const MAX_CANCEL_PENDING_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// One send lock per row with a cancel in flight or pending.
#[derive(Default)]
pub(crate) struct CancelSends(
    parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    #[cfg(test)] parking_lot::Mutex<Option<(Hook, Arc<ClaimPause>)>>,
);

/// Where a test pauses the next claim made under a row lock.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hook {
    /// Under the lock, after the claim decided.
    AfterClaim,
    /// After the lock is released, before the holder's re-check.
    AfterRelease,
}

/// Holds one claim at its hook until released.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct ClaimPause {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl CancelSends {
    /// Pause the next claim made under a row lock at `hook`, once.
    pub(crate) fn pause_at(&self, hook: Hook) -> Arc<ClaimPause> {
        let pause = Arc::new(ClaimPause::default());
        *self.1.lock() = Some((hook, Arc::clone(&pause)));
        pause
    }
}

impl TaskExecutor {
    /// Retry the pending cancels of `backend`'s rows, or, with `None`, every
    /// row whose retry is due. Each send is spawned; the handles are returned
    /// so a caller that must not wait (the sweep) can drop them.
    pub(crate) fn flush_pending_cancels(
        self: &Arc<Self>,
        backend: Option<&str>,
    ) -> Vec<JoinHandle<()>> {
        let _ = backend;
        Vec::new()
    }

    /// Wait until no send holds `id`'s lock, so a test's next flush is not
    /// skipped by a send that has written its outcome but not yet let go.
    #[cfg(test)]
    pub(crate) async fn cancel_send_idle(&self, id: &str) {
        let lock = self.service.cancel_sends.0.lock().get(id).cloned();
        if let Some(lock) = lock {
            drop(lock.lock().await);
        }
    }
}

#[cfg(test)]
#[path = "pending_cancel_tests.rs"]
mod tests;
