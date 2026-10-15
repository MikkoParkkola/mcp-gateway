// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the close-watch lease that ties a held raw subject's lifetime
//! to its stream. A session retains only a weak subject registration plus a
//! close receiver; the lease itself is owned by the stream's view, so the
//! last view clone dropping is what signals closure.

use std::sync::Weak;

use tokio::sync::watch;

use super::ViewSubject;

/// The one strong custody handle, owned only by a `StreamView`. It owns a
/// watch sender and nothing secret-bearing; dropping it publishes closure
/// to every retained receiver.
pub(super) struct CloseLease {
    sender: watch::Sender<bool>,
}

impl CloseLease {
    pub(super) fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }
}

impl Drop for CloseLease {
    fn drop(&mut self) {
        self.sender.send_replace(true);
    }
}

/// One admitted attachment as a session may retain it: a weak subject and
/// the retained close receiver for that attachment's lease. Neither field
/// owns plaintext or a strong stream lease.
pub(super) struct ActiveView {
    subject: Weak<ViewSubject>,
    close: watch::Receiver<bool>,
}

impl std::fmt::Debug for ActiveView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveView").finish_non_exhaustive()
    }
}

impl ActiveView {
    pub(super) fn new(subject: Weak<ViewSubject>, close: watch::Receiver<bool>) -> Self {
        Self { subject, close }
    }

    pub(super) fn subject_weak(&self) -> Weak<ViewSubject> {
        self.subject.clone()
    }

    pub(super) fn close_receiver(&self) -> watch::Receiver<bool> {
        self.close.clone()
    }

    pub(super) fn is_closed(&self) -> bool {
        is_closed(&self.close)
    }

    /// Closed, or its subject already gone: safe to prune. The transient
    /// upgrade is dropped with the check.
    pub(super) fn is_dead(&self) -> bool {
        self.is_closed() || self.subject.upgrade().is_none()
    }
}

/// Whether `close` has retained a closure signal.
pub(super) fn is_closed(close: &watch::Receiver<bool>) -> bool {
    *close.borrow()
}

/// Wait until `close` signals closure. A sender that is gone has already
/// published through `Drop`, so channel closure is closure too.
pub(super) async fn wait_closed(mut close: watch::Receiver<bool>) {
    loop {
        if is_closed(&close) {
            return;
        }
        if close.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wait_closed;

    #[tokio::test]
    async fn wait_closed_returns_when_the_sender_is_gone() {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        drop(sender);
        assert!(!*receiver.borrow(), "premise: the retained value is false");
        assert!(
            receiver.has_changed().is_err(),
            "premise: the native channel reports closed"
        );
        let started = tokio::time::Instant::now();
        if let Err(elapsed) =
            tokio::time::timeout(std::time::Duration::from_secs(5), wait_closed(receiver)).await
        {
            panic!(
                "VOID: wait_closed did not complete after sender drop: \
                 {elapsed} (actual elapsed {:?})",
                started.elapsed()
            );
        }
    }
}
