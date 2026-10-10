// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The receive-only boundary of an upstream task submission (MIK-7642 PR.D,
//! design r9 R9.1 / r10 R10.1).
//!
//! A task worker scopes one [`SubmitMark`] around its dispatch. The HTTP
//! transport arms it for the one task-capability `tools/call` it sends, and
//! sets `submitted` when that POST's `send()` returns: the response head
//! (status and headers) is in. From then on the only work left in the dispatch
//! is reading the body and the checks up to `offer`, so a worker that sees a
//! cancel may poll the dispatch once more to collect a handle and can never
//! cause anything to be sent. Before it, every step (connect, pool checkout,
//! TLS, writing the request) is send progress, and a cancel there drops the
//! dispatch without polling it again.
//!
//! The request body is a small, fully buffered JSON value, so "head received"
//! also means "request written". A streamed request body would need this
//! boundary re-examined: HTTP/1 is full duplex and a head can precede the end
//! of the write.
//!
//! Owned by the transport layer, so nothing in `transport/` names the task
//! service.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// One worker's view of its submission's progress.
#[derive(Debug, Default)]
pub(crate) struct SubmitMark {
    /// The task-capability POST is the exchange in flight.
    armed: AtomicBool,
    /// That POST's response head arrived.
    submitted: AtomicBool,
}

impl SubmitMark {
    /// Whether the submission's response head arrived, so a rescue poll can
    /// only receive.
    pub(crate) fn submitted(&self) -> bool {
        self.submitted.load(Ordering::Acquire)
    }
}

tokio::task_local! {
    static SUBMIT_MARK: Arc<SubmitMark>;
}

/// Run `future` with `mark` as this task's submit mark.
pub(crate) async fn with_submit_mark<F: Future>(mark: Arc<SubmitMark>, future: F) -> F::Output {
    SUBMIT_MARK.scope(mark, future).await
}

/// Arm the scoped mark for the task-capability exchange about to be sent. A
/// no-op outside a worker's scope.
pub(crate) fn arm() {
    let _ = SUBMIT_MARK.try_with(|mark| mark.armed.store(true, Ordering::Release));
}

/// Disarm the scoped mark once that exchange ended, so no later request in the
/// same dispatch can set it.
pub(crate) fn disarm() {
    let _ = SUBMIT_MARK.try_with(|mark| mark.armed.store(false, Ordering::Release));
}

/// The armed exchange's response head arrived. A no-op when no task-capability
/// exchange is armed, so an ordinary request can never set it.
pub(crate) fn response_head_received() {
    let _ = SUBMIT_MARK.try_with(|mark| {
        if mark.armed.load(Ordering::Acquire) {
            mark.submitted.store(true, Ordering::Release);
        }
    });
}
