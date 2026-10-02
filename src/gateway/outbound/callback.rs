// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! E1: the MIK-7630 event delivery sink (design §4.1). The frame commits
//! when its body is handed to the HTTP client, whatever the answer, because a
//! recipient can read the body and then fail.

use std::future::Future;

use super::{OutboundFrame, Payload};
use crate::events::CallbackFailure;

/// What the callback sender reports back to [`send_callback`].
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the MIK-7630 event sender converts to it (design row E1, #2651)"
    )
)]
pub(crate) enum CallbackSend<T> {
    /// Nothing left the process (a refused literal, DNS or connect failure
    /// before any byte): the frame's reservation is released.
    NotSent(CallbackFailure),
    /// The body was handed to the HTTP client: the frame commits, whatever
    /// the answer.
    Sent(Result<T, CallbackFailure>),
}

/// Serialize `frame` and hand the bytes to `post` (the events lane's signed
/// callback client). `principal` is the subscription's; a frame judged for
/// another key is dropped, never sent.
///
/// # Errors
/// The sender's failure, or `ConnectionRefused` for a frame that is not a
/// callback body or is bound to another principal.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the MIK-7630 event sender converts to it (design row E1, #2651)"
    )
)]
pub(crate) async fn send_callback<T, F, Fut>(
    frame: OutboundFrame,
    principal: &str,
    post: F,
) -> Result<T, CallbackFailure>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = CallbackSend<T>>,
{
    if !frame.bound_to(principal) {
        tracing::warn!("tenant_read: a callback frame judged for another principal was dropped");
        return Err(CallbackFailure::ConnectionRefused);
    }
    let Payload::Callback(body) = &frame.payload else {
        return Err(CallbackFailure::ConnectionRefused);
    };
    let body = serde_json::to_vec(body).unwrap_or_default();
    // From here the body may be on the wire: if this future is dropped while
    // the post is in flight (a cancelled worker), the frame still commits.
    // Only a sender that reports nothing left the process releases it.
    let mut pending = CommitOnDrop(Some(frame));
    match post(body).await {
        CallbackSend::NotSent(failure) => {
            pending.release();
            Err(failure)
        }
        CallbackSend::Sent(result) => result,
    }
}

/// Commits its frame when dropped, unless released first.
struct CommitOnDrop(Option<OutboundFrame>);

impl CommitOnDrop {
    /// Nothing was sent: drop the frame without committing it.
    fn release(&mut self) {
        self.0 = None;
    }
}

impl Drop for CommitOnDrop {
    fn drop(&mut self) {
        if let Some(frame) = self.0.take() {
            frame.written();
        }
    }
}
