// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio answer over `max_frame_bytes` ends the stream, and the reader
//! clears every waiting call. Only the call whose answer it was learns it was
//! too large (`Error::ResponseTooLarge`, not retried); the others keep their
//! retryable error.
//!
//! The owner is named only when the cut frame's leading top-level keys are an
//! optional `jsonrpc`, then `id`, then `result` or `error`, all within
//! [`HEAD_BYTES`]. A frame that leads with `method` is never attributed, and a
//! notification never is, since it carries no id. Named limit: a peer request
//! that puts a `result` or `error` member before its `method` cannot be told
//! from an answer once cut, and is attributed; its reach is the one call
//! waiting on that same backend, which that backend could already fail.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::error::Error;

/// How much of a cut frame is read for its owner.
const HEAD_BYTES: usize = 4096;

/// One start's record of the call whose answer was over the limit: its
/// pending key and the limit. Fresh each start, so a replacement start can
/// neither erase nor fake an earlier start's record.
pub(super) type OversizeSlot = Arc<Mutex<Option<(String, usize)>>>;

/// The pending key of the call a cut frame answers, or `None`.
pub(super) fn oversize_owner(_head: &[u8]) -> Option<String> {
    None
}

/// After a read error: record the owner when the error is a frame over the
/// limit and its head names one.
pub(super) fn note_oversize(error: &std::io::Error, frame: &[u8], slot: &OversizeSlot) {
    let Some(super::tree::FrameTooLarge(max)) =
        error.get_ref().and_then(|inner| inner.downcast_ref())
    else {
        return;
    };
    if let Some(key) = oversize_owner(frame) {
        *slot.lock() = Some((key, *max));
    }
}

/// The refusal for call `key` when its own start recorded its answer as too
/// large.
pub(super) fn too_large_for(_slot: &OversizeSlot, _key: &str) -> Option<Error> {
    None
}

#[cfg(tp5)]
#[cfg(test)]
#[path = "stdio_oversize_tests.rs"]
mod tests;
