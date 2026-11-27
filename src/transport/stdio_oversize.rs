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
pub(super) fn oversize_owner(head: &[u8]) -> Option<String> {
    let head = &head[..head.len().min(HEAD_BYTES)];
    let mut owner = None;
    // The frame is cut, so the parse always fails after the keys that decide;
    // the visitor has recorded the owner by then. serde reads keys unescaped
    // and skips nested values whole, so only depth-1 keys are ever compared.
    let _ = serde::Deserializer::deserialize_map(
        &mut serde_json::Deserializer::from_slice(head),
        Leading(&mut owner),
    );
    owner
}

/// Reads a frame's leading keys: `jsonrpc`?, `id`, then `result` or `error`.
struct Leading<'a>(&'a mut Option<String>);

impl<'de> serde::de::Visitor<'de> for Leading<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the leading keys of a JSON-RPC answer")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut key = map.next_key::<String>()?;
        if key.as_deref() == Some("jsonrpc") {
            map.next_value::<serde::de::IgnoredAny>()?;
            key = map.next_key()?;
        }
        if key.as_deref() != Some("id") {
            return Ok(());
        }
        // Built as the pending map builds its keys; an id no key can match
        // (a fraction, a value past i64, null, an object) fails here.
        let id: crate::protocol::RequestId = map.next_value()?;
        if matches!(
            map.next_key::<String>()?.as_deref(),
            Some("result" | "error")
        ) {
            *self.0 = Some(id.to_string());
        }
        Ok(())
    }
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
pub(super) fn too_large_for(slot: &OversizeSlot, key: &str) -> Option<Error> {
    match &*slot.lock() {
        Some((owner, limit)) if owner == key => Some(Error::ResponseTooLarge { limit: *limit }),
        _ => None,
    }
}

#[cfg(tp5)]
#[cfg(test)]
#[path = "stdio_oversize_tests.rs"]
mod tests;
