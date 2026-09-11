// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Incremental SSE decoder for backend streams (`MIK-7272.SUB.2b`).
//!
//! `parse_sse_response` decodes one fully-buffered body with `str::lines()`,
//! which cannot work on a stream: a chunk boundary may fall anywhere, and a
//! notification is only reachable once the whole body has arrived. This
//! decoder is sans-io -- bytes in, events out -- so the framing is testable
//! without a socket, and [`decode_sse_exchange`] drives it over a stream,
//! publishing notifications as each event completes.
//!
//! Contract pinned here so implementation and tests agree:
//! - Fields are `NAME:VALUE`; exactly one optional leading space is stripped
//!   from `VALUE` (the SSE rule), **not** `str::trim`.
//! - Line terminators are LF, CRLF and bare CR. A `\r` is removed per line
//!   before any join.
//! - Multiple `data:` fields in one block join with a single `\n`.
//! - A line with no colon, and a comment line (leading `:`), are skipped.
//! - A block whose `data` is empty is skipped, not an error.
//! - The pending-event bound covers the **whole retained event** -- every
//!   `data:` line already completed plus the partial line still in the byte
//!   buffer -- checked before the join allocates and reset once the event is
//!   emitted. Bounding only the undrained tail leaves a hole: a backend that
//!   sends a million short `data:` lines and never a blank line stays under a
//!   tail bound forever while the retained event grows without limit.
//! - [`SseDecoder::finish`] flushes a final block **not** terminated by a
//!   blank line, matching today's `str::lines()`, which accepts a last line
//!   without a trailing newline. Discarding it would silently regress
//!   backends that close without the blank line.

use crate::error::Result;
use crate::protocol::JsonRpcResponse;

/// Bytes of a still-incomplete event a stream may retain before the decoder
/// gives up.
///
/// Fixed on purpose, and deliberately not derived from
/// `ServerConfig::max_body_size`: that one is operator-tunable and governs the
/// gateway's own inbound listener, so a backend-frame bound inheriting from it
/// would shrink whenever an operator tightened an unrelated knob.
///
/// Generous on purpose too. While a legitimate response frame is arriving it
/// *is* the pending event, so tightening this toward "a retained tail should
/// be small" would reject large tool results -- exactly the defect this
/// decoder exists to remove.
pub(crate) const MAX_PENDING_SSE_BYTES: usize = 10 * 1024 * 1024;

/// One decoded `event:`/`data:` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseEvent {
    pub(crate) event: Option<String>,
    /// Every `data:` field of the block, joined with `\n`.
    pub(crate) data: String,
}

/// Byte-oriented SSE framer. Feed chunks in arrival order; take events out.
#[expect(
    dead_code,
    reason = "MIK-7272.SUB.2b (d): no lib caller until the decoder lands"
)]
pub(crate) struct SseDecoder {
    buffer: Vec<u8>,
    max_pending_bytes: usize,
}

#[expect(
    dead_code,
    reason = "MIK-7272.SUB.2b (d): no lib caller until the decoder lands"
)]
impl SseDecoder {
    /// `max_pending_bytes` bounds the whole retained pending event: the
    /// `data:` lines already accumulated plus the partial line still buffered.
    /// Bytes leave the budget once an event is emitted.
    pub(crate) fn new(max_pending_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_pending_bytes,
        }
    }

    /// Feed the next chunk; return every event it completed, in order.
    ///
    /// `Err` only when the retained *pending* event exceeds the bound, so a
    /// stream of any length decodes as long as single events stay bounded.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>> {
        let _ = (chunk, &self.buffer, self.max_pending_bytes);
        unimplemented!("MIK-7272.SUB.2b (d): incremental SSE decoder not implemented yet")
    }

    /// End of stream: flush a final block not closed by a blank line.
    pub(crate) fn finish(&mut self) -> Result<Vec<SseEvent>> {
        unimplemented!("MIK-7272.SUB.2b (d): incremental SSE decoder not implemented yet")
    }
}

/// Drive an SSE body: publish each notification to the request-scoped sink as
/// it completes, and return the response frame when it arrives.
///
/// The caller maps its `reqwest::Error` to [`crate::error::Error::Transport`]
/// before feeding, so this driver is exercisable from a plain stream fixture.
#[expect(
    dead_code,
    reason = "MIK-7272.SUB.2b (d): wired into the transport when the decoder lands"
)]
pub(crate) async fn decode_sse_exchange<S>(stream: S) -> Result<JsonRpcResponse>
where
    S: futures::Stream<Item = Result<bytes::Bytes>>,
{
    let _ = stream;
    unimplemented!("MIK-7272.SUB.2b (d): streaming SSE exchange not implemented yet")
}
