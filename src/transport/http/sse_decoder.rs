// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Incremental SSE decoder for backend streams (`MIK-7272.SUB.2b`).
//!
//! Decoding a fully-buffered body with `str::lines()` cannot work on a stream:
//! a chunk boundary may fall anywhere, and a notification is only reachable
//! once the whole body has arrived, which is one round-trip too late. This
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

use futures::StreamExt;

use crate::error::{Error, Result};
use crate::protocol::{JsonRpcMessage, JsonRpcResponse};

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
pub(crate) struct SseDecoder {
    buffer: Vec<u8>,
    max_pending_bytes: usize,
    /// Offset of the first byte of the partial, unterminated line.
    ///
    /// Without it every `push` rescans the whole retained event, which is
    /// quadratic in the frame size: a 10 MiB response arriving in 8 KiB chunks
    /// would rescan ~6 GB. The bound is still measured from the block start, so
    /// this cursor changes only where scanning *resumes*, never what counts.
    scan_pos: usize,
}

/// Next line at or after `pos`: the line's bytes and the offset past its
/// terminator.
///
/// `None` means "not yet decidable": no terminator, or a trailing lone `\r`
/// that a following chunk may complete into a CRLF. At EOF a trailing `\r` is
/// a bare-CR terminator and an unterminated remainder is a final line.
fn next_line(buf: &[u8], pos: usize, at_eof: bool) -> Option<(&[u8], usize)> {
    let rest = &buf[pos..];
    match rest.iter().position(|b| matches!(b, b'\n' | b'\r')) {
        Some(i) if rest[i] == b'\n' => Some((&rest[..i], pos + i + 1)),
        Some(i) => match rest.get(i + 1) {
            Some(b'\n') => Some((&rest[..i], pos + i + 2)),
            Some(_) => Some((&rest[..i], pos + i + 1)),
            None if at_eof => Some((&rest[..i], pos + i + 1)),
            None => None,
        },
        None if at_eof && !rest.is_empty() => Some((rest, buf.len())),
        None => None,
    }
}

/// Decode one block's lines into an event, or `None` when it carries no data.
fn build_event(block: &[u8]) -> Result<Option<SseEvent>> {
    let (mut event, mut data) = (None, Vec::new());
    let mut pos = 0;
    while let Some((line, next)) = next_line(block, pos, true) {
        pos = next;
        if line.is_empty() || line[0] == b':' {
            continue;
        }
        let line = std::str::from_utf8(line)
            .map_err(|_| Error::Transport("SSE line is not valid UTF-8".to_string()))?;
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match name {
            "event" => event = Some(value.to_string()),
            "data" => data.push(value),
            _ => {}
        }
    }
    let data = data.join("\n");
    // `data:` with nothing after it yields one empty line, not zero: the join,
    // not the line count, decides whether the block said anything.
    Ok((!data.is_empty()).then_some(SseEvent { event, data }))
}

impl SseDecoder {
    /// `max_pending_bytes` bounds the whole retained pending event: the
    /// `data:` lines already accumulated plus the partial line still buffered.
    /// Bytes leave the budget once an event is emitted.
    pub(crate) fn new(max_pending_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_pending_bytes,
            scan_pos: 0,
        }
    }

    /// Feed the next chunk; return every event it completed, in order.
    ///
    /// `Err` only when the retained *pending* event exceeds the bound, so a
    /// stream of any length decodes as long as single events stay bounded.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>> {
        self.buffer.extend_from_slice(chunk);
        self.decode(false)
    }

    /// End of stream: flush a final block not closed by a blank line.
    pub(crate) fn finish(&mut self) -> Result<Vec<SseEvent>> {
        self.decode(true)
    }

    fn oversized(&self, len: usize) -> Result<()> {
        if len > self.max_pending_bytes {
            return Err(Error::Transport(format!(
                "SSE event exceeded {} bytes without completing",
                self.max_pending_bytes
            )));
        }
        Ok(())
    }

    /// Scan the retained bytes, emitting every block a blank line closed.
    ///
    /// `block_start` is 0 on entry -- the previous call drained everything up
    /// to it -- so the retained event is `buffer[block_start..]` throughout.
    fn decode(&mut self, at_eof: bool) -> Result<Vec<SseEvent>> {
        let mut events = Vec::new();
        let (mut block_start, mut pos) = (0, self.scan_pos);
        while let Some((line, next)) = next_line(&self.buffer, pos, at_eof) {
            if !line.is_empty() {
                pos = next;
                continue;
            }
            self.oversized(pos - block_start)?;
            events.extend(build_event(&self.buffer[block_start..pos])?);
            block_start = next;
            pos = next;
        }
        if at_eof {
            self.oversized(self.buffer.len() - block_start)?;
            events.extend(build_event(&self.buffer[block_start..])?);
            self.buffer.clear();
            self.scan_pos = 0;
            return Ok(events);
        }
        self.oversized(self.buffer.len() - block_start)?;
        self.buffer.drain(..block_start);
        self.scan_pos = pos - block_start;
        Ok(events)
    }
}

/// Classify the events one chunk completed, publishing notifications as they
/// are seen and stopping at the response frame.
///
/// Publishing happens inside the loop, not after it: a notification that
/// arrived ahead of the response in the *same* chunk must still reach the sink
/// before this returns, because returning ends the caller's scope.
fn drain_events(events: Vec<SseEvent>) -> Result<Option<JsonRpcResponse>> {
    for event in events {
        let message: JsonRpcMessage = serde_json::from_str(&event.data)
            .map_err(|e| Error::Transport(format!("Failed to parse SSE data: {e}")))?;
        match message {
            JsonRpcMessage::Response(response) => return Ok(Some(response)),
            JsonRpcMessage::Notification(notification) => {
                tracing::debug!(method = %notification.method, "Notification on response stream");
                crate::transport::notification_sink::publish(vec![notification]);
            }
            JsonRpcMessage::Request(request) => {
                return Err(Error::Transport(format!(
                    "Peer sent request '{}' on the response stream",
                    request.method
                )));
            }
        }
    }
    Ok(None)
}

/// Drive an SSE body: publish each notification to the request-scoped sink as
/// it completes, and return the response frame when it arrives.
///
/// The caller maps its `reqwest::Error` to [`crate::error::Error::Transport`]
/// before feeding, so this driver is exercisable from a plain stream fixture.
pub(crate) async fn decode_sse_exchange<S>(stream: S) -> Result<JsonRpcResponse>
where
    S: futures::Stream<Item = Result<bytes::Bytes>>,
{
    let mut decoder = SseDecoder::new(MAX_PENDING_SSE_BYTES);
    tokio::pin!(stream);
    while let Some(chunk) = stream.next().await {
        if let Some(response) = drain_events(decoder.push(&chunk?)?)? {
            return Ok(response);
        }
    }
    if let Some(response) = drain_events(decoder.finish()?)? {
        return Ok(response);
    }
    Err(Error::Transport("No data in SSE response".to_string()))
}
