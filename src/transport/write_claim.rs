// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B`: whether a request frame reached the wire, decided once
//! between the writer and a caller that gave up.
//!
//! The writer claims the write before writing; a caller dropped before its
//! answer abandons the request. Whichever acts first wins: an abandoned frame
//! is never written, and a written one is the only kind worth cancelling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

const QUEUED: u8 = 0;
const WRITTEN: u8 = 1;
const ABANDONED: u8 = 2;

/// One request frame's write, shared by its caller and the writer.
#[derive(Debug, Default)]
pub(crate) struct WriteClaim(AtomicU8);

impl WriteClaim {
    pub(crate) fn new() -> Arc<Self> {
        Arc::default()
    }

    /// The writer's turn: true to write the frame, false to skip it because
    /// its caller already gave up.
    pub(crate) fn claim_write(&self) -> bool {
        self.0
            .compare_exchange(QUEUED, WRITTEN, Ordering::AcqRel, Ordering::Acquire)
            .map_or_else(|now| now == WRITTEN, |_| true)
    }

    /// The caller gave up before its answer: true if the frame was already
    /// written, so the backend has work to cancel.
    pub(crate) fn abandon(&self) -> bool {
        self.0
            .compare_exchange(QUEUED, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
            .is_err_and(|now| now == WRITTEN)
    }
}

/// The params of the `notifications/cancelled` every transport sends for a
/// request whose caller gave up, naming the id the backend received.
pub(crate) fn cancelled_params(id: &crate::protocol::RequestId) -> serde_json::Value {
    serde_json::json!({
        "requestId": id,
        "reason": "the gateway's caller abandoned the request",
    })
}

#[cfg(test)]
mod tests {
    use super::WriteClaim;

    #[test]
    fn the_first_of_write_and_abandon_wins() {
        let written = WriteClaim::new();
        assert!(written.claim_write());
        assert!(written.abandon(), "a written frame is cancelled");

        let abandoned = WriteClaim::new();
        assert!(
            !abandoned.abandon(),
            "an unwritten frame has nothing to cancel"
        );
        assert!(!abandoned.claim_write(), "and is never written");
    }
}
