// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cross-tenant read history (MIK-7116.MIN.2, design
//! docs/design/2026-10-01-min2-min4-tenant-reads.md §4.4-§4.5).
//!
//! Inside `window_secs`, the frames committed to one `caller_key` may name at
//! most one tenant. This module holds the attribution a frame carries and the
//! process-wide history the outbound judge checks it against.
//!
//! SKELETON: the types are the shape the outbound writer and the events lane
//! build against. The history records nothing yet, so every judgement passes.

// The skeleton has no production caller until the outbound writer is wired.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Firewall;
use crate::security::hash_argument;

/// Distinct tenants (committed and pending) one principal may hold; past it
/// only an overflow count grows, which conflicts with everything.
const MAX_TENANTS_PER_PRINCIPAL: usize = 256;

/// The tenants a frame names, hashed with `hash_argument`, never raw, and
/// whether part of it could not be read. Serializable so an outbox record can
/// carry the attribution taken before a redaction (§4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadAttribution {
    /// Hashed tenant ids.
    pub(crate) tenants: BTreeSet<String>,
    /// Part of the frame was not read; it counts as a fresh unknown tenant.
    pub(crate) uninspected: bool,
}

impl ReadAttribution {
    /// Neither a tenant nor an unread part.
    pub(crate) fn is_empty(&self) -> bool {
        self.tenants.is_empty() && !self.uninspected
    }

    /// The attribution of raw tenant ids, hashed.
    pub(crate) fn of(tenants: BTreeSet<String>, uninspected: bool) -> Self {
        Self {
            tenants: tenants
                .into_iter()
                .map(|id| hash_argument(&Value::String(id)))
                .collect(),
            uninspected,
        }
    }

    /// Add `other`'s tenants and unread flag.
    pub(crate) fn extend(&mut self, other: &Self) {
        self.tenants.extend(other.tenants.iter().cloned());
        self.uninspected |= other.uninspected;
    }
}

/// The verdict on one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ReadVerdict {
    /// A second tenant inside the window, delivered (observe mode).
    Flagged,
    /// A second tenant inside the window, withheld (block mode).
    Blocked,
    /// Tenant data for no identity.
    Unattributable,
}

/// What a blocked frame leaves behind for the rejection audit: the verdict
/// and the hashed denied tenants, never the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RejectionEvidence {
    /// The caller the frame was judged for.
    pub(crate) caller_key: Option<String>,
    /// Always `Blocked` or `Unattributable`.
    pub(crate) verdict: ReadVerdict,
    /// The hashed tenants of the withheld frame.
    pub(crate) attribution: ReadAttribution,
}

/// One process's read history, shared by every `Firewall` and stream writer.
#[derive(Debug, Default)]
pub(crate) struct ReadHistory {}

impl ReadHistory {
    /// A fresh history behind the `Arc` every holder shares.
    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Count the frame against `key`'s live tenants and, unless it is over
    /// and `refuse_over` is set, reserve its tenants under a ticket. `None`
    /// when the history is full of live principals (unattributable).
    pub(crate) fn reserve(
        self: &Arc<Self>,
        key: &str,
        attribution: &ReadAttribution,
        window: Duration,
        refuse_over: bool,
    ) -> Option<Reservation> {
        let _ = (self, key, attribution, window, refuse_over);
        Some(Reservation {
            over: false,
            ticket: Some(ReadTicket::default()),
        })
    }

    /// `(committed, pending)` distinct tenants held for `key`.
    #[cfg(test)]
    pub(crate) fn tenants_held(&self, key: &str) -> (usize, usize) {
        let _ = (self, key);
        (0, 0)
    }
}

/// What [`ReadHistory::reserve`] found.
#[derive(Debug)]
pub(crate) struct Reservation {
    /// The frame makes more than one tenant live for the principal.
    pub(crate) over: bool,
    /// The frame's reservation; `None` when it named nothing or was refused.
    pub(crate) ticket: Option<ReadTicket>,
}

/// A frame's reservation. Clones are the copies of one frame (fan-out): each
/// write refreshes last-seen, and the last copy to go, written or dropped,
/// releases the pending counts.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReadTicket {}

impl ReadTicket {
    /// This copy was written: its tenants are committed as of now.
    pub(crate) fn emitted(&self) {
        let _ = self;
    }
}

/// Run `future` with a request-scoped collector of the attribution its inner
/// dispatches read before any transform (§4.4, F1-F2). Returns the output and
/// what was collected.
pub(crate) async fn with_read_scope<F: Future>(
    firewall: Arc<Firewall>,
    future: F,
) -> (F::Output, ReadAttribution) {
    let _ = firewall;
    (future.await, ReadAttribution::default())
}

/// Note the attribution of a raw value read inside [`with_read_scope`],
/// before a transform maps or drops fields. Outside a scope, nothing.
pub(crate) fn note_read(value: &Value) {
    let _ = value;
}

#[cfg(test)]
#[path = "tenant_reads_tests.rs"]
mod tests;
