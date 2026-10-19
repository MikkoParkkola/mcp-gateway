// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only reads of a signing context's private settlement state, for the
//! invoke stage rows (MIK-8488). A child module, so `signing.rs` stays under
//! its size ceiling.

impl super::SigningInvocationContext {
    /// Whether the call would give its nonce back if it returned now: a step
    /// asked, none dispatched, and the witness is still held.
    pub(crate) fn refund_due_for_test(&self) -> bool {
        self.refund_due()
    }
}
