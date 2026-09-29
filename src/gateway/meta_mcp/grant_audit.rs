// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a: identity grant decisions are audited, one record per decision on a
//! personal capability per outer call.
//!
//! Signatures only: every body below is a stub, so the D3-a cells compile
//! and fail on their assertions.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "D3-a stubs: wired into the openers by the next commit"
    )
)]
#![cfg_attr(
    test,
    allow(dead_code, reason = "D3-a stubs: not every stub has a caller yet")
)]

use std::future::Future;
use std::sync::Arc;

use crate::security::TransparencyLogger;

/// One grant decision noted inside a slot, keyed by the check's own inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrantNote {
    /// The backend the check was asked about.
    pub(super) server: String,
    /// The tool the check was asked about.
    pub(super) tool: String,
    /// `trace::current()` when the note was taken; `None` outside an invocation.
    pub(super) trace_id: Option<String>,
    /// Whether the grant allowed the call.
    pub(super) allowed: bool,
}

/// Run `future` inside a grant-decision slot, or inside the one already open.
/// The outermost opener writes the selected notes before returning.
pub(super) async fn with_grant_slot<F: Future>(
    logger: Option<&Arc<TransparencyLogger>>,
    future: F,
) -> F::Output {
    let _ = logger;
    future.await
}

/// Note one decision into the open slot.
pub(super) fn note_grant_decision(note: GrantNote) {
    drop(note);
}

/// The notes that become records: every traced note, and the last untraced
/// note of a `(server, tool)` with no traced note.
pub(super) fn select_records(notes: &[GrantNote]) -> Vec<&GrantNote> {
    let _ = notes;
    Vec::new()
}

/// Test-only opt-in: while held, a check outside every slot takes the
/// fail-closed fallback instead of panicking.
#[cfg(test)]
pub(super) struct UnslottedCheckAllowed;

#[cfg(test)]
pub(super) fn allow_unslotted_check_for_test() -> UnslottedCheckAllowed {
    UnslottedCheckAllowed
}

/// Test-only: slots opened and notes taken on this thread.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct GrantBookkeeping {
    pub(super) slots_opened: usize,
    pub(super) notes_taken: usize,
}

#[cfg(test)]
pub(super) fn grant_bookkeeping_for_test() -> GrantBookkeeping {
    GrantBookkeeping::default()
}
