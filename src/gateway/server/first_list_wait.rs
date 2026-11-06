// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio session's first-list wait (MIK-9309).
//!
//! A modern stdio client cannot be told its tool list changed, so its first
//! `tools/list` waits for the surfaced backends' first fill
//! ([`MetaMcp::wait_surfaced_first_fill`]). "First" means the first list
//! whose answer was queued: a list cancelled or abandoned mid-wait leaves the
//! wait armed for its retry. A ticket scoped around each spawned dispatch
//! carries the session's flag from the `tools/list` arm, which marks that it
//! waited, to the enqueue, which commits the flag only for an answer it
//! actually queued.

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio_util::sync::CancellationToken;

use crate::gateway::meta_mcp::{InvokeScope, MetaMcp};
use crate::protocol::meta::Era;

tokio::task_local! {
    static TICKET: Ticket;
}

struct Ticket {
    answered: Arc<AtomicBool>,
    ending: CancellationToken,
    waited: Cell<bool>,
}

/// One per stdio session: whether a first list's answer was queued, and
/// whether the session has stopped reading.
#[derive(Clone, Default)]
pub(super) struct FirstList {
    answered: Arc<AtomicBool>,
    ending: CancellationToken,
}

impl FirstList {
    /// Run one dispatch, `task`, under its own ticket on this session's flag
    /// (each dispatch takes its own clone).
    pub(super) fn scope<F: Future>(self, task: F) -> impl Future<Output = F::Output> {
        let ticket = Ticket {
            answered: self.answered,
            ending: self.ending,
            waited: Cell::new(false),
        };
        TICKET.scope(ticket, task)
    }

    /// The session stopped reading (EOF, a signal, stdout gone): a first list's
    /// wait for the surfaced fills ends now, so the drain is not held for it.
    /// The caller's own-view warm beside it keeps its own deadline, as before
    /// this wait existed.
    pub(super) fn end(&self) {
        self.ending.cancel();
    }
}

/// What the stdio `tools/list` arm runs before it builds the list: the grant
/// recheck HTTP runs first (MIK-8356), then the caller's own views as HTTP
/// warms them and, beside it from the same start, a modern first list's wait
/// for the surfaced backends' first fill. Both are capped from that start,
/// so the two waits never add up.
pub(super) async fn prepare(
    meta_mcp: &MetaMcp,
    scope: InvokeScope<'_>,
    session_id: &str,
    era: Era,
) {
    let ending = matches!(era, Era::Modern)
        .then(|| {
            TICKET.try_with(|ticket| {
                let first = !ticket.answered.load(Ordering::Acquire);
                ticket.waited.set(first);
                first.then(|| ticket.ending.clone())
            })
        })
        .and_then(Result::ok)
        .flatten();
    meta_mcp.revalidate_caller_slots(scope.caller).await;
    let own_views = meta_mcp.warm_listing_views(scope, Some(session_id));
    if let Some(ending) = ending {
        let first_fill = async {
            tokio::select! {
                () = meta_mcp.wait_surfaced_first_fill(scope, Some(session_id)) => {}
                () = ending.cancelled() => {}
            }
        };
        tokio::join!(own_views, first_fill);
    } else {
        own_views.await;
    }
}

/// As an answer is queued, under the cancel lock (`send_unless_cancelled`):
/// a list that waited as the first commits the session's flag, so later lists
/// do not wait.
pub(super) fn answer_queued() {
    // Outside a ticket (a batch, a direct dispatch) nothing waited.
    let waited =
        TICKET.try_with(|ticket| ticket.waited.get().then(|| Arc::clone(&ticket.answered)));
    if let Ok(Some(answered)) = waited {
        answered.store(true, Ordering::Release);
    }
}

/// Test-only: mark the current dispatch's ticket as a first list that waited.
#[cfg(test)]
pub(super) fn mark_waited_for_test() {
    TICKET.with(|ticket| ticket.waited.set(true));
}

#[cfg(test)]
impl FirstList {
    /// Test-only: whether a first list's answer was committed.
    pub(super) fn answered_for_test(&self) -> bool {
        self.answered.load(Ordering::Acquire)
    }
}
