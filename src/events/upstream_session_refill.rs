// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tools refill a backend notice starts, polled as one arm of the
//! session loop (MIK-7951, MIK-8007).

use std::sync::{Arc, Weak};
use std::time::Instant;

use tracing::warn;

use super::{OPEN_LIMIT, Outcome, State, end_ineligible};
use crate::backend::Backend;
use crate::events::EventsHub;
use crate::events::upstream_listener::Shared;
use crate::events::upstream_need::WINDOW;

/// The refill a due notice starts, unpolled. A notice arrived: drop the cached
/// list and refill it before the hub hears, so the subscriber's re-read is
/// fresh and nothing sees an emptied cache. At most once per tick however many
/// notices came; a notice during a refill waits for the next one. A silent
/// retry keeps the cache: the failed refill already emptied it, so what is
/// there now was read after the notice, and invalidating again could void a
/// reader's fill into a new cooldown (MIK-8007).
pub(super) fn start_due_refill(state: &mut State<'_>, backend: &Arc<Backend>) -> Option<Refill> {
    if !state.take_due_refill() {
        return None;
    }
    if state.refill_announces {
        backend.invalidate_tools();
    }
    Some(start_refill(backend, &state.shared.name))
}

/// The tools refill a notice starts. The shared fetch, so a reader of the list
/// meanwhile waits on this one. Each request is bounded by the backend's own
/// `timeout`, the whole refill by `OPEN_LIMIT`. A refill that did not fill still
/// announces the change: the notice said the list changed, and the
/// subscriber's own re-read fetches it (MIK-7951).
fn start_refill(backend: &Arc<Backend>, name: &str) -> Refill {
    let (backend, name) = (Arc::clone(backend), name.to_owned());
    Box::pin(async move {
        let filled = matches!(
            tokio::time::timeout(OPEN_LIMIT, backend.get_tools_shared()).await,
            Ok(Ok(_))
        );
        if !filled {
            warn!(backend = %name, "upstream listener: tools refill did not complete; announcing the change anyway");
        }
        filled
    })
}

/// An in-flight tools refill; `true` when it filled the list.
pub(super) type Refill = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>;

/// End the session, first letting an in-flight refill finish and any tools
/// change it produced reach the hub, as when the refill ran inline and the
/// end was only seen after it. A stop still ends at once. Unlike a loop
/// iteration, nothing is maintained before this flush: the session is over.
pub(super) async fn finish_refill(
    state: &mut State<'_>,
    shared: &Shared,
    backend: &Backend,
    hub: &Weak<EventsHub>,
    refill: Option<Refill>,
    started: Instant,
) -> Outcome {
    if let Some(refill) = refill {
        tokio::select! {
            () = shared.stop.cancelled() => {
                state.release(backend).await;
                return Outcome::Stopped;
            }
            filled = refill => state.refill_ended(filled),
        }
    }
    // Also a refill that finished this iteration, its change not yet
    // announced when the transport was found replaced, and every notice
    // still inside its coalescing window: the session's state goes with it
    // (MIK-7898).
    if state.flush_at(hub, Instant::now() + WINDOW) {
        end_ineligible(shared, hub).await;
    }
    state.ended(started)
}

/// Resolves when the in-flight refill ends; never, when there is none.
pub(super) async fn refilled(refill: &mut Option<Refill>) -> bool {
    match refill {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}
