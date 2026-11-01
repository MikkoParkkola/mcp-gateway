// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One connection's life: the session loop of a backend's listener task and
//! the select arms it polls, moved from `upstream_session.rs`.

use std::sync::{Arc, Weak};
use std::time::Instant;

use tracing::debug;

use super::opening::open_first;
use super::refill::{Refill, finish_refill, refilled, start_due_refill};
use super::run::{self, begin_run};
use super::{
    FENCE_EVERY, Opening, Outcome, Pending, State, TICK, ToolsDebt, end_ineligible, failed,
    registered_anew,
};
use crate::backend::{Backend, BackendRegistry};
use crate::events::EventsHub;
use crate::events::upstream_listener::Shared;
use crate::protocol::era::PeerEra;
use crate::transport::upstream_tap::{
    FrameStream, Refused, Requested, UpstreamListen, UpstreamNote,
};

/// One connection's life.
pub(super) async fn session(
    shared: &Arc<Shared>,
    backend: &Arc<Backend>,
    hub: &Weak<EventsHub>,
    registry: &BackendRegistry,
    ran_under: &mut Option<u128>,
) -> Outcome {
    let Some(run) = begin_run(shared, backend, hub).await else {
        return failed();
    };
    *ran_under = run.lease;
    let started = Instant::now();
    let modern = run.era == PeerEra::Modern;
    let mut state = State::new(shared, run.era);
    state.fence.clone_from(&run.fence);
    state.lease = run.lease;
    // Tools debt an earlier run left under another lease is not this run's.
    run::forget_lease_debt(shared, &state);
    // The first catalogue read doubles as the legacy HTTP session's first
    // request on the shared bucket (§3).
    state.read_snapshot(backend, hub, false).await;
    if !modern && shared.key.obs.is_none() {
        // A legacy GET names a session that exists: one shared-bucket request
        // first, even when no URI is watched (§3). A per-user listener's own
        // session makes its own handshake.
        let _ = backend.read_resource_snapshot(false).await;
    }
    if let Err(ended) = open_first(shared, &mut state, &run.handle, modern).await {
        return ended;
    }
    state.handle = Some(run.handle.clone());
    let synced = tokio::select! {
        () = shared.stop.cancelled() => false,
        () = state.sync_legacy(backend, &run.handle) => true,
    };
    if !synced {
        state.release(backend).await;
        return Outcome::Stopped;
    }
    let mut tick = tokio::time::interval(TICK);
    let mut wake = shared.wake.subscribe();
    // The tools refill a notice starts. Polled as one arm of the loop's select,
    // never awaited inline, so a hanging `tools/list` (bounded by OPEN_LIMIT)
    // does not stop the session draining its other notices.
    let mut refill: Option<Refill> = None;
    loop {
        let event = tokio::select! {
            () = shared.stop.cancelled() => {
                state.release(backend).await;
                return Outcome::Stopped;
            }
            note = recv(&mut state.current) => Ev::Current(note),
            note = recv_pending(&mut state.pending) => Ev::Pending(note),
            filled = refilled(&mut refill) => Ev::Refilled(filled),
            opened = replacement_opened(&mut state.opening) => Ev::Opened(opened),
            _ = wake.changed() => Ev::Wake,
            _ = tick.tick() => Ev::Tick,
        };
        match event {
            Ev::Current(Some(note)) => {
                if state.note(note, false) {
                    return finish_refill(&mut state, shared, backend, hub, refill, started).await;
                }
            }
            Ev::Current(None) => {
                return finish_refill(&mut state, shared, backend, hub, refill, started).await;
            }
            Ev::Pending(Some(note)) => {
                state.note(note, true);
            }
            Ev::Pending(None) => state.pending_ended(),
            Ev::Opened((opened, requested)) => state.on_opened(opened, requested),
            Ev::Refilled(filled) => {
                // The refill ended (filled or timed out): the hub may hear now.
                refill = None;
                state.refill_ended(filled);
            }
            Ev::Wake | Ev::Tick => {}
        }
        // Nothing observed under a moved grant or lease is announced: the session's
        // notices and refill go with it, and the next run opens under what is held.
        if grant_moved(shared, run.fence.as_deref(), &mut state).await
            || run::lease_moved(shared, hub, run.lease)
        {
            return state.ended(started);
        }
        if refill.is_none() {
            refill = start_due_refill(&mut state, backend);
        }
        // A per-user run's transport is its own: only a replaced backend
        // (a reload) ends it.
        let current = match &run.transport {
            Some(transport) => backend_still_current(backend, transport),
            None => !registered_anew(registry, &shared.name, backend),
        };
        if !current {
            debug!(backend = %shared.name, "upstream listener: transport replaced");
            return finish_refill(&mut state, shared, backend, hub, refill, started).await;
        }
        if run.transport.is_some() && backend.connected_streamable() != run.flavour {
            debug!(backend = %shared.name, "upstream listener: transport flavour changed; reconnecting");
            return finish_refill(&mut state, shared, backend, hub, refill, started).await;
        }
        let stopped = tokio::select! {
            () = shared.stop.cancelled() => true,
            () = state.maintain(backend, hub, &run.handle, modern) => false,
        };
        if stopped {
            state.release(backend).await;
            return Outcome::Stopped;
        }
        // Kept only to release keys (D5 cleanup), and nothing is left.
        shared.cancel_if_idle();
        let tick = on_tick(backend.connected_streamable(), || shared.is_ineligible());
        if (state.flush(hub) || tick == OnTick::EndIneligible) && end_ineligible(shared, hub).await
        {
            state.release(backend).await;
            return Outcome::Stopped;
        }
    }
}

/// Whether a minted run's grant moved: a refused mint says so at once, and
/// the run reads its fence every [`FENCE_EVERY`] so a quiet stream notices
/// too. A moved run's pending tools debounce goes with it. A per-user key
/// has no snapshot or confirm clock to drop: it never reads the catalogue
/// (`read_snapshot`, `authorize_uri`).
async fn grant_moved(
    shared: &Shared,
    fence: Option<&crate::events::listener_credential::RunFence>,
    state: &mut State<'_>,
) -> bool {
    let Some(fence) = fence else {
        return false;
    };
    // Once the run's first request fixed its grant, before any refill: a
    // tools notice another run left pending was heard under that grant.
    if fence.is_fixed() {
        run::forget_foreign_debt(&mut shared.tools.lock(), fence.binding().as_deref());
    }
    if Instant::now() >= state.fence_due {
        state.fence_due = Instant::now() + FENCE_EVERY;
        fence.recheck().await;
    }
    if !fence.ended() {
        return false;
    }
    debug!(backend = %shared.name, "upstream listener: the grant moved; ending the run");
    *shared.tools.lock() = ToolsDebt::default();
    true
}

/// What a tick does about the backend's live transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnTick {
    Keep,
    EndIneligible,
}

/// A listener runs only for a backend that was eligible when subscribed.
/// Once its live connection reads the SSE handshake (`live`, as
/// `Backend::connected_streamable` reads it), a quiet stream would never
/// notice, so the tick asks the shared predicate (`refused`, the costlier
/// read) whether the backend is now refused. An undetected transport is not
/// a refusal: a stopped slot reconnects through the loop head.
pub(super) fn on_tick(live: Option<bool>, refused: impl FnOnce() -> bool) -> OnTick {
    if live == Some(false) && refused() {
        OnTick::EndIneligible
    } else {
        OnTick::Keep
    }
}

fn backend_still_current(backend: &Backend, handle: &Weak<dyn UpstreamListen>) -> bool {
    backend.listens_on(handle)
}

enum Ev {
    Current(Option<UpstreamNote>),
    Pending(Option<UpstreamNote>),
    Refilled(bool),
    Opened((Result<FrameStream, Refused>, Requested)),
    Wake,
    Tick,
}

async fn replacement_opened(
    opening: &mut Option<Opening>,
) -> (Result<FrameStream, Refused>, Requested) {
    match opening {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

async fn recv(current: &mut Option<(FrameStream, Requested)>) -> Option<UpstreamNote> {
    match current {
        Some((stream, _)) => stream.rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_pending(pending: &mut Option<Pending>) -> Option<UpstreamNote> {
    match pending {
        Some(p) => p.stream.rx.recv().await,
        None => std::future::pending().await,
    }
}
