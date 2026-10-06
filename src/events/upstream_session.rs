// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connection logic of one backend's listener task (MIK-7630 I5 design
//! §3, §5, §8, §9): open the era's channel, keep it matching the counted
//! interest, coalesce what arrives, and emit through the hub only.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::json;
use tracing::{debug, warn};

use super::EventsHub;
use super::fanout::SourceEvent;
use super::types::{SourceKind, Visibility};
use super::upstream::Kind;
use super::upstream_listener::Shared;
use super::upstream_need::ledger::drive;
use super::upstream_need::{Coalescer, Verdict, WINDOW};
use crate::backend::{Backend, BackendRegistry};
use crate::protocol::era::Era;
use crate::transport::upstream_tap::{
    FrameStream, KindSet, NoteKind, Refused, Requested, UpstreamListen, UpstreamNote, Watched,
};

/// How often the loop looks at timers; also bounds coalescing latency.
const TICK: Duration = Duration::from_millis(250);
/// A modern listen must be acknowledged within this (§3).
/// Opening a channel may not outlast this.
const OPEN_LIMIT: Duration = Duration::from_secs(30);
/// The legacy unsubscribe walk on stop may not outlast this (D5).
const RELEASE_LIMIT: Duration = Duration::from_secs(5);
/// A modern listen must be acknowledged within this (§3).
const ACK_DEADLINE: Duration = Duration::from_secs(10);
/// The catalogue is re-read one backend cache TTL after each read (§7,
/// MIK-7950), held between these: at most once a second, even with caching
/// off (a zero TTL), and at least daily, which also keeps a huge configured
/// TTL from overflowing the clock.
const SNAPSHOT_FLOOR: Duration = Duration::from_secs(1);
const SNAPSHOT_CEILING: Duration = Duration::from_secs(24 * 3600);

/// The interval to the next catalogue re-read for a backend cache TTL.
fn snapshot_interval(cache_ttl: Duration) -> Duration {
    cache_ttl.clamp(SNAPSHOT_FLOOR, SNAPSHOT_CEILING)
}
/// A failed catalogue read is retried after this.
const SNAPSHOT_RETRY: Duration = Duration::from_secs(5);
/// A stream that stayed open this long resets the backoff (§9).
const STABLE: Duration = Duration::from_secs(60);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(300);
/// A tools refill that did not fill is retried once after this: the backend's
/// list-fill cooldown, which fails every fill inside it without reaching the
/// backend (MIK-8007). Taken from it, so the two cannot drift apart.
const REFILL_RETRY: Duration = crate::backend::LIST_FILL_COOLDOWN;

/// The backend tools notices a listener task has not yet served (MIK-8007).
#[derive(Default)]
pub(super) struct ToolsDebt {
    /// The earliest the next refill may start (one per tick).
    due: Option<Instant>,
    /// That refill retries one that did not fill.
    retrying: bool,
    /// A notice the hub has not heard of yet.
    unannounced: bool,
}

enum Outcome {
    Stopped,
    /// Nothing to retry fast: the peer offers no such channel.
    Unsupported,
    Ended {
        acked: bool,
        lasted: Duration,
    },
}

fn backoff(failures: u32) -> Duration {
    let base = BACKOFF_FIRST
        .saturating_mul(1u32 << failures.min(9))
        .min(BACKOFF_CAP);
    // ±25 % jitter, so a restarted fleet does not reconnect in lockstep.
    base.mul_f64(0.75 + 0.5 * rand::random::<f64>())
}

fn event_name(backend: &str, kind: NoteKind) -> String {
    let kind = match kind {
        NoteKind::ResourceUpdated => Kind::ResourceUpdated,
        NoteKind::ResourcesChanged => Kind::ResourcesChanged,
        NoteKind::PromptsChanged => Kind::PromptsChanged,
        NoteKind::ToolsChanged => Kind::ToolsChanged,
    };
    format!("backend.{backend}.{}", kind.suffix())
}

/// The live config no longer lets this backend offer upstream events (a
/// reload, MIK-7894): stop its task and withdraw the subscriptions that only
/// the listener served. `tools_changed` stays, since the gateway announces it
/// itself.
///
/// The check and the withdrawal run under the lifecycle lock a subscribe
/// commits under, and the listener stops only if the backend is still
/// ineligible there: a reload or a transport switch that restores it first
/// keeps the listener and its subscriptions, and one admitted after the
/// restore lands after the withdrawal, so it is never deleted by it. `true`
/// when the listener was stopped.
async fn end_ineligible(shared: &Shared, hub: &Weak<EventsHub>) -> bool {
    let Some(hub) = hub.upgrade() else {
        shared.stop.cancel();
        return true;
    };
    let started = hub.lifecycle.lock().await;
    if !shared.is_ineligible() {
        return false;
    }
    shared.stop.cancel();
    let names: Vec<String> = [
        Kind::ResourceUpdated,
        Kind::ResourcesChanged,
        Kind::PromptsChanged,
    ]
    .into_iter()
    .map(|kind| format!("backend.{}.{}", shared.name, kind.suffix()))
    .collect();
    hub.withdraw(&names);
    drop(started);
    hub.reconcile_stops_in_background();
    true
}

/// The task: reconnect until stopped.
pub(super) async fn run(shared: Arc<Shared>, registry: Arc<BackendRegistry>, hub: Weak<EventsHub>) {
    let _gate = tokio::select! {
        () = shared.stop.cancelled() => return,
        gate = Arc::clone(&shared.gate).lock_owned() => gate,
    };
    let mut failures = 0u32;
    loop {
        if shared.stop.is_cancelled() {
            return;
        }
        if shared.is_ineligible() && end_ineligible(&shared, &hub).await {
            return;
        }
        let Some(backend) = registry.get(&shared.name) else {
            // Gone: park until the interest changes or the keys are deleted.
            // A removed backend owes nothing; a re-added one starts afresh.
            *shared.tools.lock() = ToolsDebt::default();
            let mut wake = shared.wake.subscribe();
            tokio::select! {
                () = shared.stop.cancelled() => return,
                _ = wake.changed() => {}
                () = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
            continue;
        };
        let delay = match session(&shared, &backend, &hub).await {
            Outcome::Stopped => return,
            Outcome::Unsupported => BACKOFF_CAP,
            Outcome::Ended { acked, lasted } => {
                failures = if acked || lasted >= STABLE {
                    0
                } else {
                    failures.saturating_add(1)
                };
                backoff(failures)
            }
        };
        tokio::select! {
            () = shared.stop.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

fn requested(shared: &Shared) -> Requested {
    let (kinds, uris) = shared.need.lock().filter();
    Requested { kinds, uris }
}

/// One connection's life.
async fn session(shared: &Arc<Shared>, backend: &Arc<Backend>, hub: &Weak<EventsHub>) -> Outcome {
    let _lease = backend.listen_lease();
    let target = match backend.listen_target().await {
        Ok(target) => target,
        Err(error) => {
            debug!(backend = %shared.name, %error, "upstream listener: backend not reachable");
            return failed();
        }
    };
    let started = Instant::now();
    let modern = target.era == Some(Era::Modern);
    let mut state = State::new(shared, if modern { Era::Modern } else { Era::Legacy });
    // The first catalogue read doubles as the legacy HTTP session's first
    // request on the shared bucket (§3).
    state.read_snapshot(backend, hub, false).await;
    if !modern {
        // A legacy GET names a session that exists: one shared-bucket request
        // first, even when no URI is watched (§3).
        let _ = backend.read_resource_snapshot(false).await;
    }
    let first = requested(shared);
    let opened = tokio::select! {
        () = shared.stop.cancelled() => return Outcome::Stopped,
        opened = tokio::time::timeout(OPEN_LIMIT, open(&target.handle, modern, first.clone(), watched_by(shared))) => {
            opened.unwrap_or(Err(Refused::Expired))
        }
    };
    match opened {
        Ok(stream) => {
            state.opened = Instant::now();
            state.current = Some((stream, first));
        }
        Err(Refused::Unsupported) => return Outcome::Unsupported,
        Err(Refused::Expired) => return failed(),
        Err(Refused::Failed(error)) => {
            debug!(backend = %shared.name, %error, "upstream listener: stream refused");
            return failed();
        }
    }
    state.sync_legacy(backend, &target.handle).await;
    let mut tick = tokio::time::interval(TICK);
    let mut wake = shared.wake.subscribe();
    // The tools refill a notice starts. Polled as one arm of the loop's select,
    // never awaited inline, so a hanging `tools/list` (bounded by OPEN_LIMIT)
    // does not stop the session draining its other notices (MIK-7937).
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
            Ev::Refilled(filled) => {
                // The refill ended (filled or timed out): the hub may hear now.
                refill = None;
                state.refill_ended(filled);
            }
            Ev::Wake | Ev::Tick => {}
        }
        if refill.is_none() {
            refill = start_due_refill(&mut state, backend);
        }
        if !backend_still_current(backend, &target.handle) {
            debug!(backend = %shared.name, "upstream listener: transport replaced");
            return finish_refill(&mut state, shared, backend, hub, refill, started).await;
        }
        let stopped = tokio::select! {
            () = shared.stop.cancelled() => true,
            () = state.maintain(backend, hub, &target.handle, modern) => false,
        };
        if stopped {
            state.release(backend).await;
            return Outcome::Stopped;
        }
        if shared.is_idle() {
            // Kept only to release keys (D5 cleanup), and nothing is left.
            shared.stop.cancel();
        }
        let tick = on_tick(backend.connected_streamable(), || shared.is_ineligible());
        if (state.flush(hub) || tick == OnTick::EndIneligible) && end_ineligible(shared, hub).await
        {
            state.release(backend).await;
            return Outcome::Stopped;
        }
    }
}

/// The legacy URI filter of `shared`'s need, read at each update (D5).
fn watched_by(shared: &Arc<Shared>) -> Watched {
    let shared = Arc::downgrade(shared);
    Watched::by(move |uri| {
        shared
            .upgrade()
            .is_some_and(|s| s.need.lock().emits(NoteKind::ResourceUpdated, Some(uri)))
    })
}

/// Who holds what this session asks a legacy peer for: the transport
/// instance and, on HTTP, its session (D5 holder generation).
fn holder_of(handle: &Weak<dyn UpstreamListen>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    Weak::as_ptr(handle).cast::<()>().hash(&mut hasher);
    handle.upgrade().map(|t| t.holder()).hash(&mut hasher);
    hasher.finish()
}

/// What a tick does about the backend's live transport (MIK-7969 H2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnTick {
    Keep,
    EndIneligible,
}

/// A listener runs only for a backend that was eligible when subscribed.
/// Once its live connection reads the SSE handshake (`live`, as
/// `Backend::connected_streamable` reads it), a quiet stream would never
/// notice, so the tick asks the shared predicate (`refused`, the costlier
/// read) whether the backend is now refused. An undetected transport is not
/// a refusal: a stopped slot reconnects through the loop head.
fn on_tick(live: Option<bool>, refused: impl FnOnce() -> bool) -> OnTick {
    if live == Some(false) && refused() {
        OnTick::EndIneligible
    } else {
        OnTick::Keep
    }
}

/// The refill a due notice starts, unpolled. A notice arrived: drop the cached
/// list and refill it before the hub hears, so the subscriber's re-read is
/// fresh and nothing sees an emptied cache. At most once per tick however many
/// notices came; a notice during a refill waits for the next one. A silent
/// retry keeps the cache: the failed refill already emptied it, so what is
/// there now was read after the notice, and invalidating again could void a
/// reader's fill into a new cooldown (MIK-8007).
fn start_due_refill(state: &mut State<'_>, backend: &Arc<Backend>) -> Option<Refill> {
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

fn failed() -> Outcome {
    Outcome::Ended {
        acked: false,
        lasted: Duration::ZERO,
    }
}

fn backend_still_current(backend: &Backend, handle: &Weak<dyn UpstreamListen>) -> bool {
    backend.listens_on(handle)
}

enum Ev {
    Current(Option<UpstreamNote>),
    Pending(Option<UpstreamNote>),
    Refilled(bool),
    Wake,
    Tick,
}

/// An in-flight tools refill; `true` when it filled the list.
type Refill = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>;

/// End the session, first letting an in-flight refill finish and any tools
/// change it produced reach the hub, as when the refill ran inline and the
/// end was only seen after it. A stop still ends at once. Unlike a loop
/// iteration, nothing is maintained before this flush: the session is over.
async fn finish_refill(
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
async fn refilled(refill: &mut Option<Refill>) -> bool {
    match refill {
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

/// Open the era's channel; the upgraded `Arc` lives only for this call.
async fn open(
    handle: &Weak<dyn UpstreamListen>,
    modern: bool,
    requested: Requested,
    watched: Watched,
) -> Result<FrameStream, Refused> {
    let Some(transport) = handle.upgrade() else {
        return Err(Refused::Failed(crate::Error::Transport(
            "transport gone".to_owned(),
        )));
    };
    if modern {
        transport.listen(requested).await
    } else {
        transport.unsolicited(watched).await
    }
}

/// A replacement listen waiting for its acknowledgement (make before break).
struct Pending {
    stream: FrameStream,
    requested: Requested,
    since: Instant,
}

#[allow(clippy::struct_excessive_bools)] // Each flag is an independent fact about the current stream.
struct State<'a> {
    shared: &'a Arc<Shared>,
    era: Era,
    current: Option<(FrameStream, Requested)>,
    pending: Option<Pending>,
    acked: Option<Instant>,
    /// What the current stream's acknowledgement honoured; a notice outside
    /// it is not delivered (MIK-7898). `None` before an acknowledgement and
    /// on a legacy stream, which has none.
    honoured: Option<(KindSet, Vec<String>)>,
    /// The peer answered the listen with `-32601` (MIK-7899).
    unsupported: bool,
    opened: Instant,
    coalescer: Coalescer,
    resource_interest_unsupported: bool,
    reread: bool,
    /// A backend tools notice waits to be handed to the hub (§14).
    tools_pending: bool,
    /// The refill in flight serves a notice the hub has not heard of yet.
    refill_announces: bool,
    snapshot_due: Instant,
    /// A catalogue read is not retried before this.
    snapshot_retry_at: Instant,
    /// A modern replacement listen is not retried before this.
    retry_open_at: Instant,
    /// Listens that ended, or failed to open, unacknowledged since the last
    /// acknowledgement (MIK-7898 SESS.2a).
    open_failures: u32,
}

impl<'a> State<'a> {
    fn new(shared: &'a Arc<Shared>, era: Era) -> Self {
        let now = Instant::now();
        Self {
            shared,
            era,
            current: None,
            pending: None,
            acked: None,
            honoured: None,
            unsupported: false,
            opened: now,
            coalescer: Coalescer::default(),
            resource_interest_unsupported: false,
            reread: false,
            tools_pending: false,
            refill_announces: false,
            // Due at once: a session that starts with no URI watched reads
            // the catalogue as soon as one is, even when the shared snapshot
            // is known from an earlier session.
            snapshot_due: now,
            snapshot_retry_at: now,
            retry_open_at: now,
            open_failures: 0,
        }
    }

    /// Take the tools refill when one is due, with the notices it serves;
    /// none while a finished refill's change is unannounced, as invalidating
    /// then would have the hub announce it over an emptied cache.
    fn take_due_refill(&mut self) -> bool {
        let mut debt = self.shared.tools.lock();
        if self.tools_pending || debt.due.is_none_or(|due| Instant::now() < due) {
            return false;
        }
        debt.due = None;
        self.refill_announces = std::mem::take(&mut debt.unannounced);
        // A newer notice earns its own retry.
        debt.retrying &= !self.refill_announces;
        true
    }

    /// A refill ended. One that did not fill (inside the backend's list-fill
    /// cooldown it never reaches the backend) is retried once, no sooner than
    /// the cooldown, so the notice is served (MIK-8007). The hub hears once
    /// per notice: a failed refill still announces (MIK-7951), and its retry
    /// only refreshes the list unless a newer notice joined it.
    fn refill_ended(&mut self, filled: bool) {
        let mut debt = self.shared.tools.lock();
        debt.retrying = !filled && !debt.retrying;
        if debt.retrying {
            let retry = Instant::now() + REFILL_RETRY;
            debt.due = Some(debt.due.map_or(retry, |due| due.max(retry)));
        }
        self.tools_pending |= std::mem::take(&mut self.refill_announces);
    }

    fn ended(&self, started: Instant) -> Outcome {
        if self.unsupported {
            return Outcome::Unsupported;
        }
        Outcome::Ended {
            acked: self.acked.is_some(),
            lasted: started.elapsed(),
        }
    }

    /// Read the catalogue snapshot when URIs are watched; a failure keeps
    /// the previous good one (an error is not absence, §7).
    async fn read_snapshot(&mut self, backend: &Backend, hub: &Weak<EventsHub>, fresh: bool) {
        if requested(self.shared).uris.is_empty() {
            return;
        }
        match backend.read_resource_snapshot(fresh).await {
            Ok(mut read) => {
                // A watched URI missing from a cached list is confirmed by a
                // read that bypasses the cache before anything is revoked.
                let watched = requested(self.shared).uris;
                if !fresh && read.complete && watched.iter().any(|u| !read.uris.contains(u)) {
                    // A failed confirmation decides nothing: keep the previous
                    // snapshot and try again later.
                    let Ok(again) = backend.read_resource_snapshot(true).await else {
                        self.snapshot_retry_at = Instant::now() + SNAPSHOT_RETRY;
                        return;
                    };
                    read = again;
                }
                let (complete, listed) = (read.complete, read.uris.clone());
                self.shared.snapshot.lock().read(read.uris, read.complete);
                if complete && let Some(hub) = hub.upgrade() {
                    hub.revoke_absent_uris(&self.shared.name, &listed).await;
                }
                self.reread = false;
                // The catalogue cache's own TTL: a shorter configured one
                // re-reads sooner, so a removal is seen as soon as the
                // cache would (MIK-7950).
                self.snapshot_due = Instant::now() + snapshot_interval(backend.cache_ttl());
            }
            Err(error) => {
                debug!(backend = %self.shared.name, %error, "upstream listener: catalogue read failed");
                self.snapshot_retry_at = Instant::now() + SNAPSHOT_RETRY;
            }
        }
    }

    /// Route one projected frame. `true` when the stream is over.
    fn note(&mut self, note: UpstreamNote, from_pending: bool) -> bool {
        match note {
            UpstreamNote::Ack { kinds, uris } => {
                self.on_ack(kinds, &uris, from_pending);
                false
            }
            UpstreamNote::Notice { kind, uri } => {
                if !self.honours(kind, uri.as_deref(), from_pending) {
                    return false;
                }
                if kind == NoteKind::ResourcesChanged && !requested(self.shared).uris.is_empty() {
                    self.reread = true;
                }
                if kind == NoteKind::ToolsChanged {
                    // Not coalesced here: the hub's own quiet window does it.
                    if self.shared.need.lock().emits(kind, None) {
                        let mut debt = self.shared.tools.lock();
                        debt.due.get_or_insert(Instant::now() + TICK);
                        debt.unannounced = true;
                    }
                } else if self.shared.need.lock().emits(kind, uri.as_deref()) {
                    self.coalescer.offer(kind, uri, Instant::now());
                }
                false
            }
            UpstreamNote::End => !from_pending,
            UpstreamNote::Unsupported => {
                // A replacement the peer refuses ends nothing; it is dropped
                // at its acknowledgement deadline like any unacknowledged one.
                self.unsupported |= !from_pending;
                !from_pending
            }
        }
    }

    /// Whether an acknowledgement covers a notice. A legacy stream has none
    /// and is not gated; on a modern one, a notice before the stream's
    /// acknowledgement (a replacement's, or the first listen's) is dropped:
    /// the acknowledgement must be the first frame (§3).
    fn honours(&self, kind: NoteKind, uri: Option<&str>, from_pending: bool) -> bool {
        if self.era == Era::Legacy {
            return true;
        }
        let (false, Some((kinds, uris))) = (from_pending, &self.honoured) else {
            return false;
        };
        match kind {
            NoteKind::ResourceUpdated => uri.is_some_and(|u| uris.iter().any(|w| w == u)),
            NoteKind::ResourcesChanged => kinds.resources_changed,
            NoteKind::PromptsChanged => kinds.prompts_changed,
            NoteKind::ToolsChanged => kinds.tools_changed,
        }
    }

    fn on_ack(&mut self, kinds: KindSet, uris: &[String], from_pending: bool) {
        let asked = if from_pending {
            self.pending.as_ref().map(|p| p.requested.clone())
        } else {
            self.current.as_ref().map(|(_, r)| r.clone())
        };
        if let Some(asked) = asked
            && (asked.kinds != kinds || asked.uris.len() != uris.len())
        {
            warn!(
                backend = %self.shared.name,
                "backend honoured less of the upstream listen than asked; the rest stays silent"
            );
        }
        if from_pending {
            // Make before break: the replacement is live, the old one goes.
            if let Some(p) = self.pending.take() {
                self.current = Some((p.stream, p.requested));
            }
        }
        self.honoured = Some((kinds, uris.to_vec()));
        self.acked = Some(Instant::now());
        self.open_failures = 0;
    }

    /// The replacement listen closed before its acknowledgement.
    fn pending_ended(&mut self) {
        self.pending = None;
        self.unacked();
    }

    /// A listen ended or failed unacknowledged: the next open waits one
    /// backoff step longer than the last (1 s doubling to 300 s, jittered).
    fn unacked(&mut self) {
        self.retry_open_at = Instant::now() + backoff(self.open_failures);
        self.open_failures = self.open_failures.saturating_add(1);
    }

    /// Keep the channel matching the counted interest and the snapshot
    /// current; runs on every wake and tick.
    async fn maintain(
        &mut self,
        backend: &Backend,
        hub: &Weak<EventsHub>,
        handle: &Weak<dyn UpstreamListen>,
        modern: bool,
    ) {
        let now = Instant::now();
        if modern {
            if self
                .pending
                .as_ref()
                .is_some_and(|p| p.since.elapsed() > ACK_DEADLINE)
            {
                self.pending = None;
                self.unacked();
            }
            if self.acked.is_none()
                && self.current.is_some()
                && self.opened.elapsed() > ACK_DEADLINE
            {
                self.current = None;
                self.unacked();
            }
            let want = requested(self.shared);
            let have = self.current.as_ref().map(|(_, r)| r.clone());
            if self.pending.is_none() && have.as_ref() != Some(&want) && now >= self.retry_open_at {
                let opened = tokio::time::timeout(
                    OPEN_LIMIT,
                    open(handle, true, want.clone(), Watched::default()),
                )
                .await
                .unwrap_or(Err(Refused::Expired));
                match opened {
                    Ok(stream) => {
                        self.pending = Some(Pending {
                            stream,
                            requested: want,
                            since: Instant::now(),
                        });
                    }
                    Err(_) => self.unacked(),
                }
            }
        } else {
            self.sync_legacy(backend, handle).await;
        }
        let watching = !requested(self.shared).uris.is_empty();
        let unread = watching && !self.shared.snapshot.lock().is_known();
        if (self.reread || unread || now >= self.snapshot_due) && now >= self.snapshot_retry_at {
            let fresh = self.reread;
            self.read_snapshot(backend, hub, fresh).await;
        }
    }

    /// Legacy: send the calls the backend's ledger has due (D5), one per
    /// URI, the whole pass bounded by `OPEN_LIMIT`; a URI the deadline cut
    /// is uncertain and the rest wait for the next pass.
    async fn sync_legacy(&mut self, backend: &Backend, handle: &Weak<dyn UpstreamListen>) {
        if self.era == Era::Modern || self.resource_interest_unsupported {
            return;
        }
        let ledger = Arc::clone(&self.shared.ledger);
        ledger.lock().observe(holder_of(handle));
        let due = ledger.lock().due(Instant::now());
        let pass = async {
            for (uri, subscribe) in due {
                if !drive(&ledger, backend, &uri, subscribe, OPEN_LIMIT).await {
                    return false;
                }
            }
            true
        };
        if !tokio::time::timeout(OPEN_LIMIT, pass).await.unwrap_or(true) {
            self.resource_interest_unsupported = true;
        }
    }

    /// Best effort on stop: a legacy peer keeps `resources/subscribe` state
    /// until told otherwise, so unsubscribe every key an answer can still
    /// release, in order, all within `RELEASE_LIMIT`. Keys not reached stay
    /// charged; a later task's passes reconcile them.
    async fn release(&mut self, backend: &Backend) {
        if self.era == Era::Modern {
            return;
        }
        let ledger = Arc::clone(&self.shared.ledger);
        let uris = ledger.lock().releasable();
        let walk = async {
            for uri in uris {
                if !drive(&ledger, backend, &uri, false, OPEN_LIMIT).await {
                    return;
                }
            }
        };
        let _ = tokio::time::timeout(RELEASE_LIMIT, walk).await;
    }

    /// Emit the coalescing windows that closed (§8), through the hub only.
    /// `true` when the backend is now ineligible: nothing was sent, and the
    /// caller ends the listener through [`end_ineligible`].
    fn flush(&mut self, hub: &Weak<EventsHub>) -> bool {
        self.flush_at(hub, Instant::now())
    }

    /// [`Self::flush`] of the windows closed by `at`.
    fn flush_at(&mut self, hub: &Weak<EventsHub>, at: Instant) -> bool {
        // Re-checked at every delivery: a reload can make the backend
        // ineligible while its listener runs (MIK-7894).
        let due = self.coalescer.due(at);
        if (self.tools_pending || !due.is_empty()) && self.shared.is_ineligible() {
            self.tools_pending = false;
            return true;
        }
        if std::mem::take(&mut self.tools_pending)
            && let Some(hub) = hub.upgrade()
        {
            hub.backend_tools_changed(&self.shared.name);
        }
        if due.is_empty() {
            return false;
        }
        let Some(hub) = hub.upgrade() else {
            return false;
        };
        for (kind, uri) in due {
            if !self.shared.need.lock().emits(kind, uri.as_deref()) {
                continue;
            }
            if let Some(uri) = &uri
                && self.shared.snapshot.lock().verdict(uri) != Verdict::Deliver
            {
                continue;
            }
            let backend = self.shared.name.clone();
            hub.emit(SourceEvent {
                kind: SourceKind::BackendNotification,
                name: event_name(&backend, kind),
                backend: backend.clone(),
                scope: Visibility::Backend(backend),
                owner: None,
                upstream_id: uuid::Uuid::new_v4().to_string(),
                occurred_at: Utc::now(),
                data: uri.map_or_else(|| json!({}), |uri| json!({ "uri": uri })),
                lifecycle_key: None,
            });
        }
        false
    }
}

#[cfg(test)]
#[path = "upstream_session_tests.rs"]
mod tests;
