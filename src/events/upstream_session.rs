// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connection logic of one backend's listener task (MIK-7630 I5 design
//! §3, §5, §8, §9): open the era's channel, keep it matching the counted
//! interest, coalesce what arrives, and emit through the hub only.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

#[cfg(test)]
use serde_json::json;
use tracing::debug;

use super::EventsHub;
use super::upstream::Kind;
use super::upstream_listener::Shared;
use super::upstream_need::Coalescer;
use crate::backend::{Backend, BackendRegistry};
use crate::protocol::era::PeerEra;
#[cfg(test)]
use crate::transport::upstream_tap::UpstreamNote;
use crate::transport::upstream_tap::{
    FrameStream, KindSet, NoteKind, Refused, Requested, UpstreamListen, Watched,
};

/// How often the loop looks at timers; also bounds coalescing latency.
const TICK: Duration = Duration::from_millis(250);
/// A modern listen must be acknowledged within this (§3).
/// Opening a channel may not outlast this.
const OPEN_LIMIT: Duration = Duration::from_secs(30);
/// A minted run reads its grant's fence this often, so a quiet stream that
/// sends no request still ends when the grant moves; the events worker's
/// sweep period.
const FENCE_EVERY: Duration = Duration::from_secs(30);
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
/// A modern stream this old is replaced make-before-break, ahead of the
/// hourly cut of its POST (`STREAM_TIMEOUT`, 3600 s, in `http/listen.rs`).
pub(super) const RECYCLE: Duration = Duration::from_secs(55 * 60);
// The replacement must open and be acknowledged before the old stream's cut.
// A block, not a bare `assert!` expression: Kani's toolchain rejects that form
// under `-D warnings` (semicolon-in-expressions-from-non-local-macros).
const _: () = {
    assert!(OPEN_LIMIT.as_secs() + ACK_DEADLINE.as_secs() < 3600 - RECYCLE.as_secs());
};
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
    /// The fence binding of the run that heard the notice.
    pub(super) fence: Option<String>,
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
    #[cfg(test)]
    {
        *shared.ran_interactive.lock() = Some(crate::oauth::login_gate::interactive());
    }
    let _gate = tokio::select! {
        () = shared.stop.cancelled() => return,
        gate = Arc::clone(&shared.gate).lock_owned() => gate,
    };
    let mut failures = 0u32;
    // One receiver for the task's life (T35): a revival sent at any point
    // after the registry check below is seen by the park that follows it.
    let mut wake = shared.wake.subscribe();
    // The lease the last run sent under; a wake that moved it cuts the backoff.
    let mut ran_under: Option<u128> = None;
    let mut cut = run::LeaseCut::default();
    loop {
        if shared.stop.is_cancelled() {
            return;
        }
        if shared.is_ineligible() && end_ineligible(&shared, &hub).await {
            return;
        }
        // Signals sent before this check are answered by it.
        wake.borrow_and_update();
        #[allow(
            clippy::disallowed_methods,
            reason = "Background: the events source watches backends; no caller request"
        )]
        let Some(backend) = registry.get(&shared.name) else {
            // Gone: park until the interest changes or the keys are deleted.
            // A removed backend owes nothing; a re-added one starts afresh.
            *shared.tools.lock() = ToolsDebt::default();
            #[cfg(test)]
            shared.before_park.pause().await;
            tokio::select! {
                () = shared.stop.cancelled() => return,
                _ = wake.changed() => {
                    #[cfg(test)]
                    shared.waits.ended(WaitEnd::Revival);
                }
                () = tokio::time::sleep(Duration::from_secs(30)) => {
                    #[cfg(test)]
                    shared.waits.ended(WaitEnd::Timer);
                }
            }
            continue;
        };
        // By transport kind: A2A has no stream to open (MIK-8835.A2A.2).
        let outcome = if backend.is_a2a() {
            poll::poll(&shared, &backend, &hub, &registry).await
        } else {
            session(&shared, &backend, &hub, &registry, &mut ran_under).await
        };
        let delay = match outcome {
            Outcome::Stopped => return,
            Outcome::Unsupported => BACKOFF_CAP,
            // A stream cut at its hourly end (a legacy GET) reconnects at once.
            Outcome::Ended { lasted, .. } if lasted >= shared.recycle => {
                failures = 0;
                Duration::ZERO
            }
            Outcome::Ended { acked, lasted } => {
                failures = if acked || lasted >= STABLE {
                    0
                } else {
                    failures.saturating_add(1)
                };
                backoff(failures)
            }
        };
        #[cfg(test)]
        shared.before_backoff.pause().await;
        // A revival cuts the wait; a filter change does not, so churn on the
        // subscriptions cannot reconnect a failing backend early (T35).
        let mut deadline = cut.deadline(&shared, &hub, ran_under, delay, BACKOFF_FIRST);
        #[cfg(test)]
        shared.waits.begin();
        loop {
            tokio::select! {
                () = shared.stop.cancelled() => return,
                () = tokio::time::sleep_until(deadline) => {
                    #[cfg(test)]
                    shared.waits.ended(WaitEnd::Timer);
                    break;
                }
                _ = wake.changed() => {
                    if registered_anew(&registry, &shared.name, &backend) {
                        #[cfg(test)]
                        shared.waits.ended(WaitEnd::Revival);
                        break;
                    }
                    deadline = cut.on_wake(&shared, &hub, ran_under, deadline, BACKOFF_FIRST);
                }
            }
        }
    }
}

/// What ended a wait: a revival signal, or the wait's own timer (T35).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitEnd {
    Revival,
    Timer,
}

/// The task's waits, seen from a test: what ended each one, in order, so a
/// row asserts the cause of a reconnect instead of timing it, and a signal
/// that the task has begun a backoff wait, so a row sends its revival
/// during the wait instead of after a sleep.
#[cfg(test)]
#[derive(Debug, Default)]
pub(super) struct WaitProbe {
    ends: parking_lot::Mutex<Vec<WaitEnd>>,
    pub(super) began: tokio::sync::Notify,
}

#[cfg(test)]
impl WaitProbe {
    fn begin(&self) {
        self.began.notify_one();
    }

    fn ended(&self, cause: WaitEnd) {
        self.ends.lock().push(cause);
    }

    /// The causes recorded so far.
    pub(super) fn ends(&self) -> Vec<WaitEnd> {
        self.ends.lock().clone()
    }
}

/// Whether the registry no longer holds `ended` under `name`: the backend
/// was removed or replaced since its session ended.
fn registered_anew(registry: &BackendRegistry, name: &str, ended: &Arc<Backend>) -> bool {
    #[allow(
        clippy::disallowed_methods,
        reason = "Background: the events source watches backends; no caller request"
    )]
    registry
        .get(name)
        .is_none_or(|now| !Arc::ptr_eq(&now, ended))
}

fn requested(shared: &Shared) -> Requested {
    let (kinds, uris) = shared.need.lock().filter();
    Requested { kinds, uris }
}

fn failed() -> Outcome {
    Outcome::Ended {
        acked: false,
        lasted: Duration::ZERO,
    }
}

/// A replacement listen being opened (D2): polled as one arm of the loop's
/// select, so the current stream keeps draining while it opens.
type Opening = std::pin::Pin<
    Box<dyn std::future::Future<Output = (Result<FrameStream, Refused>, Requested)> + Send>,
>;

/// A replacement listen waiting for its acknowledgement (make before break).
struct Pending {
    stream: FrameStream,
    requested: Requested,
    since: Instant,
}

#[allow(clippy::struct_excessive_bools)] // Each flag is an independent fact about the current stream.
struct State<'a> {
    shared: &'a Arc<Shared>,
    era: PeerEra,
    current: Option<(FrameStream, Requested)>,
    pending: Option<Pending>,
    opening: Option<Opening>,
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
    /// The session's transport, which the legacy release walk names as the
    /// holder of its calls (D5).
    handle: Option<Weak<dyn UpstreamListen>>,
    /// The last URI a legacy pass reached; the next resumes after it.
    legacy_cursor: Option<String>,
    /// A minted run's fence, whose binding stamps every occurrence emitted.
    fence: Option<Arc<crate::events::listener_credential::RunFence>>,
    /// When the run next reads its fence.
    fence_due: Instant,
    /// A leased run's generation, stamped on every occurrence emitted.
    lease: Option<u128>,
}

impl<'a> State<'a> {
    fn new(shared: &'a Arc<Shared>, era: PeerEra) -> Self {
        let now = Instant::now();
        Self {
            shared,
            era,
            current: None,
            pending: None,
            opening: None,
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
            handle: None,
            legacy_cursor: None,
            fence: None,
            fence_due: now + FENCE_EVERY,
            lease: None,
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
        // A per-user listener reads no catalogue through the backend's shared
        // transport, whose credential is the gateway's: its URIs are admitted
        // (an unread catalogue proves nothing, §7) rather than judged by the
        // gateway's view.
        if self.shared.key.obs.is_some() || requested(self.shared).uris.is_empty() {
            return;
        }
        let epoch = self.shared.snapshot.lock().epoch();
        // A grant after this point is not judged by this read.
        let granted_by = hub.upgrade().map_or(0, |hub| hub.store.generation_now());
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
                // A clear while this read was out (the last URI interest left,
                // the instance was replaced) drops it, revocations included.
                if !self
                    .shared
                    .snapshot
                    .lock()
                    .read_at(epoch, (read.uris, complete), granted_by)
                {
                    return;
                }
                if complete && let Some(hub) = hub.upgrade() {
                    hub.revoke_absent_uris(&self.shared.key, &listed, granted_by)
                        .await;
                }
                self.reread = false;
                // The catalogue cache's own TTL: a shorter configured one
                // re-reads sooner, so a removal is seen as soon as the
                // cache would (MIK-7950).
                self.snapshot_due = Instant::now() + snapshot_interval(backend.cache_ttl());
            }
            Err(error) => {
                debug!(backend = %self.shared.name, error = %self.shared.error_text(&error), "upstream listener: catalogue read failed");
                self.snapshot_retry_at = Instant::now() + SNAPSHOT_RETRY;
            }
        }
    }

    /// A replacement open finished: it waits for its acknowledgement, or
    /// the next open backs off.
    fn on_opened(&mut self, opened: Result<FrameStream, Refused>, requested: Requested) {
        self.opening = None;
        match opened {
            Ok(stream) => {
                self.pending = Some(Pending {
                    stream,
                    requested,
                    since: Instant::now(),
                });
            }
            Err(_) => self.unacked(),
        }
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
            // An acknowledged stream this old is replaced with the same
            // filter, before the hourly cut of its POST (D2).
            let aged = self.acked.is_some() && self.opened.elapsed() >= self.shared.recycle;
            if self.pending.is_none()
                && self.opening.is_none()
                && (have.as_ref() != Some(&want) || aged)
                && now >= self.retry_open_at
            {
                let handle = handle.clone();
                self.opening = Some(Box::pin(async move {
                    let opened = tokio::time::timeout(
                        OPEN_LIMIT,
                        open(&handle, true, want.clone(), Watched::default()),
                    )
                    .await
                    .unwrap_or(Err(Refused::Expired));
                    (opened, want)
                }));
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
}

#[path = "upstream_session_open.rs"]
mod opening;
use opening::open;

#[path = "upstream_session_refill.rs"]
mod refill;
#[cfg(test)]
use refill::{Refill, finish_refill, start_due_refill};

#[path = "upstream_session_notes.rs"]
mod notes;

#[path = "upstream_session_legacy.rs"]
mod legacy;

#[path = "upstream_session_poll.rs"]
mod poll;

#[path = "upstream_session_run.rs"]
mod run;

#[path = "upstream_session_conn.rs"]
mod conn;
use conn::session;
#[cfg(test)]
use conn::{OnTick, on_tick};
use legacy::watched_by;
#[cfg(test)]
use run::{pick_session, runs_modern};

#[cfg(test)]
#[path = "upstream_session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "upstream_session_seam_tests.rs"]
mod seam_tests;

#[cfg(test)]
#[path = "upstream_session_iso_tests.rs"]
mod iso_tests;
