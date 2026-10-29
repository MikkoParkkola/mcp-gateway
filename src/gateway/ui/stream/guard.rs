// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission, the one RAII guard, and the shared watcher's state.
//!
//! The hub lives in app state (inside the dashboard bootstrap, which every
//! gateway builds once), so a watcher restart never resets a generation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config_reload::Generation;

/// Streams open at once. A few browser tabs per operator, each holding a
/// watcher subscription and a credential re-check every second; a fixed
/// constant, not a setting.
pub(crate) const MAX_UI_STREAMS: usize = 32;
/// Streams one credential may hold, so one key cannot take the whole cap.
pub(crate) const MAX_PER_CREDENTIAL: usize = 4;

/// Why a stream was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    Global,
    Credential,
}

/// The shared view every stream reads: generations and the latest payloads.
#[derive(Clone, Debug, Default)]
pub(super) struct Snapshot {
    /// Rises when the full (admin) status changes.
    pub(super) status_gen: u64,
    /// Rises when the counts-only status changes; admin-only change rates
    /// never show in it.
    pub(super) counts_gen: u64,
    pub(super) reload_gen: u64,
    pub(super) full: Value,
    pub(super) counts: Value,
    /// Observed by the running watcher; false from a (re)start until its
    /// first tick, so a new stream never sends what was left from before.
    pub(super) fresh: bool,
}

impl Snapshot {
    /// The generation of the status view this caller is shown.
    pub(super) fn status_gen_for(&self, admin: bool) -> u64 {
        if admin {
            self.status_gen
        } else {
            self.counts_gen
        }
    }
}

#[derive(Default)]
struct Inner {
    streams: usize,
    per_credential: HashMap<String, usize>,
    watcher: Option<JoinHandle<()>>,
    /// The last generation the watcher saw, kept across watcher restarts so
    /// a reload applied while no stream was open still counts.
    last_generation: Option<Arc<Generation>>,
}

struct Shared {
    boot: u64,
    inner: Mutex<Inner>,
    snapshot: watch::Sender<Snapshot>,
    /// Held by a watcher for its whole publishing life, so two never publish
    /// at once. A successor starts only after the previous watcher was
    /// aborted (the last guard's drop) or finished; an aborted watcher's
    /// guard drops with it, so the lock never outlives a cancellable watcher.
    /// Waiting for it is cancel-safe, unlike a chain of join handles.
    ///
    /// Release is bounded by cancellation: the retire path always aborts the
    /// old watcher, which takes effect at its next await. What runs under the
    /// lock is `status_body`. Verified so far: the breaker and descriptor-gate
    /// log lines now run after their guards drop, so neither logs under the
    /// breaker state lock or the tools cache guard. Other logging under
    /// writer-side locks is not yet verified and belongs to the
    /// logging-under-lock sweep. A watcher stuck in synchronous code with no
    /// await is the one case abort cannot interrupt.
    publish_lock: Arc<tokio::sync::Mutex<()>>,
    /// Test seam: credential validation never answers while set.
    #[cfg(test)]
    hang_validation: std::sync::atomic::AtomicBool,
    /// Test seam: the watcher handover probe.
    #[cfg(test)]
    probe: super::probe::PublishProbe,
    /// Sends whose channel reservation is outstanding right now. Credential
    /// checks outside the reservation wait do not count. Test builds only.
    #[cfg(test)]
    awaiting_room: std::sync::atomic::AtomicUsize,
}

/// Caps, the watcher's lifetime and its published state.
pub(crate) struct StreamHub {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for StreamHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamHub")
    }
}

impl Default for StreamHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts one outstanding channel reservation until it drops.
#[cfg(test)]
pub(super) struct RoomWait {
    shared: Arc<Shared>,
}

#[cfg(test)]
impl Drop for RoomWait {
    fn drop(&mut self) {
        self.shared
            .awaiting_room
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Holds one stream's slot, its credential's slot and a watcher reference.
/// Dropping it, by whatever exit, gives all three back.
pub(super) struct Guard {
    hub: Arc<Shared>,
    credential: String,
}

impl StreamHub {
    /// A hub with a random boot id.
    pub(crate) fn new() -> Self {
        use rand::RngExt;
        Self {
            shared: Arc::new(Shared {
                boot: rand::rng().random(),
                inner: Mutex::new(Inner::default()),
                snapshot: watch::channel(Snapshot::default()).0,
                publish_lock: Arc::new(tokio::sync::Mutex::new(())),
                #[cfg(test)]
                hang_validation: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                probe: super::probe::PublishProbe::default(),
                #[cfg(test)]
                awaiting_room: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// This process's random boot id.
    pub(super) fn boot(&self) -> u64 {
        self.shared.boot
    }

    /// Streams open now.
    #[cfg(test)]
    pub(crate) fn open_streams(&self) -> usize {
        self.shared.lock().streams
    }

    /// Whether the watcher task is running.
    #[cfg(test)]
    pub(crate) fn watcher_running(&self) -> bool {
        self.shared.lock().watcher.is_some()
    }

    /// End the watcher task as a crash would, leaving the refcount alone.
    /// The handle lets a test wait until the task has finished.
    #[cfg(test)]
    pub(crate) fn kill_watcher_for_test(&self) -> Option<tokio::task::AbortHandle> {
        let watcher = self.shared.lock().watcher.as_ref()?.abort_handle();
        watcher.abort();
        Some(watcher)
    }

    /// Make credential validation hang (or not), as a stuck key-server or
    /// discovery fetch would.
    #[cfg(test)]
    pub(crate) fn hang_validation_for_test(&self, on: bool) {
        use std::sync::atomic::Ordering::SeqCst;
        self.shared.hang_validation.store(on, SeqCst);
    }

    /// Sends waiting for room in their channel right now.
    #[cfg(test)]
    pub(crate) fn sends_awaiting_room(&self) -> usize {
        self.shared
            .awaiting_room
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Count one outstanding reservation until the returned token drops.
    #[cfg(test)]
    pub(super) fn room_wait_started(&self) -> RoomWait {
        self.shared
            .awaiting_room
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        RoomWait {
            shared: Arc::clone(&self.shared),
        }
    }

    #[cfg(test)]
    pub(super) fn validation_hangs(&self) -> bool {
        self.shared
            .hang_validation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Take a slot for `credential`, starting the watcher with `start` if
    /// this is the first stream.
    pub(super) fn admit(
        &self,
        credential: &str,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> Result<Guard, Refusal> {
        let mut inner = self.shared.lock();
        if inner.streams >= MAX_UI_STREAMS {
            return Err(Refusal::Global);
        }
        let held = inner
            .per_credential
            .entry(credential.to_owned())
            .or_insert(0);
        if *held >= MAX_PER_CREDENTIAL {
            return Err(Refusal::Credential);
        }
        *held += 1;
        inner.streams += 1;
        self.start_if_needed(&mut inner, start);
        Ok(Guard {
            hub: Arc::clone(&self.shared),
            credential: credential.to_owned(),
        })
    }

    /// The lock a watcher holds while it publishes.
    pub(super) fn publish_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.shared.publish_lock)
    }

    /// Start the watcher if none is running, or if the last one ended on its
    /// own while streams were open (logged at warn).
    pub(super) fn ensure_watcher(&self, start: impl FnOnce() -> JoinHandle<()>) {
        self.start_if_needed(&mut self.shared.lock(), start);
    }

    fn start_if_needed(&self, inner: &mut Inner, start: impl FnOnce() -> JoinHandle<()>) {
        if inner.watcher.as_ref().is_some_and(JoinHandle::is_finished) {
            tracing::warn!("ui stream: the watcher ended unexpectedly; starting a new one");
            inner.watcher = None;
        }
        if inner.watcher.is_none() {
            self.shared
                .snapshot
                .send_if_modified(|s| std::mem::replace(&mut s.fresh, false));
            inner.watcher = Some(start());
        }
    }

    /// Whether `now` replaced the generation seen last, counting reloads
    /// applied while the watcher was stopped. The first sight is not one.
    pub(super) fn reloaded(&self, now: &Arc<Generation>) -> bool {
        let prev = self.shared.lock().last_generation.replace(Arc::clone(now));
        prev.is_some_and(|p| !Arc::ptr_eq(&p, now))
    }

    /// A receiver on the published snapshot.
    pub(super) fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.shared.snapshot.subscribe()
    }

    /// Publish what the watcher saw this tick. Generations rise only on a
    /// change; `uptime_secs` never counts as one.
    pub(super) fn observe(&self, full: Value, counts: Value, reloaded: bool) {
        #[cfg(test)]
        self.shared.probe.before_publish();
        self.shared.snapshot.send_if_modified(|s| {
            let full_changed = !same_ignoring_uptime(&s.full, &full);
            let counts_changed = !same_ignoring_uptime(&s.counts, &counts);
            let changed = full_changed || counts_changed;
            s.status_gen += u64::from(full_changed);
            s.counts_gen += u64::from(counts_changed);
            s.reload_gen += u64::from(reloaded);
            s.full = full;
            s.counts = counts;
            let was_fresh = std::mem::replace(&mut s.fresh, true);
            changed || reloaded || !was_fresh
        });
        #[cfg(test)]
        self.shared.probe.after_publish();
    }

    /// The handover probe (tests only).
    #[cfg(test)]
    pub(crate) fn probe(&self) -> &super::probe::PublishProbe {
        &self.shared.probe
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Two status payloads are the same when only `uptime_secs` differs.
pub(super) fn same_ignoring_uptime(a: &Value, b: &Value) -> bool {
    let (Some(x), Some(y)) = (a.as_object(), b.as_object()) else {
        return a == b;
    };
    let kept =
        |m: &serde_json::Map<String, Value>| m.keys().filter(|k| *k != "uptime_secs").count();
    kept(x) == kept(y)
        && x.iter()
            .filter(|(k, _)| *k != "uptime_secs")
            .all(|(k, v)| y.get(k) == Some(v))
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut inner = self.hub.lock();
        inner.streams = inner.streams.saturating_sub(1);
        if let Some(held) = inner.per_credential.get_mut(&self.credential) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                inner.per_credential.remove(&self.credential);
            }
        }
        if inner.streams == 0
            && let Some(watcher) = inner.watcher.take()
        {
            // Always abort before a successor can start (see `publish_lock`).
            watcher.abort();
        }
    }
}
