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
use tokio::task::AbortHandle;

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
    pub(super) status_gen: u64,
    pub(super) reload_gen: u64,
    pub(super) full: Value,
    pub(super) counts: Value,
    /// Observed by the running watcher; false from a (re)start until its
    /// first tick, so a new stream never sends what was left from before.
    pub(super) fresh: bool,
}

#[derive(Default)]
struct Inner {
    streams: usize,
    per_credential: HashMap<String, usize>,
    watcher: Option<AbortHandle>,
}

struct Shared {
    boot: u64,
    inner: Mutex<Inner>,
    snapshot: watch::Sender<Snapshot>,
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

    /// Take a slot for `credential`, starting the watcher with `start` if
    /// this is the first stream.
    pub(super) fn admit(
        &self,
        credential: &str,
        start: impl FnOnce() -> AbortHandle,
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
        if inner.watcher.is_none() {
            self.shared
                .snapshot
                .send_if_modified(|s| std::mem::replace(&mut s.fresh, false));
            inner.watcher = Some(start());
        }
        Ok(Guard {
            hub: Arc::clone(&self.shared),
            credential: credential.to_owned(),
        })
    }

    /// A receiver on the published snapshot.
    pub(super) fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.shared.snapshot.subscribe()
    }

    /// Publish what the watcher saw this tick. Generations rise only on a
    /// change; `uptime_secs` never counts as one.
    pub(super) fn observe(&self, full: Value, counts: Value, reloaded: bool) {
        self.shared.snapshot.send_if_modified(|s| {
            let changed = !same_ignoring_uptime(&s.full, &full) || s.counts != counts;
            s.status_gen += u64::from(changed);
            s.reload_gen += u64::from(reloaded);
            s.full = full;
            s.counts = counts;
            let was_fresh = std::mem::replace(&mut s.fresh, true);
            changed || reloaded || !was_fresh
        });
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
            watcher.abort();
        }
    }
}
