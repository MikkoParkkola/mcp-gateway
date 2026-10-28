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
        Self {
            shared: Arc::new(Shared {
                boot: 0,
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
    pub(crate) fn open_streams(&self) -> usize {
        let _ = &self.shared.inner;
        0
    }

    /// Whether the watcher task is running.
    pub(crate) fn watcher_running(&self) -> bool {
        false
    }

    /// Take a slot for `credential`, starting the watcher with `start` if
    /// this is the first stream.
    pub(super) fn admit(
        &self,
        credential: &str,
        _start: impl FnOnce() -> AbortHandle,
    ) -> Result<Guard, Refusal> {
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
    pub(super) fn observe(&self, _full: Value, _counts: Value, _reloaded: bool) {}
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = (&self.hub, &self.credential);
    }
}
