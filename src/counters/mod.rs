// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854 red stub: the counter store's API with plausible but wrong
//! answers (nothing counted, nothing cut, nothing quarantined), so every
//! store test is seen failing at its own assertion before the real store
//! replaces this file.

use serde::{Deserialize, Serialize};

use crate::security::audit::{AuditOutcome, CredentialKind};

pub(crate) mod persist;

pub(crate) const MAX_LABELS: usize = 512;
pub(crate) const MAX_PAIRS: usize = 2_048;
pub(crate) const MAX_LABEL_BYTES: usize = 128;
pub(crate) const HALF_BUCKETS: usize = 96;
pub(crate) const DAYS: usize = 30;
pub(crate) const MAX_MARKERS: usize = 1_000;
pub(crate) const HALF: u64 = 1_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Metric {
    Calls,
    Blocks,
    Errors,
    Firewall,
    CacheHits,
}

impl Metric {
    pub(crate) const ALL: [Self; 5] = [
        Self::Calls,
        Self::Blocks,
        Self::Errors,
        Self::Firewall,
        Self::CacheHits,
    ];
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub blocked: bool,
    pub error: bool,
    pub firewall: bool,
    pub cache_hit: bool,
    pub replay: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Outcome {
    Audited {
        outcome: AuditOutcome,
        firewall: bool,
        cache_hit: bool,
    },
    Replay,
    AdmissionRefused,
}

impl Tally {
    pub(crate) fn from_outcome(_outcome: Outcome) -> Self {
        Self::default()
    }

    pub(crate) const fn is_empty(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Label<'a> {
    Known(&'a str),
    Untrusted,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Call<'a> {
    pub caller: &'a str,
    pub server: Label<'a>,
    pub tool: Label<'a>,
    pub tally: Tally,
}

pub(crate) fn caller_label(_kind: CredentialKind, account: &str) -> String {
    account.to_owned()
}

pub(crate) fn normalize(label: &str) -> String {
    label.to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dim {
    Server,
    Tool,
    Caller,
    CallerServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MarkerKind {
    Restart,
    Upgrade,
    ConfigReload,
    Pause,
    SwitchOff,
    SwitchOn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Marker {
    pub at: u64,
    pub kind: MarkerKind,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Window {
    Day,
    TwoDays,
    Month,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter<'a> {
    All,
    Server(&'a str),
    Tool(&'a str, &'a str),
    Caller(&'a str),
    CallerServer(&'a str, &'a str),
    Overflow(Dim),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Query<'a> {
    pub metric: Metric,
    pub window: Window,
    pub filter: Filter<'a>,
    pub compare: bool,
}

impl<'a> Query<'a> {
    pub(crate) const fn new(metric: Metric, window: Window, filter: Filter<'a>) -> Self {
        Self {
            metric,
            window,
            filter,
            compare: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Point {
    pub t: u64,
    pub v: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeriesView {
    pub points: Vec<Point>,
    pub previous: Option<Vec<Point>>,
    pub previous_complete: bool,
    pub folded: bool,
    pub since: u64,
}

#[derive(Debug)]
pub(crate) struct RestoreError;

#[derive(Debug)]
pub(crate) struct CounterStore {
    since: u64,
    lock: parking_lot::Mutex<()>,
}

impl CounterStore {
    pub(crate) fn new(since: u64) -> Self {
        Self {
            since,
            lock: parking_lot::Mutex::new(()),
        }
    }

    pub(crate) fn record<Tz: chrono::TimeZone>(&self, _call: &Call<'_>, _at: u64, _zone: &Tz) {}

    pub(crate) fn mark(&self, _kind: MarkerKind, _subject: Option<&str>, _at: u64) {}

    pub(crate) fn markers(&self, _from: u64) -> Vec<Marker> {
        Vec::new()
    }

    pub(crate) fn since(&self) -> u64 {
        self.since
    }

    pub(crate) fn series<Tz: chrono::TimeZone>(
        &self,
        _query: &Query<'_>,
        _now: u64,
        _zone: &Tz,
    ) -> SeriesView {
        SeriesView {
            points: Vec::new(),
            previous: None,
            previous_complete: true,
            folded: false,
            since: self.since,
        }
    }

    pub(crate) fn to_bytes(&self, _binary_version: &str, _saved_at: u64) -> Vec<u8> {
        b"{}".to_vec()
    }

    pub(crate) fn from_bytes<Tz: chrono::TimeZone>(
        _bytes: &[u8],
        now: u64,
        _binary_version: &str,
        _zone: &Tz,
    ) -> Result<(Self, bool), RestoreError> {
        Ok((Self::new(now), false))
    }

    #[cfg(test)]
    pub(crate) fn labels(&self, _dim: Dim) -> usize {
        0
    }

    #[cfg(test)]
    pub(crate) fn sweeps(&self) -> u64 {
        0
    }

    #[cfg(test)]
    pub(crate) fn lock_is_free(&self) -> bool {
        self.lock.try_lock().is_some()
    }

    #[cfg(test)]
    pub(crate) fn new_unbounded_for_test(since: u64) -> Self {
        Self::new(since)
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "persist_tests.rs"]
mod persist_tests;

#[cfg(test)]
#[path = "view_tests.rs"]
mod view_tests;
