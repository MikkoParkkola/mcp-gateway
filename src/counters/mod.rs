// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windowed, persisted call counters and the marker ledger the web
//! UI draws its history from (ADR-017, ADR-026).
//!
//! Each logical call is counted once, where its one invocation record is
//! written (ADR-017). A series holds 96
//! half-hour buckets and 30 host-local days. Labels come only from config,
//! the catalogue and verified credentials: a name the caller chose adds to
//! its dimension's overflow count and is stored nowhere. Every dimension is
//! capped, so memory and `counters.json` are bounded by the constants below,
//! never by traffic.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use chrono::TimeZone;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::security::audit::{AuditOutcome, CredentialKind};

use crate::local_day as day;
mod latency;
// The latency readers serve the web UI, as `view` does.
#[cfg(any(test, feature = "webui"))]
mod latency_view;
pub(crate) mod persist;
mod ring;
mod snapshot;
// The readers serve the web UI's history routes; without them nothing reads.
#[cfg(any(test, feature = "webui"))]
mod sums;
#[cfg(any(test, feature = "webui"))]
mod view;

pub(crate) use latency::End;
#[cfg(test)]
pub(crate) use latency_view::LatPoint;
#[cfg(feature = "webui")]
pub(crate) use latency_view::ServerLatency;

/// The value a series reports for a send of `elapsed`: its bin's midpoint.
#[cfg(test)]
pub(crate) fn latency_bin_ms(elapsed: std::time::Duration) -> u64 {
    latency::bin_ms(latency::bin_of(elapsed))
}
pub(crate) use ring::Series;
// Named only by the web UI's routes; the module's own tests use it in place.
#[cfg(feature = "webui")]
pub(crate) use sums::CallWindows;
#[cfg(any(test, feature = "webui"))]
pub(crate) use view::{Filter, Query, Window};
#[cfg(test)]
pub(crate) use view::{Point, SeriesView};

/// Labels one dimension keeps before new ones add to its overflow count.
pub(crate) const MAX_LABELS: usize = 512;
/// Caller × server pairs kept before new ones add to the overflow count.
pub(crate) const MAX_PAIRS: usize = 2_048;
/// Longest label, in bytes; a longer one is cut and given a hash suffix.
pub(crate) const MAX_LABEL_BYTES: usize = 128;
/// Half-hour buckets per series: 48 hours.
pub(crate) const HALF_BUCKETS: usize = 96;
/// Local days per series.
pub(crate) const DAYS: usize = 30;
/// Markers kept, at most, and for at most [`MARKER_SECS`].
pub(crate) const MAX_MARKERS: usize = 1_000;
const MARKER_SECS: u64 = 30 * 86_400;
/// Width of a half-hour bucket, in seconds.
pub(crate) const HALF: u64 = 1_800;

/// What a series counts.
#[cfg(any(test, feature = "webui"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Metric {
    Calls,
    Blocks,
    Errors,
    Firewall,
    CacheHits,
}

#[cfg(any(test, feature = "webui"))]
impl Metric {
    /// Every metric, in bucket order.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 5] = [
        Self::Calls,
        Self::Blocks,
        Self::Errors,
        Self::Firewall,
        Self::CacheHits,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// How one finished call moves the counters. A replay is the delivery of an
/// answer its first execution already counted, so it moves none.
#[allow(clippy::struct_excessive_bools)] // Each flag is one metric's increment, independent of the others.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub blocked: bool,
    pub error: bool,
    pub firewall: bool,
    pub cache_hit: bool,
    pub replay: bool,
}

/// What a writer knows about a finished call.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Outcome {
    /// A call with an invocation record: its outcome, whether a firewall
    /// refused it (carried from the verdict, never read back from the body),
    /// and whether the gateway's response cache answered it.
    Audited {
        outcome: AuditOutcome,
        firewall: bool,
        cache_hit: bool,
    },
    /// An idempotency replay of a call already counted.
    Replay,
    /// A `tools/call` refused because the audit log could not admit it.
    AdmissionRefused,
}

impl Tally {
    /// The counter moves for `outcome`. Firewall provenance wins over the
    /// audit outcome: a direct response-firewall refusal is answered 200 with
    /// an error code, which the audit record classes as an error.
    pub(crate) fn from_outcome(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Replay => Self {
                replay: true,
                ..Self::default()
            },
            Outcome::AdmissionRefused => Self {
                error: true,
                ..Self::default()
            },
            Outcome::Audited { firewall: true, .. } => Self {
                blocked: true,
                firewall: true,
                ..Self::default()
            },
            Outcome::Audited {
                outcome, cache_hit, ..
            } => match outcome {
                AuditOutcome::Ok => Self {
                    cache_hit,
                    ..Self::default()
                },
                AuditOutcome::Denied(_) => Self {
                    blocked: true,
                    ..Self::default()
                },
                AuditOutcome::ToolError | AuditOutcome::Invalid(_) | AuditOutcome::Error(_) => {
                    Self {
                        error: true,
                        ..Self::default()
                    }
                }
            },
        }
    }

    /// Whether this tally moves nothing.
    pub(crate) const fn is_empty(self) -> bool {
        self.replay
    }

    fn counts(self) -> [u64; 5] {
        if self.replay {
            return [0; 5];
        }
        [
            1,
            u64::from(self.blocked),
            u64::from(self.error),
            u64::from(self.firewall),
            u64::from(self.cache_hit),
        ]
    }
}

/// A server or tool name as the counting site resolved it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Label<'a> {
    /// Configured (a server) or catalogued (a tool): kept as a label.
    Known(&'a str),
    /// Chosen by the caller: adds to the overflow count, stored nowhere.
    Untrusted,
}

/// One finished call. `caller` is a [`caller_label`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Call<'a> {
    pub caller: &'a str,
    pub server: Label<'a>,
    pub tool: Label<'a>,
    pub tally: Tally,
}

/// A caller's label, namespaced by how it presented itself, so that an API
/// key named `bearer` and the static bearer stay two callers. `account` is
/// the audit record's account: the key name, the OIDC actor id, or empty.
pub(crate) fn caller_label(kind: CredentialKind, account: &str) -> String {
    match kind {
        CredentialKind::ApiKey => format!("key:{account}"),
        CredentialKind::StaticBearer => "bearer".to_owned(),
        CredentialKind::OidcBearer => format!("oidc:{account}"),
        CredentialKind::DashboardSession => format!("session:{account}"),
        CredentialKind::KeyServerToken => format!("token:{account}"),
        CredentialKind::LocalTransport => "local".to_owned(),
        CredentialKind::None => "anonymous".to_owned(),
    }
}

/// `label` cut to [`MAX_LABEL_BYTES`] on a character boundary, with an 8-hex
/// SHA-256 suffix when cut, so two long labels sharing a prefix stay apart.
pub(crate) fn normalize(label: &str) -> String {
    if label.len() <= MAX_LABEL_BYTES {
        return label.to_owned();
    }
    let digest = crate::hashing::sha256_hex(label.as_bytes());
    let marker = format!("~{}", &digest[..8]);
    crate::truncate::truncate(
        label,
        crate::truncate::Budget::Bytes(MAX_LABEL_BYTES),
        &marker,
        crate::truncate::Suffix::Within,
    )
}

/// A daily bucket's key: the local date as days from the common era.
fn day_key(date: chrono::NaiveDate) -> u64 {
    use chrono::Datelike;
    u64::try_from(date.num_days_from_ce()).unwrap_or_default()
}

/// A dimension the store keeps labels for.
#[cfg(any(test, feature = "webui"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dim {
    Server,
    Tool,
    Caller,
    CallerServer,
}

/// What a marker marks.
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

/// One event drawn on every chart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Marker {
    /// Unix seconds.
    pub at: u64,
    pub kind: MarkerKind,
    /// A configured server name or a version string, never caller input.
    pub subject: Option<String>,
}

/// The binary version a restored `counters.json` was saved by, and the one
/// now running, when they differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionChange {
    pub from: String,
    pub to: String,
}

/// One capped label map plus the overflow count past its cap.
#[derive(Debug, Clone)]
pub(crate) struct Dimension<K: Hash + Eq> {
    labels: HashMap<K, Series>,
    overflow: Series,
    cap: usize,
    /// The half-hour bucket of the last sweep, so a stream of new labels
    /// against a full dimension sweeps at most once per bucket.
    last_sweep: Option<u64>,
}

impl<K: Hash + Eq + Clone> Dimension<K> {
    fn new(cap: usize) -> Self {
        Self {
            labels: HashMap::new(),
            overflow: Series::default(),
            cap,
            last_sweep: None,
        }
    }

    /// Add `counts` under `key`, or to the overflow when `key` is `None` or
    /// the cap is met. Returns whether a sweep ran.
    fn add(&mut self, key: Option<K>, at: u64, day: Option<u64>, counts: [u64; 5]) -> bool {
        let Some(key) = key else {
            self.overflow.add(at, day, counts);
            return false;
        };
        if let Some(series) = self.labels.get_mut(&key) {
            series.add(at, day, counts);
            return false;
        }
        let mut swept = false;
        let bucket = at / HALF;
        if self.labels.len() >= self.cap && self.last_sweep != Some(bucket) {
            self.last_sweep = Some(bucket);
            self.labels.retain(|_, series| !series.aged(at, day));
            swept = true;
        }
        if self.labels.len() < self.cap {
            self.labels
                .entry(key)
                .or_insert_with(|| Series::admitted_at(at))
                .add(at, day, counts);
        } else {
            self.overflow.add(at, day, counts);
        }
        swept
    }

    /// Record one call's backend send time on `key`'s series, or on the
    /// overflow when `key` is `None` or holds no slot (it was counted there).
    fn sample(
        &mut self,
        key: Option<&K>,
        at: u64,
        day: Option<u64>,
        sample: (std::time::Duration, End),
    ) {
        let series = match key.and_then(|k| self.labels.get_mut(k)) {
            Some(series) => series,
            None => &mut self.overflow,
        };
        series.latency.add(at, day, sample.0, sample.1);
    }
}

/// Everything one store holds, cloned whole for a save.
#[derive(Debug, Clone)]
pub(crate) struct Inner {
    since: u64,
    global: Series,
    server: Dimension<String>,
    tool: Dimension<(String, String)>,
    caller: Dimension<String>,
    caller_server: Dimension<(String, String)>,
    markers: VecDeque<Marker>,
    marker_cap: usize,
    sweeps: u64,
    /// The local day the last record fell on, so the hot path is one
    /// comparison and the zone is read once a day. One store counts in one
    /// zone: the host's.
    today: Option<day::LocalDay>,
}

impl Inner {
    fn new(since: u64, caps: [usize; 3]) -> Self {
        let [labels, pairs, markers] = caps;
        Self {
            since,
            global: Series::default(),
            server: Dimension::new(labels),
            tool: Dimension::new(labels),
            caller: Dimension::new(labels),
            caller_server: Dimension::new(pairs),
            markers: VecDeque::new(),
            marker_cap: markers,
            sweeps: 0,
            today: None,
        }
    }

    /// The daily bucket `at` falls in: the cached day while `at` is inside
    /// it, else the zone is read again, past midnight or for a clock that
    /// stepped back.
    fn day_of<Tz: TimeZone>(&mut self, at: u64, zone: &Tz) -> u64 {
        let day = match self.today {
            Some(day) if day.start <= at && at < day.end => day,
            _ => {
                let day = day::local_day(zone, at);
                self.today = Some(day);
                day
            }
        };
        day_key(day.date)
    }

    fn mark(&mut self, kind: MarkerKind, subject: Option<&str>, at: u64) {
        let marker = Marker {
            at,
            kind,
            subject: subject.map(normalize),
        };
        let position = self.markers.partition_point(|m| m.at <= at);
        self.markers.insert(position, marker);
        while self.markers.len() > self.marker_cap {
            self.markers.pop_front();
        }
        let newest = self.markers.back().map_or(at, |m| m.at);
        while self
            .markers
            .front()
            .is_some_and(|m| m.at + MARKER_SECS < newest)
        {
            self.markers.pop_front();
        }
    }
}

/// The counters and markers, behind one lock.
///
/// ponytail: one global lock held for one map lookup and one ring update per
/// call; shard per dimension if the invoke-path bench shows contention.
#[derive(Debug)]
pub(crate) struct CounterStore {
    inner: Mutex<Inner>,
    /// Lock acquisitions by the readers, so a row can prove a batch read
    /// takes one, whatever the label count. Per store, never global.
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
    /// Label windows a batch read walked bucket by bucket, so a row can prove
    /// that labels the store does not hold share one walk.
    #[cfg(test)]
    window_walks: std::sync::atomic::AtomicUsize,
}

impl CounterStore {
    /// An empty store whose coverage starts at `since`.
    pub(crate) fn new(since: u64) -> Self {
        Self::from_inner(Inner::new(since, [MAX_LABELS, MAX_PAIRS, MAX_MARKERS]))
    }

    fn from_inner(inner: Inner) -> Self {
        Self {
            inner: Mutex::new(inner),
            #[cfg(test)]
            reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            window_walks: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Count `call`, finished at unix second `at`, on `zone`'s days.
    #[cfg(test)]
    pub(crate) fn record<Tz: TimeZone>(&self, call: &Call<'_>, at: u64, zone: &Tz) {
        self.record_timed(call, at, zone, None);
    }

    /// [`Self::record`], plus the call's backend send time when a send began:
    /// one sample per counted call, under the same lock, in the
    /// same bucket and on the same server label as its count.
    pub(crate) fn record_timed<Tz: TimeZone>(
        &self,
        call: &Call<'_>,
        at: u64,
        zone: &Tz,
        sample: Option<(std::time::Duration, End)>,
    ) {
        if call.tally.is_empty() {
            return;
        }
        let counts = call.tally.counts();
        let server = match call.server {
            Label::Known(name) => Some(normalize(name)),
            Label::Untrusted => None,
        };
        let tool = match (&server, call.tool) {
            (Some(server), Label::Known(tool)) => Some((server.clone(), normalize(tool))),
            _ => None,
        };
        let caller = normalize(call.caller);
        let pair = server.clone().map(|server| (caller.clone(), server));
        let sampled = sample.map(|sample| (server.clone(), sample));
        let mut inner = self.inner.lock();
        let day = Some(inner.day_of(at, zone));
        inner.global.add(at, day, counts);
        let swept = [
            inner.server.add(server, at, day, counts),
            inner.tool.add(tool, at, day, counts),
            inner.caller.add(Some(caller), at, day, counts),
            inner.caller_server.add(pair, at, day, counts),
        ];
        inner.sweeps += swept.iter().map(|&s| u64::from(s)).sum::<u64>();
        if let Some((server, sample)) = sampled {
            inner.global.latency.add(at, day, sample.0, sample.1);
            inner.server.sample(server.as_ref(), at, day, sample);
        }
    }

    /// Record a marker at unix second `at`.
    pub(crate) fn mark(&self, kind: MarkerKind, subject: Option<&str>, at: u64) {
        self.inner.lock().mark(kind, subject, at);
    }

    /// Record a marker now. On a clock that cannot be read, nothing: a
    /// recorder writes nothing.
    pub(crate) fn mark_now(&self, kind: MarkerKind, subject: Option<&str>) {
        if let Ok(now) = crate::clock::unix_secs() {
            self.mark(kind, subject, now);
        }
    }

    /// Markers at or after `from`, oldest first.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn markers(&self, from: u64) -> Vec<Marker> {
        let inner = self.read_lock();
        inner
            .markers
            .iter()
            .filter(|m| m.at >= from)
            .cloned()
            .collect()
    }

    /// The newest `limit` markers at or after `from`, newest first, and how
    /// many markers are at or after `from` in all. One lock, and only the
    /// rows returned are cloned.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn newest_markers(&self, from: u64, limit: usize) -> (Vec<Marker>, usize) {
        let inner = self.read_lock();
        let mut in_window = inner.markers.iter().rev().filter(|m| m.at >= from);
        let newest: Vec<Marker> = in_window.by_ref().take(limit).cloned().collect();
        let total = newest.len() + in_window.count();
        (newest, total)
    }

    /// When coverage began.
    #[cfg(test)]
    pub(crate) fn since(&self) -> u64 {
        self.inner.lock().since
    }

    /// A copy of everything, taken under the lock and released before the
    /// caller serializes it.
    pub(crate) fn snapshot(&self) -> Inner {
        self.inner.lock().clone()
    }

    /// The file bytes for this store: the snapshot is taken under the lock,
    /// serialized after it is released.
    #[cfg(test)]
    pub(crate) fn encode(&self, binary_version: &str, saved_at: u64) -> Vec<u8> {
        snapshot::encode(&self.saved_snapshot(saved_at), binary_version, saved_at)
    }

    /// The copy of the store a save at `saved_at` writes: half-hour latency
    /// slots the clock has left are closed, not saved as live histograms
    /// (the live store closes them on its next record). Every save path
    /// takes it, so what a test encodes is what the gateway writes.
    pub(crate) fn saved_snapshot(&self, saved_at: u64) -> Inner {
        let mut inner = self.snapshot();
        inner.global.latency.finalize(saved_at, None);
        inner.server.overflow.latency.finalize(saved_at, None);
        for series in inner.server.labels.values_mut() {
            series.latency.finalize(saved_at, None);
        }
        inner
    }

    /// Restore from `bytes` at `now`, re-applying every bound. Returns the
    /// store and whether anything had to be cut back. A file saved by another
    /// binary version records an `upgrade` marker.
    ///
    /// # Errors
    ///
    /// The bytes are not a version-1 `counters.json`.
    #[cfg(test)]
    pub(crate) fn from_bytes<Tz: TimeZone>(
        bytes: &[u8],
        now: u64,
        binary_version: &str,
        zone: &Tz,
    ) -> Result<(Self, bool), snapshot::RestoreError> {
        Self::from_bytes_noting_change(bytes, now, binary_version, zone)
            .map(|(store, cut, _)| (store, cut))
    }

    /// [`Self::from_bytes`], also returning the version change it marked: the
    /// one value the server keeps for `GET /ui/api/gateway`, taken from the
    /// restore itself and never read back from marker history.
    ///
    /// # Errors
    ///
    /// The bytes are not a version-1 `counters.json`.
    pub(crate) fn from_bytes_noting_change<Tz: TimeZone>(
        bytes: &[u8],
        now: u64,
        binary_version: &str,
        zone: &Tz,
    ) -> Result<(Self, bool, Option<VersionChange>), snapshot::RestoreError> {
        let (mut inner, saved_version, cut) = snapshot::from_bytes(bytes, now, zone)?;
        let change = (saved_version != binary_version).then(|| VersionChange {
            from: saved_version,
            to: binary_version.to_owned(),
        });
        if let Some(change) = &change {
            let subject = format!("{} → {}", change.from, change.to);
            inner.mark(MarkerKind::Upgrade, Some(&subject), now);
        }
        Ok((Self::from_inner(inner), cut, change))
    }

    /// Labels a dimension holds now.
    #[cfg(test)]
    pub(crate) fn labels(&self, dim: Dim) -> usize {
        let inner = self.inner.lock();
        match dim {
            Dim::Server => inner.server.labels.len(),
            Dim::Tool => inner.tool.labels.len(),
            Dim::Caller => inner.caller.labels.len(),
            Dim::CallerServer => inner.caller_server.labels.len(),
        }
    }

    /// Sweeps run so far, across dimensions.
    #[cfg(test)]
    pub(crate) fn sweeps(&self) -> u64 {
        self.inner.lock().sweeps
    }

    /// Whether the store's lock is free right now.
    #[cfg(test)]
    pub(crate) fn lock_is_free(&self) -> bool {
        self.inner.try_lock().is_some()
    }

    /// A store with no caps, to build an oversized file for a restore test.
    #[cfg(test)]
    pub(crate) fn new_unbounded_for_test(since: u64) -> Self {
        Self::from_inner(Inner::new(since, [usize::MAX; 3]))
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "pairs_tests.rs"]
mod pairs_tests;

#[cfg(test)]
#[path = "persist_tests.rs"]
mod persist_tests;

#[cfg(test)]
#[path = "sums_tests.rs"]
mod sums_tests;
#[cfg(test)]
#[path = "view_tests.rs"]
mod view_tests;

#[cfg(test)]
#[path = "timing_tests.rs"]
mod timing_tests;
