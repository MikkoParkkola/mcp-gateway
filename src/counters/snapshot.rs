// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `counters.json` format. A restore re-applies every bound to what it
//! reads, so an oversized file is cut back to the caps instead of trusted.

use std::hash::Hash;

use chrono::TimeZone;
use serde::{Deserialize, Serialize};

use super::latency::{LatencySeries, SeriesFile};
use super::{
    Dimension, HALF, Inner, MAX_LABELS, MAX_MARKERS, MAX_PAIRS, Marker, Series, day, normalize,
};

const FORMAT: u32 = 1;

/// Why a file could not be restored.
#[derive(Debug)]
pub(crate) enum RestoreError {
    /// Not JSON, or not this shape.
    Parse(serde_json::Error),
    /// A format this binary does not know.
    Version(u32),
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "counters.json does not parse: {error}"),
            Self::Version(v) => write!(
                f,
                "counters.json has format {v}, this binary reads {FORMAT}"
            ),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DimFile<K> {
    labels: Vec<(K, Series)>,
    overflow: Series,
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    binary_version: String,
    saved_at: u64,
    since: u64,
    global: Series,
    server: DimFile<String>,
    tool: DimFile<(String, String)>,
    caller: DimFile<String>,
    caller_server: DimFile<(String, String)>,
    markers: Vec<Marker>,
    /// Backend latency. Additive: a file without it restores
    /// empty latency, and a binary without this field ignores it.
    #[serde(default)]
    latency: LatencyFile,
}

/// The latency of the global series, the server labels and their overflow.
#[derive(Default, Serialize, Deserialize)]
struct LatencyFile {
    #[serde(default)]
    global: SeriesFile,
    #[serde(default)]
    server: Vec<(String, SeriesFile)>,
    #[serde(default)]
    overflow: SeriesFile,
}

fn latency_file(inner: &Inner) -> LatencyFile {
    let mut server: Vec<(String, SeriesFile)> = inner
        .server
        .labels
        .iter()
        .filter(|(_, s)| !s.latency.is_empty())
        .map(|(k, s)| (k.clone(), s.latency.to_file()))
        .collect();
    server.sort_by(|a, b| a.0.cmp(&b.0));
    LatencyFile {
        global: inner.global.latency.to_file(),
        server,
        overflow: inner.server.overflow.latency.to_file(),
    }
}

/// Only the format version, read first so a file of another format is told
/// apart from a broken one.
#[derive(Deserialize)]
struct Head {
    version: u32,
}

/// `series` without its latency, which the file keeps apart
/// ([`latency_file`]): the counts only, so a save copies no histogram twice.
fn counts_of(series: &Series) -> Series {
    Series {
        half: series.half.clone(),
        day: series.day.clone(),
        admitted: series.admitted,
        latency: super::latency::LatencySeries::default(),
    }
}

fn dim_file<K: Hash + Eq + Clone + Ord>(dim: &Dimension<K>) -> DimFile<K> {
    let mut labels: Vec<(K, Series)> = dim
        .labels
        .iter()
        .map(|(k, s)| (k.clone(), counts_of(s)))
        .collect();
    // Stable bytes for the same store: sorted, not hash order.
    labels.sort_by(|a, b| a.0.cmp(&b.0));
    DimFile {
        labels,
        overflow: counts_of(&dim.overflow),
    }
}

/// `inner` as file bytes.
pub(super) fn encode(inner: &Inner, binary_version: &str, saved_at: u64) -> Vec<u8> {
    let file = File {
        version: FORMAT,
        binary_version: binary_version.to_owned(),
        saved_at,
        since: inner.since,
        global: counts_of(&inner.global),
        server: dim_file(&inner.server),
        tool: dim_file(&inner.tool),
        caller: dim_file(&inner.caller),
        caller_server: dim_file(&inner.caller_server),
        markers: inner.markers.iter().cloned().collect(),
        latency: latency_file(inner),
    };
    // Plain data with string keys only: serialization cannot fail.
    serde_json::to_vec(&file).unwrap_or_default()
}

/// `series` with only the buckets a window ending at `now` holds.
fn windowed<Tz: TimeZone>(series: &Series, now: u64, zone: &Tz) -> Series {
    let mut kept = Series::admitted_at(series.admitted);
    let today = Some(super::day_key(day::local_day(zone, now).date));
    for (bucket, counts) in series.half.buckets() {
        kept.half.add(bucket, counts);
    }
    kept.half.expire(now / HALF);
    for (key, counts) in series.day.buckets() {
        kept.day.add(key, counts);
    }
    if let Some(today) = today {
        kept.day.expire(today);
    }
    kept
}

fn add_series(into: &mut Series, from: &Series) {
    // Two labels that normalize to one: the earlier admission covers it.
    into.admitted = into.admitted.min(from.admitted);
    for (bucket, counts) in from.half.buckets() {
        into.half.add(bucket, counts);
    }
    for (key, counts) in from.day.buckets() {
        into.day.add(key, counts);
    }
}

/// Rebuild one dimension from `file` under `cap`, labels normalized. Labels
/// past the cap add to the overflow. Returns whether anything was cut.
fn restore_dim<K: Hash + Eq + Clone, Tz: TimeZone>(
    file: DimFile<K>,
    cap: usize,
    now: u64,
    zone: &Tz,
    key: impl Fn(&K) -> K,
) -> (Dimension<K>, bool) {
    let mut dim = Dimension::new(cap);
    let mut cut = false;
    dim.overflow = windowed(&file.overflow, now, zone);
    for (label, series) in file.labels {
        let normalized = key(&label);
        let series = windowed(&series, now, zone);
        if dim.labels.len() < cap || dim.labels.contains_key(&normalized) {
            let admitted = series.admitted;
            add_series(
                dim.labels
                    .entry(normalized)
                    .or_insert_with(|| Series::admitted_at(admitted)),
                &series,
            );
        } else {
            add_series(&mut dim.overflow, &series);
            cut = true;
        }
    }
    (dim, cut)
}

/// Parse `bytes` and rebuild the store's state at `now`. Returns the state,
/// the binary version that saved it, and whether anything was cut back.
pub(super) fn from_bytes<Tz: TimeZone>(
    bytes: &[u8],
    now: u64,
    zone: &Tz,
) -> Result<(Inner, String, bool), RestoreError> {
    let head: Head = serde_json::from_slice(bytes).map_err(RestoreError::Parse)?;
    if head.version != FORMAT {
        return Err(RestoreError::Version(head.version));
    }
    let file: File = serde_json::from_slice(bytes).map_err(RestoreError::Parse)?;
    let one = |k: &String| normalize(k);
    let two = |k: &(String, String)| (normalize(&k.0), normalize(&k.1));
    let (server, a) = restore_dim(file.server, MAX_LABELS, now, zone, one);
    let (tool, b) = restore_dim(file.tool, MAX_LABELS, now, zone, two);
    let (caller, c) = restore_dim(file.caller, MAX_LABELS, now, zone, one);
    let (caller_server, d) = restore_dim(file.caller_server, MAX_PAIRS, now, zone, two);
    let mut inner = Inner::new(file.since, [MAX_LABELS, MAX_PAIRS, MAX_MARKERS]);
    inner.global = windowed(&file.global, now, zone);
    inner.server = server;
    // Latency rides on the restored labels; a label the restore cut (past
    // the cap) loses its latency, as its counts went to the overflow.
    let today = Some(super::day_key(day::local_day(zone, now).date));
    inner.global.latency = LatencySeries::from_file(&file.latency.global, now, today);
    inner.server.overflow.latency = LatencySeries::from_file(&file.latency.overflow, now, today);
    for (label, latency) in &file.latency.server {
        if let Some(series) = inner.server.labels.get_mut(&normalize(label)) {
            series.latency = LatencySeries::from_file(latency, now, today);
        }
    }
    inner.tool = tool;
    inner.caller = caller;
    inner.caller_server = caller_server;
    let markers = file.markers.len();
    let mut subjects_cut = false;
    for marker in file.markers {
        subjects_cut |= marker.subject.as_deref().is_some_and(|s| normalize(s) != s);
        inner.mark(marker.kind, marker.subject.as_deref(), marker.at);
    }
    while inner
        .markers
        .front()
        .is_some_and(|m| m.at + super::MARKER_SECS < now)
    {
        inner.markers.pop_front();
    }
    let cut = a || b || c || d || subjects_cut || markers > MAX_MARKERS;
    Ok((inner, file.binary_version, cut))
}

#[cfg(test)]
#[path = "latency_persist_tests.rs"]
mod latency_persist_tests;
