// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `spend-history.json`: the cost tracker's hour and local-day series, kept
//! across restarts (ADR-017).
//!
//! The file sits beside `costs.json` and never inside it, so that file keeps
//! its shape and its same-day rule, and a build without this file ignores it.
//! It is written by the cost save, in the same `COST_WRITE` turn, after
//! `costs.json`. It holds numbers, ISO dates and key names only.
//!
//! A key is matched by the fingerprint of its full name; the `name` beside it
//! is for a person reading the file and is never matched on. A saved row no
//! configured key claims joins the carried overflow, so totals stay exact and
//! no other key inherits it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::tally::{self, BUCKET_HOURS, KEPT_DAYS, Series};
use super::{CostTracker, KeyCost};

/// The file's name inside the data directory.
pub(crate) const FILE_NAME: &str = "spend-history.json";

/// Keys saved with a row of their own; the rest are summed into `overflow`
/// (ADR-017's cardinality cap, a constant).
pub(crate) const MAX_KEYS: usize = 512;

/// Hex characters in a key's fingerprint: the first 16 bytes of the SHA-256
/// of its full name.
const FP_HEX: usize = 32;

/// One series as saved: `[hour, tokens, micro-USD]` and `[date, tokens,
/// micro-USD]`, oldest first.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Rows {
    hours: Vec<(u64, u64, u64)>,
    days: Vec<(NaiveDate, u64, u64)>,
}

/// One key's saved series.
#[derive(Debug, Serialize, Deserialize)]
struct KeyRows {
    fp: String,
    name: String,
    #[serde(flatten)]
    rows: Rows,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct History {
    keyless: Rows,
    keys: Vec<KeyRows>,
    overflow: Rows,
}

/// `name`'s fingerprint: what a saved row is matched by.
fn fingerprint(name: &str) -> String {
    let mut hex = crate::hashing::sha256_hex(name.as_bytes());
    hex.truncate(FP_HEX);
    hex
}

impl Rows {
    fn of(series: &Series) -> Self {
        Self {
            hours: series.hours.rows(),
            days: series.days.rows(),
        }
    }

    /// Why these rows cannot be replayed, if they cannot: a series over its
    /// row caps, an hour whose start second does not fit, or a repeated hour
    /// or date.
    fn flaw(&self, what: &str) -> Option<String> {
        let max_hours = usize::try_from(BUCKET_HOURS + 1).unwrap_or(usize::MAX);
        let max_days = usize::try_from(KEPT_DAYS).unwrap_or(usize::MAX);
        if self.hours.len() > max_hours || self.days.len() > max_days {
            return Some(format!("{what} holds more rows than one series keeps"));
        }
        if self
            .hours
            .iter()
            .any(|(h, ..)| h.checked_mul(3600).is_none())
        {
            return Some(format!("{what} holds an hour past the clock's range"));
        }
        let hours: HashSet<u64> = self.hours.iter().map(|(h, ..)| *h).collect();
        let days: HashSet<NaiveDate> = self.days.iter().map(|(d, ..)| *d).collect();
        if hours.len() < self.hours.len() || days.len() < self.days.len() {
            return Some(format!("{what} repeats an hour or a date"));
        }
        None
    }

    /// Add every row into `into` through the adds a live record uses, at
    /// unix second `now`, so a restored row ages by the same cuts. An hour
    /// is replayed at its first second.
    fn replay(&self, into: &mut Series, now: u64) {
        let today = tally::local_date(now);
        for &(hour, tokens, micro) in &self.hours {
            into.hours.add(hour * 3600, now, tokens, micro);
        }
        for &(date, tokens, micro) in &self.days {
            into.days.add_slot(date, today, tokens, micro);
        }
    }
}

impl History {
    /// Why the file must not be restored, if it must not.
    fn flaw(&self) -> Option<String> {
        if self.keys.len() > MAX_KEYS {
            return Some(format!("more than {MAX_KEYS} keys"));
        }
        let mut seen = HashSet::new();
        for key in &self.keys {
            let shaped = key.fp.len() == FP_HEX
                && key
                    .fp
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !shaped {
                return Some("a key fingerprint is not 32 lowercase hex digits".to_owned());
            }
            if !seen.insert(key.fp.as_str()) {
                return Some("two keys share a fingerprint".to_owned());
            }
        }
        let series = [
            (&self.keyless, "the keyless series"),
            (&self.overflow, "the overflow"),
        ];
        series
            .into_iter()
            .chain(self.keys.iter().map(|k| (&k.rows, "a key")))
            .find_map(|(rows, what)| rows.flaw(what))
    }
}

/// Fill `tracker` from `<data_dir>/spend-history.json` at unix second `now`.
/// A saved key row attaches to the entry in `key_names` with the same
/// fingerprint; any other row joins the carried overflow. No file is a fresh
/// start. A file that cannot be read or is refused is set aside, as
/// `counters.json` is, and the tracker starts empty with one warning; when it
/// cannot be set aside, this run saves no history, so its bytes survive.
pub(crate) fn restore(tracker: &CostTracker, data_dir: &Path, key_names: &[String], now: u64) {
    let path = data_dir.join(FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => return set_aside(tracker, &path, now, &e.to_string()),
    };
    let history = match serde_json::from_slice::<History>(&bytes) {
        Ok(history) => history,
        Err(e) => return set_aside(tracker, &path, now, &e.to_string()),
    };
    if let Some(why) = history.flaw() {
        return set_aside(tracker, &path, now, &why);
    }
    let by_fp: HashMap<String, &String> = key_names.iter().map(|n| (fingerprint(n), n)).collect();
    history.keyless.replay(&mut tracker.keyless.lock(), now);
    let mut carried = tracker.carried.lock();
    history.overflow.replay(&mut carried, now);
    for key in &history.keys {
        let Some(name) = by_fp.get(&key.fp) else {
            key.rows.replay(&mut carried, now);
            continue;
        };
        let entry = tracker
            .per_key
            .entry((*name).clone())
            .or_insert_with(|| Arc::new(KeyCost::new(name)));
        key.rows.replay(&mut entry.spend.lock().0, now);
    }
    drop(carried);
    tracing::info!(keys = history.keys.len(), "Restored spend history");
}

fn set_aside(tracker: &CostTracker, path: &Path, now: u64, why: &str) {
    match crate::counters::persist::quarantine(path, now) {
        Ok(aside) => tracing::warn!(
            reason = why,
            moved_to = %aside.display(),
            "Spend history unreadable; set aside, the history starts empty"
        ),
        Err(e) => {
            tracker.history_off.store(true, Ordering::Relaxed);
            tracing::warn!(
                reason = why,
                error = %e,
                "Spend history unreadable and could not be set aside; the history starts empty and this run will not save it"
            );
        }
    }
}

/// Write `tracker`'s series to `<data_dir>/spend-history.json` at unix second
/// `now`. Returns whether the file now holds them; a failure is logged. When
/// they encode to the bytes this tracker last wrote there and the file is
/// still in place, nothing is written: an idle gateway rewrites and syncs
/// nothing.
pub(crate) fn save(tracker: &CostTracker, data_dir: &Path, now: u64) -> bool {
    save_with(tracker, data_dir, now, &mut || {}, || Ok(()))
}

/// [`save`] with two test seams: `after_copy` runs after each series is
/// copied, and `before_rename` runs once the scratch file is written.
fn save_with(
    tracker: &CostTracker,
    data_dir: &Path,
    now: u64,
    after_copy: &mut dyn FnMut(),
    before_rename: impl FnOnce() -> std::io::Result<()>,
) -> bool {
    if tracker.history_off.load(Ordering::Relaxed) {
        return false;
    }
    let path = data_dir.join(FILE_NAME);
    let bytes = match serde_json::to_vec(&snapshot(tracker, now, after_copy)) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "Spend history not saved: cannot encode it");
            return false;
        }
    };
    let digest = crate::hashing::sha256_hex(&bytes);
    let mut last = tracker.history_last.lock();
    let same = last
        .as_ref()
        .is_some_and(|(at, sum)| *at == path && *sum == digest);
    if same && still_private(&path) {
        return true;
    }
    let written = crate::config_persistence::write_atomic_checked(
        &path,
        &bytes,
        crate::config_persistence::FileMode::Private,
        crate::config_persistence::Symlink::Replace,
        before_rename,
    );
    match written {
        Ok(()) => {
            *last = Some((path, digest));
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "Spend history not saved");
            false
        }
    }
}

/// Whether `path` is still what a private write leaves there: a plain file,
/// not a link, owned by this process's user, with no group or other bit. A
/// save that would skip an unchanged state writes anyway when it is not, so
/// the skip never keeps a widened file. Windows keeps no such mode bits and
/// its access list is not re-read here, so there every save writes.
fn still_private(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mine = meta.uid() == rustix::process::geteuid().as_raw();
        meta.file_type().is_file() && mine && meta.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

#[cfg(tp2)]
#[cfg(test)]
#[path = "spend_history_file_tests.rs"]
mod file_tests;

/// The file's contents at `now`. The key map is walked once for its handles,
/// so a name appears at most once; each series is copied under its own lock,
/// one at a time. Every copy is then aged to one cutoff, the newest hour and
/// the newest date any copy or `now` holds, before the keys are ranked by
/// their 30-day spend; the keys past [`MAX_KEYS`] are summed into the
/// overflow with the carried one. No live series is read after the copies.
fn snapshot(tracker: &CostTracker, now: u64, after_copy: &mut dyn FnMut()) -> History {
    let handles: Vec<(String, Arc<KeyCost>)> = tracker
        .per_key
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    let mut keys = Vec::with_capacity(handles.len());
    for (name, key) in handles {
        keys.push((name, key.spend.lock().0.clone()));
        after_copy();
    }
    let mut keyless = tracker.keyless.lock().clone();
    after_copy();
    let mut overflow = tracker.carried.lock().clone();

    let all = || keys.iter().map(|(_, s)| s).chain([&keyless, &overflow]);
    let hour = all()
        .filter_map(|s| s.hours.newest())
        .fold(now / 3600, u64::max);
    let date = all()
        .filter_map(|s| s.days.newest())
        .fold(tally::local_date(now), NaiveDate::max);
    for series in keys
        .iter_mut()
        .map(|(_, s)| s)
        .chain([&mut keyless, &mut overflow])
    {
        series.age(hour, date);
    }

    // Most 30-day spend first; the name breaks a tie, so a save is stable.
    let mut ranked: Vec<(u64, String, Series)> = keys
        .into_iter()
        .map(|(name, series)| (series.days.micro_total(), name, series))
        .collect();
    ranked.sort_by(|(x, a, _), (y, b, _)| y.cmp(x).then_with(|| a.cmp(b)));
    let folded = ranked.split_off(ranked.len().min(MAX_KEYS));
    for (.., series) in &folded {
        overflow.merge(series);
    }
    let keys = ranked.into_iter().map(|(_, name, series)| (name, series));
    History {
        keyless: Rows::of(&keyless),
        keys: keys
            .map(|(name, series)| KeyRows {
                fp: fingerprint(&name),
                name: crate::counters::normalize(&name),
                rows: Rows::of(&series),
            })
            .collect(),
        overflow: Rows::of(&overflow),
    }
}
