// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A small bounded memo of a pure function of a text (MIK-8259).
//!
//! The egress classifiers re-ran their regex sets over the same catalogue
//! text on every `tools/list` answer. A memo keyed by the exact text returns
//! the same result without the scan. It is safe only for a function of the
//! text alone: anything that depends on the caller, the policy or the time
//! stays outside it, at the call site.
//!
//! Backend text is attacker-controllable, so the memo is bounded by entries
//! and by stored bytes, and the oldest entry is evicted first. A backend that
//! varies its text on every list just cycles the memo: no hits, bounded
//! memory.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Texts shorter than this scan in about a microsecond: not memoised.
pub(crate) const MIN_TEXT_BYTES: usize = 1024;
/// Texts longer than this are never stored.
pub(crate) const MAX_TEXT_BYTES: usize = 64 * 1024;
/// ponytail: 16 entries, so more than 16 distinct hot texts (callers or
/// profiles that each see a different catalogue) thrash back to today's
/// cost; correctness holds. Raise it if `hits`/`misses` show thrashing.
pub(crate) const MAX_ENTRIES: usize = 16;
/// Stored text bytes across all entries.
pub(crate) const MAX_STORED_BYTES: usize = 1024 * 1024;

/// A bounded, oldest-first memo from an exact text to `V`.
pub(crate) struct TextMemo<V> {
    /// The `memo` label on `mcp_egress_scan_memo_total`.
    name: &'static str,
    entries: Mutex<Entries<V>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

struct Entries<V> {
    by_text: HashMap<Arc<str>, V>,
    oldest_first: VecDeque<Arc<str>>,
    stored_bytes: usize,
}

impl<V: Clone> TextMemo<V> {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            entries: Mutex::new(Entries {
                by_text: HashMap::new(),
                oldest_first: VecDeque::new(),
                stored_bytes: 0,
            }),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// `compute(text)`'s result, from the memo when this exact text is held.
    /// `compute` must depend on `text` alone. It runs outside the lock, so
    /// two concurrent misses on one text may both compute; both get the same
    /// result.
    pub(crate) fn get_or_compute(&self, text: &str, compute: impl FnOnce() -> V) -> V {
        if !(MIN_TEXT_BYTES..=MAX_TEXT_BYTES).contains(&text.len()) {
            return compute();
        }
        if let Some(value) = self.lock().by_text.get(text) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.count("hit");
            return value.clone();
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.count("miss");
        let value = compute();
        let mut entries = self.lock();
        if !entries.by_text.contains_key(text) {
            let key: Arc<str> = Arc::from(text);
            entries.stored_bytes += key.len();
            entries.oldest_first.push_back(Arc::clone(&key));
            entries.by_text.insert(key, value.clone());
            while entries.by_text.len() > MAX_ENTRIES || entries.stored_bytes > MAX_STORED_BYTES {
                let Some(oldest) = entries.oldest_first.pop_front() else {
                    break;
                };
                entries.stored_bytes -= oldest.len();
                entries.by_text.remove(&oldest);
            }
        }
        value
    }

    /// Hits and misses, so a thrashing memo (more hot texts than entries)
    /// shows as a falling hit share: the signal for raising `MAX_ENTRIES`.
    fn count(&self, outcome: &'static str) {
        telemetry_metrics::counter!("mcp_egress_scan_memo_total", "memo" => self.name, "outcome" => outcome)
            .increment(1);
    }

    /// Lookups served from the memo.
    #[cfg(test)]
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Lookups that ran the computation (memoisable texts only).
    #[cfg(test)]
    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Entries held and their stored text bytes.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        let entries = self.lock();
        (entries.by_text.len(), entries.stored_bytes)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries<V>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "text_memo_tests.rs"]
mod tests;
