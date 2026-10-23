// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8408` stage 1: the process-local replay receipt store.
//!
//! A stored plan answer that is read again must renew the reader's relay
//! receipts exactly as its live delivery recorded them, never by re-deriving
//! receipts from the stored text (design E1/F2). This store holds, per
//! stored entry, immutable [`ReplayReceipt`] snapshots of the committed
//! in-plan receipts, in memory only: the fingerprints in them are keyed per
//! process and are worthless after a restart, so nothing here reaches disk.
//! A snapshot's segments hold the raw delivered text; that text is bounded
//! by the per-entry cap ([`REPLAY_ENTRY_BYTES`], 1 MiB) and the total
//! budget ([`REPLAY_RECEIPT_BYTES`], 32 MiB), and is never persisted. The
//! budget counts fingerprint and text bytes plus a per-item estimate
//! ([`REPLAY_ITEM_OVERHEAD`]); struct layout, spare capacity, the keys and
//! the index are not counted, so actual memory can run somewhat above it
//! (conservative accounting: MIK-8550). The entry cap bounds that counted
//! size, not the answer: a keyed sync replay serves at most `RESULT_LIMIT`
//! (512 KiB, fixed) and a task re-read at most `tasks.max_record_bytes`
//! (default 512 KiB), yet an answer of many small segments can count past
//! 1 MiB under those limits, and its entry is then not stored (`too_large`).
//!
//! One store sits beside each relay detector and is shared wherever the
//! detector is shared (F6). Its lock is its own: nothing in here calls the
//! detector, so its lock is never held while the detector's state lock is
//! taken, nor the other way round.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::super::collusion_digest::ReplayReceipt;
use crate::security::ReplayCalls;

/// Total bytes of replay receipts held across every stored entry (E1),
/// following the sketch store's 32 MiB pattern: past it the oldest entry
/// goes.
pub(in super::super) const REPLAY_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
/// The most one stored entry may hold; a larger entry is not stored (E1).
pub(in super::super) const REPLAY_ENTRY_BYTES: usize = 1024 * 1024;
/// Fixed bytes charged per stored item (one receipt, one segment, one join,
/// one call, one seam source) beside the item's own text and fingerprint
/// bytes: an allowance for the `Vec`/`Arc` headers and heap bookkeeping of
/// one allocation, deliberately at or above the true header so the byte
/// budget errs small. An entry's size is its fingerprint bytes (8 per
/// fingerprint, 4 per staged join index) plus its text bytes plus this
/// overhead per item it holds.
pub(in super::super) const REPLAY_ITEM_OVERHEAD: usize = 64;

/// One entry evicted for the total byte budget.
const REPLAY_EVICTED_METRIC: &str = "mcp_gateway_collusion_plan_replay_evicted_total";
/// One replay that staged nothing, by `reason` (`absent`, `too_large`,
/// `big_step`, `staged`, `nested_seam`, `expired`, `filtered`,
/// `over_bound`).
const REPLAY_SKIPPED_METRIC: &str = "mcp_gateway_collusion_plan_replay_skipped_total";

/// Count one replay that staged nothing, for `reason`. The store itself
/// counts `absent`, `expired` and `too_large`; the caller counts `big_step`
/// (a snapshot a judged big-step digest refused), `staged` (a step still
/// staged at capture), `nested_seam` (design F5 as kept by d4 H3),
/// `filtered` (excuse sets dropped against a changed answer, F4) and
/// `over_bound` (a replayed answer over the keep bound) at its own drop
/// points.
pub(in super::super) fn count_replay_skipped(reason: &'static str) {
    telemetry_metrics::counter!(REPLAY_SKIPPED_METRIC, "reason" => reason).increment(1);
}

/// The stored entry a replay serves, never the reader (E1, F1).
///
/// The sync arm carries the identity and operation hashes execution
/// admission already computes (`canonical_json_sha256` strings) and the
/// round discriminator `admit_round` takes, as strings: those are the
/// values the callers hold, so no second, lossy hash to an integer stands
/// between admission and this key. The task arm carries the task id and
/// its store revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum StoredKey {
    /// A retained sync delivery: admission identity, round, operation.
    Sync {
        identity: String,
        round: String,
        operation: String,
    },
    /// A stored task row, at one revision of it.
    Task { id: String, revision: u64 },
}

/// One stored entry's replay material: its receipts and, beside them, the
/// calls its run dispatched, `(label, server, tool)` each (d4 H2, the
/// in-memory form of d3 D1(i)), held only until `expires`.
pub(in super::super) struct ReplayEntry {
    pub(in super::super) receipts: Vec<ReplayReceipt>,
    pub(in super::super) calls: ReplayCalls,
    /// Digest of the delivered answer the receipts were committed against
    /// (`canonical_json_sha256` of the plan answer, as the gateway kept
    /// them to it): the unfiltered replay path is allowed only for a
    /// replayed answer with the same digest (F4). Empty when no answer
    /// was noted at capture, which never matches and always filters.
    pub(in super::super) answer_digest: String,
    pub(in super::super) expires: Instant,
}

/// An entry as stored, with its insertion sequence (its eviction age) and
/// its accounted bytes.
struct Held {
    entry: Arc<ReplayEntry>,
    seq: u64,
    bytes: usize,
}

#[derive(Default)]
struct Inner {
    by_key: HashMap<StoredKey, Held>,
    /// Oldest first, by insertion sequence; an overwrite re-ages its entry.
    order: BTreeMap<u64, StoredKey>,
    next: u64,
    bytes: usize,
}

impl Inner {
    /// Take `key`'s entry out, releasing its bytes.
    fn take(&mut self, key: &StoredKey) -> Option<Held> {
        let held = self.by_key.remove(key)?;
        self.order.remove(&held.seq);
        self.bytes = self.bytes.saturating_sub(held.bytes);
        Some(held)
    }

    /// Take the oldest entry out, if any.
    fn take_oldest(&mut self) -> Option<()> {
        let (_, key) = self.order.pop_first()?;
        if let Some(held) = self.by_key.remove(&key) {
            self.bytes = self.bytes.saturating_sub(held.bytes);
        }
        Some(())
    }
}

/// The replay receipts of every stored plan entry of one detector, byte
/// bounded in total and per entry (E1). See the module docs for its lock
/// discipline.
pub(in super::super) struct ReplayReceipts {
    inner: Mutex<Inner>,
    /// [`REPLAY_RECEIPT_BYTES`]; smaller only in tests.
    total_cap: usize,
    /// [`REPLAY_ENTRY_BYTES`]; smaller only in tests.
    entry_cap: usize,
    /// Entries evicted for the total budget (telemetry twin, for tests).
    evicted: AtomicU64,
}

impl ReplayReceipts {
    pub(in super::super) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            total_cap: REPLAY_RECEIPT_BYTES,
            entry_cap: REPLAY_ENTRY_BYTES,
            evicted: AtomicU64::new(0),
        }
    }

    /// A store whose total and per-entry byte caps are `total` and `entry`,
    /// so a row can cross either cheaply (tests only).
    #[cfg(test)]
    pub(in super::super) fn with_budget_for_test(total: usize, entry: usize) -> Self {
        Self {
            total_cap: total,
            entry_cap: entry,
            ..Self::new()
        }
    }

    /// Store `receipts` and `calls` under `key`, overwriting any entry the
    /// key already holds (F1), live until `now + retention` — `now` is the
    /// caller's receipt clock, as the detector's `*_at` records take it.
    /// An entry over the per-entry cap is not stored, counted
    /// `reason=too_large`, and the key's previous entry goes with it, so a
    /// key never replays an older commit's receipts. Past the total cap
    /// the oldest entries are evicted until it fits, counted.
    pub(in super::super) fn insert(
        &self,
        key: StoredKey,
        receipts: Vec<ReplayReceipt>,
        calls: ReplayCalls,
        answer_digest: String,
        now: Instant,
        retention: Duration,
    ) {
        let mut bytes = receipts
            .iter()
            .map(ReplayReceipt::bytes)
            .fold(0_usize, usize::saturating_add)
            .saturating_add(answer_digest.len());
        for (_, server, tool) in &calls {
            bytes = bytes
                .saturating_add(server.len())
                .saturating_add(tool.len())
                .saturating_add(REPLAY_ITEM_OVERHEAD);
        }
        // What to count is decided under the lock and counted after it
        // is dropped: no counter increment runs with the lock held.
        let mut evicted_now = 0_u64;
        let too_large = bytes > self.entry_cap || bytes > self.total_cap;
        {
            let mut inner = self.inner.lock();
            // Overwrite or refusal, the previous entry under the key goes first.
            inner.take(&key);
            if !too_large {
                while inner.bytes.saturating_add(bytes) > self.total_cap {
                    if inner.take_oldest().is_none() {
                        break;
                    }
                    evicted_now = evicted_now.saturating_add(1);
                }
                let seq = inner.next;
                inner.next = inner.next.saturating_add(1);
                inner.bytes = inner.bytes.saturating_add(bytes);
                inner.order.insert(seq, key.clone());
                inner.by_key.insert(
                    key,
                    Held {
                        entry: Arc::new(ReplayEntry {
                            receipts,
                            calls,
                            answer_digest,
                            expires: now.checked_add(retention).unwrap_or(now),
                        }),
                        seq,
                        bytes,
                    },
                );
            }
        }
        if too_large {
            count_replay_skipped("too_large");
        }
        if evicted_now > 0 {
            self.evicted.fetch_add(evicted_now, Ordering::Relaxed);
            telemetry_metrics::counter!(REPLAY_EVICTED_METRIC).increment(evicted_now);
        }
    }

    /// Drop `key`'s entry: a non-plan commit under the key, or its stored
    /// entry's removal (F1, G36). Absent is a no-op.
    pub(in super::super) fn remove(&self, key: &StoredKey) {
        self.inner.lock().take(key);
    }

    /// The entry under `key` at `now`, if one is held and live. Past its
    /// expiry the lookup removes it and misses, counted `reason=expired`;
    /// no entry at all is counted `reason=absent` (G36).
    pub(in super::super) fn lookup(
        &self,
        key: &StoredKey,
        now: Instant,
    ) -> Option<Arc<ReplayEntry>> {
        // The miss reason is decided under the lock and counted after
        // it is dropped: no counter increment runs with the lock held.
        let (found, skipped) = {
            let mut inner = self.inner.lock();
            let entry = inner.by_key.get(key).map(|held| Arc::clone(&held.entry));
            match entry {
                None => (None, Some("absent")),
                Some(entry) if now >= entry.expires => {
                    inner.take(key);
                    (None, Some("expired"))
                }
                Some(entry) => (Some(entry), None),
            }
        };
        if let Some(reason) = skipped {
            count_replay_skipped(reason);
        }
        found
    }

    /// Entries evicted for the total budget so far (tests only).
    #[cfg(test)]
    pub(in super::super) fn evicted_for_test(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }
}
