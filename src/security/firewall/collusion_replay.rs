// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8408` stage 1: the process-local replay receipt store.
//!
//! A stored plan answer that is read again must renew the reader's relay
//! receipts exactly as its live delivery recorded them, never by re-deriving
//! receipts from the stored text (design E1/F2). This store holds, per
//! stored entry, immutable [`ReplayReceipt`] snapshots of the committed
//! in-plan receipts. The fingerprints in them are keyed per process, so a
//! task's entry is persisted in its row stamped with the process epoch and
//! rebuilt here by a read only under the same epoch (`replay_persist`); a
//! sync entry never reaches disk. A snapshot's segments hold the raw
//! delivered text; that text is bounded by the per-entry cap
//! ([`REPLAY_ENTRY_BYTES`], 1 MiB) and the total budget
//! ([`REPLAY_RECEIPT_BYTES`], 32 MiB), and is persisted only when the task's
//! stored result delivers every segment of it. The
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
    /// The insertion sequence it was stored under: a [`ReplayHandle`]
    /// belongs to it only when their sequences match.
    seq: u64,
}

/// An entry as stored, with its insertion sequence (its eviction age) and
/// its accounted bytes.
struct Held {
    entry: Arc<ReplayEntry>,
    seq: u64,
    bytes: usize,
    /// How long the entry may stay: kept until it expires, or pending on
    /// the deliveries still holding it (ADR-029 pending-snapshot rule).
    life: Life,
}

/// A stored entry's lifecycle. Every capture, and every entry a task read
/// rebuilds from its row, starts [`Life::Pending`] and is [`Life::Kept`]
/// once a write that is not under `off` delivers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Life {
    Kept,
    Pending {
        /// Deliveries holding a [`ReplayHandle`] that is neither settled
        /// nor released.
        outstanding: u32,
        /// A write under an effective `off` delivered it.
        delivered_off: bool,
    },
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

    /// Take out every entry expired at `now`, whatever its age order.
    fn sweep(&mut self, now: Instant) {
        let expired: Vec<StoredKey> = self
            .by_key
            .iter()
            .filter(|(_, held)| now >= held.entry.expires)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            self.take(key);
        }
    }

    /// The pending entry under `key` taken at `seq`, if it is still that
    /// one; a replaced, evicted, expired or kept entry gives `None`.
    fn pending_at(&mut self, key: &StoredKey, seq: u64) -> Option<&mut Held> {
        self.by_key
            .get_mut(key)
            .filter(|held| held.seq == seq && matches!(held.life, Life::Pending { .. }))
    }

    /// One outstanding delivery of `key`'s pending entry `seq` ended, under
    /// `off` when it was written under an effective `off`. Once none is
    /// outstanding, an entry delivered under `off` goes.
    fn end_delivery(&mut self, key: &StoredKey, seq: u64, off: bool) {
        let Some(held) = self.pending_at(key, seq) else {
            return;
        };
        if let Life::Pending {
            outstanding,
            delivered_off,
        } = &mut held.life
        {
            *outstanding = outstanding.saturating_sub(1);
            *delivered_off |= off;
            if *outstanding == 0 && *delivered_off {
                self.take(key);
            }
        }
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

/// One entry's accounted bytes: its receipts, its answer digest and, per
/// call, the names plus [`REPLAY_ITEM_OVERHEAD`].
fn entry_bytes(receipts: &[ReplayReceipt], calls: &ReplayCalls, answer_digest: &str) -> usize {
    let mut bytes = receipts
        .iter()
        .map(ReplayReceipt::bytes)
        .fold(0_usize, usize::saturating_add)
        .saturating_add(answer_digest.len());
    for (_, server, tool) in calls {
        bytes = bytes
            .saturating_add(server.len())
            .saturating_add(tool.len())
            .saturating_add(REPLAY_ITEM_OVERHEAD);
    }
    bytes
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
    #[cfg(test)]
    pub(in super::super) fn insert(
        &self,
        key: StoredKey,
        receipts: Vec<ReplayReceipt>,
        calls: ReplayCalls,
        answer_digest: String,
        now: Instant,
        retention: Duration,
    ) {
        self.insert_with(
            key,
            (receipts, calls, answer_digest),
            (now, retention),
            Life::Kept,
        );
    }

    /// [`Self::insert`] with the entry's starting `life`, returning its
    /// sequence; `None` when it was not stored (`too_large`). Expired
    /// entries are swept first (activity-driven, as the detector sweeps;
    /// a read sweeps nothing but its own key, as `lookup` does).
    fn insert_with(
        &self,
        key: StoredKey,
        (receipts, calls, answer_digest): (Vec<ReplayReceipt>, ReplayCalls, String),
        (now, retention): (Instant, Duration),
        life: Life,
    ) -> Option<u64> {
        let bytes = entry_bytes(&receipts, &calls, &answer_digest);
        let (stored, evicted) = {
            let mut inner = self.inner.lock();
            self.insert_locked(
                &mut inner,
                key,
                (receipts, calls, answer_digest),
                (now, retention, bytes),
                life,
            )
        };
        self.count_insert(stored.is_none(), evicted);
        stored
    }

    /// The insertion under the held lock: the expired swept, the key's
    /// previous entry taken out, then (when it fits the caps) the entry
    /// stored with `life`, evicting the oldest past the total cap. Its
    /// sequence (`None`: too large) and how many were evicted, for the
    /// caller to count once the lock is dropped.
    fn insert_locked(
        &self,
        inner: &mut Inner,
        key: StoredKey,
        (receipts, calls, answer_digest): (Vec<ReplayReceipt>, ReplayCalls, String),
        (now, retention, bytes): (Instant, Duration, usize),
        life: Life,
    ) -> (Option<u64>, u64) {
        let mut evicted = 0_u64;
        inner.sweep(now);
        // Overwrite or refusal, the previous entry under the key goes first.
        inner.take(&key);
        if !self.admits(bytes) {
            return (None, evicted);
        }
        while inner.bytes.saturating_add(bytes) > self.total_cap {
            if inner.take_oldest().is_none() {
                break;
            }
            evicted = evicted.saturating_add(1);
        }
        let seq = inner.next;
        inner.next = inner.next.saturating_add(1);
        inner.bytes = inner.bytes.saturating_add(bytes);
        inner.order.insert(seq, key.clone());
        inner.by_key.insert(
            key,
            Held {
                entry: Arc::new(ReplayEntry {
                    seq,
                    receipts,
                    calls,
                    answer_digest,
                    expires: now.checked_add(retention).unwrap_or(now),
                }),
                seq,
                bytes,
                life,
            },
        );
        (Some(seq), evicted)
    }

    /// Count what one insertion decided under the lock: a refusal for size,
    /// and the entries it evicted.
    fn count_insert(&self, too_large: bool, evicted: u64) {
        if too_large {
            count_replay_skipped("too_large");
        }
        if evicted > 0 {
            self.evicted.fetch_add(evicted, Ordering::Relaxed);
            telemetry_metrics::counter!(REPLAY_EVICTED_METRIC).increment(evicted);
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
    #[cfg(test)]
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

/// One delivery's hold on a pending entry: its key and the insertion
/// sequence it was taken against, never the payload, so every byte stays
/// under the store's caps. Settled at the delivery's write; dropped
/// unsettled, it releases. A handle whose entry was replaced, evicted or
/// expired acts on nothing.
pub(crate) struct ReplayHandle {
    /// `None` once settled or discarded, so `Drop` releases nothing.
    store: Option<std::sync::Weak<ReplayReceipts>>,
    key: StoredKey,
    seq: u64,
}

impl std::fmt::Debug for ReplayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayHandle")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl ReplayHandle {
    /// Its answer was not retained (E1): its pending entry goes. A kept
    /// entry, or a newer capture under the key, is untouched.
    pub(crate) fn discard(self) {
        if let Some(store) = self.store.as_ref().and_then(std::sync::Weak::upgrade) {
            store.discard(self);
        }
    }

    /// The key and sequence, consuming the handle without releasing it.
    fn into_parts(mut self) -> (StoredKey, u64) {
        self.store = None;
        (self.key.clone(), self.seq)
    }
}

impl Drop for ReplayHandle {
    fn drop(&mut self) {
        if let Some(store) = self.store.take().and_then(|weak| weak.upgrade()) {
            store.release_seq(&self.key, self.seq);
        }
    }
}

impl ReplayReceipts {
    /// [`Self::insert`] for a judge-time capture: stored pending with one
    /// outstanding delivery, whose handle is returned. `None` when nothing
    /// was stored (`too_large`).
    pub(in super::super) fn insert_pending(
        self: &Arc<Self>,
        key: StoredKey,
        receipts: Vec<ReplayReceipt>,
        calls: ReplayCalls,
        answer_digest: String,
        now: Instant,
        retention: Duration,
    ) -> Option<ReplayHandle> {
        let seq = self.insert_with(
            key.clone(),
            (receipts, calls, answer_digest),
            (now, retention),
            Life::Pending {
                outstanding: 1,
                delivered_off: false,
            },
        )?;
        Some(self.handle(key, seq))
    }

    /// [`Self::lookup`] for a replay that will deliver the entry: a pending
    /// entry gains one outstanding delivery, whose handle is returned; a
    /// kept entry needs none. The entry, its expiry check and the handle
    /// are taken under one lock, so the handle always names the entry
    /// returned, never one that replaced it in between.
    pub(in super::super) fn acquire(
        self: &Arc<Self>,
        key: &StoredKey,
        now: Instant,
    ) -> Option<Acquired> {
        // The miss reason is decided under the lock and counted after it
        // is dropped, as `lookup` does.
        let (found, skipped) = acquire_locked(&mut self.inner.lock(), key, now);
        if let Some(reason) = skipped {
            count_replay_skipped(reason);
        }
        let (entry, seq) = found?;
        let handle = seq.map(|seq| self.handle(key.clone(), seq));
        Acquired::pair(entry, handle)
    }

    /// Whether an entry of these parts fits the per-entry and total caps, as
    /// an insertion would admit it.
    pub(in super::super) fn fits(
        &self,
        receipts: &[ReplayReceipt],
        calls: &ReplayCalls,
        answer_digest: &str,
    ) -> bool {
        self.admits(entry_bytes(receipts, calls, answer_digest))
    }

    /// The one admission rule by size: an entry of `bytes` fits the
    /// per-entry cap and the total cap. Insertion and [`Self::fits`] (a
    /// stored task read's judgement) both ask it, so they cannot disagree.
    fn admits(&self, bytes: usize) -> bool {
        bytes <= self.entry_cap && bytes <= self.total_cap
    }

    /// [`Self::acquire`] for a stored task read that holds the entry's
    /// persisted parts: a live entry under `key` is acquired as it is;
    /// otherwise the parts are inserted pending with this read as its one
    /// outstanding delivery, settled at its write (capture-if-absent). The
    /// check and the insertion run under one lock, so two reads that both
    /// find nothing leave exactly one entry, held by both. `None` when the
    /// parts are over the caps (`too_large`).
    pub(in super::super) fn adopt(
        self: &Arc<Self>,
        key: &StoredKey,
        parts: (Vec<ReplayReceipt>, ReplayCalls, String),
        now: Instant,
        retention: Duration,
    ) -> Option<Acquired> {
        let bytes = entry_bytes(&parts.0, &parts.1, &parts.2);
        let lapsed;
        let (found, evicted) = {
            let mut inner = self.inner.lock();
            let (live, missed) = acquire_locked(&mut inner, key, now);
            // A lapsed entry is counted as a lookup counts it; an absent one
            // is not a miss here, the parts rebuild it.
            lapsed = missed == Some("expired");
            if let Some(found) = live {
                (Some(found), 0)
            } else {
                let (seq, evicted) = self.insert_locked(
                    &mut inner,
                    key.clone(),
                    parts,
                    (now, retention, bytes),
                    Life::Pending {
                        outstanding: 1,
                        delivered_off: false,
                    },
                );
                let entry = seq.and_then(|seq| {
                    inner
                        .by_key
                        .get(key)
                        .map(|held| (Arc::clone(&held.entry), Some(seq)))
                });
                (entry, evicted)
            }
        };
        if lapsed {
            count_replay_skipped("expired");
        }
        self.count_insert(found.is_none(), evicted);
        let (entry, seq) = found?;
        let handle = seq.map(|seq| self.handle(key.clone(), seq));
        Acquired::pair(entry, handle)
    }

    /// `handle`'s delivery was written; `off` when the write-time action
    /// is an effective `off`. A write not under `off` keeps the entry;
    /// one under `off` ends that delivery, and once none is outstanding an
    /// entry still pending goes (nothing delivered while off is held).
    pub(in super::super) fn settle(&self, handle: ReplayHandle, off: bool) {
        let (key, seq) = handle.into_parts();
        let mut inner = self.inner.lock();
        if off {
            inner.end_delivery(&key, seq, true);
        } else if let Some(held) = inner.pending_at(&key, seq) {
            held.life = Life::Kept;
        }
    }

    /// `handle`'s answer was not retained (E1): its pending entry goes.
    /// A kept entry, or a newer capture under the key, is untouched.
    pub(in super::super) fn discard(&self, handle: ReplayHandle) {
        let (key, seq) = handle.into_parts();
        let mut inner = self.inner.lock();
        if inner.pending_at(&key, seq).is_some() {
            inner.take(&key);
        }
    }

    /// One outstanding delivery of the entry `seq` under `key` ended
    /// unwritten.
    fn release_seq(&self, key: &StoredKey, seq: u64) {
        self.inner.lock().end_delivery(key, seq, false);
    }

    fn handle(self: &Arc<Self>, key: StoredKey, seq: u64) -> ReplayHandle {
        ReplayHandle {
            store: Some(Arc::downgrade(self)),
            key,
            seq,
        }
    }

    /// The lifecycle of `key`'s entry (tests only).
    #[cfg(test)]
    pub(in super::super) fn life_for_test(&self, key: &StoredKey) -> TestLife {
        match self.inner.lock().by_key.get(key).map(|held| held.life) {
            None => TestLife::Absent,
            Some(Life::Kept) => TestLife::Kept,
            Some(Life::Pending {
                outstanding,
                delivered_off,
            }) => TestLife::Pending {
                outstanding,
                delivered_off,
            },
        }
    }

    /// A weak reference to `key`'s payload, to show what keeps it alive
    /// (tests only).
    #[cfg(test)]
    pub(in super::super) fn entry_weak_for_test(
        &self,
        key: &StoredKey,
    ) -> Option<std::sync::Weak<ReplayEntry>> {
        self.inner
            .lock()
            .by_key
            .get(key)
            .map(|held| Arc::downgrade(&held.entry))
    }

    /// Entries the store holds now (tests only).
    #[cfg(test)]
    pub(in super::super) fn len_for_test(&self) -> usize {
        self.inner.lock().by_key.len()
    }

    /// Bytes the store holds now (tests only).
    #[cfg(test)]
    pub(in super::super) fn bytes_for_test(&self) -> usize {
        self.inner.lock().bytes
    }
}

/// A live entry acquired, with its sequence when it is pending.
type Found = (Arc<ReplayEntry>, Option<u64>);

/// The live entry under `key` at `now`, under the held lock, with one more
/// outstanding delivery when it is pending (its sequence then names the
/// handle to hand out); else the miss reason, an expired entry taken out.
fn acquire_locked(
    inner: &mut Inner,
    key: &StoredKey,
    now: Instant,
) -> (Option<Found>, Option<&'static str>) {
    match inner.by_key.get(key).map(|held| now >= held.entry.expires) {
        None => (None, Some("absent")),
        Some(true) => {
            inner.take(key);
            (None, Some("expired"))
        }
        Some(false) => {
            let Some(held) = inner.by_key.get_mut(key) else {
                return (None, Some("absent"));
            };
            let seq = match &mut held.life {
                Life::Kept => None,
                Life::Pending { outstanding, .. } => {
                    *outstanding = outstanding.saturating_add(1);
                    Some(held.seq)
                }
            };
            (Some((Arc::clone(&held.entry), seq)), None)
        }
    }
}

/// An entry's lifecycle as a row reads it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum TestLife {
    Absent,
    Kept,
    Pending {
        outstanding: u32,
        delivered_off: bool,
    },
}

/// A replay's snapshot and its handle, as one value: the only way a handle
/// on an existing entry is handed out ([`ReplayReceipts::acquire`]), and
/// built only through [`Acquired::pair`], which refuses a handle that does
/// not belong to the snapshot. A delivery therefore settles exactly the
/// entry whose receipts it staged.
pub(crate) struct Acquired {
    entry: Arc<ReplayEntry>,
    handle: Option<ReplayHandle>,
}

impl std::fmt::Debug for Acquired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acquired")
            .field("seq", &self.entry.seq)
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl Acquired {
    /// `entry` with `handle`, or `None` when the handle was taken against
    /// another entry (another insertion sequence). A kept entry has no
    /// handle.
    pub(in super::super) fn pair(
        entry: Arc<ReplayEntry>,
        handle: Option<ReplayHandle>,
    ) -> Option<Self> {
        if handle.as_ref().is_some_and(|h| h.seq != entry.seq) {
            return None;
        }
        Some(Self { entry, handle })
    }

    /// The snapshot and its handle, taken apart for the delivery.
    pub(in super::super) fn into_parts(self) -> (Arc<ReplayEntry>, Option<ReplayHandle>) {
        (self.entry, self.handle)
    }
}
