// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8123`: the holders of one tracked fingerprint.
//!
//! Every (source, caller) record stays exact: no fingerprint is switched off
//! because many sources delivered it. A caller keeps at most
//! [`MAX_RECORDS_PER_CALLER`] records per fingerprint; records past
//! [`INLINE_RECORDS`] draw from one global pool shared by every fingerprint,
//! so memory is today's inline records plus the pool, whatever the fan-out.
//! A record that does not fit is dropped when it is plain under the lists it
//! is recorded under (only an excuse is lost) and, when it is sensitive, kept
//! as one of the caller's *overflow* pairs: its source identity and inferred
//! fact, judged at witness like any held copy, but never excused by an exact
//! copy the sender holds. A caller whose pairs no longer fit, by count or by
//! bytes, or past the total budget, is *unattributed*: judged sensitive and
//! covered by no flow until that mark ages out. Text `common_principals`
//! distinct callers hold is `Common`, decided from every caller seen, records
//! kept or not.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::origin::Origin;
use super::{Copies, Holder};
use crate::security::firewall::CollusionView;

/// Records one fingerprint keeps without drawing on the pool.
pub(super) const INLINE_RECORDS: usize = 8;
/// Records one caller keeps for one fingerprint.
pub(super) const MAX_RECORDS_PER_CALLER: usize = 64;
/// Overflow pairs one caller keeps for one fingerprint: past it the caller's
/// overflow is unattributed.
pub(super) const OVERFLOW_PAIRS_PER_CALLER: usize = 16;
/// Bytes of overflow pairs one caller keeps for one fingerprint.
pub(super) const OVERFLOW_BYTES_PER_CALLER: usize = 4 * 1024;
/// Bytes of overflow pairs across every caller and fingerprint.
pub(super) const OVERFLOW_BYTES_TOTAL: usize = 1024 * 1024;
/// Records past [`INLINE_RECORDS`], across every fingerprint. At most
/// 65,536 x `size_of::<Holder>()` bytes (asserted by a unit row).
pub(super) const EXTRA_RECORD_POOL: usize = 65_536;

/// The holders of a fingerprint that is still judged.
#[derive(Default)]
pub(super) struct Tracked {
    /// Exact (source, caller) records.
    pub(super) records: Vec<Holder>,
    /// Every caller that received it, with its latest delivery: `Common` is
    /// decided from these, so a dropped record never hides a caller.
    callers: Vec<(u64, Instant)>,
    /// Callers with a sensitive record that did not fit.
    overflow: Vec<Overflow>,
}

/// One caller's sensitive records past its cap, for one fingerprint.
struct Overflow {
    principal: u64,
    pairs: Vec<Pair>,
    /// Set when a pair did not fit: what was lost is judged sensitive and
    /// covered by no flow. Only new unattributed evidence extends it.
    unattributed: Option<Copies>,
}

/// An overflowed record: its source identity and inferred fact.
struct Pair {
    origin: Origin,
    inferred: bool,
    copies: Copies,
}

/// The bytes one pair is charged beside its name.
const PAIR_BYTES: usize = std::mem::size_of::<Pair>();

/// The overflow bytes held across every fingerprint: pairs, plus each name
/// once while some pair holds it.
pub(super) struct Budget {
    pub(super) total: usize,
    pub(super) limit: usize,
    names: HashMap<Arc<str>, usize>,
}

impl Budget {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            total: 0,
            limit,
            names: HashMap::new(),
        }
    }

    /// What adding a pair of `origin` would charge.
    fn charge(&self, origin: &Origin) -> usize {
        PAIR_BYTES
            + names(origin)
                .filter(|n| !self.names.contains_key(*n))
                .map(|n| n.len())
                .sum::<usize>()
    }

    fn take(&mut self, origin: &Origin) {
        self.total += self.charge(origin);
        for name in names(origin) {
            *self.names.entry(Arc::clone(name)).or_default() += 1;
        }
    }

    fn give_back(&mut self, origin: &Origin) {
        self.total -= PAIR_BYTES;
        for name in names(origin) {
            if let Some(n) = self.names.get_mut(name) {
                *n -= 1;
                if *n == 0 {
                    self.names.remove(name);
                    self.total -= name.len();
                }
            }
        }
    }
}

fn names(origin: &Origin) -> Box<dyn Iterator<Item = &Arc<str>> + '_> {
    match origin {
        Origin::One(name) => Box::new(std::iter::once(name)),
        Origin::Each(names) => Box::new(names.iter()),
    }
}

/// A pair's bytes as its caller's bound counts them: the pair and its names.
fn caller_bytes(pair: &Pair) -> usize {
    PAIR_BYTES + names(&pair.origin).map(|n| n.len()).sum::<usize>()
}

/// What adding a delivery did, for the detector's counters.
pub(super) enum Added {
    /// Kept, merged into its record, or turned the text `Common`.
    Kept,
    /// A plain record did not fit: dropped.
    PlainDropped,
    /// A sensitive record took the place of the caller's plain one from
    /// `source`, whose excuse is gone.
    PlainReplaced { source: u64 },
    /// A sensitive record did not fit: kept as its caller's overflow.
    Overflowed,
}

impl Tracked {
    /// Pool records this fingerprint holds.
    /// Charged by allocated capacity, not length, so storage a removal
    /// left behind still counts until it is freed.
    pub(super) fn pool_records(&self) -> usize {
        self.records.capacity().saturating_sub(INLINE_RECORDS)
    }

    /// Distinct callers seen inside the window.
    pub(super) fn callers(&self) -> usize {
        self.callers.len()
    }

    /// Drop what left the window at `now`: records, callers and overflow,
    /// giving the overflow's bytes back to `budget`.
    pub(super) fn expire(&mut self, now: Instant, window: Duration, budget: &mut Budget) {
        let live = |at: Instant| now.saturating_duration_since(at) <= window;
        self.records.retain(|r| live(r.copies.latest()));
        if self.records.capacity() > INLINE_RECORDS {
            self.records
                .shrink_to(self.records.len().max(INLINE_RECORDS));
        }
        self.callers.retain(|(_, at)| live(*at));
        for slot in &mut self.overflow {
            slot.pairs.retain(|pair| {
                let keep = live(pair.copies.latest());
                if !keep {
                    budget.give_back(&pair.origin);
                }
                keep
            });
            if slot.unattributed.is_some_and(|c| !live(c.latest())) {
                slot.unattributed = None;
            }
        }
        self.overflow
            .retain(|slot| !slot.pairs.is_empty() || slot.unattributed.is_some());
    }

    /// Give every overflow pair's bytes back: the entry is going.
    pub(super) fn release(&mut self, budget: &mut Budget) {
        for slot in self.overflow.drain(..) {
            for pair in &slot.pairs {
                budget.give_back(&pair.origin);
            }
        }
    }

    /// Add `new` delivered at `now`, its retention decided by the lists of
    /// `view`, the generation it is recorded under. `room` is how many pool
    /// records this fingerprint may hold in all.
    pub(super) fn add(
        &mut self,
        new: Holder,
        (now, window): (Instant, Duration),
        (view, room): (&CollusionView, usize),
        budget: &mut Budget,
    ) -> Added {
        // `MIK-8066` D6: an unread holder is evidence, never a caller.
        if !new.unread {
            self.note_caller(new.principal, now);
        }
        if let Some(r) = self
            .records
            .iter_mut()
            .find(|r| r.source == new.source && r.principal == new.principal)
        {
            // Kept by their own times, whatever order calls arrive in.
            r.copies.add(&new.copies, window);
            match (&mut r.inferred, new.inferred) {
                (Some(held), Some(more)) => held.add(&more, window),
                (held, more) => *held = held.or(more),
            }
            return Added::Kept;
        }
        let mine = self
            .records
            .iter()
            .filter(|r| r.principal == new.principal)
            .count();
        let fits = mine < MAX_RECORDS_PER_CALLER && self.records.len() < INLINE_RECORDS + room;
        if fits {
            // Past the inline records, grow by one: the pool is charged by
            // capacity, so doubling would spend slots no record uses. The
            // record goes in only once its storage fits the pool, so the
            // bound holds whatever spare capacity the allocator returns.
            if self.records.len() >= INLINE_RECORDS {
                // Room for exactly one more, so the push never reallocates.
                self.records.reserve_exact(1);
                self.records.shrink_to(self.records.len() + 1);
            }
            if self.pool_records() <= room {
                self.records.push(new);
                return Added::Kept;
            }
            self.records.shrink_to_fit();
        }
        if new.inferred.is_none() && !new.origin.listed(view) {
            return Added::PlainDropped;
        }
        // A plain record of the same caller gives way to a sensitive one.
        let plain = |r: &Holder| {
            r.principal == new.principal
                && r.inferred
                    .is_none_or(|c| now.saturating_duration_since(c.latest()) > window)
                && !r.origin.listed(view)
        };
        if let Some(i) = self.records.iter().position(plain) {
            let source = self.records[i].source;
            self.records[i] = new;
            return Added::PlainReplaced { source };
        }
        self.overflow_pair(new, now, window, budget);
        Added::Overflowed
    }

    /// Keep `new` as a pair of its caller's overflow, or mark the caller
    /// unattributed when the pair does not fit its count, its bytes or the
    /// total budget. A pair already held is refreshed, never the mark.
    fn overflow_pair(&mut self, new: Holder, now: Instant, window: Duration, budget: &mut Budget) {
        let pair = Pair {
            inferred: new.inferred.is_some(),
            origin: new.origin,
            copies: new.copies,
        };
        let mine = self
            .overflow
            .iter()
            .position(|s| s.principal == new.principal);
        let i = mine.unwrap_or_else(|| {
            self.overflow.push(Overflow {
                principal: new.principal,
                pairs: Vec::new(),
                unattributed: None,
            });
            self.overflow.len() - 1
        });
        let slot = &mut self.overflow[i];
        if let Some(held) = slot
            .pairs
            .iter_mut()
            .find(|p| p.origin == pair.origin && p.inferred == pair.inferred)
        {
            held.copies.add(&pair.copies, window);
            return;
        }
        let bytes: usize = slot.pairs.iter().map(caller_bytes).sum::<usize>() + caller_bytes(&pair);
        let fits = slot.pairs.len() < OVERFLOW_PAIRS_PER_CALLER
            && bytes <= OVERFLOW_BYTES_PER_CALLER
            && budget.total + budget.charge(&pair.origin) <= budget.limit;
        if fits {
            budget.take(&pair.origin);
            slot.pairs.push(pair);
            return;
        }
        match &mut slot.unattributed {
            Some(copies) => copies.add(&Copies::one(now), window),
            None => slot.unattributed = Some(Copies::one(now)),
        }
    }

    fn note_caller(&mut self, principal: u64, now: Instant) {
        match self.callers.iter_mut().find(|(p, _)| *p == principal) {
            Some((_, at)) => *at = (*at).max(now),
            None => self.callers.push((principal, now)),
        }
    }

    /// Whether `principal` is unattributed (tests only).
    #[cfg(test)]
    pub(super) fn unattributed(&self, principal: u64) -> bool {
        self.overflow
            .iter()
            .any(|s| s.principal == principal && s.unattributed.is_some())
    }

    /// `principal`'s overflow pairs `(source, inferred)` (tests only).
    #[cfg(test)]
    pub(super) fn pairs_of(&self, principal: u64) -> Vec<(Arc<str>, bool)> {
        self.overflow
            .iter()
            .filter(|s| s.principal == principal)
            .flat_map(|s| &s.pairs)
            .filter_map(|p| match &p.origin {
                Origin::One(name) => Some((Arc::clone(name), p.inferred)),
                Origin::Each(_) => None,
            })
            .collect()
    }

    /// The most overflow bytes one caller holds here (tests only).
    #[cfg(test)]
    pub(super) fn max_caller_bytes(&self) -> usize {
        self.overflow
            .iter()
            .map(|s| s.pairs.iter().map(caller_bytes).sum())
            .max()
            .unwrap_or(0)
    }

    /// Whether `principal`'s own sensitive copy is held only as overflow at
    /// `now`: its record did not fit, so no exact copy of it can excuse it
    /// (`MIK-8201`: such a refusal is named capacity).
    pub(super) fn overflowed(&self, principal: u64, now: Instant, window: Duration) -> bool {
        self.overflow.iter().any(|s| {
            s.principal == principal
                && (s.unattributed.is_some_and(|c| c.held(now, window))
                    || s.pairs.iter().any(|p| p.copies.held(now, window)))
        })
    }

    /// A caller other than `sender` whose overflow counts for an egress
    /// through `egress` at `now`, judged by `view`: an unattributed mark, or
    /// a pair sensitive under `view` that no flow of `view` allows. No exact
    /// copy the sender holds excuses either.
    pub(super) fn overflow_witness(
        &self,
        sender: u64,
        (now, window): (Instant, Duration),
        (view, egress): (&CollusionView, &str),
    ) -> Option<u64> {
        let counts = |p: &Pair| {
            p.copies.held(now, window)
                && (p.inferred || p.origin.listed(view))
                && !p.origin.flows_to(view, egress)
        };
        self.overflow
            .iter()
            .find(|s| {
                s.principal != sender
                    && (s.unattributed.is_some_and(|c| c.held(now, window))
                        || s.pairs.iter().any(counts))
            })
            .map(|s| s.principal)
    }
}
