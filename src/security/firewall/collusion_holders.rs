// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8123`: the holders of one tracked fingerprint.
//!
//! Every (source, caller) record stays exact: no fingerprint is switched off
//! because many sources delivered it. A caller keeps at most
//! [`MAX_RECORDS_PER_CALLER`] records per fingerprint; records past
//! [`INLINE_RECORDS`] draw from one global pool shared by every fingerprint,
//! so memory is today's inline records plus the pool, whatever the fan-out.
//! A record that does not fit is dropped when it is plain (only an excuse is
//! lost) and, when it is sensitive, kept as the caller's *overflow*: the
//! caller held sensitive text whose source and flows are gone, so any other
//! caller's egress of it counts, whatever its flows and whatever exact copy
//! the sender holds. Text `common_principals` distinct callers hold is
//! `Common`, decided from every caller seen, records kept or not.

use std::time::{Duration, Instant};

use super::{Copies, Holder};

/// Records one fingerprint keeps without drawing on the pool.
pub(super) const INLINE_RECORDS: usize = 8;
/// Records one caller keeps for one fingerprint.
pub(super) const MAX_RECORDS_PER_CALLER: usize = 64;
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
    /// Callers with a sensitive record that did not fit, and when they got
    /// it sensitive. Only sensitive deliveries add to it.
    overflow: Vec<(u64, Copies)>,
}

/// What adding a delivery did, for the detector's counters.
pub(super) enum Added {
    /// Kept, merged into its record, or turned the text `Common`.
    Kept,
    /// A plain record did not fit: dropped.
    PlainDropped,
    /// A sensitive record did not fit: kept as its caller's overflow.
    Overflowed,
}

impl Tracked {
    /// Pool records this fingerprint holds.
    pub(super) fn pool_records(&self) -> usize {
        self.records.len().saturating_sub(INLINE_RECORDS)
    }

    /// Distinct callers seen inside the window.
    pub(super) fn callers(&self) -> usize {
        self.callers.len()
    }

    /// Drop what left the window at `now`: records, callers and overflow.
    pub(super) fn expire(&mut self, now: Instant, window: Duration) {
        let live = |at: Instant| now.saturating_duration_since(at) <= window;
        self.records.retain(|r| live(r.copies.latest()));
        self.callers.retain(|(_, at)| live(*at));
        self.overflow.retain(|(_, copies)| live(copies.latest()));
    }

    /// Add `new` delivered at `now`. `room` is how many pool records this
    /// fingerprint may hold in all.
    pub(super) fn add(
        &mut self,
        new: Holder,
        now: Instant,
        window: Duration,
        room: usize,
    ) -> Added {
        self.note_caller(new.principal, now);
        if let Some(r) = self
            .records
            .iter_mut()
            .find(|r| r.source == new.source && r.principal == new.principal)
        {
            // Kept by their own times, whatever order calls arrive in.
            r.copies.add(&new.copies, window);
            match (&mut r.sensitive, new.sensitive) {
                (Some(held), Some(more)) => held.add(&more, window),
                (held, more) => *held = held.or(more),
            }
            r.flows.merge(new.flows);
            return Added::Kept;
        }
        let mine = self
            .records
            .iter()
            .filter(|r| r.principal == new.principal)
            .count();
        let fits = mine < MAX_RECORDS_PER_CALLER && self.records.len() < INLINE_RECORDS + room;
        if fits {
            self.records.push(new);
            return Added::Kept;
        }
        let Some(sensitive) = new.sensitive else {
            return Added::PlainDropped;
        };
        // A plain record of the same caller gives way to a sensitive one.
        let plain = |r: &Holder| {
            r.principal == new.principal && !r.sensitive.is_some_and(|c| c.held(now, window))
        };
        if let Some(i) = self.records.iter().position(plain) {
            self.records[i] = new;
            return Added::Kept;
        }
        match self.overflow.iter_mut().find(|(p, _)| *p == new.principal) {
            Some((_, copies)) => copies.add(&sensitive, window),
            None => self.overflow.push((new.principal, sensitive)),
        }
        Added::Overflowed
    }

    fn note_caller(&mut self, principal: u64, now: Instant) {
        match self.callers.iter_mut().find(|(p, _)| *p == principal) {
            Some((_, at)) => *at = (*at).max(now),
            None => self.callers.push((principal, now)),
        }
    }

    /// A caller other than `sender` whose overflow is held at `now`: it
    /// counts for any egress of the fingerprint (its source and flows are
    /// gone, so no exact copy excuses it and no flow allows it).
    pub(super) fn overflow_witness(
        &self,
        sender: u64,
        now: Instant,
        window: Duration,
    ) -> Option<u64> {
        self.overflow
            .iter()
            .find(|(p, copies)| *p != sender && copies.held(now, window))
            .map(|(p, _)| *p)
    }
}
