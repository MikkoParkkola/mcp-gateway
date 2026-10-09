// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8148`: what each per-user view of one backend last showed.
//!
//! A per-user slot's catalogue is what that caller's discovery serves. A change
//! to it is announced to the backend's audience as a content-free relist hint
//! (lead ruling 2026-10-09, option a): nothing here decides WHO hears it, only
//! WHETHER a view changed. Over-announcing is allowed; missing a change is not.

use std::collections::HashMap;

use super::fingerprint;

/// Tombstones kept per backend before the oldest is dropped.
// ponytail: O(n) oldest-scan on overflow; an indexed LRU if the cap ever binds often.
const TOMBSTONE_CAP: usize = 4096;

/// What the drain can see of one per-user slot now.
#[derive(Clone, Copy)]
pub(in crate::gateway::server) enum SlotSeen {
    /// No slot holds this binding (never opened, or evicted).
    Absent,
    /// The slot exists but has stored no list: discovery fills it on demand.
    Unfilled,
    /// The slot holds a list with this fingerprint, filtered as discovery serves it.
    Holds(u64),
}

/// What an evicted slot last showed, for its caller's next first fill.
struct Tombstone {
    shown: u64,
    /// Age, for the cap.
    stamp: u64,
    /// The account lease it was filled under (`acct:` bindings only).
    lease: Option<(String, (u64, u64))>,
}

/// The per-user views of one backend instance.
#[derive(Default)]
pub(super) struct Views {
    instance: u64,
    /// Raw binding -> fingerprint last compared for it.
    live: HashMap<String, u64>,
    /// Stable audience -> what its evicted slot last showed.
    tombstones: HashMap<String, Tombstone>,
    stamp: u64,
    /// The descriptor filter's fingerprint at the last recompute.
    filter: Option<u64>,
}

/// An `acct:` binding's stable account part and its lease revision.
struct AcctBinding<'a> {
    audience: &'a str,
    generation: &'a str,
    revision: (u64, u64),
}

/// Parse `acct:v1:{digest}:{len}:{generation}:{epoch}:{token_revision}:...`
/// (`personal_accounts/vault.rs` `cache_binding`).
fn acct(binding: &str) -> Option<AcctBinding<'_>> {
    let rest = binding.strip_prefix("acct:v1:")?;
    let digest_end = "acct:v1:".len() + rest.find(':')?;
    let rest = &binding[digest_end + 1..];
    let (len, rest) = rest.split_once(':')?;
    let len: usize = len.parse().ok()?;
    let generation = rest.get(..len)?;
    let mut tail = rest.get(len..)?.strip_prefix(':')?.split(':');
    let epoch = tail.next()?.parse().ok()?;
    let token_revision = tail.next()?.parse().ok()?;
    Some(AcctBinding {
        audience: &binding[..digest_end],
        generation,
        revision: (epoch, token_revision),
    })
}

/// The part of a binding that names the caller across credential refreshes.
/// `idp:` bindings carry no revision, so they are their own audience.
fn audience(binding: &str) -> &str {
    acct(binding).map_or(binding, |a| a.audience)
}

impl Views {
    pub(super) fn new(instance: u64) -> Self {
        Self {
            instance,
            ..Self::default()
        }
    }

    /// Re-key to `instance`. A replaced instance's slots are gone with it, so
    /// what they showed becomes tombstones the successor's fills compare to.
    /// A predecessor that showed tools is announced: the successor may never
    /// open a per-user slot, and then nothing else would tell those callers.
    pub(super) fn adopt(&mut self, instance: u64) -> bool {
        if self.instance == instance {
            return false;
        }
        self.instance = instance;
        let empty = fingerprint(&[]);
        let mut changed = self.tombstones.values().any(|tomb| tomb.shown != empty);
        for (binding, shown) in std::mem::take(&mut self.live) {
            changed |= shown != empty;
            changed |= self.bury(&binding, shown);
        }
        changed
    }

    /// Whether listeners must hear about this slot after what was `seen`.
    pub(super) fn slot(&mut self, binding: &str, seen: SlotSeen) -> bool {
        match seen {
            SlotSeen::Unfilled => false,
            SlotSeen::Absent => match self.live.remove(binding) {
                Some(shown) => self.bury(binding, shown),
                None => false,
            },
            SlotSeen::Holds(visible) => {
                let before = match self.live.get(binding) {
                    Some(&shown) => Some(shown),
                    None => self.baseline(binding),
                };
                self.live.insert(binding.to_string(), visible);
                before != Some(visible)
            }
        }
    }

    /// Recompute every slot: `present` is every per-user slot the backend holds
    /// now, and `filter` the descriptor filter's fingerprint. A slot remembered
    /// but not present was evicted. A filter change cannot be recomputed for an
    /// evicted caller, so it is announced when any evicted view showed tools.
    pub(super) fn recompute(&mut self, present: &[(String, SlotSeen)], filter: u64) -> bool {
        let empty = fingerprint(&[]);
        let filter_moved = self
            .filter
            .replace(filter)
            .is_some_and(|before| before != filter);
        let mut changed = false;
        let gone: Vec<String> = self
            .live
            .keys()
            .filter(|binding| !present.iter().any(|(b, _)| b == *binding))
            .cloned()
            .collect();
        for binding in gone {
            changed |= self.slot(&binding, SlotSeen::Absent);
        }
        for (binding, seen) in present {
            changed |= self.slot(binding, *seen);
        }
        // LAST, after every bury: a view evicted since the last look, or
        // between listing the slots and reading one (a present Absent), counts.
        changed |= filter_moved && self.tombstones.values().any(|tomb| tomb.shown != empty);
        changed
    }

    /// A revoked grant: its caller loses what it was shown, which may be a
    /// list this drain never saw (the revocation can overtake the first
    /// store's nudge), so it is always announced. Nothing is kept: a later
    /// grant's first fill compares with nothing.
    pub(super) fn revoked(&mut self, prefix: &str) -> bool {
        self.live.retain(|binding, _| !binding.starts_with(prefix));
        // An account tombstone is keyed by the grant, which the prefix extends.
        self.tombstones.retain(|audience, _| {
            !audience.starts_with(prefix) && !prefix.starts_with(audience.as_str())
        });
        true
    }

    /// Whether any per-user view last showed tools: removing the backend
    /// then changes what those callers see.
    pub(super) fn any_shown(&self) -> bool {
        let empty = fingerprint(&[]);
        self.tombstones.values().any(|tomb| tomb.shown != empty)
            || self.live.values().any(|&shown| shown != empty)
    }

    /// What a binding's first store is compared with, or `None` when it must
    /// be announced whatever it holds.
    ///
    /// An account lease compares with the NEWEST revision of the same grant,
    /// live or evicted (K1, and an eviction never lets an older lease win). A
    /// new grant generation while another one of the same caller is live has
    /// no order to compare by, so it is announced. Otherwise what an evicted
    /// slot of the same caller last showed (K2), else nothing.
    fn baseline(&mut self, binding: &str) -> Option<u64> {
        let key = audience(binding).to_string();
        let tomb = self.tombstones.remove(&key);
        if let Some(me) = acct(binding) {
            let live = self.live.iter().filter_map(|(other, &shown)| {
                let o = acct(other)?;
                (o.audience == me.audience && o.generation == me.generation)
                    .then_some((o.revision, shown))
            });
            let buried = tomb.as_ref().and_then(|t| {
                let (generation, revision) = t.lease.as_ref()?;
                (generation == me.generation).then_some((*revision, t.shown))
            });
            let newest = live.chain(buried).max_by_key(|(revision, _)| *revision);
            // A late fill from an OLDER lease leaves a newer tombstone in
            // place, so the next refresh still compares with it.
            let newer_buried = tomb.as_ref().is_some_and(|t| {
                t.lease
                    .as_ref()
                    .is_some_and(|(g, r)| g == me.generation && *r > me.revision)
            });
            if newer_buried {
                let shown = newest.map(|(_, shown)| shown);
                if let Some(tomb) = tomb {
                    self.tombstones.insert(key, tomb);
                }
                return shown;
            }
            if let Some((_, shown)) = newest {
                return Some(shown);
            }
            let other_generation_live = self
                .live
                .keys()
                .any(|other| acct(other).is_some_and(|o| o.audience == me.audience));
            if other_generation_live {
                return None;
            }
        }
        Some(tomb.map_or_else(|| fingerprint(&[]), |t| t.shown))
    }

    /// Keep what an evicted slot showed, empty included, so the caller's next
    /// fill is compared with it. A tombstone from a newer lease of the same
    /// grant is never replaced by an older one. Returns true when the cap
    /// drops the oldest tombstone: that caller's next fill can no longer be
    /// compared, so the drop itself is announced instead.
    fn bury(&mut self, binding: &str, shown: u64) -> bool {
        let lease = acct(binding).map(|a| (a.generation.to_string(), a.revision));
        let key = audience(binding).to_string();
        if let (Some((generation, revision)), Some(kept)) = (&lease, self.tombstones.get(&key))
            && let Some((kept_generation, kept_revision)) = &kept.lease
            && kept_generation == generation
            && kept_revision > revision
        {
            return false;
        }
        self.stamp += 1;
        self.tombstones.insert(
            key,
            Tombstone {
                shown,
                stamp: self.stamp,
                lease,
            },
        );
        if self.tombstones.len() <= TOMBSTONE_CAP {
            return false;
        }
        let oldest = self
            .tombstones
            .iter()
            .min_by_key(|(_, tomb)| tomb.stamp)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            self.tombstones.remove(&oldest);
        }
        true
    }
}

#[cfg(test)]
#[path = "views_tests.rs"]
mod tests;
