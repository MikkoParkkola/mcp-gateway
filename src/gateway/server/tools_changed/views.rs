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

/// The per-user views of one backend instance.
#[derive(Default)]
pub(super) struct Views {
    instance: u64,
    /// Raw binding -> fingerprint last compared for it.
    live: HashMap<String, u64>,
    /// Stable audience -> (fingerprint an evicted slot last showed, age stamp).
    tombstones: HashMap<String, (u64, u64)>,
    stamp: u64,
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
    /// Returns whether a tombstone overflow forces an announcement.
    pub(super) fn adopt(&mut self, instance: u64) -> bool {
        if self.instance == instance {
            return false;
        }
        self.instance = instance;
        let mut overflow = false;
        for (binding, shown) in std::mem::take(&mut self.live) {
            overflow |= self.bury(&binding, shown);
        }
        overflow
    }

    /// Whether listeners must hear about this slot after what was `seen`.
    pub(super) fn slot(&mut self, binding: &str, seen: SlotSeen) -> bool {
        let empty = fingerprint(&[]);
        match seen {
            SlotSeen::Unfilled => false,
            SlotSeen::Absent => match self.live.remove(binding) {
                Some(shown) if shown != empty => self.bury(binding, shown),
                _ => false,
            },
            SlotSeen::Holds(visible) => {
                let before = match self.live.get(binding) {
                    Some(&shown) => shown,
                    None => self.baseline(binding),
                };
                self.live.insert(binding.to_string(), visible);
                visible != before
            }
        }
    }

    /// Recompute every slot: `present` is every per-user slot the backend holds
    /// now. A slot remembered but not present was evicted.
    pub(super) fn recompute(&mut self, present: &[(String, SlotSeen)]) -> bool {
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
        changed
    }

    /// A revoked grant: its caller loses what the slot showed. No tombstone,
    /// so a later grant's first fill compares with nothing.
    pub(super) fn revoked(&mut self, binding: &str) -> bool {
        let empty = fingerprint(&[]);
        self.tombstones.remove(audience(binding));
        matches!(self.live.remove(binding), Some(shown) if shown != empty)
    }

    /// Whether any per-user view last showed tools: removing the backend
    /// then changes what those callers see.
    pub(super) fn any_shown(&self) -> bool {
        let empty = fingerprint(&[]);
        !self.tombstones.is_empty() || self.live.values().any(|&shown| shown != empty)
    }

    /// What a binding's first store is compared with. A refreshed account
    /// lease inherits from the newest revision of the same grant still
    /// present (K1), so a refresh that changes nothing stays silent; else from
    /// what an evicted slot of the same caller last showed (K2); else nothing.
    fn baseline(&mut self, binding: &str) -> u64 {
        if let Some(me) = acct(binding) {
            let predecessor = self
                .live
                .iter()
                .filter_map(|(other, &shown)| {
                    let o = acct(other)?;
                    (o.audience == me.audience && o.generation == me.generation)
                        .then_some((o.revision, shown))
                })
                .max_by_key(|(revision, _)| *revision);
            if let Some((_, shown)) = predecessor {
                return shown;
            }
        }
        self.tombstones
            .remove(audience(binding))
            .map_or_else(|| fingerprint(&[]), |(shown, _)| shown)
    }

    /// Keep what an evicted slot showed. Returns true when the cap drops the
    /// oldest tombstone: that caller's next fill can no longer be compared, so
    /// the drop itself is announced instead of risking a silent change.
    fn bury(&mut self, binding: &str, shown: u64) -> bool {
        self.stamp += 1;
        self.tombstones
            .insert(audience(binding).to_string(), (shown, self.stamp));
        if self.tombstones.len() <= TOMBSTONE_CAP {
            return false;
        }
        let oldest = self
            .tombstones
            .iter()
            .min_by_key(|(_, (_, stamp))| *stamp)
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
