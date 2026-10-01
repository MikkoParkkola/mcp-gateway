// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The subscription and verification store: an in-memory image that serves
//! reads, every mutation committed to disk under one lock (design §5).
//! Methods block on file I/O; async callers run them on a blocking thread.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use super::records::{
    Subscription, Verified, create_private_dir, load_records, remove_record, verified_file,
    write_record,
};

/// Bounds on verification records whose last subscription has ended.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TailPolicy {
    pub ttl: Duration,
    pub max: usize,
    pub max_per_principal: usize,
}

/// The subscription caps checked by an admission of a new key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caps {
    pub per_principal: usize,
    pub global: usize,
}

/// Why an admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapHit {
    PerPrincipal(usize),
    Global(usize),
}

/// A `(principal, url)` pair, the unit a verification belongs to.
type Pair = (String, String);

#[derive(Default)]
struct State {
    subs: HashMap<String, Subscription>,
    /// Keyed by `verified_file(principal, url)`.
    verified: HashMap<String, Verified>,
}

/// Per-pair facts over every subscription, built in one pass so tail
/// maintenance is linear in the store, not quadratic.
struct PairIndex {
    live: HashSet<Pair>,
    latest_expiry: HashMap<Pair, DateTime<Utc>>,
}

impl State {
    fn index(&self, now: DateTime<Utc>) -> PairIndex {
        let mut index = PairIndex {
            live: HashSet::new(),
            latest_expiry: HashMap::new(),
        };
        for sub in self.subs.values() {
            let pair = (sub.principal.clone(), sub.url.clone());
            if let Some(at) = sub.expires_at {
                let slot = index.latest_expiry.entry(pair.clone()).or_insert(at);
                *slot = (*slot).max(at);
            }
            if sub.live(now) {
                index.live.insert(pair);
            }
        }
        index
    }

    fn pair_live(&self, principal: &str, url: &str, now: DateTime<Utc>) -> bool {
        self.subs
            .values()
            .any(|s| s.principal == principal && s.url == url && s.live(now))
    }
}

impl PairIndex {
    /// When the pair's verification stopped being held by a live
    /// subscription: the recorded end, else the latest expiry, else the
    /// opt-in itself (an orphan record ages out from when it was made).
    fn ended_at(&self, record: &Verified) -> DateTime<Utc> {
        let pair = (record.principal.clone(), record.url.clone());
        record
            .last_subscription_ended_at
            .or_else(|| self.latest_expiry.get(&pair).copied())
            .unwrap_or(record.verified_at)
    }
}

/// The store. One per gateway.
pub(crate) struct Store {
    subs_dir: PathBuf,
    verified_dir: PathBuf,
    state: Mutex<State>,
}

impl Store {
    /// Open (creating) the store at `root`, sweeping expired subscriptions
    /// and trimming the verification tail.
    pub(crate) fn open(root: &Path, now: DateTime<Utc>, tail: TailPolicy) -> std::io::Result<Self> {
        let subs_dir = root.join("subs");
        let verified_dir = root.join("verified");
        create_private_dir(root)?;
        create_private_dir(&subs_dir)?;
        create_private_dir(&verified_dir)?;
        let mut state = State::default();
        for (_, sub) in load_records::<Subscription>(&subs_dir) {
            state.subs.insert(sub.id.clone(), sub);
        }
        for (path, record) in load_records::<Verified>(&verified_dir) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                state.verified.insert(name.to_owned(), record);
            }
        }
        let store = Self {
            subs_dir,
            verified_dir,
            state: Mutex::new(state),
        };
        {
            let mut state = store.state.lock();
            store.sweep(&mut state, now)?;
            store.trim_tails(&mut state, now, tail)?;
        }
        Ok(store)
    }

    /// Remove expired subscriptions. A pair left with no live subscription
    /// records its latest expiry as the start of its verification tail.
    fn sweep(&self, state: &mut State, now: DateTime<Utc>) -> std::io::Result<()> {
        let expired: Vec<String> = state
            .subs
            .values()
            .filter(|s| !s.live(now))
            .map(|s| s.id.clone())
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        let index = state.index(now);
        let ended: Vec<(String, Verified)> = state
            .verified
            .iter()
            .filter(|(_, r)| r.last_subscription_ended_at.is_none())
            .filter(|(_, r)| !index.live.contains(&(r.principal.clone(), r.url.clone())))
            .map(|(key, r)| {
                let mut record = r.clone();
                record.last_subscription_ended_at = Some(index.ended_at(r));
                (key.clone(), record)
            })
            .collect();
        for (key, record) in ended {
            write_record(&self.verified_dir, &key, &record)?;
            state.verified.insert(key, record);
        }
        for id in expired {
            remove_record(&self.subs_dir, &format!("{id}.json"))?;
            state.subs.remove(&id);
        }
        Ok(())
    }

    pub(crate) fn get(&self, id: &str) -> Option<Subscription> {
        self.state.lock().subs.get(id).cloned()
    }

    /// Whether `(principal, url)` holds a usable opt-in: held by a live
    /// subscription, or ended less than `tail.ttl` ago.
    pub(crate) fn is_verified(
        &self,
        principal: &str,
        url: &str,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> bool {
        let state = self.state.lock();
        let Some(record) = state.verified.get(&verified_file(principal, url)) else {
            return false;
        };
        if state.pair_live(principal, url, now) {
            return true;
        }
        let latest = state
            .subs
            .values()
            .filter(|s| s.principal == principal && s.url == url)
            .filter_map(|s| s.expires_at)
            .max();
        let ended = record
            .last_subscription_ended_at
            .or(latest)
            .unwrap_or(record.verified_at);
        let ttl = chrono::Duration::from_std(tail.ttl).unwrap_or(chrono::Duration::MAX);
        now - ended < ttl
    }

    /// Cap check, rotation and commit as one step under the store lock,
    /// after sweeping what has expired: two admissions cannot both pass a
    /// cap that only one fits under, and two rotations of one key cannot
    /// both rotate from the same old row. A refresh of a live key is never
    /// capped. `verified_now` stamps a fresh opt-in. The verification is
    /// written before the subscription, so a failed commit never leaves a
    /// subscription without a durable opt-in.
    pub(crate) fn admit(
        &self,
        mut sub: Subscription,
        verified_now: bool,
        caps: Caps,
        grace: chrono::Duration,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<Result<(), CapHit>> {
        let mut state = self.state.lock();
        self.sweep(&mut state, now)?;
        match state.subs.get(&sub.id) {
            Some(old) => {
                if old.secret == sub.secret {
                    sub.previous_secret.clone_from(&old.previous_secret);
                    sub.previous_until = old.previous_until;
                } else {
                    sub.previous_secret = Some(old.secret.clone());
                    sub.previous_until = Some(now + grace);
                }
                sub.failed_since = old.failed_since;
                sub.last_delivery_at = old.last_delivery_at;
                sub.last_error.clone_from(&old.last_error);
            }
            None => {
                let mine = state
                    .subs
                    .values()
                    .filter(|s| s.principal == sub.principal)
                    .count();
                if mine >= caps.per_principal {
                    return Ok(Err(CapHit::PerPrincipal(caps.per_principal)));
                }
                if state.subs.len() >= caps.global {
                    return Ok(Err(CapHit::Global(caps.global)));
                }
            }
        }
        let key = verified_file(&sub.principal, &sub.url);
        let record = match state.verified.get(&key) {
            Some(existing) if !verified_now => Verified {
                last_subscription_ended_at: None,
                ..existing.clone()
            },
            _ => Verified {
                v: 1,
                principal: sub.principal.clone(),
                url: sub.url.clone(),
                verified_at: now,
                last_subscription_ended_at: None,
            },
        };
        let prior = state.verified.get(&key).cloned();
        write_record(&self.verified_dir, &key, &record)?;
        state.verified.insert(key.clone(), record);
        if let Err(error) = write_record(&self.subs_dir, &format!("{}.json", sub.id), &sub) {
            // Put the verification back as it was, so a failed commit
            // neither leaves an extra record nor resets an existing tail.
            match prior {
                Some(prior) => {
                    let _ = write_record(&self.verified_dir, &key, &prior);
                    state.verified.insert(key, prior);
                }
                None => {
                    let _ = remove_record(&self.verified_dir, &key);
                    state.verified.remove(&key);
                }
            }
            return Err(error);
        }
        state.subs.insert(sub.id.clone(), sub);
        self.trim_tails(&mut state, now, tail)?;
        Ok(Ok(()))
    }

    /// Whether a new key for `principal` would pass the caps now. Advisory:
    /// lets subscribe refuse before any outbound verification;
    /// [`Self::admit`] decides.
    pub(crate) fn would_admit(
        &self,
        principal: &str,
        caps: Caps,
        now: DateTime<Utc>,
    ) -> Result<(), CapHit> {
        let state = self.state.lock();
        let (mine, all) = state
            .subs
            .values()
            .filter(|s| s.live(now))
            .fold((0, 0), |(m, a), s| {
                (m + usize::from(s.principal == principal), a + 1)
            });
        if mine >= caps.per_principal {
            return Err(CapHit::PerPrincipal(caps.per_principal));
        }
        if all >= caps.global {
            return Err(CapHit::Global(caps.global));
        }
        Ok(())
    }

    /// Delete subscription `id`. Expired rows are swept first, so an
    /// unsubscribe never restarts a tail that expiry already began. When
    /// it was the pair's last, the pair's verification enters the tail,
    /// and the tail is trimmed.
    pub(crate) fn remove(
        &self,
        id: &str,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<bool> {
        let mut state = self.state.lock();
        self.sweep(&mut state, now)?;
        let Some(sub) = state.subs.get(id).cloned() else {
            self.trim_tails(&mut state, now, tail)?;
            return Ok(false);
        };
        remove_record(&self.subs_dir, &format!("{id}.json"))?;
        state.subs.remove(id);
        if !state.pair_live(&sub.principal, &sub.url, now) {
            let key = verified_file(&sub.principal, &sub.url);
            if let Some(mut record) = state.verified.get(&key).cloned() {
                record.last_subscription_ended_at = Some(now);
                write_record(&self.verified_dir, &key, &record)?;
                state.verified.insert(key, record);
            }
        }
        self.trim_tails(&mut state, now, tail)?;
        Ok(true)
    }

    /// Drop tail records past their TTL, then evict the oldest beyond the
    /// per-principal and global caps. A record held by a live subscription
    /// is never a tail and never evicted.
    fn trim_tails(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<()> {
        let ttl = chrono::Duration::from_std(tail.ttl).unwrap_or(chrono::Duration::MAX);
        let index = state.index(now);
        let mut tails: Vec<(DateTime<Utc>, String, String)> = state
            .verified
            .iter()
            .filter(|(_, r)| !index.live.contains(&(r.principal.clone(), r.url.clone())))
            .map(|(key, r)| (index.ended_at(r), key.clone(), r.principal.clone()))
            .collect();
        tails.sort();
        let mut per_principal: HashMap<String, usize> = HashMap::new();
        for (_, _, principal) in &tails {
            *per_principal.entry(principal.clone()).or_default() += 1;
        }
        let mut kept = tails.len();
        let mut evict: Vec<String> = Vec::new();
        for (ended, key, principal) in &tails {
            let count = per_principal.get_mut(principal).expect("counted above");
            if now - *ended >= ttl || *count > tail.max_per_principal || kept > tail.max {
                evict.push(key.clone());
                *count -= 1;
                kept -= 1;
            }
        }
        for key in evict {
            remove_record(&self.verified_dir, &key)?;
            state.verified.remove(&key);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
