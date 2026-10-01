// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The subscription and verification store: an in-memory image that serves
//! reads, every mutation committed to disk under one lock (design §5).
//! Methods block on file I/O; async callers run them on a blocking thread.

use std::collections::HashMap;
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

#[derive(Default)]
struct State {
    subs: HashMap<String, Subscription>,
    /// Keyed by `verified_file(principal, url)`.
    verified: HashMap<String, Verified>,
}

impl State {
    fn pair_live(&self, principal: &str, url: &str, now: DateTime<Utc>) -> bool {
        self.subs
            .values()
            .any(|s| s.principal == principal && s.url == url && s.live(now))
    }

    /// When the pair's verification stopped being held by a live
    /// subscription: the recorded end, else the latest expiry, else the
    /// opt-in itself (an orphan record ages out from when it was made).
    fn ended_at(&self, record: &Verified) -> DateTime<Utc> {
        record
            .last_subscription_ended_at
            .or_else(|| {
                self.subs
                    .values()
                    .filter(|s| s.principal == record.principal && s.url == record.url)
                    .filter_map(|s| s.expires_at)
                    .max()
            })
            .unwrap_or(record.verified_at)
    }
}

/// Why an admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapHit {
    PerPrincipal(usize),
    Global(usize),
}

/// The subscription caps checked by an admission of a new key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caps {
    pub per_principal: usize,
    pub global: usize,
}

/// The store. One per gateway.
pub(crate) struct Store {
    subs_dir: PathBuf,
    verified_dir: PathBuf,
    state: Mutex<State>,
}

impl Store {
    /// Open (creating) the store at `root`, dropping expired subscriptions
    /// and tail records past `tail.ttl`.
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
        store.sweep(&mut store.state.lock(), now)?;
        store.trim_tails(&mut store.state.lock(), now, tail)?;
        Ok(store)
    }

    /// Remove expired subscriptions. A pair left with no live subscription
    /// records its latest expiry as the start of its verification tail.
    fn sweep(&self, state: &mut State, now: DateTime<Utc>) -> std::io::Result<()> {
        let expired: Vec<Subscription> = state
            .subs
            .values()
            .filter(|s| !s.live(now))
            .cloned()
            .collect();
        for sub in &expired {
            let key = verified_file(&sub.principal, &sub.url);
            if !state.pair_live(&sub.principal, &sub.url, now)
                && let Some(record) = state.verified.get(&key)
            {
                let ended = state.ended_at(record);
                if record.last_subscription_ended_at != Some(ended) {
                    let mut record = record.clone();
                    record.last_subscription_ended_at = Some(ended);
                    write_record(&self.verified_dir, &key, &record)?;
                    state.verified.insert(key, record);
                }
            }
        }
        for sub in expired {
            remove_record(&self.subs_dir, &format!("{}.json", sub.id))?;
            state.subs.remove(&sub.id);
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
        let ttl = chrono::Duration::from_std(tail.ttl).unwrap_or(chrono::Duration::MAX);
        now - state.ended_at(record) < ttl
    }

    /// Cap check and commit as one step under the store lock, after
    /// sweeping what has expired: two admissions cannot both pass a cap that
    /// only one fits under. A refresh of a live key is never capped.
    /// `verified_now` stamps a fresh opt-in.
    pub(crate) fn admit(
        &self,
        sub: Subscription,
        verified_now: bool,
        caps: Caps,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<Result<(), CapHit>> {
        let mut state = self.state.lock();
        self.sweep(&mut state, now)?;
        if !state.subs.contains_key(&sub.id) {
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
        write_record(&self.subs_dir, &format!("{}.json", sub.id), &sub)?;
        state.subs.insert(sub.id.clone(), sub);
        write_record(&self.verified_dir, &key, &record)?;
        state.verified.insert(key, record);
        self.trim_tails(&mut state, now, tail)?;
        Ok(Ok(()))
    }

    /// Whether a new key for `principal` would pass the caps now. Advisory:
    /// lets subscribe refuse before any outbound verification; [`Self::admit`]
    /// decides.
    pub(crate) fn would_admit(
        &self,
        principal: &str,
        caps: Caps,
        now: DateTime<Utc>,
    ) -> Result<(), CapHit> {
        let state = self.state.lock();
        let live = state.subs.values().filter(|s| s.live(now));
        let (mine, all) = live.fold((0, 0), |(m, a), s| {
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

    /// Delete subscription `id`. When it was the pair's last, the pair's
    /// verification enters the tail, and the tail is trimmed.
    pub(crate) fn remove(
        &self,
        id: &str,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<bool> {
        let mut state = self.state.lock();
        let Some(sub) = state.subs.get(id).cloned() else {
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
        let mut tails: Vec<(DateTime<Utc>, String, String)> = state
            .verified
            .iter()
            .filter(|(_, r)| !state.pair_live(&r.principal, &r.url, now))
            .map(|(key, r)| {
                let ended = state.ended_at(r);
                (ended, key.clone(), r.principal.clone())
            })
            .collect();
        tails.sort();
        let mut evict: Vec<String> = Vec::new();
        let mut per_principal: HashMap<String, usize> = HashMap::new();
        for (_, _, principal) in &tails {
            *per_principal.entry(principal.clone()).or_default() += 1;
        }
        let mut kept = tails.len();
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
