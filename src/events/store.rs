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

use super::outbox::{DeadLetter, OutboxRecord};
use super::records::{
    Placed, Subscription, Verified, create_private_dir, load_records, remove_record, verified_file,
    write_record,
};

#[path = "store_hold.rs"]
mod hold;
#[path = "store_pending.rs"]
mod pending;
pub(crate) use hold::{Held, Judged};
pub(crate) use pending::{Claim, Claimed, Revived, Settle};

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

/// How long a subscription is granted for. It becomes a time only at the
/// commit instant, after the challenge and every wait before the store lock,
/// so a slow commit cannot eat a short TTL: `ttl` from then, never past
/// `until` (a bounded credential's own expiry). Neither means no expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Grant {
    pub ttl: Option<chrono::Duration>,
    pub until: Option<DateTime<Utc>>,
}

impl Grant {
    /// The expiry of a grant committed at `at`.
    pub(crate) fn expires_at(self, at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match (self.ttl.map(|ttl| at + ttl), self.until) {
            (Some(granted), Some(until)) => Some(granted.min(until)),
            (granted, until) => granted.or(until),
        }
    }
}

/// An admission and the expiry it committed.
pub(crate) type Admitted = (Admission, Option<DateTime<Utc>>);

/// How an admitted subscription met the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// No live row held this id.
    Inserted,
    /// A live row held this id and was replaced.
    Refreshed,
}

/// Why an admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapHit {
    PerPrincipal(usize),
    Global(usize),
    /// The caller skipped the challenge on a cached opt-in that is gone or
    /// past its tail by commit time: it must verify again.
    Unverified,
    /// A held row's refresh found the row gone or expired at the commit.
    HeldRowGone,
}

/// How a commit treats the hold of the row it replaces (MIK-8057,
/// MIK-8076), decided under the store lock with the commit itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldCommit {
    /// A held row's refresh: keeps the live row's hold and payload fields;
    /// [`CapHit::HeldRowGone`] when that row is gone or expired.
    Keep,
    /// Checked against the routes at the commit: a hold of the key ends
    /// with the row put in place.
    End,
}

/// A `(principal, url)` pair, the unit a verification belongs to.
type Pair = (String, String);

#[derive(Default)]
struct State {
    subs: HashMap<String, Subscription>,
    /// Keyed by `verified_file(principal, url)`.
    verified: HashMap<String, Verified>,
    /// Pending deliveries, keyed by event id.
    outbox: HashMap<String, OutboxRecord>,
    /// Dead letters with their file size, keyed by event id.
    dead: HashMap<String, (DeadLetter, u64)>,
    /// Webhook subscriptions the routes do not offer or serve now, and why
    /// (MIK-8057, MIK-8076): they take no record. Recomputed by every route
    /// refresh, never persisted.
    held: HashMap<String, Held>,
    /// Rows whose hold stamp is in memory but whose write failed: written
    /// again by the next route refresh.
    hold_unsynced: HashSet<String>,
}

/// Per-pair facts over every subscription, built in one pass so tail
/// maintenance is linear in the store, not quadratic.
struct PairIndex {
    live: HashSet<Pair>,
    latest_expiry: HashMap<Pair, DateTime<Utc>>,
}

impl State {
    /// Remove row `id`, with its hold: no hold outlives its row, so the same
    /// key subscribed again is judged afresh (MIK-8057).
    fn drop_row(&mut self, id: &str) {
        self.subs.remove(id);
        self.held.remove(id);
        self.hold_unsynced.remove(id);
    }

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

    /// Whether the pair holds a usable opt-in: a verification record held
    /// by a live subscription, or one whose tail has not run out.
    fn verified_usable(
        &self,
        principal: &str,
        url: &str,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> bool {
        let Some(record) = self.verified.get(&verified_file(principal, url)) else {
            return false;
        };
        if self.pair_live(principal, url, now) {
            return true;
        }
        let latest = self
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
    outbox_dir: PathBuf,
    dead_dir: PathBuf,
    state: Mutex<State>,
    /// Test-only: the next dead letter put in place reports its directory
    /// sync as failed, the one way a burial errors after the dead letter is
    /// in memory.
    #[cfg(test)]
    fail_next_dead_sync: std::sync::atomic::AtomicBool,
}

impl Store {
    /// Open (creating) the store at `root`, sweeping expired subscriptions
    /// and trimming the verification tail.
    pub(crate) fn open(root: &Path, now: DateTime<Utc>, tail: TailPolicy) -> std::io::Result<Self> {
        let subs_dir = root.join("subs");
        let verified_dir = root.join("verified");
        let outbox_dir = root.join("outbox");
        let dead_dir = root.join("dead");
        create_private_dir(root)?;
        for dir in [&subs_dir, &verified_dir, &outbox_dir, &dead_dir] {
            create_private_dir(dir)?;
        }
        let mut state = State::default();
        for (_, sub) in load_records::<Subscription>(&subs_dir) {
            state.subs.insert(sub.id.clone(), sub);
        }
        for (path, record) in load_records::<Verified>(&verified_dir) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                state.verified.insert(name.to_owned(), record);
            }
        }
        pending::load(&mut state, &outbox_dir, &dead_dir, now)?;
        let store = Self {
            subs_dir,
            verified_dir,
            outbox_dir,
            dead_dir,
            state: Mutex::new(state),
            #[cfg(test)]
            fail_next_dead_sync: std::sync::atomic::AtomicBool::new(false),
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
            let placed = write_record(&self.verified_dir, &key, &record)?;
            state.verified.insert(key, record);
            placed.durable()?;
        }
        for id in expired {
            // Its pending records go with it: a later subscribe of the same
            // key re-creates this id, and must not inherit them.
            self.cancel_pending(state, &id)?;
            remove_record(&self.subs_dir, &format!("{id}.json"))?;
            state.drop_row(&id);
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
        self.state.lock().verified_usable(principal, url, now, tail)
    }

    /// Cap check, rotation and commit as one step under the store lock,
    /// after sweeping what has expired: two admissions cannot both pass a
    /// cap that only one fits under, and two rotations of one key cannot
    /// both rotate from the same old row. A refresh of a live key is never
    /// capped. `verified_now` stamps a fresh opt-in. The verification is
    /// written before the subscription, so a failed commit never leaves a
    /// subscription without a durable opt-in. Answers the committed expiry
    /// with the admission, read under the same lock. The sweep, the tail cap, the
    /// opt-in read and the expiry all use one instant, taken under the lock:
    /// the later of `now` and the clock, since the commit can wait on a
    /// challenge, the lifecycle lock and a blocking thread.
    pub(crate) fn admit_granted(
        &self,
        mut sub: Subscription,
        grant: Grant,
        verified_now: bool,
        (caps, grace, tail): (Caps, chrono::Duration, TailPolicy),
        now: DateTime<Utc>,
        hold: HoldCommit,
    ) -> std::io::Result<Result<Admitted, CapHit>> {
        let mut state = self.state.lock();
        let at = Utc::now().max(now);
        self.sweep(&mut state, at)?;
        if hold == HoldCommit::Keep {
            let Some(old) = state.subs.get(&sub.id).filter(|s| s.live(at)) else {
                return Ok(Err(CapHit::HeldRowGone));
            };
            sub.payload_fields.clone_from(&old.payload_fields);
            sub.unoffered_since = old.unoffered_since;
            sub.held_until = old.held_until;
        }
        // A tail over the cap in force is gone before it can vouch.
        self.trim_tails(&mut state, at, tail)?;
        sub.granted_at = at;
        sub.expires_at = grant.expires_at(at);
        // Read under the lock with the commit, so racing identical subscribes
        // cannot both read as the first.
        let refreshed = state.subs.contains_key(&sub.id);
        if let Some(old) = state.subs.get(&sub.id) {
            if old.secret == sub.secret {
                sub.previous_secret.clone_from(&old.previous_secret);
                sub.previous_until = old.previous_until;
            } else {
                sub.previous_secret = Some(old.secret.clone());
                sub.previous_until = Some(at + grace);
            }
            sub.failed_since = old.failed_since;
            sub.last_delivery_at = old.last_delivery_at;
            sub.last_error.clone_from(&old.last_error);
        } else {
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
        if !verified_now && !state.verified_usable(&sub.principal, &sub.url, at, tail) {
            return Ok(Err(CapHit::Unverified));
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
                verified_at: at,
                last_subscription_ended_at: None,
            },
        };
        let prior = state.verified.get(&key).cloned();
        let verified_placed = write_record(&self.verified_dir, &key, &record)?;
        state.verified.insert(key.clone(), record);
        if let Placed::NotSynced(error) = verified_placed {
            return Err(error);
        }
        let name = format!("{}.json", sub.id);
        let placed = match write_record(&self.subs_dir, &name, &sub) {
            Ok(placed) => placed,
            Err(error) => {
                // Not put in place (the previous row, if any, is intact): put
                // the verification back as it was, so a failed commit neither
                // leaves an extra record nor resets a tail.
                // Memory follows the disk: it changes only where the
                // restore reached it.
                let restored = if let Some(prior) = prior {
                    write_record(&self.verified_dir, &key, &prior).map(|_| {
                        state.verified.insert(key, prior);
                    })
                } else {
                    remove_record(&self.verified_dir, &key).map(|()| {
                        state.verified.remove(&key);
                    })
                };
                if let Err(restore) = restored {
                    tracing::warn!(%restore, "events store: verification rollback failed");
                }
                return Err(error);
            }
        };
        // In place: memory follows the disk even when the directory sync
        // failed, and that failure is then reported.
        let expires_at = sub.expires_at;
        if hold == HoldCommit::End {
            state.held.remove(&sub.id);
            state.hold_unsynced.remove(&sub.id);
        }
        state.subs.insert(sub.id.clone(), sub);
        placed.durable()?;
        self.trim_tails(&mut state, at, tail)?;
        let admission = if refreshed {
            Admission::Refreshed
        } else {
            Admission::Inserted
        };
        Ok(Ok((admission, expires_at)))
    }

    /// [`Self::admit_granted`] with the expiry the row already carries.
    #[cfg(test)]
    pub(crate) fn admit(
        &self,
        sub: Subscription,
        verified_now: bool,
        caps: Caps,
        grace: chrono::Duration,
        now: DateTime<Utc>,
        tail: TailPolicy,
    ) -> std::io::Result<Result<Admission, CapHit>> {
        let grant = Grant {
            ttl: None,
            until: sub.expires_at,
        };
        let policy = (caps, grace, tail);
        self.admit_granted(sub, grant, verified_now, policy, now, HoldCommit::End)
            .map(|admitted| admitted.map(|(admission, _)| admission))
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
        self.remove_where(id, now, tail, |_| true)
    }

    /// Delete subscription `id` when `still` holds for the stored row under
    /// the store lock: a revocation decided on an earlier snapshot never
    /// deletes a row a concurrent refresh has re-bound to another credential.
    pub(crate) fn remove_where(
        &self,
        id: &str,
        now: DateTime<Utc>,
        tail: TailPolicy,
        still: impl FnOnce(&Subscription) -> bool,
    ) -> std::io::Result<bool> {
        let mut state = self.state.lock();
        self.sweep(&mut state, now)?;
        let Some(sub) = state.subs.get(id).cloned().filter(|s| still(s)) else {
            self.trim_tails(&mut state, now, tail)?;
            return Ok(false);
        };
        // Cancelled in the same hold of the lock: no attempt can start for
        // this subscription once the removal returns (design §6.4).
        self.cancel_pending(&mut state, id)?;
        remove_record(&self.subs_dir, &format!("{id}.json"))?;
        state.drop_row(id);
        if !state.pair_live(&sub.principal, &sub.url, now) {
            let key = verified_file(&sub.principal, &sub.url);
            if let Some(mut record) = state.verified.get(&key).cloned() {
                record.last_subscription_ended_at = Some(now);
                let placed = write_record(&self.verified_dir, &key, &record)?;
                state.verified.insert(key, record);
                placed.durable()?;
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
        // Two passes, oldest first: expiry and each principal's own cap
        // before the global cap, so one principal's churn evicts its own
        // records before anyone else's.
        let mut evict: Vec<String> = Vec::new();
        let mut kept: Vec<&String> = Vec::new();
        for (ended, key, principal) in &tails {
            let count = per_principal.get_mut(principal).expect("counted above");
            if now - *ended >= ttl || *count > tail.max_per_principal {
                evict.push(key.clone());
                *count -= 1;
            } else {
                kept.push(key);
            }
        }
        let over = kept.len().saturating_sub(tail.max);
        evict.extend(kept.into_iter().take(over).cloned());
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
