// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Outbox and dead letters inside the store (design §5). They share the
//! subscription lock, so an unsubscribe and a worker's claim serialise: once
//! the unsubscribe commits, no attempt for that subscription can start, and
//! the unsubscribe answer waits out one already claimed.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};

use super::{State, Store};
use crate::events::outbox::{
    DeadLetter, DeadPolicy, DeadReason, Enqueued, Evicted, OutboxCaps, OutboxRecord, OutboxState,
};
use crate::events::records::{Subscription, load_records, remove_record, write_record};

/// How long a record whose settlement the disk refused waits to be tried
/// again.
const SETTLE_RETRY: chrono::TimeDelta = chrono::TimeDelta::seconds(30);

/// A record the worker may now send, with the subscription as it is now.
pub(crate) struct Claimed {
    pub record: OutboxRecord,
    pub subscription: Subscription,
}

/// The answer to a claim.
pub(crate) enum Claim {
    Ready(Box<Claimed>),
    /// The record or its subscription is gone, or it is not sendable now.
    Skip,
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Settle {
    Delivered,
    Retry {
        next: DateTime<Utc>,
        status: &'static str,
    },
    Dead {
        reason: DeadReason,
        status: Option<&'static str>,
    },
}

/// Due records, one per subscription, and when the next one falls due.
pub(crate) struct Due {
    pub ready: Vec<OutboxRecord>,
    pub next: Option<DateTime<Utc>>,
}

/// Load `dead/` and `outbox/` into `state`. A record left `in_flight` by a
/// crash returns to `pending`, due now, with its id and bytes unchanged (F1).
/// An outbox record whose dead letter is already written was settled before
/// the crash: it is removed, never sent again.
pub(super) fn load(
    state: &mut State,
    outbox_dir: &Path,
    dead_dir: &Path,
    now: DateTime<Utc>,
) -> std::io::Result<()> {
    for (_, dead) in load_records::<DeadLetter>(dead_dir) {
        let size = dead_size(&dead);
        state
            .dead
            .insert(dead.record.event_id.clone(), (dead, size));
    }
    for (_, mut record) in load_records::<OutboxRecord>(outbox_dir) {
        if state.dead.contains_key(&record.event_id) {
            remove_record(outbox_dir, &OutboxRecord::file(&record.event_id))?;
            continue;
        }
        if record.state == OutboxState::InFlight {
            record.state = OutboxState::Pending;
            record.next_attempt_at = now;
            write_record(outbox_dir, &OutboxRecord::file(&record.event_id), &record)?.durable()?;
        }
        state.outbox.insert(record.event_id.clone(), record);
    }
    Ok(())
}

fn dead_size(dead: &DeadLetter) -> u64 {
    serde_json::to_vec_pretty(dead).map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX))
}

/// Whether `sub` may be attempted at `now`.
fn sendable(sub: &Subscription, now: DateTime<Utc>) -> bool {
    sub.active && sub.live(now)
}

impl Store {
    /// Write `record` unless a cap or a missing subscription refuses it.
    /// Pending records are never dropped to make room (F11).
    pub(crate) fn enqueue(
        &self,
        record: OutboxRecord,
        caps: OutboxCaps,
    ) -> std::io::Result<Enqueued> {
        let mut state = self.state.lock();
        if !state.subs.contains_key(&record.subscription_id) {
            return Ok(Enqueued::NoSubscription);
        }
        // The same occurrence offered twice keeps the record already
        // retrying or on the wire, attempt count and all.
        if state.outbox.contains_key(&record.event_id) {
            return Ok(Enqueued::Written);
        }
        if state.outbox.len() >= caps.global {
            return Ok(Enqueued::DroppedGlobal);
        }
        let mine = state
            .outbox
            .values()
            .filter(|r| r.subscription_id == record.subscription_id)
            .count();
        if mine >= caps.per_subscription {
            return Ok(Enqueued::DroppedPerSubscription);
        }
        let placed = write_record(
            &self.outbox_dir,
            &OutboxRecord::file(&record.event_id),
            &record,
        )?;
        state.outbox.insert(record.event_id.clone(), record);
        placed.durable()?;
        Ok(Enqueued::Written)
    }

    /// Due records, at most one per subscription not in `busy`, each the
    /// oldest due record of a subscription that may be attempted now.
    /// Records whose subscription is gone or expired are cancelled here; a
    /// suspended subscription keeps its records.
    pub(crate) fn due(&self, now: DateTime<Utc>, busy: &HashSet<String>) -> std::io::Result<Due> {
        let mut state = self.state.lock();
        let orphans: Vec<String> = state
            .outbox
            .values()
            .filter(|r| {
                !state
                    .subs
                    .get(&r.subscription_id)
                    .is_some_and(|s| s.live(now))
            })
            .map(|r| r.event_id.clone())
            .collect();
        for id in orphans {
            remove_record(&self.outbox_dir, &OutboxRecord::file(&id))?;
            state.outbox.remove(&id);
        }
        let mut first: HashMap<&str, &OutboxRecord> = HashMap::new();
        let mut next: Option<DateTime<Utc>> = None;
        for record in state.outbox.values() {
            let open = state
                .subs
                .get(&record.subscription_id)
                .is_some_and(|s| sendable(s, now));
            if !open
                || record.state != OutboxState::Pending
                || busy.contains(&record.subscription_id)
            {
                continue;
            }
            if record.next_attempt_at > now {
                next = Some(next.map_or(record.next_attempt_at, |n| n.min(record.next_attempt_at)));
                continue;
            }
            let slot = first.entry(&record.subscription_id).or_insert(record);
            if (record.created_at, &record.event_id) < (slot.created_at, &slot.event_id) {
                *slot = record;
            }
        }
        let mut ready: Vec<OutboxRecord> = first.into_values().cloned().collect();
        ready.sort_by(|a, b| {
            (a.next_attempt_at, &a.event_id).cmp(&(b.next_attempt_at, &b.event_id))
        });
        Ok(Due { ready, next })
    }

    /// Mark `event_id` in flight for one more attempt, if its subscription
    /// still exists and may be attempted. Persisted before the POST, so a
    /// crash retries the same attempt number at most once (F1).
    pub(crate) fn claim(&self, event_id: &str, now: DateTime<Utc>) -> std::io::Result<Claim> {
        let mut state = self.state.lock();
        let Some(record) = state.outbox.get(event_id) else {
            return Ok(Claim::Skip);
        };
        let Some(subscription) = state
            .subs
            .get(&record.subscription_id)
            .filter(|s| sendable(s, now))
            .cloned()
        else {
            return Ok(Claim::Skip);
        };
        if record.state != OutboxState::Pending {
            return Ok(Claim::Skip);
        }
        let mut record = record.clone();
        record.state = OutboxState::InFlight;
        record.attempt += 1;
        record.first_attempt_at.get_or_insert(now);
        let placed = write_record(&self.outbox_dir, &OutboxRecord::file(event_id), &record)?;
        state.outbox.insert(event_id.to_owned(), record.clone());
        // The claim is in place; an unsynced one can only mean one more
        // duplicate after a crash, so the attempt goes ahead (F1).
        if let Err(error) = placed.durable() {
            tracing::warn!(%error, "events store: claim not synced");
        }
        Ok(Claim::Ready(Box::new(Claimed {
            record,
            subscription,
        })))
    }

    /// Record how an attempt ended. A record cancelled while its POST was
    /// on the wire stays cancelled: nothing is written back for it. A
    /// settlement the disk refused leaves the record pending, due after
    /// [`SETTLE_RETRY`], never stranded in flight.
    pub(crate) fn settle(
        &self,
        event_id: &str,
        outcome: Settle,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        let mut state = self.state.lock();
        let Some(record) = state.outbox.get(event_id).cloned() else {
            return Ok(Vec::new());
        };
        let sub_id = record.subscription_id.clone();
        let settled = self.settle_record(&mut state, record, outcome, now, policy);
        if settled.is_err() {
            if state.dead.contains_key(event_id) {
                // The dead letter is in place, if unsynced: never resend.
                state.outbox.remove(event_id);
            } else if let Some(left) = state.outbox.get_mut(event_id) {
                left.state = OutboxState::Pending;
                left.next_attempt_at = now + SETTLE_RETRY;
            }
        }
        let (delivered, error) = match outcome {
            Settle::Delivered => (true, None),
            Settle::Retry { status, .. }
            | Settle::Dead {
                status: Some(status),
                ..
            } => (false, Some(status)),
            Settle::Dead { status: None, .. } => return settled,
        };
        // The subscription's delivery history is a status line: a failed
        // write of it never undoes the settlement.
        if let Err(error) = self.touch(&mut state, &sub_id, |s| {
            if delivered {
                s.last_delivery_at = Some(now);
            }
            s.last_error = error.map(str::to_owned);
        }) {
            tracing::warn!(%error, "events store: subscription status not written");
        }
        settled
    }

    /// Move `record` to its settled place: gone, pending again, or dead.
    /// Memory changes only once the disk has.
    fn settle_record(
        &self,
        state: &mut State,
        mut record: OutboxRecord,
        outcome: Settle,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        let event_id = record.event_id.clone();
        let file = OutboxRecord::file(&event_id);
        match outcome {
            Settle::Delivered => {
                remove_record(&self.outbox_dir, &file)?;
                state.outbox.remove(&event_id);
                Ok(Vec::new())
            }
            Settle::Retry { next, status } => {
                record.state = OutboxState::Pending;
                record.next_attempt_at = next;
                record.last_status = Some(status.to_owned());
                write_record(&self.outbox_dir, &file, &record)?.durable()?;
                state.outbox.insert(event_id, record);
                Ok(Vec::new())
            }
            Settle::Dead { reason, status } => {
                if let Some(status) = status {
                    record.last_status = Some(status.to_owned());
                }
                // Buried first: once the dead letter is durable, load drops
                // the outbox file even if the unlink below never happens.
                let evicted = self.bury(state, record, reason, now, policy)?;
                state.outbox.remove(&event_id);
                remove_record(&self.outbox_dir, &file)?;
                Ok(evicted)
            }
        }
    }

    /// Dead-letter a record that never entered the outbox (fan-out refusals:
    /// oversize, firewall block).
    pub(crate) fn dead_letter(
        &self,
        record: OutboxRecord,
        reason: DeadReason,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        let mut state = self.state.lock();
        self.bury(&mut state, record, reason, now, policy)
    }

    /// Apply retention and the dead-letter caps now.
    pub(crate) fn sweep_dead(
        &self,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        let mut state = self.state.lock();
        self.evict_dead(&mut state, now, policy)
    }

    /// Suspend subscription `id` after sustained failure; its records stay
    /// pending until a refresh reactivates it.
    pub(crate) fn suspend(&self, id: &str) -> std::io::Result<()> {
        let mut state = self.state.lock();
        self.touch(&mut state, id, |s| s.active = false)
    }

    /// The id of every stored subscription.
    pub(crate) fn subscription_ids(&self) -> HashSet<String> {
        self.state.lock().subs.keys().cloned().collect()
    }

    /// Every subscription, for fan-out matching.
    pub(crate) fn subscriptions(&self) -> Vec<Subscription> {
        self.state.lock().subs.values().cloned().collect()
    }

    /// Cancel every pending record of subscription `id` (unsubscribe,
    /// revocation), under the caller's hold of the lock.
    pub(super) fn cancel_pending(&self, state: &mut State, id: &str) -> std::io::Result<()> {
        let cancelled: Vec<String> = state
            .outbox
            .values()
            .filter(|r| r.subscription_id == id)
            .map(|r| r.event_id.clone())
            .collect();
        for event_id in cancelled {
            remove_record(&self.outbox_dir, &OutboxRecord::file(&event_id))?;
            state.outbox.remove(&event_id);
        }
        Ok(())
    }

    /// Apply `change` to subscription `id` and persist it when it changed.
    fn touch(
        &self,
        state: &mut State,
        id: &str,
        change: impl FnOnce(&mut Subscription),
    ) -> std::io::Result<()> {
        let Some(sub) = state.subs.get(id) else {
            return Ok(());
        };
        let mut updated = sub.clone();
        change(&mut updated);
        let same = updated.active == sub.active
            && updated.last_error == sub.last_error
            && updated.last_delivery_at == sub.last_delivery_at;
        if same {
            return Ok(());
        }
        let placed = write_record(&self.subs_dir, &format!("{id}.json"), &updated)?;
        state.subs.insert(id.to_owned(), updated);
        placed.durable()
    }

    /// Move `record` into `dead/`, then apply retention and the caps.
    fn bury(
        &self,
        state: &mut State,
        mut record: OutboxRecord,
        reason: DeadReason,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        record.state = OutboxState::Pending;
        let dead = DeadLetter {
            record,
            reason: reason.as_str().to_owned(),
            dead_at: now,
        };
        let id = dead.record.event_id.clone();
        let placed = write_record(&self.dead_dir, &OutboxRecord::file(&id), &dead)?;
        let size = dead_size(&dead);
        state.dead.insert(id, (dead, size));
        placed.durable()?;
        self.evict_dead(state, now, policy)
    }

    /// Drop dead letters past retention, then the oldest beyond the count
    /// and byte caps.
    fn evict_dead(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Vec<Evicted>> {
        let retention =
            chrono::Duration::from_std(policy.retention).unwrap_or(chrono::Duration::MAX);
        let mut by_age: Vec<(DateTime<Utc>, String, u64)> = state
            .dead
            .iter()
            .map(|(id, (d, size))| (d.dead_at, id.clone(), *size))
            .collect();
        by_age.sort();
        let mut count = by_age.len();
        let mut bytes: u64 = by_age.iter().map(|(_, _, s)| *s).sum();
        let mut evicted = Vec::new();
        for (dead_at, id, size) in by_age {
            let expired = now - dead_at >= retention;
            if !expired && count <= policy.max_records && bytes <= policy.max_bytes {
                break;
            }
            remove_record(&self.dead_dir, &OutboxRecord::file(&id))?;
            if let Some((dead, _)) = state.dead.remove(&id) {
                evicted.push(Evicted {
                    event_id: id,
                    subscription_id: dead.record.subscription_id,
                    reason: dead.reason,
                });
            }
            count -= 1;
            bytes = bytes.saturating_sub(size);
        }
        Ok(evicted)
    }
}

#[cfg(test)]
#[path = "store_pending_tests.rs"]
mod tests;
