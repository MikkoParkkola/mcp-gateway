// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Outbox and dead letters inside the store (design §5). They share the
//! subscription lock, so an unsubscribe and a worker's claim serialise: once
//! the unsubscribe commits, no attempt for that subscription can start, and
//! the unsubscribe answer waits out one already claimed.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use super::{State, Store};
use crate::events::outbox::{
    DeadLetter, DeadPolicy, DeadReason, Enqueued, Evicted, OutboxCaps, OutboxRecord, OutboxState,
};
use crate::events::records::{Subscription, remove_record, write_record};

/// How long a record whose settlement the disk refused waits to be tried
/// again.
const SETTLE_RETRY: chrono::TimeDelta = crate::duration_bound::delta!(seconds, 30);

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
    /// Retried after a claim that sent nothing (the audit log refused): it
    /// keeps its attempt number but does not count toward the attempt limit.
    Unsent {
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
    /// Records of expired rows buried by this call, for their receipts.
    pub buried: Vec<OutboxRecord>,
    /// Dead letters those burials evicted, receipted after them.
    pub evicted: Vec<Evicted>,
}

fn dead_size(dead: &DeadLetter) -> u64 {
    serde_json::to_vec_pretty(dead).map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX))
}

#[cfg_attr(
    not(feature = "webui"),
    allow(
        dead_code,
        reason = "dead-letter administration is served by the web UI router"
    )
)]
/// A dead letter without its body, for the admin listing.
#[derive(Debug, Clone)]
pub(crate) struct DeadSummary {
    pub event_id: String,
    pub subscription_id: String,
    pub name: String,
    pub reason: String,
    pub dead_at: DateTime<Utc>,
    pub size: u64,
    pub attempts: u32,
}

#[cfg_attr(
    not(feature = "webui"),
    allow(
        dead_code,
        reason = "dead-letter administration is served by the web UI router"
    )
)]
/// What [`Store::revive`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Revived {
    Written,
    /// The subscription is gone or expired.
    NoSubscription,
    /// The subscription is suspended until its subscriber refreshes it.
    Suspended,
    /// The outbox is at a cap.
    Full,
    /// The outbox already holds this event id.
    AlreadyPending,
    /// The dead letter was swept, evicted or replayed meanwhile.
    Missing,
    /// A clock before 1970 dated no lease: transient (MIK-8202).
    Undated,
}

/// Whether `sub` may be attempted at `now`.
fn sendable(sub: &Subscription, now: DateTime<Utc>) -> bool {
    sub.active && sub.live(now)
}

/// What a settlement or burial did, as one receipt taken under the store lock.
#[derive(Debug, Default)]
pub(crate) struct Settled {
    /// Dead letters the retention and caps then evicted.
    pub evicted: Vec<Evicted>,
    /// This call wrote the dead letter of the occurrence it was given, whether
    /// or not the caps evicted it a moment later.
    pub buried: bool,
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
        // The record's fan-out stamp is the one reading that matched it.
        let now = record.created_at;
        self.enqueue_locked(&mut state, record, caps, now)
    }

    fn enqueue_locked(
        &self,
        state: &mut State,
        record: OutboxRecord,
        caps: OutboxCaps,
        now: DateTime<Utc>,
    ) -> std::io::Result<Enqueued> {
        // An expired row kept for its burials takes no new record, so the
        // worker can always settle it (MIK-8061); nor does a held one: what
        // it filters on or relies on is not served now (MIK-8057, MIK-8076).
        if !state
            .subs
            .get(&record.subscription_id)
            // Judged on the caller's reading, never a second read (MIK-8202).
            .is_some_and(|sub| sub.live(now))
            || state.held.contains_key(&record.subscription_id)
        {
            return Ok(Enqueued::NoSubscription);
        }
        // The same occurrence offered twice keeps the record already
        // retrying or on the wire, attempt count and all. So does a later
        // occurrence re-admitted under the id while the first is held (past
        // the inbound dedupe window, as a suspension or an outage can hold it):
        // receivers dedupe on the event id, so it is coalesced, not sent.
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
    /// Records whose subscription is gone are cancelled here, and those of an
    /// expired one settled (`expire_pending`) under `policy`; a
    /// suspended subscription keeps its records.
    pub(crate) fn due(
        &self,
        now: DateTime<Utc>,
        busy: &HashSet<String>,
        policy: DeadPolicy,
    ) -> std::io::Result<Due> {
        let mut state = self.state.lock();
        // A record whose row is gone was left by an unsubscribe: dropped, as
        // the unsubscribe meant (design 9).
        let orphans: Vec<String> = state
            .outbox
            .values()
            .filter(|r| !state.subs.contains_key(&r.subscription_id))
            .map(|r| r.event_id.clone())
            .collect();
        for id in orphans {
            remove_record(&self.outbox_dir, &OutboxRecord::file(&id))?;
            state.outbox.remove(&id);
        }
        let (buried, evicted, more) = self.settle_expired(&mut state, now, policy);
        let mut first: HashMap<&str, &OutboxRecord> = HashMap::new();
        // Expired records left past this batch are due at once.
        let mut next: Option<DateTime<Utc>> = more.then_some(now);
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
        Ok(Due {
            ready,
            next,
            buried,
            evicted,
        })
    }

    /// Whether subscription `id` has a pending record due at `now`, one on
    /// the wire notwithstanding.
    pub(crate) fn has_due(&self, id: &str, now: DateTime<Utc>) -> bool {
        self.state.lock().outbox.values().any(|r| {
            r.subscription_id == id && r.state == OutboxState::Pending && r.next_attempt_at <= now
        })
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
        let synced = placed.durable();
        drop(state);
        if let Err(error) = synced {
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
    /// On a clock that cannot be read (MIK-8202) nothing is dated; a burial
    /// waits, pending with `dead_as`, for the next readable attempt.
    pub(crate) fn settle(
        &self,
        event_id: &str,
        created_at: DateTime<Utc>,
        outcome: Settle,
        now: Result<DateTime<Utc>, crate::clock::ClockBeforeEpoch>,
        policy: DeadPolicy,
    ) -> std::io::Result<Settled> {
        let now = now.ok();
        let mut state = self.state.lock();
        // Only the claimed occurrence: a later one under the same id, admitted
        // after the claim was cancelled, is not settled by the old answer.
        let Some(record) = state
            .outbox
            .get(event_id)
            .filter(|r| r.created_at == created_at)
            .cloned()
        else {
            return Ok(Settled::default());
        };
        let sub_id = record.subscription_id.clone();
        let mut settled = self.settle_record(&mut state, record, outcome, now, policy);
        // Logged once `state` is released.
        let mut burial_cleanup = None;
        if settled.is_err() {
            // The claimed occurrence's own stamp: a dead letter left under the
            // same id by an earlier occurrence is not this burial. Reached when
            // the dead letter is in place but its directory sync failed.
            let buried = state.buried_occurrence(event_id, created_at);
            if buried {
                // The dead letter is in place, if unsynced: never resend. The
                // burial happened, so its receipt stands: only the cleanup after
                // it failed, and that is logged, not allowed to hide the burial.
                state.outbox.remove(event_id);
                burial_cleanup = settled.err();
                settled = Ok(Settled {
                    evicted: Vec::new(),
                    buried: true,
                });
            } else if let Some(left) = state.outbox.get_mut(event_id) {
                left.state = OutboxState::Pending;
                // Undated, the record keeps its own date, never 1969.
                left.next_attempt_at = now.map_or(left.next_attempt_at, |n| n + SETTLE_RETRY);
                match outcome {
                    Settle::Dead { reason, .. } => left.dead_as = Some(reason),
                    // Still not a send: the refusal counts even if its write failed.
                    Settle::Unsent { .. } => left.unsent = left.unsent.saturating_add(1),
                    Settle::Delivered | Settle::Retry { .. } => {}
                }
                if matches!(outcome, Settle::Dead { .. } | Settle::Unsent { .. }) {
                    // Best effort now; the next claim writes it in any case.
                    let _ = write_record(&self.outbox_dir, &OutboxRecord::file(event_id), &*left);
                }
            }
        }
        let status_line = match outcome {
            Settle::Delivered => Some((true, None)),
            Settle::Retry { status, .. }
            | Settle::Unsent { status, .. }
            | Settle::Dead {
                status: Some(status),
                ..
            } => Some((false, Some(status))),
            Settle::Dead { status: None, .. } => None,
        };
        // The subscription's delivery history is a status line: a failed
        // write of it never undoes the settlement.
        let touched = status_line.map(|(delivered, error)| {
            self.touch(&mut state, &sub_id, |s| {
                if delivered && now.is_some() {
                    s.last_delivery_at = now;
                }
                s.last_error = error.map(str::to_owned);
            })
        });
        drop(state);
        if let Some(error) = burial_cleanup {
            tracing::warn!(%error, "events store: cleanup after a burial failed");
        }
        if let Some(Err(error)) = touched {
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
        now: Option<DateTime<Utc>>,
        policy: DeadPolicy,
    ) -> std::io::Result<Settled> {
        let event_id = record.event_id.clone();
        let file = OutboxRecord::file(&event_id);
        match outcome {
            Settle::Delivered => {
                remove_record(&self.outbox_dir, &file)?;
                state.outbox.remove(&event_id);
                Ok(Settled::default())
            }
            Settle::Retry { next, status } | Settle::Unsent { next, status } => {
                if matches!(outcome, Settle::Unsent { .. }) {
                    record.unsent = record.unsent.saturating_add(1);
                }
                record.state = OutboxState::Pending;
                record.next_attempt_at = next;
                record.last_status = Some(status.to_owned());
                write_record(&self.outbox_dir, &file, &record)?.durable()?;
                state.outbox.insert(event_id, record);
                Ok(Settled::default())
            }
            Settle::Dead { reason, status } => {
                if let Some(status) = status {
                    record.last_status = Some(status.to_owned());
                }
                let Some(now) = now else {
                    // No dead_at of 1969: the burial waits, pending with its
                    // reason and its date, for the next readable attempt.
                    record.state = OutboxState::Pending;
                    record.dead_as = Some(reason);
                    write_record(&self.outbox_dir, &file, &record)?.durable()?;
                    state.outbox.insert(event_id, record);
                    return Ok(Settled::default());
                };
                // Entombed first: once the dead letter is durable, load drops
                // the outbox file even if the unlink below never happens.
                // Eviction runs last, so it never removes that marker first.
                self.entomb(state, record, reason, now)?;
                state.outbox.remove(&event_id);
                // The dead letter is durable: a cleanup that fails after it is
                // logged, and the burial and every eviction already made keep
                // their receipts.
                let mut evicted = Vec::new();
                if let Err(error) = remove_record(&self.outbox_dir, &file)
                    .and_then(|()| self.evict_dead(state, now, policy, &mut evicted))
                {
                    tracing::warn!(%error, "events store: cleanup after a burial failed");
                }
                Ok(Settled {
                    evicted,
                    // Taken before the caps run: the burial happened even if
                    // they evict it at once.
                    buried: true,
                })
            }
        }
    }

    /// Suspend subscription `id` after sustained failure; its records stay
    /// pending until a refresh reactivates it.
    pub(crate) fn suspend(&self, id: &str) -> std::io::Result<()> {
        let mut state = self.state.lock();
        self.touch(&mut state, id, |s| s.active = false)
    }

    /// The subscription row to sign claimed `record` with, read now: `None`
    /// once the claim was cancelled (unsubscribe, revocation, expiry), even
    /// if a resubscribe has since re-created the same subscription id.
    pub(crate) fn signing_row(&self, record: &OutboxRecord) -> Option<Subscription> {
        let state = self.state.lock();
        let claimed = state
            .outbox
            .get(&record.event_id)
            .is_some_and(|r| r.state == OutboxState::InFlight && r.created_at == record.created_at);
        if claimed {
            state.subs.get(&record.subscription_id).cloned()
        } else {
            None
        }
    }

    /// The id of every subscription still live at `now`.
    pub(crate) fn live_subscription_ids(&self, now: DateTime<Utc>) -> HashSet<String> {
        self.state
            .lock()
            .subs
            .values()
            .filter(|s| s.live(now))
            .map(|s| s.id.clone())
            .collect()
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
        updated.generation = self.next_generation()?;
        let placed = write_record(&self.subs_dir, &format!("{id}.json"), &updated)?;
        state.subs.insert(id.to_owned(), updated);
        placed.durable()
    }
}

#[path = "store_dead.rs"]
mod dead;

#[path = "store_expiry.rs"]
mod expiry;
pub(super) use expiry::load;

#[cfg(test)]
#[path = "store_pending_tests.rs"]
mod tests;
