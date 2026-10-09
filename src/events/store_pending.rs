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
use crate::events::records::{Subscription, remove_record, remove_record_durable, write_record};

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
        self.enqueue_locked(&mut state, record, caps)
    }

    fn enqueue_locked(
        &self,
        state: &mut State,
        record: OutboxRecord,
        caps: OutboxCaps,
    ) -> std::io::Result<Enqueued> {
        // An expired row kept for its burials takes no new record, so the
        // worker can always settle it (MIK-8061); nor does a held one: what
        // it filters on or relies on is not served now (MIK-8057, MIK-8076).
        if !state
            .subs
            .get(&record.subscription_id)
            // A clock before 1970 reads no lease live (MIK-8202).
            .is_some_and(Subscription::live_now)
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

    #[cfg_attr(
        not(feature = "webui"),
        allow(
            dead_code,
            reason = "dead-letter administration is served by the web UI router"
        )
    )]
    /// Every dead letter's metadata, oldest first: never a body, so a full
    /// directory is listed without copying it.
    pub(crate) fn dead_summaries(&self) -> Vec<DeadSummary> {
        let state = self.state.lock();
        let mut all: Vec<DeadSummary> = state
            .dead
            .values()
            .map(|(d, size)| DeadSummary {
                event_id: d.record.event_id.clone(),
                subscription_id: d.record.subscription_id.clone(),
                name: d.record.name.clone(),
                reason: d.reason.clone(),
                dead_at: d.dead_at,
                size: *size,
                attempts: d.record.attempt,
            })
            .collect();
        all.sort_by(|a, b| (a.dead_at, &a.event_id).cmp(&(b.dead_at, &b.event_id)));
        all
    }

    #[cfg_attr(
        not(feature = "webui"),
        allow(
            dead_code,
            reason = "dead-letter administration is served by the web UI router"
        )
    )]
    /// Dead letter `event_id`, body included.
    pub(crate) fn dead_letter_by_id(&self, event_id: &str) -> Option<DeadLetter> {
        self.state.lock().dead.get(event_id).map(|(d, _)| d.clone())
    }

    #[cfg_attr(
        not(feature = "webui"),
        allow(
            dead_code,
            reason = "dead-letter administration is served by the web UI router"
        )
    )]
    /// Move dead letter `event_id` back to the outbox as `record` (the same
    /// event id and fan-out stamp, a fresh attempt count), in one locked step: the dead letter
    /// leaves `dead/` only once the record is placed. `dead_at` names the
    /// dead letter the caller scanned, so one buried again meanwhile is not
    /// replayed on the old verdict.
    pub(crate) fn revive(
        &self,
        event_id: &str,
        dead_at: DateTime<Utc>,
        record: OutboxRecord,
        caps: OutboxCaps,
        clock: impl FnOnce() -> Result<DateTime<Utc>, crate::clock::ClockBeforeEpoch>,
    ) -> std::io::Result<Revived> {
        let mut state = self.state.lock();
        // Read under the lock: an expiry that lands while this waits counts.
        // A clock before 1970 dates no lease: nothing is revived (MIK-8202).
        let Ok(now) = clock() else {
            return Ok(Revived::NoSubscription);
        };
        let Some(stamp) = state
            .dead
            .get(event_id)
            .filter(|(dead, _)| dead.dead_at == dead_at)
            .map(|(dead, _)| dead.record.created_at)
        else {
            return Ok(Revived::Missing);
        };
        // The occurrence's own fan-out stamp: should a crash leave this record
        // and its dead letter both on disk, `load` reads them as one settled
        // occurrence and keeps only the dead letter.
        // Marked replayed here, whoever replays it: at its subscription's
        // expiry it is buried, never dropped (MIK-8061).
        let record = OutboxRecord {
            created_at: stamp,
            replayed: true,
            ..record
        };
        match state.subs.get(&record.subscription_id) {
            // An expired subscription takes nothing, even before its sweep.
            Some(sub) if sub.live(now) => {
                // Suspended: never attempted, and dropped unburied should it
                // expire unrefreshed, so the dead letter stays.
                if !sub.active {
                    return Ok(Revived::Suspended);
                }
            }
            _ => return Ok(Revived::NoSubscription),
        }
        // The same occurrence is already pending: nothing to place, and the
        // dead letter is not dropped for a record that is not the replay.
        if state.outbox.contains_key(event_id) {
            return Ok(Revived::AlreadyPending);
        }
        let placed = self.enqueue_locked(&mut state, record, caps);
        match placed {
            Ok(Enqueued::Written) => {}
            Ok(Enqueued::NoSubscription) => return Ok(Revived::NoSubscription),
            Ok(Enqueued::DroppedGlobal | Enqueued::DroppedPerSubscription) => {
                return Ok(Revived::Full);
            }
            // Placed but not durable: roll it back, so a crash cannot lose
            // both copies. The dead letter stands.
            Err(error) => {
                if state.outbox.remove(event_id).is_some() {
                    let _ = remove_record(&self.outbox_dir, &OutboxRecord::file(event_id));
                }
                return Err(error);
            }
        }
        // The dead file must be unlinked before the replay counts: if it
        // cannot be, the new record is rolled back so one of the two stands.
        // A sync failure after the unlink is logged, never undone.
        // A failed rollback unlink leaves a stray outbox file; it carries the
        // dead letter's stamp, so `load` drops it on the next start.
        if let Err(error) = remove_record(&self.dead_dir, &OutboxRecord::file(event_id)) {
            state.outbox.remove(event_id);
            let _ = remove_record(&self.outbox_dir, &OutboxRecord::file(event_id));
            return Err(error);
        }
        state.dead.remove(event_id);
        Ok(Revived::Written)
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
        created_at: DateTime<Utc>,
        outcome: Settle,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Settled> {
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
        if settled.is_err() {
            // The claimed occurrence's own stamp: a dead letter left under the
            // same id by an earlier occurrence is not this burial. Reached when
            // the dead letter is in place but its directory sync failed.
            let buried = state
                .dead
                .get(event_id)
                .is_some_and(|(dead, _)| dead.record.created_at == created_at);
            if buried {
                // The dead letter is in place, if unsynced: never resend. The
                // burial happened, so its receipt stands: only the cleanup after
                // it failed, and that is logged, not allowed to hide the burial.
                state.outbox.remove(event_id);
                if let Err(error) = &settled {
                    tracing::warn!(%error, "events store: cleanup after a burial failed");
                }
                settled = Ok(Settled {
                    evicted: Vec::new(),
                    buried: true,
                });
            } else if let Some(left) = state.outbox.get_mut(event_id) {
                left.state = OutboxState::Pending;
                left.next_attempt_at = now + SETTLE_RETRY;
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
        let (delivered, error) = match outcome {
            Settle::Delivered => (true, None),
            Settle::Retry { status, .. }
            | Settle::Unsent { status, .. }
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

    /// Dead-letter a record that never entered the outbox (fan-out refusals:
    /// oversize, firewall block).
    pub(crate) fn dead_letter(
        &self,
        record: OutboxRecord,
        reason: DeadReason,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Settled> {
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
        let mut evicted = Vec::new();
        match self.evict_dead(&mut state, now, policy, &mut evicted) {
            Ok(()) => Ok(evicted),
            // What was evicted before the failure is gone: its receipts are
            // returned, and the next sweep retries the rest.
            Err(error) if !evicted.is_empty() => {
                tracing::warn!(%error, "events store: eviction stopped early");
                Ok(evicted)
            }
            Err(error) => Err(error),
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

    /// Move `record` into `dead/`, then apply retention and the caps.
    fn bury(
        &self,
        state: &mut State,
        record: OutboxRecord,
        reason: DeadReason,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> std::io::Result<Settled> {
        let (event_id, created_at) = (record.event_id.clone(), record.created_at);
        if let Err(error) = self.entomb(state, record, reason, now) {
            // In place but unsynced is still a burial: its receipt stands.
            let in_place = state
                .dead
                .get(&event_id)
                .is_some_and(|(dead, _)| dead.record.created_at == created_at);
            if !in_place {
                return Err(error);
            }
            tracing::warn!(%error, "events store: dead letter written but not synced");
        }
        // The dead letter is written: a failed eviction after it is logged and
        // the burial's receipt still stands.
        let mut evicted = Vec::new();
        if let Err(error) = self.evict_dead(state, now, policy, &mut evicted) {
            tracing::warn!(%error, "events store: eviction after a burial failed");
        }
        Ok(Settled {
            evicted,
            buried: true,
        })
    }

    /// Write `record` into `dead/`.
    fn entomb(
        &self,
        state: &mut State,
        mut record: OutboxRecord,
        reason: DeadReason,
        now: DateTime<Utc>,
    ) -> std::io::Result<()> {
        record.state = OutboxState::Pending;
        record.dead_as = None;
        let dead = DeadLetter {
            record,
            reason: reason.as_str().to_owned(),
            dead_at: now,
        };
        let id = dead.record.event_id.clone();
        let placed = write_record(&self.dead_dir, &OutboxRecord::file(&id), &dead)?;
        #[cfg(test)]
        let placed = if self
            .fail_next_dead_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            crate::events::records::Placed::NotSynced(std::io::Error::other("injected"))
        } else {
            placed
        };
        let size = dead_size(&dead);
        state.dead.insert(id, (dead, size));
        placed.durable()
    }

    /// Drop dead letters past retention, then the oldest beyond the count
    /// and byte caps, pushing each onto `evicted` as it goes: a failure part
    /// way leaves the completed evictions in `evicted` for their receipts.
    fn evict_dead(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
        policy: DeadPolicy,
        evicted: &mut Vec<Evicted>,
    ) -> std::io::Result<()> {
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
        for (dead_at, id, size) in by_age {
            let expired = now - dead_at >= retention;
            if !expired && count <= policy.max_records && bytes <= policy.max_bytes {
                break;
            }
            // An expiry burial not yet durable keeps its outbox copy: its dead
            // letter is not evicted before the burial completes and is
            // receipted (MIK-8061).
            let unfinished = state.dead.get(&id).is_some_and(|(dead, _)| {
                state
                    .outbox
                    .get(&id)
                    .is_some_and(|r| r.created_at == dead.record.created_at)
            });
            if unfinished {
                continue;
            }
            // The dead letter is the marker that keeps an outbox copy left by
            // a failed unlink from being sent again: that copy goes first,
            // unless the outbox holds a later occurrence under the same id.
            if !state.outbox.contains_key(&id) {
                remove_record_durable(&self.outbox_dir, &OutboxRecord::file(&id))?;
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
        Ok(())
    }
}

#[path = "store_expiry.rs"]
mod expiry;
pub(super) use expiry::load;

#[cfg(test)]
#[path = "store_pending_tests.rs"]
mod tests;
