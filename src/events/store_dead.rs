// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dead letters inside the store (design §5): the admin listing, replay,
//! and burial with its retention and caps, under the same lock as the outbox.

use chrono::{DateTime, Utc};

use super::super::{State, Store};
use super::{DeadSummary, Revived, Settled, dead_size};
use crate::events::outbox::{
    DeadLetter, DeadPolicy, DeadReason, Enqueued, Evicted, OutboxCaps, OutboxRecord, OutboxState,
};
use crate::events::records::{remove_record, remove_record_durable, write_record};

impl Store {
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
        // A clock before 1970 dates no lease: nothing is revived, and the
        // replay is refused as transient (MIK-8202).
        let Ok(now) = clock() else {
            return Ok(Revived::Undated);
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
        let placed = self.enqueue_locked(&mut state, record, caps, now);
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
            let in_place = state.buried_occurrence(&event_id, created_at);
            if !in_place {
                return Err(error);
            }
            tracing::warn!(
                // The pre-split module path, kept as the log target.
                target: "mcp_gateway::events::store::pending",
                %error,
                "events store: dead letter written but not synced"
            );
        }
        // The dead letter is written: a failed eviction after it is logged and
        // the burial's receipt still stands.
        let mut evicted = Vec::new();
        if let Err(error) = self.evict_dead(state, now, policy, &mut evicted) {
            tracing::warn!(
                // The pre-split module path, kept as the log target.
                target: "mcp_gateway::events::store::pending",
                %error,
                "events store: eviction after a burial failed"
            );
        }
        Ok(Settled {
            evicted,
            buried: true,
        })
    }

    /// Write `record` into `dead/`.
    pub(super) fn entomb(
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
    pub(super) fn evict_dead(
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
