// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Loading the outbox and dead letters at open, and settling the records of
//! expired subscriptions (MIK-8061).

use std::path::Path;

use chrono::{DateTime, Utc};

use super::super::{State, Store};
use super::dead_size;
use crate::events::outbox::{
    DeadLetter, DeadPolicy, DeadReason, Evicted, OutboxRecord, OutboxState, callback_host_of,
};
use crate::events::records::{load_records, remove_record, write_record};

/// The most expired-row records one `due` call settles: the worker holds the
/// receipt order across them, so a large expired subscription is settled
/// over several ticks rather than in one long hold.
const EXPIRY_BATCH: usize = 64;

/// Load `dead/` and `outbox/` into `state`. A record left `in_flight` by a
/// crash returns to `pending`, due now, with its id and bytes unchanged (F1).
/// An outbox record whose dead letter is already written was settled before
/// the crash: it is removed, never sent again.
pub(in crate::events::store) fn load(
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
    // An outbox copy beside its dead letter is dropped below: the dead
    // letters' directory entries are made durable first, or the store does
    // not open and both copies stay, none loaded as sendable (MIK-8061).
    crate::events::records::sync_dir(dead_dir).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("events store: cannot sync {}: {error}", dead_dir.display()),
        )
    })?;
    for (_, mut record) in load_records::<OutboxRecord>(outbox_dir) {
        // The same occurrence, not a later one re-admitted under the same id
        // once the inbound dedupe window passed: its fan-out time matches.
        let settled = state
            .dead
            .get(&record.event_id)
            .is_some_and(|(dead, _)| dead.record.created_at == record.created_at);
        if settled {
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

impl Store {
    /// One tick's expiry settlement: this batch's burials, with the
    /// dead-letter caps applied after them as
    /// every burial applies them (a failed eviction is retried by the next
    /// sweep). Answers the burials, the evictions, and whether more expired
    /// records remain past this batch.
    pub(super) fn settle_expired(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
        policy: DeadPolicy,
    ) -> (Vec<OutboxRecord>, Vec<Evicted>, bool) {
        let (buried, more) = self.expire_pending(state, now);
        let mut evicted = Vec::new();
        if !buried.is_empty()
            && let Err(error) = self.evict_dead(state, now, policy, &mut evicted)
        {
            tracing::warn!(%error, "events store: eviction after an expiry burial failed");
        }
        (buried, evicted, more)
    }

    /// Settle at most [`EXPIRY_BATCH`] records of expired rows (MIK-8061): a
    /// record that was replayed or tried is buried as `subscription_expired`,
    /// its outbox copy removed only once the dead letter is durable; one never
    /// tried is dropped; one in flight is left to settle. A row left with no
    /// record is removed, its tail stamped at its expiry. Answers the records
    /// buried, for their receipts, and whether more remain past this batch.
    pub(super) fn expire_pending(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
    ) -> (Vec<OutboxRecord>, bool) {
        // The oldest batch by key first, then only those records cloned.
        let mut keys: Vec<(DateTime<Utc>, String)> = state
            .outbox
            .values()
            .filter(|r| r.state == OutboxState::Pending)
            .filter(|r| {
                state
                    .subs
                    .get(&r.subscription_id)
                    .is_some_and(|s| !s.live(now))
            })
            .map(|r| (r.created_at, r.event_id.clone()))
            .collect();
        keys.sort();
        let more = keys.len() > EXPIRY_BATCH;
        keys.truncate(EXPIRY_BATCH);
        let mut buried = Vec::new();
        let mut settled_any = false;
        for (_, id) in keys {
            let Some(mut record) = state.outbox.get(&id).cloned() else {
                continue;
            };
            // A record written before fan-out stamped its host takes it from
            // its row now: the row may be gone when the burial is receipted.
            if record.callback_host.is_empty()
                && let Some(sub) = state.subs.get(&record.subscription_id)
            {
                record.callback_host = callback_host_of(&sub.url);
            }
            let bury = record.needs_burial_at_expiry();
            let placed = bury.then(|| self.entomb(state, record.clone(), DeadReason::Expired, now));
            // Receipted once, as soon as its dead letter is in place, durable
            // or not, as every burial is: a restart before the copy is gone
            // then loses no receipt, and a retry adds none.
            let in_place = bury
                && state
                    .dead
                    .get(&id)
                    .is_some_and(|(dead, _)| dead.record.created_at == record.created_at);
            if in_place && state.expiry_receipted.insert(id.clone()) {
                buried.push(record.clone());
            }
            if let Some(Err(error)) = placed {
                // Not durable: the outbox copy stays and the next tick
                // buries it again; a record is never in neither place.
                tracing::warn!(%error, "events store: an expiry burial is not durable yet");
                continue;
            }
            if let Err(error) = remove_record(&self.outbox_dir, &OutboxRecord::file(&id)) {
                tracing::warn!(%error, "events store: an expired record's copy was not removed; retried next tick");
                break;
            }
            state.outbox.remove(&id);
            state.expiry_receipted.remove(&id);
            settled_any = true;
        }
        let settled: Vec<String> = state
            .subs
            .values()
            .filter(|s| !s.live(now))
            .filter(|s| !state.outbox.values().any(|r| r.subscription_id == s.id))
            .map(|s| s.id.clone())
            .collect();
        if !settled.is_empty()
            && let Err(error) = self.remove_settled_rows(state, &settled, now)
        {
            tracing::warn!(%error, "events store: a settled expired row was not removed; retried next tick");
        }
        // Due again at once only while batches make progress: a batch the
        // disk refuses waits for the next tick, never spins.
        (buried, more && settled_any)
    }
}
