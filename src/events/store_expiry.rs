// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Loading the outbox and dead letters at open, and settling the records of
//! expired subscriptions (MIK-8061).

use std::path::Path;

use chrono::{DateTime, Utc};

use super::super::{State, Store};
use super::dead_size;
use crate::events::outbox::{DeadLetter, DeadReason, OutboxRecord, OutboxState};
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
    /// Settle at most [`EXPIRY_BATCH`] records of expired rows (MIK-8061): a
    /// record that was replayed or tried is buried as `subscription_expired`,
    /// its outbox copy removed only once the dead letter is durable; one never
    /// tried is dropped; one in flight is left to settle. A row left with no
    /// record is removed, its tail stamped at its expiry. Answers the records
    /// buried, for their receipts.
    pub(super) fn expire_pending(
        &self,
        state: &mut State,
        now: DateTime<Utc>,
    ) -> std::io::Result<Vec<OutboxRecord>> {
        let mut expiring: Vec<OutboxRecord> = state
            .outbox
            .values()
            .filter(|r| r.state == OutboxState::Pending)
            .filter(|r| {
                state
                    .subs
                    .get(&r.subscription_id)
                    .is_some_and(|s| !s.live(now))
            })
            .cloned()
            .collect();
        expiring.sort_by(|a, b| (a.created_at, &a.event_id).cmp(&(b.created_at, &b.event_id)));
        expiring.truncate(EXPIRY_BATCH);
        let mut buried = Vec::new();
        for record in expiring {
            let id = record.event_id.clone();
            if record.needs_burial_at_expiry() {
                if let Err(error) = self.entomb(state, record.clone(), DeadReason::Expired, now) {
                    // Not durable: the outbox copy stays and the next tick
                    // buries it again; a record is never in neither place.
                    tracing::warn!(%error, "events store: an expiry burial is not durable yet");
                    continue;
                }
                buried.push(record);
            }
            remove_record(&self.outbox_dir, &OutboxRecord::file(&id))?;
            state.outbox.remove(&id);
        }
        let settled: Vec<String> = state
            .subs
            .values()
            .filter(|s| !s.live(now))
            .filter(|s| !state.outbox.values().any(|r| r.subscription_id == s.id))
            .map(|s| s.id.clone())
            .collect();
        for id in settled {
            self.remove_settled_row(state, &id, now)?;
        }
        Ok(buried)
    }
}
