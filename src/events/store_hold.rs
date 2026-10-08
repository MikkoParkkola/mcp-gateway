// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Held webhook subscriptions (MIK-8057, MIK-8076): no read of the
//! capability catalogue deletes one. A subscription the routes do not offer,
//! or cannot serve, is held: it takes no record, its queued records drain,
//! it resumes when the routes serve it again, and it ends at its lease or at
//! `held_until`, whichever is first.

use chrono::{DateTime, Utc};

use super::{State, Store};
use crate::events::records::{Subscription, WatchClass, write_record};

/// Why a subscription is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    /// What the subscriber is told.
    pub reason: &'static str,
    /// The filter key or payload field the route no longer serves; `None`
    /// when the type is not offered at all.
    pub key: Option<String>,
}

/// One held type in the admin listing (design-8057 r4): its rows held.
#[derive(Debug, Default)]
pub(crate) struct HeldType {
    pub name: String,
    pub count: usize,
    pub earliest_expiry: Option<DateTime<Utc>>,
    pub latest_expiry: Option<DateTime<Utc>>,
    /// Records still queued for them, draining.
    pub pending_records: usize,
}

/// What a route refresh decided for one stored subscription.
#[derive(Debug, Default)]
pub(crate) struct Judged {
    pub held: Option<Held>,
    /// The payload fields to record for a row that has none yet (a row
    /// written before MIK-8076): its type's fields now.
    pub backfill: Option<Vec<String>>,
}

impl Store {
    /// Apply what `judge` decides for each live row it owns (`Some`): hold
    /// it, stamping a row that becomes held (`unoffered_since` now,
    /// `held_until` now plus `max_ttl`), or resume it, clearing the stamp;
    /// and back-fill payload fields and the watch class. A row the judge
    /// does not own (`None`) keeps its hold state as it is: each source
    /// judges its own rows (MIK-8122). A row past its effective expiry is
    /// left to the expiry path, never resumed. The held set is in place even
    /// when a stamp write fails; the next judgement writes it again.
    pub(crate) fn apply_holds(
        &self,
        judge: &dyn Fn(&Subscription) -> Option<Judged>,
        now: DateTime<Utc>,
        max_ttl: chrono::Duration,
    ) -> std::io::Result<()> {
        let mut state = self.state.lock();
        let mut verdicts = Vec::new();
        let mut changed = Vec::new();
        for sub in state.subs.values().filter(|s| s.live(now)) {
            let Some(judged) = judge(sub) else {
                continue;
            };
            let mut row = sub.clone();
            if let Some(fields) = judged.backfill
                && row.payload_fields.is_empty()
            {
                row.payload_fields = fields;
            }
            if let Some(why) = judged.held {
                if row.unoffered_since.is_none() {
                    row.unoffered_since = Some(now);
                    row.held_until = Some(now + max_ttl);
                }
                verdicts.push((row.id.clone(), Some(why)));
            } else {
                row.unoffered_since = None;
                row.held_until = None;
                verdicts.push((row.id.clone(), None));
            }
            if row.payload_fields != sub.payload_fields
                || row.unoffered_since != sub.unoffered_since
                || row.held_until != sub.held_until
                || state.hold_unsynced.contains(&row.id)
            {
                changed.push(row);
            }
        }
        for (id, verdict) in verdicts {
            match verdict {
                Some(why) => state.held.insert(id, why),
                None => state.held.remove(&id),
            };
        }
        let mut first_error = None;
        for row in changed {
            if let Err(error) = self.persist_row(&mut state, row) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// In memory first, so the hold bounds the row on time even when the
    /// write fails; a failed write is retried by the next refresh.
    fn persist_row(&self, state: &mut State, row: Subscription) -> std::io::Result<()> {
        let id = row.id.clone();
        let written = write_record(&self.subs_dir, &format!("{id}.json"), &row)
            .and_then(crate::events::records::Placed::durable);
        state.subs.insert(id.clone(), row);
        if written.is_ok() {
            state.hold_unsynced.remove(&id);
        } else {
            state.hold_unsynced.insert(id);
        }
        written
    }

    /// Record `class` on every row of watch type `name` written before the
    /// class was recorded (MIK-8122). Hold state is left as it is.
    pub(crate) fn backfill_watch_class(
        &self,
        name: &str,
        class: WatchClass,
    ) -> std::io::Result<()> {
        let mut state = self.state.lock();
        let legacy: Vec<Subscription> = state
            .subs
            .values()
            .filter(|s| s.name == name && s.watch_class.is_none())
            .cloned()
            .collect();
        for mut row in legacy {
            row.watch_class = Some(class);
            self.persist_row(&mut state, row)?;
        }
        Ok(())
    }

    /// Why subscription `id` is held, if it is.
    pub(crate) fn held(&self, id: &str) -> Option<Held> {
        self.state.lock().held.get(id).cloned()
    }

    /// The event types of `principal`'s held subscriptions, sorted, with
    /// how many rows each.
    pub(crate) fn held_types_of(&self, principal: &str) -> Vec<(String, usize)> {
        let state = self.state.lock();
        let mut types = std::collections::BTreeMap::<String, usize>::new();
        for id in state.held.keys() {
            if let Some(sub) = state.subs.get(id).filter(|s| s.principal == principal) {
                *types.entry(sub.name.clone()).or_default() += 1;
            }
        }
        types.into_iter().collect()
    }

    /// Every held subscription's type, with its row count, earliest and
    /// latest end, and the records still queued for those rows.
    pub(crate) fn held_listing(&self) -> Vec<HeldType> {
        let state = self.state.lock();
        let mut types = std::collections::BTreeMap::<String, HeldType>::new();
        for id in state.held.keys() {
            let Some(sub) = state.subs.get(id) else {
                continue;
            };
            let end = sub.effective_expiry();
            let entry = types.entry(sub.name.clone()).or_insert_with(|| HeldType {
                name: sub.name.clone(),
                ..HeldType::default()
            });
            entry.count += 1;
            entry.earliest_expiry = either(entry.earliest_expiry, end, std::cmp::min);
            entry.latest_expiry = either(entry.latest_expiry, end, std::cmp::max);
        }
        for record in state.outbox.values() {
            let held_type = state
                .held
                .contains_key(&record.subscription_id)
                .then(|| state.subs.get(&record.subscription_id))
                .flatten()
                .and_then(|sub| types.get_mut(&sub.name));
            if let Some(entry) = held_type {
                entry.pending_records += 1;
            }
        }
        types.into_values().collect()
    }
}

/// `pick` of two ends when both are set, else whichever is.
fn either(
    a: Option<DateTime<Utc>>,
    b: Option<DateTime<Utc>>,
    pick: fn(DateTime<Utc>, DateTime<Utc>) -> DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(pick(a, b)),
        (a, b) => a.or(b),
    }
}
