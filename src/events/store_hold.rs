// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Held webhook subscriptions (MIK-8057, MIK-8076): no read of the
//! capability catalogue deletes one. A subscription the routes do not offer,
//! or cannot serve, is held: it takes no record, its queued records drain,
//! it resumes when the routes serve it again, and it ends at its lease or at
//! `held_until`, whichever is first.

use chrono::{DateTime, Utc};

use super::{State, Store};
use crate::events::records::{Subscription, write_record};

/// Why a subscription is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    /// What the subscriber is told.
    pub reason: &'static str,
    /// The filter key or payload field the route no longer serves; `None`
    /// when the type is not offered at all.
    pub key: Option<String>,
}

/// One held type in the admin listing: its name, its row count, and the
/// earliest and latest end among them.
pub(crate) type HeldType = (String, usize, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// What a route refresh decided for one stored subscription.
#[derive(Debug, Default)]
pub(crate) struct Judged {
    pub held: Option<Held>,
    /// The payload fields to record for a row that has none yet (a row
    /// written before MIK-8076): its type's fields now.
    pub backfill: Option<Vec<String>>,
}

impl Store {
    /// Under the catalogue gate the caller holds: replace the held set with
    /// what `judge` decides for every live row, stamp a row that becomes
    /// held (`unoffered_since` now, `held_until` now plus `max_ttl`), clear
    /// the stamp of one that resumes, and back-fill payload fields. A row past
    /// its effective expiry is left to the expiry path, never resumed. The
    /// held set is in place even when a stamp write fails; the next refresh
    /// writes it again.
    pub(crate) fn apply_holds(
        &self,
        judge: &dyn Fn(&Subscription) -> Judged,
        now: DateTime<Utc>,
        max_ttl: chrono::Duration,
    ) -> std::io::Result<()> {
        let mut state = self.state.lock();
        let mut held = std::collections::HashMap::new();
        let mut changed = Vec::new();
        for sub in state.subs.values().filter(|s| s.live(now)) {
            let judged = judge(sub);
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
                held.insert(row.id.clone(), why);
            } else {
                row.unoffered_since = None;
                row.held_until = None;
            }
            if row.payload_fields != sub.payload_fields
                || row.unoffered_since != sub.unoffered_since
                || row.held_until != sub.held_until
                || state.hold_unsynced.contains(&row.id)
            {
                changed.push(row);
            }
        }
        state.held = held;
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

    /// Why subscription `id` is held, if it is.
    pub(crate) fn held(&self, id: &str) -> Option<Held> {
        self.state.lock().held.get(id).cloned()
    }

    /// End the hold of `id`: its row was just checked against the routes
    /// at a commit, under the catalogue gate, and they serve it.
    pub(crate) fn clear_hold(&self, id: &str) {
        self.state.lock().held.remove(id);
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
    /// latest end, for the admin listing.
    pub(crate) fn held_listing(&self) -> Vec<HeldType> {
        let state = self.state.lock();
        let mut types = std::collections::BTreeMap::<
            String,
            (usize, Option<DateTime<Utc>>, Option<DateTime<Utc>>),
        >::new();
        for id in state.held.keys() {
            let Some(sub) = state.subs.get(id) else {
                continue;
            };
            let end = sub.effective_expiry();
            let entry = types.entry(sub.name.clone()).or_default();
            entry.0 += 1;
            entry.1 = match (entry.1, end) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            entry.2 = match (entry.2, end) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        types
            .into_iter()
            .map(|(name, (n, lo, hi))| (name, n, lo, hi))
            .collect()
    }
}
