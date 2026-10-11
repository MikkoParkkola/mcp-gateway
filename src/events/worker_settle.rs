// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How an attempt settles: refusals before the send, and the one place a
//! settlement reads the clock (MIK-8202).

use std::sync::Arc;

use super::{
    Clock, Ctx, OutboxRecord, SOURCE_UNAVAILABLE, Services, Settle, Verdict, clock_unsent,
    refusal_retry, unsent_later,
};
use crate::events::EventsHub;

impl EventsHub {
    /// A refusal that stands, before the attempt is on record: the attempt is
    /// recorded, the row revoked, and the record settled. Removed, the record
    /// went with it and this settles nothing. Not removed (a store error, a
    /// refresh re-bound the row, or a clock that failed at the revocation),
    /// the record goes back to pending, unsent; the refused attempt counts
    /// toward its bounds on a readable clock, and the next attempt re-checks.
    pub(super) async fn revoke_before_send(
        self: &Arc<Self>,
        services: &Services,
        ctx: &Ctx<'_>,
        sub: &crate::events::records::Subscription,
        record: &OutboxRecord,
    ) {
        if !self
            .recorded_or_retry(services, ctx, "access_revoked")
            .await
        {
            return;
        }
        self.revoke(sub).await;
        self.settle_with(services, record, |now| {
            refusal_retry("access_revoked", record, now)
        })
        .await;
    }

    /// Settle an attempt its source did not admit, before the attempt is on
    /// record; `true` when settled. An admission or a type no source offers
    /// goes on (MIK-8202).
    pub(super) async fn settled_by_source(
        self: &Arc<Self>,
        services: &Services,
        ctx: &Ctx<'_>,
        sub: &crate::events::records::Subscription,
        record: &OutboxRecord,
        verdict: Verdict,
    ) -> bool {
        match verdict {
            Verdict::Admits | Verdict::Unoffered => return false,
            Verdict::Refuses => self.revoke_before_send(services, ctx, sub, record).await,
            Verdict::Undated => self.settle(services, record, clock_unsent(record)).await,
            Verdict::Unavailable => {
                self.settle_with(services, record, |now| {
                    unsent_later(SOURCE_UNAVAILABLE, record, now)
                })
                .await;
            }
        }
        true
    }

    /// Settle the claimed occurrence `record`; a later occurrence that has
    /// since taken its event id is left alone.
    pub(super) async fn settle(&self, services: &Services, record: &OutboxRecord, outcome: Settle) {
        self.settle_with(services, record, |_| outcome).await;
    }

    /// [`Self::settle`] with an outcome built from the settle's one reading
    /// of the clock, the same reading the store dates the settlement by
    /// (MIK-8202).
    pub(super) async fn settle_with(
        &self,
        services: &Services,
        record: &OutboxRecord,
        outcome: impl FnOnce(Clock) -> Settle,
    ) {
        // Read on the attempt's own task, not the blocking pool.
        let now = crate::clock::utc_now();
        self.settle_at(services, record, outcome(now), now).await;
    }

    /// Settle with the caller's reading `now`; reads no clock.
    pub(super) async fn settle_at(
        &self,
        services: &Services,
        record: &OutboxRecord,
        outcome: Settle,
        now: Clock,
    ) {
        let (id, created_at, policy) = (
            record.event_id.clone(),
            record.created_at,
            self.dead_policy(),
        );
        // Only a burial evicts: it holds the receipt order from its store
        // call through its last receipt.
        let _ordered = match outcome {
            Settle::Dead { .. } => Some(self.receipts.lock().await),
            _ => None,
        };
        let settled = self
            .blocking(move |store| store.settle(&id, created_at, outcome, now, policy))
            .await;
        let (evicted, buried) = settled.map_or((Vec::new(), false), |s| (s.evicted, s.buried));
        #[cfg(test)]
        self.before_receipts.pause().await;
        // The burial's own receipt first: a cancelled occurrence settles
        // nothing, and one the caps evicted at once still happened.
        if let Settle::Dead { reason, .. } = outcome
            && buried
        {
            self.dead_lettered(services, record, reason).await;
        }
        services.audit_evictions(evicted).await;
    }
}
