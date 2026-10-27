// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How an attempt settles: refusals before the send, and the one place a
//! settlement reads the clock (MIK-8202).

use std::sync::Arc;

use super::{
    AccessVerdict, Attempt, CLOCK_UNREADABLE, Clock, Ctx, DeadReason, HELD, OutboxRecord,
    SOURCE_UNAVAILABLE, Services, Settle, Verdict, clock_unsent, grant, quiet_dead, refusal_retry,
    unsent_later, unsent_now,
};
use crate::events::EventsHub;

impl EventsHub {
    /// A refusal that stands, before the attempt is on record: the attempt is
    /// recorded, the row revoked, and the record settled. Removed, the record
    /// went with it and this settles nothing. Not removed (a store error, a
    /// refresh re-bound the row, or a clock that failed at the revocation),
    /// the record goes back to pending, not sent; on a readable clock the
    /// refused attempt counts toward its bounds, and the next attempt
    /// re-checks.
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

    /// Settle an attempt its source refused or could not date, before the
    /// attempt is on record; `true` when settled. An admission, a type no
    /// source offers and a source error go on to the bounds (MIK-8202).
    pub(super) async fn settled_by_source(
        self: &Arc<Self>,
        services: &Services,
        ctx: &Ctx<'_>,
        sub: &crate::events::records::Subscription,
        record: &OutboxRecord,
        verdict: Verdict,
    ) -> bool {
        match verdict {
            Verdict::Admits | Verdict::Unoffered | Verdict::Unavailable => return false,
            Verdict::Refuses => self.revoke_before_send(services, ctx, sub, record).await,
            Verdict::Undated => self.settle(services, record, clock_unsent(record)).await,
        }
        true
    }

    /// The access re-check after the waits before the send (MIK-7907): the
    /// source's verdict read again, then the caller's admission. `true` when
    /// it settled the attempt.
    pub(super) async fn settled_by_recheck<'a>(
        self: &Arc<Self>,
        services: &Services,
        sub: &crate::events::records::Subscription,
        record: &OutboxRecord,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) -> bool {
        let admission = match self.source_verdict(sub).await {
            // Access is read again after the verdict's own wait (MIK-7907):
            // a grant lost meanwhile is refused like one lost before. It must
            // not yield: a reload landing inside it would follow the verdict
            // unseen. Its one await, `TokenStore::live_jti`, completes at
            // once in the only store there is (`InMemoryTokenStore`); a store
            // that waits needs the verdict read again after this check.
            Verdict::Admits => services.admission(sub, grant(record)).await,
            Verdict::Refuses => AccessVerdict::Refuses,
            Verdict::Undated => AccessVerdict::Undated,
            Verdict::Unavailable => {
                services.audit_outcome(&ended(SOURCE_UNAVAILABLE)).await;
                self.settle_with(services, record, |now| {
                    unsent_later(SOURCE_UNAVAILABLE, record, now)
                })
                .await;
                return true;
            }
            Verdict::Unoffered => {
                services.audit_outcome(&ended(HELD)).await;
                self.settle_with(services, record, |now| refusal_retry(HELD, record, now))
                    .await;
                return true;
            }
        };
        match admission {
            AccessVerdict::Admits => {}
            // The refusal may be the clock's: kept, unsent (MIK-8202).
            AccessVerdict::Undated => {
                services.audit_outcome(&ended(CLOCK_UNREADABLE)).await;
                self.settle(services, record, clock_unsent(record)).await;
                return true;
            }
            AccessVerdict::Refuses => {
                services.audit_outcome(&ended("access_revoked")).await;
                self.revoke(sub).await;
                self.settle_with(services, record, |now| {
                    refusal_retry("access_revoked", record, now)
                })
                .await;
                return true;
            }
        }
        false
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

    /// Settle a record that cannot go out after the waits before its send:
    /// past its lease it is unsent; past its bounds it is dead and unsent; on
    /// a clock that cannot be read it is neither sent nor buried. The record just written says
    /// how that attempt ended. `true` when settled here.
    pub(super) async fn settled_unsendable<'a>(
        &self,
        services: &Services,
        record: &OutboxRecord,
        current: &crate::events::records::Subscription,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) -> bool {
        #[cfg(test)]
        self.before_window.pause().await;
        // One reading judges the lease and the retry window.
        let Ok(now) = crate::clock::utc_now() else {
            services.audit_outcome(&ended(CLOCK_UNREADABLE)).await;
            self.settle(services, record, clock_unsent(record)).await;
            return true;
        };
        // An expired row kept for its burials still signs but is not sent
        // to: unsent, and the next expiry pass settles it.
        if !current.live(now) {
            services.audit_outcome(&ended("subscription_expired")).await;
            self.settle_with(services, record, |now| {
                unsent_now("subscription_expired", record, now)
            })
            .await;
            return true;
        }
        // After every wait, the row must still be observed as
        // it was at fan-out (same grant, identity config and lease); nothing
        // awaits between this and the send. A shared row compares `None`.
        if self.observed_now(current, &services.live.get()) != Ok(record.observed.clone()) {
            services.audit_outcome(&ended("observation_changed")).await;
            self.settle(services, record, quiet_dead(DeadReason::Observation))
                .await;
            return true;
        }
        if !self.overdue(record, now) {
            return false;
        }
        services.audit_outcome(&ended("exhausted")).await;
        self.settle(services, record, quiet_dead(DeadReason::Exhausted))
            .await;
        true
    }
}
