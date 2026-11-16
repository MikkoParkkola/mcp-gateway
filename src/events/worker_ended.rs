// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An ended row's notice: the attempt path of the one
//! outbox record that reports a subscription's ending to its callback.

use std::sync::Arc;

use super::{
    Attempt, CLOCK_UNREADABLE, Ctx, DeadReason, OutboxRecord, SENDING, Services, Settle,
    clock_unsent, quiet_dead, unsent_now, wire_body,
};
use crate::events::EventsHub;
use crate::events::records::Subscription;
use crate::gateway::outbound::{OutboundFrame, Payload};

impl EventsHub {
    /// One attempt of an ended row's notice. None of a live row's checks
    /// apply: access, the source's verdict and its recheck, the vault fence,
    /// the reload gate, the budget and the tenant read verdict all judge a
    /// grant the ending already removed, and the body is the gateway's own
    /// (design Y' 4, Y'' 6). The retry policy, the audit-first record and the
    /// row read before the send stay: an unsubscribe that removed the ended
    /// row by then cancels the send. Its answer never counts toward
    /// suspending a live row under the same id. Three decisions read the
    /// clock, once each, as an event's attempt does: the bounds here, the
    /// signature's date in [`Self::send_ended`], the answer's judgement in
    /// [`Self::settle_ended`].
    pub(super) async fn attempt_ended(
        self: &Arc<Self>,
        services: &Services,
        record: &OutboxRecord,
        sub: &Subscription,
    ) {
        let url = url::Url::parse(&sub.url).ok();
        let ctx = Ctx {
            sub,
            record,
            event_id: &record.event_id,
            host: url
                .as_ref()
                .and_then(url::Url::host_str)
                .unwrap_or_default()
                .to_owned(),
        };
        if let Some(reason) = record.dead_as {
            self.settle(services, record, quiet_dead(reason)).await;
            return;
        }
        let Ok(now) = crate::clock::utc_now() else {
            self.settle(services, record, clock_unsent(record)).await;
            return;
        };
        if self.overdue(record, now) {
            if self.recorded_or_retry(services, &ctx, "exhausted").await {
                self.settle(services, record, quiet_dead(DeadReason::Exhausted))
                    .await;
            }
            return;
        }
        let wire = record.body().and_then(|body| wire_body(&body));
        let (Some(url), Some((value, body_sha256))) = (url, wire) else {
            self.settle(services, record, quiet_dead(DeadReason::Exhausted))
                .await;
            return;
        };
        let ended = |status: &'static str| Attempt {
            body_sha256: &body_sha256,
            ..ctx.attempt(status)
        };
        if services.audit_attempt(&ended(SENDING)).await.is_err() {
            self.retry_unsent(services, record).await;
            return;
        }
        self.send_ended(services, record, &url, value, &ended).await;
    }

    /// Read the ended row last, then sign with it at one reading of the clock
    /// and post the notice's stored bytes.
    async fn send_ended<'a>(
        &self,
        services: &Services,
        record: &OutboxRecord,
        url: &url::Url,
        value: serde_json::Value,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) {
        let Some(current) = self.store.signing_row(record) else {
            services.audit_outcome(&ended("cancelled")).await;
            self.settle_with(services, record, |now| unsent_now("cancelled", record, now))
                .await;
            return;
        };
        #[cfg(test)]
        self.before_send.pause().await;
        let Ok(now) = crate::clock::utc_now() else {
            services.audit_outcome(&ended(CLOCK_UNREADABLE)).await;
            self.settle(services, record, clock_unsent(record)).await;
            return;
        };
        // The gateway's own body: no tenant content to judge.
        let frame = OutboundFrame::unjudged(Payload::Callback(value));
        let handle = services.alias(&current.id);
        let answer = self
            .send_event(url, &current, &handle, &record.event_id, frame, now, None)
            .await;
        self.settle_ended(services, record, &answer, ended).await;
    }

    /// Judge, record and settle the answer to a notice at one reading of the
    /// clock.
    async fn settle_ended<'a>(
        &self,
        services: &Services,
        record: &OutboxRecord,
        answer: &Result<super::super::client::Answer, super::CallbackFailure>,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) {
        let now = crate::clock::utc_now();
        let (outcome, status) = self.judge(record, answer, now);
        services
            .audit_outcome(&Attempt {
                delivered: matches!(outcome, Settle::Delivered),
                ..ended(status)
            })
            .await;
        self.settle_at(services, record, outcome, now).await;
    }
}
