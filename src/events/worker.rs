// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivery worker (design §3.2 step 7, §6.5): serial within one
//! subscription, at most `max_in_flight` across them. Before every attempt
//! it re-checks access, takes a rate token and charges the budget; then it
//! signs the stored bytes afresh and POSTs, audits, and settles the record.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::Semaphore;

use super::EventsHub;
use super::client::ReadBody;
use super::outbox::{DeadReason, OutboxRecord};
use super::services::{Attempt, SENDING, Services};
use super::store::{Claim, Claimed, Settle};
use super::types::CallbackFailure;
use crate::gateway::outbound::{self, Admission, CallbackSend, OutboundFrame};
use crate::security::tenant_reads::ReadVerdict;

/// How often dead-letter retention runs while the gateway is up.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Longest the worker sleeps with nothing scheduled (a safety net only).
const IDLE: Duration = Duration::from_secs(5);
/// Back off before the next attempt of a record that was refused before its
/// POST: the access re-check failed or the audit log refused the record.
const REFUSAL_RETRY: chrono::TimeDelta = chrono::TimeDelta::seconds(30);

impl EventsHub {
    /// Run the worker until the runtime stops.
    pub(super) async fn deliver_forever(self: Arc<Self>, services: &Arc<Services>) {
        let slots = Arc::new(Semaphore::new(self.config.max_in_flight));
        let mut swept: Option<Instant> = None;
        loop {
            if swept.is_none_or(|at| at.elapsed() >= SWEEP_EVERY) {
                swept = Some(Instant::now());
                let policy = self.dead_policy();
                let evicted = self
                    .blocking(move |store| store.sweep_dead(Utc::now(), policy))
                    .await;
                services.audit_evictions(evicted.unwrap_or_default()).await;
                // Gone subscriptions take their rate and failure state along.
                let held = self.store.live_subscription_ids(Utc::now());
                self.runtime.rates.retain(&held);
                self.runtime.failures.retain(&held);
                // Expiry removes subscriptions without a call of its own.
                self.reconcile_stops().await;
            }
            let wait = self.dispatch(services, &slots).await;
            tokio::select! {
                () = self.runtime.wake.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Start every attempt that is due, has a token and a slot; how long to
    /// sleep before looking again.
    async fn dispatch(
        self: &Arc<Self>,
        services: &Arc<Services>,
        slots: &Arc<Semaphore>,
    ) -> Duration {
        // The catalogue is partial until the startup scan has run: a record
        // of a route removed while down must not be sent first (MIK-7772).
        if !self
            .runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return IDLE;
        }
        let held = self.runtime.busy.lock().clone();
        let Some(due) = self
            .blocking(move |store| store.due(Utc::now(), &held))
            .await
        else {
            return IDLE;
        };
        let mut wait = due
            .next
            .and_then(|at| (at - Utc::now()).to_std().ok())
            .unwrap_or(IDLE)
            .min(IDLE);
        for record in due.ready {
            let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
                // Every slot is busy: a finishing attempt wakes the worker.
                break;
            };
            if let Err(later) = self
                .runtime
                .rates
                .take(&record.subscription_id, Instant::now())
            {
                // Delayed, never dropped: the record stays due.
                wait = wait.min(later);
                drop(permit);
                continue;
            }
            self.runtime
                .busy
                .lock()
                .insert(record.subscription_id.clone());
            let (hub, services) = (Arc::clone(self), Arc::clone(services));
            tokio::spawn(async move {
                hub.attempt(&services, &record.event_id).await;
                hub.runtime.busy.lock().remove(&record.subscription_id);
                drop(permit);
                hub.runtime.wake.notify_one();
            });
        }
        wait
    }

    /// One attempt of record `event_id`, end to end. Its source verdicts
    /// share one wait on a catalogue that does not answer (MIK-7921).
    async fn attempt(self: &Arc<Self>, services: &Services, event_id: &str) {
        let failed = std::cell::Cell::new(false);
        super::upstream_listener::FAILED_LOOKUP
            .scope(failed, self.attempt_once(services, event_id))
            .await;
    }

    async fn attempt_once(self: &Arc<Self>, services: &Services, event_id: &str) {
        let now = Utc::now();
        let claim_id = event_id.to_owned();
        let Some(Claim::Ready(claimed)) = self
            .blocking(move |store| store.claim(&claim_id, now))
            .await
        else {
            return;
        };
        let Claimed {
            record,
            subscription: sub,
        } = *claimed;
        let url = url::Url::parse(&sub.url).ok();
        let ctx = Ctx {
            sub: &sub,
            record: &record,
            event_id,
            host: url
                .as_ref()
                .and_then(url::Url::host_str)
                .unwrap_or_default()
                .to_owned(),
        };
        if !services.admits_subscription(&sub, grant(&record)).await {
            if !self
                .recorded_or_retry(services, &ctx, "access_revoked")
                .await
            {
                return;
            }
            self.revoke(&sub).await;
            // Removed: the record went with it and this settles nothing. Not
            // removed (a store error, or a refresh re-bound the row): the
            // record goes back to pending and the next attempt re-checks.
            let next = Utc::now() + REFUSAL_RETRY;
            let retry = Settle::Retry {
                next,
                status: "access_revoked",
            };
            self.settle(services, &record, retry).await;
            return;
        }
        let verdict = self.source_verdict(&sub).await;
        if verdict == Verdict::Refuses {
            if !self
                .recorded_or_retry(services, &ctx, "access_revoked")
                .await
            {
                return;
            }
            self.revoke(&sub).await;
            self.settle(services, &record, refusal_retry("access_revoked"))
                .await;
            return;
        }
        // A record a crash or a long suspension carried past its bounds is
        // dead before it is sent again, never after (§6.5).
        if let Some(reason) = record.dead_as {
            self.settle(services, &record, quiet_dead(reason)).await;
            return;
        }
        if self.overdue(&record, Utc::now()) {
            if !self.recorded_or_retry(services, &ctx, "exhausted").await {
                return;
            }
            self.settle(services, &record, quiet_dead(DeadReason::Exhausted))
                .await;
            return;
        }
        // Held, unsent and uncharged, until a source offers the type again
        // or the record runs past its bounds above (MIK-7976).
        if verdict == Verdict::Unoffered {
            if self.recorded_or_retry(services, &ctx, HELD).await {
                self.settle(services, &record, refusal_retry(HELD)).await;
            }
            return;
        }
        // An unsubscribe that waited past its bound has removed the
        // subscription by now: nothing is charged or sent for it. Otherwise
        // the current row signs, so a secret rotated since the claim counts.
        if self.store.signing_row(&record).is_none() {
            return;
        }
        let (Some(body), Some(url)) = (record.body(), url) else {
            self.settle(services, &record, quiet_dead(DeadReason::Exhausted))
                .await;
            return;
        };
        self.record_and_send(services, &ctx, &url, body).await;
    }

    /// The source's own verdict, every attempt (design §3.2 step 7): a
    /// resource that left the backend's catalogue is not delivered. A backend
    /// name no source offers any more (the backend left the config or a
    /// reload made it ineligible, MIK-7894) is refused too, so a record a
    /// failed withdrawal left behind is not sent. Any other name no source
    /// offers is held, not refused: a source installed after the worker
    /// started, or a partial capability scan (MIK-7772), says nothing about
    /// the subscription, so it is kept (MIK-7976).
    async fn source_verdict(&self, sub: &super::records::Subscription) -> Verdict {
        match self.source_offering(&sub.name) {
            Some(source) => {
                let refused = source
                    .authorize(&sub.principal, &sub.name, &sub.arguments)
                    .await
                    .is_err_and(|e| e.code == -32012);
                if refused {
                    Verdict::Refuses
                } else {
                    Verdict::Admits
                }
            }
            None if sub.name.starts_with(super::backend_source::NAME_PREFIX) => Verdict::Refuses,
            None => Verdict::Unoffered,
        }
    }

    /// Put an attempt that ends without a send (`status`) on record. When the
    /// log refuses it the record goes back to retry with its subscription
    /// intact, so the ending is recorded once the log recovers instead of
    /// being lost to the removal or the burial that follows (MIK-7842).
    /// `false` when the caller must stop.
    async fn recorded_or_retry(
        self: &Arc<Self>,
        services: &Services,
        ctx: &Ctx<'_>,
        status: &'static str,
    ) -> bool {
        let Err(error) = services.audit_attempt(&ctx.attempt(status)).await else {
            return true;
        };
        tracing::warn!(%error, status, subscription = %ctx.sub.id, "events: attempt record not written; retrying");
        let retry = Settle::Retry {
            next: Utc::now() + REFUSAL_RETRY,
            status: "audit_unavailable",
        };
        self.settle(services, ctx.record, retry).await;
        false
    }

    /// Put the attempt on record, then charge and send it. The record comes
    /// first: a log that refuses it means no POST, and the record goes back
    /// to retry (SAFETY.2).
    async fn record_and_send(
        self: &Arc<Self>,
        services: &Services,
        ctx: &Ctx<'_>,
        url: &url::Url,
        body: Vec<u8>,
    ) {
        let (sub, record, event_id) = (ctx.sub, ctx.record, ctx.event_id);
        let Some((value, body_sha256)) = wire_body(&body) else {
            self.settle(services, record, quiet_dead(DeadReason::Exhausted))
                .await;
            return;
        };
        let ended = |status: &'static str| Attempt {
            body_sha256: &body_sha256,
            ..ctx.attempt(status)
        };
        if services.audit_attempt(&ended(SENDING)).await.is_err() {
            let next = Utc::now() + REFUSAL_RETRY;
            let retry = Settle::Retry {
                next,
                status: "audit_unavailable",
            };
            self.settle(services, record, retry).await;
            return;
        }
        // MIN.2 E1, before the checks below: its own audit wait can span a
        // rotation or an unsubscribe too. A frame dropped by a later refusal
        // releases its reservation unsent.
        let Some((frame, verdict)) = self
            .admit_delivery(services, sub, record, value, ended("tenant"))
            .await
        else {
            return;
        };
        // The same waits can span a reload that made the backend ineligible
        // (MIK-7894): the verdict is read again after them, before the row
        // that signs, so only sync steps sit between it and the send.
        match self.source_verdict(sub).await {
            // Access is read again after the verdict's own wait (MIK-7907):
            // a grant lost meanwhile is refused like one lost before. It must
            // not yield: a reload landing inside it would follow the verdict
            // unseen. Its one await, `TokenStore::live_jti`, completes at
            // once in the only store there is (`InMemoryTokenStore`); a store
            // that waits needs the verdict read again after this check.
            Verdict::Admits if !services.admits_subscription(sub, grant(record)).await => {
                services.audit_outcome(&ended("access_revoked")).await;
                self.revoke(sub).await;
                self.settle(services, record, refusal_retry("access_revoked"))
                    .await;
                return;
            }
            Verdict::Admits => {}
            Verdict::Refuses => {
                services.audit_outcome(&ended("access_revoked")).await;
                self.revoke(sub).await;
                self.settle(services, record, refusal_retry("access_revoked"))
                    .await;
                return;
            }
            Verdict::Unoffered => {
                services.audit_outcome(&ended(HELD)).await;
                self.settle(services, record, refusal_retry(HELD)).await;
                return;
            }
        }
        // The wait for the record can span a rotation or an unsubscribe: the
        // row that signs is read after it, never before.
        let Some(current) = self.store.signing_row(record) else {
            services.audit_outcome(&ended("cancelled")).await;
            return;
        };
        // Past its bounds after the wait for the record: dead, unsent, and the
        // record just written says how that attempt ended.
        if self.overdue(record, Utc::now()) {
            services.audit_outcome(&ended("exhausted")).await;
            self.settle(services, record, quiet_dead(DeadReason::Exhausted))
                .await;
            return;
        }
        // Charged once the attempt is on record, so a retry after an audit
        // outage is not charged for an attempt that never left. A type its
        // source exempts (a budget event) is never charged.
        let key = sub.api_key.as_ref().map(|k| k.name.as_str());
        let charged = self
            .source_offering(&record.name)
            .is_none_or(|source| source.charges(&record.name));
        if charged && !services.charge(&record.name, key, self.config.cost_per_delivery_usd) {
            services.audit_outcome(&ended("budget")).await;
            self.settle(services, record, quiet_dead(DeadReason::Budget))
                .await;
            return;
        }
        let answer = self
            .send_event(url, &current, event_id, frame, sub.read_key.as_deref())
            .await;
        let (outcome, status) = self.judge(record, &answer);
        let delivered = matches!(outcome, Settle::Delivered);
        services
            .audit_outcome(&Attempt {
                delivered,
                cross_tenant_read: verdict,
                ..ended(status)
            })
            .await;
        if self
            .runtime
            .failures
            .record(&sub.id, delivered, Instant::now())
        {
            let id = sub.id.clone();
            self.blocking(move |store| store.suspend(&id)).await;
            tracing::warn!(subscription = %sub.id, "events: sustained delivery failure, subscription suspended");
        }
        self.settle(services, record, outcome).await;
    }

    /// MIN.2 E1: the delivery is a read by the subscription's caller, on the
    /// history its answers share. A blocked one is audited and dead-lettered
    /// `tenant` here; `None` then.
    async fn admit_delivery(
        &self,
        services: &Services,
        sub: &super::records::Subscription,
        record: &OutboxRecord,
        value: serde_json::Value,
        blocked: Attempt<'_>,
    ) -> Option<(OutboundFrame, Option<ReadVerdict>)> {
        let evidence = match outbound::callback_frame(
            services.guard(),
            sub.read_key.as_deref(),
            value,
            record.attribution_under(&services.attribution_keys()),
        ) {
            Admission::Admitted(frame) => {
                let verdict = frame.verdict();
                let frame = outbound::recorded(frame, services.audit.as_ref()).await;
                if frame.is_withheld() {
                    // The log refused the tenant_read record under
                    // fail-closed: nothing was sent, so this is an audit
                    // outage to retry, never a transport failure.
                    let retry = Settle::Retry {
                        next: Utc::now() + REFUSAL_RETRY,
                        status: "audit_unavailable",
                    };
                    self.settle(services, record, retry).await;
                    return None;
                }
                return Some((frame, verdict));
            }
            Admission::Blocked(evidence) => evidence,
        };
        if let Some(log) = &services.audit {
            outbound::audit_rejection(log, &evidence).await;
        }
        services
            .audit_outcome(&Attempt {
                cross_tenant_read: Some(evidence.verdict),
                ..blocked
            })
            .await;
        self.settle(services, record, quiet_dead(DeadReason::Tenant))
            .await;
        None
    }

    /// The one path an event's bytes take to a callback: signed with the
    /// subscription's current secret, and its previous one during the
    /// rotation grace, through the hardened client.
    async fn send_event(
        &self,
        url: &url::Url,
        sub: &super::records::Subscription,
        event_id: &str,
        frame: OutboundFrame,
        key: Option<&str>,
    ) -> Result<super::client::Answer, CallbackFailure> {
        let now = Utc::now();
        let current = super::client::decode_whsec(&sub.secret);
        let previous = sub
            .previous_secret
            .as_deref()
            .filter(|_| sub.previous_until.is_some_and(|until| until > now))
            .and_then(super::client::decode_whsec);
        let keys: Vec<&[u8]> = current
            .iter()
            .chain(previous.iter())
            .map(Vec::as_slice)
            .collect();
        outbound::send_callback(frame, key.unwrap_or_default(), |body| async move {
            // Only a failure before any byte could be written releases the
            // frame's reservation; any other may follow a written byte, and
            // the frame commits.
            match self
                .client
                .post_tracked(url, &sub.id, event_id, &keys, body, ReadBody::Discard)
                .await
            {
                Err((failure, true)) => CallbackSend::NotSent(failure),
                Err((failure, false)) => CallbackSend::Sent(Err(failure)),
                Ok(answer) => CallbackSend::Sent(Ok(answer)),
            }
        })
        .await
    }

    /// Settle the claimed occurrence `record`; a later occurrence that has
    /// since taken its event id is left alone.
    async fn settle(&self, services: &Services, record: &OutboxRecord, outcome: Settle) {
        let (id, created_at, policy) = (
            record.event_id.clone(),
            record.created_at,
            self.dead_policy(),
        );
        let settled = self
            .blocking(move |store| store.settle(&id, created_at, outcome, Utc::now(), policy))
            .await;
        let (evicted, buried) = settled.map_or((Vec::new(), false), |s| (s.evicted, s.buried));
        services.audit_evictions(evicted).await;
        // The burial's own receipt: a cancelled occurrence settles nothing, and
        // one the caps evicted at once still happened.
        if let Settle::Dead { reason, .. } = outcome
            && buried
        {
            self.dead_lettered(services, record, reason).await;
        }
    }

    /// The governance record of a dead letter (design 3.7).
    pub(super) async fn dead_lettered(
        &self,
        services: &Services,
        record: &OutboxRecord,
        reason: DeadReason,
    ) {
        // Stamped at fan-out from the subscription the record is for; a record
        // written before the stamp existed falls back to the store.
        let host = if record.callback_host.is_empty() {
            self.store
                .get(&record.subscription_id)
                .and_then(|s| url::Url::parse(&s.url).ok())
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_default()
        } else {
            record.callback_host.clone()
        };
        services
            .audit_lifecycle(
                &super::governance::Lifecycle {
                    action: "events.dead_letter",
                    subscription_id: &record.subscription_id,
                    event_name: &record.name,
                    callback_host: &host,
                    detail: reason.as_str(),
                    event_id: Some(&record.event_id),
                    failed_with: Some(-32015),
                },
                super::governance::Attribution::Gateway,
            )
            .await;
    }
}

/// What one claimed attempt knows about itself, for its audit records.
struct Ctx<'a> {
    sub: &'a super::records::Subscription,
    record: &'a OutboxRecord,
    event_id: &'a str,
    host: String,
}

impl Ctx<'_> {
    /// The attempt as a record states it: failed, with no body hash yet.
    fn attempt(&self, status: &'static str) -> Attempt<'_> {
        Attempt {
            subscription_id: &self.sub.id,
            event_id: self.event_id,
            name: &self.record.name,
            backend: &self.record.backend,
            number: self.record.attempt,
            principal: &self.sub.principal,
            api_key_name: self.sub.api_key.as_ref().map(|k| k.name.as_str()),
            credential_kind: self
                .sub
                .credential_kind
                .unwrap_or(crate::security::audit::CredentialKind::None),
            credential_principal: self.sub.credential_principal.as_deref(),
            tenants: &self.record.tenants,
            callback_host: &self.host,
            status,
            body_sha256: "",
            firewall: self.record.firewall.as_deref().unwrap_or("unrecorded"),
            delivered: false,
            cross_tenant_read: None,
        }
    }
}

impl EventsHub {
    fn retry_policy(&self) -> Retry {
        Retry {
            base: self.config.retry_base,
            max_attempts: self.config.retry_max_attempts,
            window: self.config.retry_window,
        }
    }

    /// Whether claimed attempt `record.attempt` lies past the attempt limit
    /// or the retry window.
    fn overdue(&self, record: &super::outbox::OutboxRecord, now: chrono::DateTime<Utc>) -> bool {
        overdue(
            record.attempt,
            record.first_attempt_at.unwrap_or(now),
            now,
            self.retry_policy(),
        )
    }

    /// Settle an answer under the configured retry policy, with jitter.
    fn judge(
        &self,
        record: &super::outbox::OutboxRecord,
        answer: &Result<super::client::Answer, CallbackFailure>,
    ) -> (Settle, &'static str) {
        let policy = self.retry_policy();
        let now = Utc::now();
        let first = record.first_attempt_at.unwrap_or(now);
        judge(
            answer,
            record.attempt,
            first,
            now,
            policy,
            rand::random::<f64>(),
        )
    }
}

/// The retry policy (design §6.5).
#[derive(Debug, Clone, Copy)]
struct Retry {
    base: Duration,
    max_attempts: u32,
    window: Duration,
}

/// How attempt number `attempt` (1-based) ended, and its status category:
/// 2xx delivered; 410 and 413 dead at once; anything else retried with
/// exponential backoff and full jitter (`jitter` in `[0, 1)`), base x 3^n,
/// `Retry-After` on 429 honoured, every retry inside the window from the
/// first attempt, then dead `exhausted`.
fn judge(
    answer: &Result<super::client::Answer, CallbackFailure>,
    attempt: u32,
    first: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    policy: Retry,
    jitter: f64,
) -> (Settle, &'static str) {
    let (status, retry_after) = match answer {
        Err(failure) => (failure.as_str(), None),
        Ok(answer) => match answer.status {
            200..=299 => return (Settle::Delivered, "delivered"),
            410 => return (dead(DeadReason::Gone, "http_4xx"), "http_4xx"),
            413 => return (dead(DeadReason::TooLarge, "http_4xx"), "http_4xx"),
            429 => ("http_4xx", answer.retry_after),
            400..=499 => ("http_4xx", None),
            500..=599 => ("http_5xx", None),
            300..=399 => ("http_3xx", None),
            _ => ("http_other", None),
        },
    };
    let window_end = window_end(first, policy.window);
    if attempt >= policy.max_attempts || now >= window_end {
        return (dead(DeadReason::Exhausted, status), status);
    }
    let exponent = i32::try_from(attempt.saturating_sub(1)).unwrap_or(i32::MAX);
    let ceiling = policy.base.as_secs_f64() * 3_f64.powi(exponent);
    let backoff = Duration::from_secs_f64(
        (ceiling * jitter.clamp(0.0, 1.0)).min(policy.window.as_secs_f64()),
    );
    let delay = retry_after.map_or(backoff, |after| after.min(policy.window));
    let next = chrono::Duration::from_std(delay)
        .ok()
        .and_then(|d| now.checked_add_signed(d))
        .map_or(window_end, |at| at.min(window_end));
    (Settle::Retry { next, status }, status)
}

/// The end of the retry window that opened at `first`.
fn window_end(first: chrono::DateTime<Utc>, window: Duration) -> chrono::DateTime<Utc> {
    chrono::Duration::from_std(window)
        .ok()
        .and_then(|w| first.checked_add_signed(w))
        .unwrap_or(chrono::DateTime::<Utc>::MAX_UTC)
}

/// Whether attempt number `attempt` (1-based, already claimed) may not be
/// sent: past the attempt limit, or a retry at or after the window's end.
/// The first attempt is never overdue.
fn overdue(
    attempt: u32,
    first: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    policy: Retry,
) -> bool {
    attempt > policy.max_attempts || (attempt > 1 && now >= window_end(first, policy.window))
}

/// The stored body as a JSON value, with the SHA-256 of what goes on the
/// wire: the frame's own serialisation, which is what the audit hashes.
fn wire_body(stored: &[u8]) -> Option<(serde_json::Value, String)> {
    use sha2::Digest as _;
    let value: serde_json::Value = serde_json::from_slice(stored).ok()?;
    let sent = serde_json::to_vec(&value).ok()?;
    Some((value, hex::encode(sha2::Sha256::digest(sent))))
}

#[cfg(test)]
mod wire_tests {
    use super::wire_body;

    /// The audited hash is the hash of the bytes the callback frame posts:
    /// `send_callback` serialises the same value with `serde_json::to_vec`.
    #[test]
    fn the_audited_hash_is_the_hash_of_the_posted_bytes() {
        use sha2::Digest as _;
        let stored = br#"{"eventId":"e","data":{"b":1,"a":[1.5,"x"]},"cursor":null}"#;
        let (value, hash) = wire_body(stored).expect("a JSON body");
        let posted = serde_json::to_vec(&value).expect("serialises");
        assert_eq!(hash, hex::encode(sha2::Sha256::digest(posted)));
    }

    #[test]
    fn a_body_that_is_not_json_has_no_wire_form() {
        assert!(wire_body(b"not json").is_none());
    }
}

/// What a subscription's source says of its event type at an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Admits,
    /// Refused: the subscription is revoked.
    Refuses,
    /// No source offers the type: the record waits, the subscription stays.
    Unoffered,
}

/// The status of an attempt held because no source offers its type: nothing
/// was revoked, the type is only unavailable for now.
const HELD: &str = "source_unavailable";

/// The backend grant a delivery of `record` needs: none for an owner-scoped
/// event, which was authorized where it was made.
fn grant(record: &OutboxRecord) -> Option<&str> {
    (!record.owner_scoped).then_some(record.backend.as_str())
}

/// Back to pending after a refusal before the POST, ending `status`: a
/// revoked subscription's record goes with it, a held one waits.
fn refusal_retry(status: &'static str) -> Settle {
    Settle::Retry {
        next: Utc::now() + REFUSAL_RETRY,
        status,
    }
}

/// Dead without a new HTTP status: the subscription's last error stands.
const fn quiet_dead(reason: DeadReason) -> Settle {
    Settle::Dead {
        reason,
        status: None,
    }
}

const fn dead(reason: DeadReason, status: &'static str) -> Settle {
    Settle::Dead {
        reason,
        status: Some(status),
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
