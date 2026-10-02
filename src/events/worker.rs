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
use super::services::{Attempt, Services};
use super::store::{Claim, Claimed, Settle};
use super::types::CallbackFailure;
use crate::gateway::outbound::{self, Admission, CallbackSend, OutboundFrame};
use crate::security::tenant_reads::ReadVerdict;

/// How often dead-letter retention runs while the gateway is up.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Longest the worker sleeps with nothing scheduled (a safety net only).
const IDLE: Duration = Duration::from_secs(5);

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

    /// One attempt of record `event_id`, end to end.
    async fn attempt(self: &Arc<Self>, services: &Services, event_id: &str) {
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
        let key = sub.api_key.as_ref().map(|k| k.name.as_str());
        let url = url::Url::parse(&sub.url).ok();
        let host = url
            .as_ref()
            .and_then(url::Url::host_str)
            .unwrap_or_default()
            .to_owned();
        // Every attempt is audited, a refused one too (§3.7).
        let refused = |status: &'static str| Attempt {
            subscription_id: &sub.id,
            event_id,
            name: &record.name,
            backend: &record.backend,
            number: record.attempt,
            principal: &sub.principal,
            api_key_name: key,
            credential_kind: sub
                .credential_kind
                .unwrap_or(crate::security::audit::CredentialKind::None),
            credential_principal: sub.credential_principal.as_deref(),
            tenants: &record.tenants,
            callback_host: &host,
            status,
            body_sha256: "",
            delivered: false,
            cross_tenant_read: None,
        };
        if !services.admits_subscription(&sub, &record.backend).await {
            services.audit_attempt(&refused("access_revoked")).await;
            self.revoke(&sub).await;
            // Removed: the record went with it and this settles nothing. Not
            // removed (a store error, or a refresh re-bound the row): the
            // record goes back to pending and the next attempt re-checks.
            let next = Utc::now() + chrono::TimeDelta::seconds(30);
            let retry = Settle::Retry {
                next,
                status: "access_revoked",
            };
            self.settle(services, &record, retry).await;
            return;
        }
        // A record a crash or a long suspension carried past its bounds is
        // dead before it is sent again, never after (§6.5).
        if let Some(reason) = record.dead_as {
            self.bury(services, &record, reason).await;
            return;
        }
        if self.overdue(&record, Utc::now()) {
            services.audit_attempt(&refused("exhausted")).await;
            self.bury(services, &record, DeadReason::Exhausted).await;
            return;
        }
        // An unsubscribe that waited past its bound has removed the
        // subscription by now: nothing is charged or sent for it. Otherwise
        // the current row signs, so a secret rotated since the claim counts.
        let Some(current) = self.store.signing_row(&record) else {
            return;
        };
        if !services.charge(&record.name, key, self.config.cost_per_delivery_usd) {
            services.audit_attempt(&refused("budget")).await;
            self.bury(services, &record, DeadReason::Budget).await;
            return;
        }
        let (Some((value, body_sha256)), Some(url)) = (wire_body(&record), url) else {
            self.bury(services, &record, DeadReason::Exhausted).await;
            return;
        };
        let Some((frame, verdict)) = self
            .admit_delivery(services, &sub, &record, value, refused("tenant"))
            .await
        else {
            return;
        };
        let answer = self
            .send_event(&url, &current, event_id, frame, sub.read_key.as_deref())
            .await;
        let (outcome, status) = self.judge(&record, &answer);
        let delivered = matches!(outcome, Settle::Delivered);
        services
            .audit_attempt(&Attempt {
                body_sha256: &body_sha256,
                delivered,
                cross_tenant_read: verdict,
                ..refused(status)
            })
            .await;
        self.track_failures(&sub, delivered).await;
        self.settle(services, &record, outcome).await;
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
                return Some((frame, verdict));
            }
            Admission::Blocked(evidence) => evidence,
        };
        if let Some(log) = &services.audit {
            outbound::audit_rejection(log, &evidence).await;
        }
        services
            .audit_attempt(&Attempt {
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

    /// Suspend a subscription whose deliveries keep failing.
    async fn track_failures(&self, sub: &super::records::Subscription, delivered: bool) {
        if self
            .runtime
            .failures
            .record(&sub.id, delivered, Instant::now())
        {
            let id = sub.id.clone();
            self.blocking(move |store| store.suspend(&id)).await;
            tracing::warn!(subscription = %sub.id, "events: sustained delivery failure, subscription suspended");
        }
    }

    /// Dead-letter the claimed occurrence without a status.
    async fn bury(&self, services: &Services, record: &OutboxRecord, reason: DeadReason) {
        self.settle(services, record, quiet_dead(reason)).await;
    }

    /// Settle the claimed occurrence `record`; a later occurrence that has
    /// since taken its event id is left alone.
    async fn settle(&self, services: &Services, record: &OutboxRecord, outcome: Settle) {
        let (id, created_at, policy) = (
            record.event_id.clone(),
            record.created_at,
            self.dead_policy(),
        );
        let evicted = self
            .blocking(move |store| store.settle(&id, created_at, outcome, Utc::now(), policy))
            .await;
        services.audit_evictions(evicted.unwrap_or_default()).await;
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

/// Dead without a new HTTP status: the subscription's last error stands.
/// The stored body as a JSON value, with the SHA-256 of what goes on the
/// wire: the frame's own serialisation, which is what the audit hashes.
fn wire_body(record: &OutboxRecord) -> Option<(serde_json::Value, String)> {
    use sha2::Digest as _;
    let value: serde_json::Value = serde_json::from_slice(&record.body()?).ok()?;
    let sent = serde_json::to_vec(&value).ok()?;
    Some((value, hex::encode(sha2::Sha256::digest(sent))))
}

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
