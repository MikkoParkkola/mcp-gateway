// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivery worker (design §3.2 step 7, §6.5): serial within one
//! subscription, at most `max_in_flight` across them. Before every attempt
//! it re-checks access, takes a rate token and charges the budget; then it
//! signs the stored bytes afresh and POSTs, audits, and settles the record.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use super::EventsHub;
use super::client::ReadBody;
use super::outbox::DeadReason;
use super::services::{Attempt, Services};
use super::store::{Claim, Claimed, Settle};
use super::types::CallbackFailure;

/// How often dead-letter retention runs while the gateway is up.
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Longest the worker sleeps with nothing scheduled (a safety net only).
const IDLE: Duration = Duration::from_secs(5);

/// Subscriptions with an attempt on the wire.
type Busy = Arc<Mutex<HashSet<String>>>;

impl EventsHub {
    /// Run the worker until the runtime stops.
    pub(super) async fn deliver_forever(self: Arc<Self>, services: &Arc<Services>) {
        let busy: Busy = Arc::new(Mutex::new(HashSet::new()));
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
            }
            let wait = self.dispatch(services, &busy, &slots).await;
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
        busy: &Busy,
        slots: &Arc<Semaphore>,
    ) -> Duration {
        let held = busy.lock().clone();
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
            busy.lock().insert(record.subscription_id.clone());
            let (hub, services, busy) = (Arc::clone(self), Arc::clone(services), Arc::clone(busy));
            tokio::spawn(async move {
                hub.attempt(&services, &record.event_id).await;
                busy.lock().remove(&record.subscription_id);
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
        let key = sub.api_key_name.as_deref();
        if !services.admits(key, &record.backend) {
            self.revoke(&sub.id).await;
            return;
        }
        if !services.charge(&record.name, key, self.config.cost_per_delivery_usd) {
            self.settle(
                services,
                event_id,
                Settle::Dead {
                    reason: DeadReason::Budget,
                    status: None,
                },
            )
            .await;
            return;
        }
        let (Some(body), Ok(url)) = (record.body(), url::Url::parse(&sub.url)) else {
            self.settle(
                services,
                event_id,
                Settle::Dead {
                    reason: DeadReason::Exhausted,
                    status: None,
                },
            )
            .await;
            return;
        };
        let body_sha256 = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(&body))
        };
        let answer = self.send_event(&url, &sub, event_id, body).await;
        let (outcome, status) = self.judge(&record, &answer);
        let delivered = matches!(outcome, Settle::Delivered);
        services
            .audit_attempt(&Attempt {
                subscription_id: &sub.id,
                event_id,
                name: &record.name,
                backend: &record.backend,
                attempt: record.attempt,
                principal: &sub.principal,
                api_key_name: key,
                tenants: &record.tenants,
                callback_host: url.host_str().unwrap_or_default(),
                status,
                body_sha256: &body_sha256,
                delivered,
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
        self.settle(services, event_id, outcome).await;
    }

    /// The one path an event's bytes take to a callback: signed with the
    /// subscription's current secret, and its previous one during the
    /// rotation grace, through the hardened client.
    async fn send_event(
        &self,
        url: &url::Url,
        sub: &super::records::Subscription,
        event_id: &str,
        body: Vec<u8>,
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
        self.client
            .post(url, &sub.id, event_id, &keys, body, ReadBody::Discard)
            .await
    }

    async fn settle(&self, services: &Services, event_id: &str, outcome: Settle) {
        let (id, policy) = (event_id.to_owned(), self.dead_policy());
        let evicted = self
            .blocking(move |store| store.settle(&id, outcome, Utc::now(), policy))
            .await;
        services.audit_evictions(evicted.unwrap_or_default()).await;
    }
}

impl EventsHub {
    /// Settle an answer under the configured retry policy, with jitter.
    fn judge(
        &self,
        record: &super::outbox::OutboxRecord,
        answer: &Result<super::client::Answer, CallbackFailure>,
    ) -> (Settle, &'static str) {
        let policy = Retry {
            base: self.config.retry_base,
            max_attempts: self.config.retry_max_attempts,
            window: self.config.retry_window,
        };
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
    let window_end = chrono::Duration::from_std(policy.window)
        .ok()
        .and_then(|w| first.checked_add_signed(w))
        .unwrap_or(chrono::DateTime::<Utc>::MAX_UTC);
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

const fn dead(reason: DeadReason, status: &'static str) -> Settle {
    Settle::Dead {
        reason,
        status: Some(status),
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
