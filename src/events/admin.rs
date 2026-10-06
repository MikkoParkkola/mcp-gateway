// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dead-letter administration (design §3.8, §18): the listing and replay
//! behind the admin route and the CLI. A replay goes back through the same
//! access re-check and firewall scan a fresh occurrence passes.

use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use serde_json::{Value, json};

use super::EventsHub;
use super::fanout::MAX_BODY;
use super::outbox::{DeadReason, OutboxRecord, OutboxState};
use super::services::{Scan, Subject};
use super::store::Revived;

/// Why a replay did not happen. The dead letter is untouched in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayRefusal {
    NotFound,
    SubscriptionGone,
    /// Suspended until its subscriber refreshes it.
    SubscriptionSuspended,
    AccessRevoked,
    FirewallBlocked,
    TooLarge,
    OutboxFull,
    AlreadyPending,
    /// The pipeline is not running or the store failed.
    Unavailable,
}

impl ReplayRefusal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::SubscriptionGone => "subscription_gone",
            Self::SubscriptionSuspended => "subscription_suspended",
            Self::AccessRevoked => "access_revoked",
            Self::FirewallBlocked => "firewall_blocked",
            Self::TooLarge => "too_large",
            Self::OutboxFull => "outbox_full",
            Self::AlreadyPending => "already_pending",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Whether `reason` names a dead-letter reason (the listing's filter).
pub(crate) fn is_dead_reason(reason: &str) -> bool {
    [
        DeadReason::Gone,
        DeadReason::TooLarge,
        DeadReason::Exhausted,
        DeadReason::FirewallBlocked,
        DeadReason::Budget,
    ]
    .iter()
    .any(|r| r.as_str() == reason)
}

impl EventsHub {
    /// The dead letters as the admin listing shows them: ids, reasons, times
    /// and sizes, never a body, a secret or a callback URL.
    pub(crate) fn list_dead_letters(
        &self,
        subscription: Option<&str>,
        reason: Option<&str>,
    ) -> Vec<Value> {
        self.store
            .dead_summaries()
            .into_iter()
            .filter(|d| subscription.is_none_or(|s| d.subscription_id == s))
            .filter(|d| reason.is_none_or(|r| d.reason == r))
            .map(|d| {
                json!({
                    "eventId": d.event_id,
                    "subscriptionId": d.subscription_id,
                    "name": d.name,
                    "reason": d.reason,
                    "deadAt": d.dead_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "sizeBytes": d.size,
                    "attempts": d.attempts,
                })
            })
            .collect()
    }

    /// Replay dead letter `event_id`: access re-check, fresh firewall scan,
    /// then a new outbox record under the same event id.
    pub(crate) async fn replay_dead(
        self: &Arc<Self>,
        event_id: &str,
        actor: &super::governance::Actor,
    ) -> Result<(), ReplayRefusal> {
        let services = self
            .runtime
            .services
            .get()
            .ok_or(ReplayRefusal::Unavailable)?;
        let dead = self
            .store
            .dead_letter_by_id(event_id)
            .ok_or(ReplayRefusal::NotFound)?;
        let now = Utc::now();
        let sub = self
            .store
            .subscriptions()
            .into_iter()
            .find(|s| s.id == dead.record.subscription_id && s.live(now))
            .ok_or(ReplayRefusal::SubscriptionGone)?;
        let grant = (!dead.record.owner_scoped).then_some(dead.record.backend.as_str());
        if !services.admits_subscription(&sub, grant).await {
            return Err(ReplayRefusal::AccessRevoked);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&dead.record.body_b64)
            .map_err(|_| ReplayRefusal::Unavailable)?;
        let mut body: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReplayRefusal::Unavailable)?;
        let mut data = body["data"].take();
        let before = data.clone();
        let subject = Subject {
            event_id,
            principal: &sub.principal,
            backend: &dead.record.backend,
            name: &dead.record.name,
        };
        let scan = services.scan(&mut data, &subject);
        if scan == Scan::Block {
            return Err(ReplayRefusal::FirewallBlocked);
        }
        let verdict = services.firewall_verdict(scan, data != before);
        body["data"] = data;
        let bytes = serde_json::to_vec(&body).map_err(|_| ReplayRefusal::Unavailable)?;
        if bytes.len() > MAX_BODY {
            return Err(ReplayRefusal::TooLarge);
        }
        let record = OutboxRecord {
            body_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            attempt: 0,
            next_attempt_at: now,
            first_attempt_at: None,
            state: OutboxState::Pending,
            last_status: None,
            dead_as: None,
            firewall: Some(verdict.to_owned()),
            ..dead.record.clone()
        };
        let (caps, dead_at) = (self.outbox_caps(), dead.dead_at);
        let id = event_id.to_owned();
        match self
            .blocking(move |store| store.revive(&id, dead_at, record, caps, Utc::now))
            .await
        {
            Some(Revived::Written) => {
                self.runtime.wake.notify_one();
                let host = url::Url::parse(&sub.url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_default();
                services
                    .audit_lifecycle(
                        &super::governance::Lifecycle {
                            action: "events.replay",
                            subscription_id: &sub.id,
                            event_name: &dead.record.name,
                            callback_host: &host,
                            detail: "replayed",
                            event_id: Some(event_id),
                            failed_with: None,
                        },
                        super::governance::Attribution::Admin(actor),
                    )
                    .await;
                Ok(())
            }
            Some(Revived::NoSubscription) => Err(ReplayRefusal::SubscriptionGone),
            Some(Revived::Suspended) => Err(ReplayRefusal::SubscriptionSuspended),
            Some(Revived::Full) => Err(ReplayRefusal::OutboxFull),
            Some(Revived::AlreadyPending) => Err(ReplayRefusal::AlreadyPending),
            Some(Revived::Missing) => Err(ReplayRefusal::NotFound),
            None => Err(ReplayRefusal::Unavailable),
        }
    }

    /// Replay every dead letter of `subscription`; the count replayed and
    /// each refusal.
    pub(crate) async fn replay_all(
        self: &Arc<Self>,
        subscription: &str,
        actor: &super::governance::Actor,
    ) -> (usize, Vec<(String, ReplayRefusal)>) {
        let mut replayed = 0;
        let mut refused = Vec::new();
        for entry in self.list_dead_letters(Some(subscription), None) {
            let id = entry["eventId"].as_str().unwrap_or_default().to_owned();
            match self.replay_dead(&id, actor).await {
                Ok(()) => replayed += 1,
                Err(why) => refused.push((id, why)),
            }
        }
        (replayed, refused)
    }
}
