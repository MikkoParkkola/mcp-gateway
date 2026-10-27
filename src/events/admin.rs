// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dead-letter administration (design §3.8, §18): the listing and replay
//! behind the admin route and the CLI. A replay goes back through the same
//! access re-check and firewall scan a fresh occurrence passes.

use std::sync::Arc;

use base64::Engine as _;
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
    /// The row is no longer observed as the record was: re-granted, its
    /// lease rotated, or its identity config changed. The send path would
    /// bury it again.
    ObservationChanged,
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
            Self::ObservationChanged => "observation_changed",
            Self::FirewallBlocked => "firewall_blocked",
            Self::TooLarge => "too_large",
            Self::OutboxFull => "outbox_full",
            Self::AlreadyPending => "already_pending",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Whether `reason` names a dead-letter reason (the listing's filter): any
/// reason a dead letter can be written with, so none is left unfilterable.
pub(crate) fn is_dead_reason(reason: &str) -> bool {
    serde_json::from_value::<DeadReason>(serde_json::Value::from(reason)).is_ok()
}

impl EventsHub {
    /// The held webhook subscriptions per type (MIK-8057): how many, the
    /// earliest and latest expiry among them, and the records still queued
    /// for them. No subscriber, URL or secret.
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "served by the web UI router")
    )]
    pub(crate) fn list_held(&self) -> Vec<Value> {
        self.store
            .held_listing()
            .into_iter()
            .map(|t| {
                json!({
                    "type": t.name,
                    "count": t.count,
                    "earliestExpiry": t.earliest_expiry,
                    "latestExpiry": t.latest_expiry,
                    "pendingRecords": t.pending_records,
                })
            })
            .collect()
    }

    /// Each passthrough subscription's held credential, as the admin view
    /// lists it: its backend, its handle (never the stored id),
    /// its state (`active`, `credential_needed`, `credential_rejected`) and,
    /// while active, when the lease ends. Never the token or a digest of it.
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "served by the web UI router")
    )]
    pub(crate) async fn list_leases(&self) -> Vec<Value> {
        let Some(services) = self.runtime.services.get() else {
            return Vec::new();
        };
        let config = services.live.get();
        let mut out = Vec::new();
        for sub in self.store.subscriptions() {
            let Some((backend, _)) = super::upstream::parse_name(&sub.name) else {
                continue;
            };
            if sub.obs_basis.as_ref().is_none_or(|b| {
                b.strategy != crate::identity_propagation::PropagationStrategyKind::Passthrough
            }) {
                continue;
            }
            let state = match super::observation::observe_row(&config, backend, &sub) {
                Ok(Some(obs)) => {
                    self.leases
                        .state(&super::lease::LeaseKey {
                            backend: backend.to_owned(),
                            obs,
                        })
                        .await
                }
                _ => super::lease::LeaseState::CredentialNeeded,
            };
            let (state, expires_at) = match state {
                super::lease::LeaseState::Active { expires_at } => ("active", Some(expires_at)),
                super::lease::LeaseState::CredentialNeeded => ("credential_needed", None),
                super::lease::LeaseState::CredentialRejected => ("credential_rejected", None),
            };
            out.push(json!({
                "backend": backend,
                "subscription": services.alias(&sub.id),
                "state": state,
                "expiresAt": expires_at,
            }));
        }
        out
    }

    /// The dead letters as the admin listing shows them: event ids, the
    /// subscription's alias, reasons, times and sizes, never a body, a secret,
    /// a callback URL or a stored subscription id.
    pub(crate) fn list_dead_letters(
        &self,
        subscription: Option<&str>,
        reason: Option<&str>,
    ) -> Vec<Value> {
        // The listing names a subscription by its alias, never the stored id;
        // the filter takes either, so a script holding a stored id still works
        // (MIK-8697 §11.2).
        let alias = |id: &str| self.runtime.services.get().map(|s| s.alias(id));
        self.store
            .dead_summaries()
            .into_iter()
            .filter(|d| {
                subscription.is_none_or(|s| {
                    d.subscription_id == s || alias(&d.subscription_id).as_deref() == Some(s)
                })
            })
            .filter(|d| reason.is_none_or(|r| d.reason == r))
            .map(|d| {
                json!({
                    "eventId": d.event_id,
                    "subscriptionAlias": alias(&d.subscription_id),
                    "name": d.name,
                    "reason": d.reason,
                    "deadAt": d.dead_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "sizeBytes": d.size,
                    "attempts": d.attempts,
                })
            })
            .collect()
    }

    /// Replay dead letter `event_id`: access re-check, the send path's
    /// observation check, fresh firewall scan, then a new outbox record under
    /// the same event id.
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
        // A lease is not judged on a clock before 1970: nothing is replayed
        // to a subscription it cannot date, and the refusal is transient, not
        // a subscription gone (MIK-8202).
        let Ok(now) = crate::clock::utc_now() else {
            return Err(ReplayRefusal::Unavailable);
        };
        let sub = self
            .store
            .subscriptions()
            .into_iter()
            .find(|s| s.id == dead.record.subscription_id && s.live(now))
            .ok_or(ReplayRefusal::SubscriptionGone)?;
        let grant = (!dead.record.owner_scoped).then_some(dead.record.backend.as_str());
        match services.admission(&sub, grant).await {
            super::services::AccessVerdict::Admits => {}
            super::services::AccessVerdict::Refuses => return Err(ReplayRefusal::AccessRevoked),
            // No verdict on the access: the clock cannot be read (MIK-8202).
            super::services::AccessVerdict::Undated => return Err(ReplayRefusal::Unavailable),
        }
        self.still_observed(&sub.id, &dead.record, services, now)?;
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
        let changed = data != before;
        body["data"] = data;
        let bytes = serde_json::to_vec(&body).map_err(|_| ReplayRefusal::Unavailable)?;
        if bytes.len() > MAX_BODY {
            return Err(ReplayRefusal::TooLarge);
        }
        let verdict =
            services.replay_verdict(scan, changed, dead.record.firewall.as_deref(), &bytes);
        let record = OutboxRecord {
            body_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            attempt: 0,
            unsent: 0,
            next_attempt_at: now,
            first_attempt_at: None,
            state: OutboxState::Pending,
            last_status: None,
            dead_as: None,
            firewall: Some(verdict.to_owned()),
            replayed: true,
            ..dead.record.clone()
        };
        let (caps, dead_at) = (self.outbox_caps(), dead.dead_at);
        let id = event_id.to_owned();
        match self
            .blocking(move |store| store.revive(&id, dead_at, record, caps, crate::clock::utc_now))
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
            Some(Revived::Undated) | None => Err(ReplayRefusal::Unavailable),
        }
    }

    /// The send path's own observation check, on the row as it is after the
    /// admission await (a re-grant may have landed meanwhile): a record it
    /// would bury again is refused here, by name, and nothing is queued. A
    /// row changed between this and `revive` is still buried at send.
    fn still_observed(
        &self,
        subscription_id: &str,
        record: &OutboxRecord,
        services: &super::Services,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), ReplayRefusal> {
        let current = (self.store.subscriptions().into_iter())
            .find(|s| s.id == subscription_id && s.live(now))
            .ok_or(ReplayRefusal::SubscriptionGone)?;
        if self.observed_now(&current, &services.live.get()) == Ok(record.observed.clone()) {
            Ok(())
        } else {
            Err(ReplayRefusal::ObservationChanged)
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

#[cfg(test)]
#[path = "admin_replay_obs_tests.rs"]
mod replay_obs_tests;
