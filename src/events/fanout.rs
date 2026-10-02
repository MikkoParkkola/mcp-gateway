// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fan-out (design §3.2 steps 2-6): each source occurrence is matched to
//! live subscriptions, access is re-checked now, the body is built once and
//! scanned, and one outbox record per subscription is written.

use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::EventsHub;
use super::outbox::{DeadReason, Enqueued, OutboxRecord, OutboxState};
use super::records::Subscription;
use super::services::{Scan, Services, Subject};
use super::types::{SourceKind, Visibility};

/// The draft's SHOULD ceiling on a delivery body (design §6.5).
pub(crate) const MAX_BODY: usize = 262_144;

/// One occurrence from a source.
#[derive(Debug, Clone)]
pub(crate) struct SourceEvent {
    pub kind: SourceKind,
    pub name: String,
    /// The backend whose visibility gates the occurrence.
    pub backend: String,
    /// Who may receive this occurrence: a backend's callers, or the owner.
    pub scope: Visibility,
    /// Stable per occurrence (design §3.6).
    pub upstream_id: String,
    pub occurred_at: DateTime<Utc>,
    pub data: Value,
}

/// `evt_` + 32 hex of SHA-256 over kind, upstream id and subscription id:
/// stable across retries and restarts, distinct per subscription.
pub(crate) fn event_id(kind: SourceKind, upstream_id: &str, subscription_id: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in [kind.as_str(), upstream_id, subscription_id] {
        hasher.update(part.as_bytes());
        hasher.update([0_u8]);
    }
    format!("evt_{}", &hex::encode(hasher.finalize())[..32])
}

/// The delivery body: exactly the protocol fields and the source's data.
pub(crate) fn body(event_id: &str, event: &SourceEvent, data: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "eventId": event_id,
        "name": event.name,
        "timestamp": event.occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "data": data,
        "cursor": null,
    }))
    .unwrap_or_default()
}

impl EventsHub {
    /// Fan one occurrence out to every matching subscription.
    pub(super) async fn fan_out(self: &Arc<Self>, services: &Services, event: &SourceEvent) {
        let now = Utc::now();
        let Some(source) = self.source(event.kind) else {
            return;
        };
        let matching: Vec<Subscription> = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|s| s.name == event.name && s.live(now))
            .filter(|s| source.matches(&s.principal, &s.arguments, event))
            .collect();
        for sub in matching {
            if !services
                .admits_subscription(&sub, event.scope.grant_backend())
                .await
            {
                self.revoke(&sub).await;
                continue;
            }
            self.offer(services, event, &sub).await;
        }
        self.runtime.wake.notify_one();
    }

    /// Build, scan and write one subscription's record.
    async fn offer(self: &Arc<Self>, services: &Services, event: &SourceEvent, sub: &Subscription) {
        let id = event_id(event.kind, &event.upstream_id, &sub.id);
        let mut data = event.data.clone();
        // Attribution before redaction (MIN.2 row E1): what the source named.
        let tenants = services.tenants(&data);
        let scan = services.scan(
            &mut data,
            &Subject {
                event_id: &id,
                principal: &sub.principal,
                backend: &event.backend,
                name: &event.name,
            },
        );
        let bytes = body(&id, event, &data);
        let now = Utc::now();
        let record = OutboxRecord {
            v: 1,
            event_id: id,
            subscription_id: sub.id.clone(),
            name: event.name.clone(),
            backend: event.backend.clone(),
            owner_scoped: event.scope == Visibility::Owner,
            tenants,
            body_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            attempt: 0,
            next_attempt_at: now,
            first_attempt_at: None,
            created_at: now,
            state: OutboxState::Pending,
            last_status: None,
            dead_as: None,
        };
        let refusal = if scan == Scan::Block {
            Some(DeadReason::FirewallBlocked)
        } else if bytes.len() > MAX_BODY {
            Some(DeadReason::TooLarge)
        } else {
            None
        };
        if let Some(reason) = refusal {
            let policy = self.dead_policy();
            let evicted = self
                .blocking(move |store| store.dead_letter(record, reason, now, policy))
                .await;
            services.audit_evictions(evicted.unwrap_or_default()).await;
            return;
        }
        let caps = self.outbox_caps();
        match self
            .blocking(move |store| store.enqueue(record, caps))
            .await
        {
            Some(Enqueued::Written | Enqueued::NoSubscription) => {}
            Some(dropped) => {
                self.runtime.count_drop();
                tracing::warn!(?dropped, subscription = %sub.id, "events: outbox full, occurrence dropped");
            }
            None => self.runtime.count_drop(),
        }
    }

    /// Delete every subscription to an event type a reload removed; their
    /// pending records go with them (design §9). Synchronous, inside the
    /// reload, so a later reload that restores the type cannot interleave.
    pub(crate) fn withdraw(&self, names: &[String]) {
        let tail = super::tail_policy(&self.config);
        let now = Utc::now();
        for sub in self.store.subscriptions() {
            if names.contains(&sub.name)
                && let Err(error) = self.store.remove(&sub.id, now, tail)
            {
                tracing::warn!(%error, "events: withdrawn subscription not removed");
            }
        }
    }

    /// Delete subscription `refused`, the snapshot the access check refused,
    /// with its pending records (F9), unless a refresh has since re-bound it
    /// to another credential.
    pub(super) async fn revoke(self: &Arc<Self>, refused: &Subscription) {
        let tail = super::tail_policy(&self.config);
        let snapshot = refused.clone();
        let removed = self
            .blocking(move |store| {
                store.remove_where(&snapshot.id, Utc::now(), tail, |row| {
                    row.credential_principal == snapshot.credential_principal
                        && row.binding == snapshot.binding
                        && row.api_key == snapshot.api_key
                })
            })
            .await;
        if removed == Some(true) {
            tracing::info!("events: subscription revoked, access no longer granted");
        }
    }
}

#[cfg(test)]
#[path = "fanout_tests.rs"]
mod tests;
