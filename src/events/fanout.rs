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
    /// The owner's digest, for sources whose occurrences belong to one owner;
    /// carried so fan-out needs no read of the record the source describes.
    pub owner: Option<String>,
    /// Stable per occurrence (design §3.6).
    pub upstream_id: String,
    pub occurred_at: DateTime<Utc>,
    pub data: Value,
    /// Set by a source whose upstream work is per lifecycle key (a
    /// credentialed watch): the occurrence then reaches only subscriptions
    /// holding this key (design §4, MIK-7811). The core enforces key
    /// equality only; a source whose work runs under one principal's
    /// credential must put that principal in its `lifecycle_key`, computed
    /// from the same canonical arguments on both sides.
    pub lifecycle_key: Option<String>,
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

/// The `_meta` key the gateway's provenance receipt rides under: inside the
/// signed body, outside `payloadSchema` (design §3.6).
const PROVENANCE_KEY: &str = "io.github.mikkoparkkola/provenance";

/// Whether every configured capability directory was read by the startup
/// scan. A partial scan builds a partial catalogue, which proves nothing about
/// a route's absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogueScan {
    Complete,
    Partial,
}

/// The delivery body: exactly the protocol fields, the source's data and
/// the provenance receipt in `_meta`.
pub(crate) fn body(event_id: &str, event: &SourceEvent, data: &Value, receipt: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "eventId": event_id,
        "name": event.name,
        "timestamp": event.occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "data": data,
        "cursor": null,
        "_meta": { PROVENANCE_KEY: receipt },
    }))
    .unwrap_or_default()
}

impl EventsHub {
    /// Fan one occurrence out to every matching subscription.
    pub(super) async fn fan_out(self: &Arc<Self>, services: &Services, event: &SourceEvent) {
        let Some(source) = self.source(event.kind) else {
            return;
        };
        // Matched under the catalogue gate a route refresh holds while it
        // swaps the routes and judges the held set: no match against new
        // routes reaches a subscription they hold (MIK-8076). No I/O and no
        // await under it.
        let matching: Vec<Subscription> = {
            let _gate = self.catalogue_lock();
            self.store
                .subscriptions()
                .into_iter()
                // A clock before 1970 reads no lease live: nothing is
                // delivered on a lease it cannot date (MIK-8202).
                .filter(|s| s.name == event.name && s.live_now())
                .filter(|s| self.store.held(&s.id).is_none())
                // A keyed occurrence belongs to its key's holders alone (MIK-7811).
                .filter(|s| {
                    // A row's own key first: a held watch keeps its class's
                    // key whatever the catalogue says now (MIK-8122).
                    event.lifecycle_key.as_deref().is_none_or(|key| {
                        source.row_key(s).unwrap_or_else(|| {
                            source.lifecycle_key(&s.principal, &s.name, &s.arguments)
                        }) == key
                    })
                })
                .filter(|s| source.matches(&s.principal, &s.arguments, event))
                .collect()
        };
        for sub in matching {
            if !services
                .admits_subscription(&sub, event.scope.grant_backend())
                .await
            {
                self.revoke(&sub).await;
                continue;
            }
            // An occurrence that carries its owner was authorized where it was
            // made: the record it describes may be gone (an expired task).
            if event.owner.is_some() {
                self.offer(services, event, &sub).await;
                continue;
            }
            match source
                .authorize(&sub.principal, &sub.name, &sub.arguments)
                .await
            {
                Ok(()) => {}
                // The source no longer lets the principal hold this: the
                // subscription ends, so its upstream work can stop.
                Err(refusal) if refusal.code == -32012 => {
                    self.revoke(&sub).await;
                    continue;
                }
                // Anything else (a store hiccup) skips this occurrence only.
                Err(_) => continue,
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
        // Wrapped as the delivered envelope carries it, so an `arg_keys` entry
        // named `data` still binds the value to its key.
        let attribution = services.attribute(&json!({ "data": &data }));
        let attribution_keys = services.attribution_keys();
        let scan = services.scan(
            &mut data,
            &Subject {
                event_id: &id,
                principal: &sub.principal,
                backend: &event.backend,
                name: &event.name,
            },
        );
        let firewall = services.firewall_verdict(scan, data != event.data);
        let bytes = body(
            &id,
            event,
            &data,
            &services.provenance(&event.backend, &event.name),
        );
        let now = Utc::now();
        let record = OutboxRecord {
            v: 1,
            event_id: id,
            subscription_id: sub.id.clone(),
            name: event.name.clone(),
            backend: event.backend.clone(),
            // Asks no backend grant at delivery: owner and operator events
            // are authorized by their source, not by a backend's grant.
            owner_scoped: event.scope.grant_backend().is_none(),
            callback_host: super::outbox::callback_host_of(&sub.url),
            tenants,
            attribution,
            attribution_keys,
            firewall: Some(firewall.to_owned()),
            body_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            attempt: 0,
            unsent: 0,
            next_attempt_at: now,
            first_attempt_at: None,
            created_at: now,
            state: OutboxState::Pending,
            last_status: None,
            dead_as: None,
            replayed: false,
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
            let buried = record.clone();
            // Receipt order, as in the worker's burials: see `receipts`.
            let _ordered = self.receipts.lock().await;
            let settled = self
                .blocking(move |store| store.dead_letter(record, reason, now, policy))
                .await;
            let (evicted, receipt) = settled.map_or((Vec::new(), false), |s| (s.evicted, s.buried));
            if receipt {
                self.dead_lettered(services, &buried, reason).await;
            }
            services.audit_evictions(evicted).await;
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
    ///
    /// `false` when a subscription could not be removed.
    pub(crate) fn withdraw(&self, names: &[String]) -> bool {
        let tail = super::tail_policy(&self.config);
        let now = Utc::now();
        let mut all_removed = true;
        for sub in self.store.subscriptions() {
            if names.contains(&sub.name)
                && let Err(error) = self.store.remove(&sub.id, now, tail)
            {
                tracing::warn!(%error, "events: withdrawn subscription not removed");
                all_removed = false;
            }
        }
        all_removed
    }

    /// Once the startup capability scan has registered the webhook routes:
    /// withdraw the subscriptions of backends removed while the gateway was
    /// down (MIK-7803), hold the webhook subscriptions the routes do not offer
    /// or serve (MIK-8057; nothing is sent to them, nothing deleted), and let
    /// the worker start. `false`, with the worker still held, when a removal
    /// failed: the caller retries.
    #[cfg(test)]
    pub(crate) fn reconcile_catalogue(&self, scan: CatalogueScan) -> bool {
        self.reconcile_catalogue_after(&|| scan)
    }

    /// [`Self::reconcile_catalogue`], with the scan given by `refresh`, run
    /// under the same catalogue gate first: the startup refresh of the
    /// webhook routes and the withdraw decision share one hold, so no other
    /// refresh lands between them (MIK-7944). A capability catalogue swap is
    /// not held off by this gate (MIK-8027).
    pub(crate) fn reconcile_catalogue_after(&self, refresh: &dyn Fn() -> CatalogueScan) -> bool {
        // Held through the snapshot and the withdrawal, so a capability reload
        // cannot restore a route in between and lose its subscriptions.
        let _gate = self.catalogue_lock();
        let scan = refresh();
        // With webhooks off no route can come back, so a partial capability
        // scan proves nothing about them: their catalogue is complete (empty).
        let webhooks_on = self
            .sources
            .read()
            .iter()
            .any(|source| source.kind() == SourceKind::Webhook);
        // Backends are registered before the hub starts, so their catalogue is
        // complete whatever the capability scan did: a backend removed while
        // the gateway was down takes its subscriptions with it (MIK-7803).
        let offered: std::collections::HashSet<String> =
            self.catalogue().into_iter().map(|d| d.name).collect();
        if !self.withdraw(&self.absent_backend_names(&offered)) {
            return false;
        }
        if !webhooks_on {
            // No route can be offered: every webhook row is held until it
            // lapses (MIK-8057).
            self.hold_unserved(&std::collections::BTreeMap::new());
        }
        if scan == CatalogueScan::Partial && webhooks_on {
            tracing::warn!(
                "events: the startup catalogue is partial (a capability directory could not \
                 be read) or its webhook refresh was refused; webhook subscriptions it does \
                 not serve are held, and resume when a reload serves them"
            );
        }
        let held = self.store.held_listing();
        if !held.is_empty() {
            let types: Vec<(&str, usize)> =
                held.iter().map(|t| (t.name.as_str(), t.count)).collect();
            tracing::info!(
                ?types,
                "events: webhook subscriptions held: their type is not offered or served now"
            );
        }
        self.release_worker()
    }

    /// Run [`Self::reconcile_catalogue_after`] until it succeeds, on the
    /// blocking pool, waiting `retry` between attempts; each attempt refreshes
    /// and recomputes from the stored state. Every failed attempt is
    /// logged, a join error with its cause: a retry that fails silently
    /// cannot be diagnosed (MIK-7891). `pass` names the startup pass in
    /// those logs, so a stuck deferred withdraw reads apart from the first
    /// pass (MIK-8027).
    pub(crate) async fn reconcile_until_done(
        self: &Arc<Self>,
        pass: &'static str,
        refresh: Arc<dyn Fn() -> CatalogueScan + Send + Sync>,
        retry: std::time::Duration,
    ) {
        for attempt in 1_u64.. {
            let (hub, refresh) = (Arc::clone(self), Arc::clone(&refresh));
            match tokio::task::spawn_blocking(move || hub.reconcile_catalogue_after(&*refresh))
                .await
            {
                Ok(true) => return,
                Ok(false) => tracing::warn!(
                    pass,
                    attempt,
                    retry_secs = retry.as_secs(),
                    "events: startup reconcile could not remove a stale subscription \
                     (cause in the preceding log line); the worker stays held, retrying"
                ),
                Err(error) => tracing::warn!(
                    pass,
                    attempt,
                    %error,
                    "events: startup reconcile task failed; the worker stays held, retrying"
                ),
            }
            tokio::time::sleep(retry).await;
        }
    }

    /// Stored `backend.<x>.<kind>` names whose backend `x` is gone. A backend
    /// always offers `tools_changed`, so its absence is the test; the upstream
    /// kinds depend on a listener that is not up yet at startup and are not
    /// judged by themselves.
    fn absent_backend_names(&self, offered: &std::collections::HashSet<String>) -> Vec<String> {
        self.store
            .subscriptions()
            .into_iter()
            .map(|sub| sub.name)
            .filter(|name| {
                name.strip_prefix(super::backend_source::NAME_PREFIX)
                    .and_then(|rest| rest.rsplit_once('.'))
                    .is_some_and(|(backend, _kind)| {
                        !offered.contains(&format!("backend.{backend}.tools_changed"))
                    })
            })
            .collect()
    }

    /// Reconciliation is over: the delivery worker may start.
    fn release_worker(&self) -> bool {
        self.runtime
            .reconciled
            .store(true, std::sync::atomic::Ordering::Release);
        self.runtime.wake.notify_one();
        true
    }

    /// Under the catalogue gate the caller holds: re-register the webhook
    /// routes of `capabilities` ([`super::reload::refresh_webhooks`]), then
    /// hold every stored webhook subscription they do not offer or serve and
    /// resume every one they serve again (MIK-8057, MIK-8076). Nothing is
    /// deleted.
    ///
    /// # Errors
    /// The live event type the reload would narrow (T52); the routes stay
    /// as they were, and the stored rows are judged against them.
    pub(crate) fn refresh_webhooks(
        &self,
        registry: &Arc<parking_lot::RwLock<crate::gateway::WebhookRegistry>>,
        capabilities: &[crate::capability::CapabilityDefinition],
    ) -> Result<(), String> {
        match super::reload::refresh_webhooks(registry, capabilities) {
            Ok(shapes) => {
                self.hold_unserved(&shapes);
                Ok(())
            }
            // The routes left live may be ones no row was judged against yet,
            // as when a startup scan registered them: judge against those.
            Err(narrowed) => {
                self.hold_unserved(&super::reload::live_shapes(registry));
                Err(narrowed)
            }
        }
    }

    /// Judge every stored webhook subscription against `shapes`; a stamp
    /// that could not be written is logged and written by the next refresh.
    fn hold_unserved(&self, shapes: &std::collections::BTreeMap<String, super::reload::Shape>) {
        let judge = |sub: &Subscription| super::reload::judge(sub, shapes);
        if let Err(error) = self
            .store
            .apply_holds(&judge, Utc::now(), self.hold_bound())
        {
            tracing::warn!(%error, "events: a held subscription's stamp was not written; retried at the next refresh");
        }
    }

    /// The longest a hold keeps a row: the maximum lease.
    pub(super) fn hold_bound(&self) -> chrono::Duration {
        chrono::Duration::from_std(self.config.max_ttl).unwrap_or(chrono::Duration::days(1))
    }

    /// Serializes startup reconciliation with capability reloads.
    pub(crate) fn catalogue_lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.catalogue_gate.lock()
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
            self.reconcile_stops().await;
        }
    }
}

#[cfg(test)]
#[path = "fanout_tests.rs"]
mod tests;
