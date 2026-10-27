// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker tests' shared fixtures: callbacks, queued records, logged
//! services and test sources. Split from `worker_tests.rs`; every worker test
//! file reaches them through it.

use super::*;

/// A callback that counts the connections made to it; the handshake never
/// completes, which is all the test needs to see.
pub(super) async fn counting_callback() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

/// One subscription to `port` and one pending record for it.
pub(super) fn queued(hub: &EventsHub, port: u16, event_id: &str) {
    queued_as(hub, port, event_id, "webhook.c.r.received");
}

/// [`queued`] for the event type `name`.
pub(super) fn queued_as(hub: &EventsHub, port: u16, event_id: &str, name: &str) {
    queued_with(hub, port, event_id, name, |_, _| {});
}

/// [`queued_as`], with the subscription and the record changed by `edit`
/// before they are stored.
pub(super) fn queued_with(
    hub: &EventsHub,
    port: u16,
    event_id: &str,
    name: &str,
    edit: impl FnOnce(&mut crate::events::records::Subscription, &mut OutboxRecord),
) {
    queued_stamped(hub, port, event_id, name, edit, |_, _| {});
}

/// [`queued_with`], then `stamp` sets the record from the stored row, as
/// fan-out stamps it: admission hands the row its incarnation.
pub(super) fn queued_stamped(
    hub: &EventsHub,
    port: u16,
    event_id: &str,
    name: &str,
    edit: impl FnOnce(&mut crate::events::records::Subscription, &mut OutboxRecord),
    stamp: impl FnOnce(&crate::events::records::Subscription, &mut OutboxRecord),
) {
    use crate::events::outbox::{Enqueued, OutboxCaps, OutboxState};
    use crate::events::records::Subscription;
    use crate::events::store::{Caps, TailPolicy};
    let now = Utc::now();
    let mut sub = Subscription {
        generation: 0,
        incarnation: 0,
        v: 1,
        id: "sub_worker".into(),
        principal: "p".into(),
        api_key: None,
        credential_kind: Some(crate::security::audit::CredentialKind::None),
        credential_principal: None,
        binding: None,
        legacy_api_key_name: None,
        read_key: None,
        url: format!("https://127.0.0.1:{port}/cb"),
        name: name.into(),
        arguments: serde_json::json!({}),
        secret: format!("whsec_{}=", "A".repeat(43)),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + crate::duration_bound::delta!(hours, 1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
        payload_fields: Vec::new(),
        unoffered_since: None,
        held_until: None,
        watch_class: None,
        observed_identity: None,
        obs_basis: None,
    };
    let tail = TailPolicy {
        ttl: Duration::from_secs(3600),
        max: 10,
        max_per_principal: 10,
    };
    let caps = Caps {
        per_principal: 10,
        global: 10,
    };
    let mut record = OutboxRecord {
        v: 1,
        event_id: event_id.into(),
        subscription_id: "sub_worker".into(),
        name: name.into(),
        backend: "b".into(),
        owner_scoped: false,
        callback_host: String::new(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        unsent: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        replayed: false,
        attribution: None,
        attribution_keys: Vec::new(),
        firewall: None,
        observed: None,
    };
    edit(&mut sub, &mut record);
    let id = sub.id.clone();
    hub.store
        .admit(sub, true, caps, chrono::Duration::zero(), now, tail)
        .expect("io")
        .expect("admitted");
    let stored = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|row| row.id == id);
    stamp(&stored.expect("stored"), &mut record);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    assert_eq!(
        hub.store.enqueue(record, caps).expect("io"),
        Enqueued::Written
    );
}

/// A second pending record for the subscription `queued` made.
pub(super) fn queued_event(hub: &EventsHub, event_id: &str) {
    use crate::events::outbox::{OutboxCaps, OutboxState};
    let now = Utc::now();
    let record = OutboxRecord {
        v: 1,
        event_id: event_id.into(),
        subscription_id: "sub_worker".into(),
        name: "webhook.c.r.received".into(),
        backend: "b".into(),
        owner_scoped: false,
        callback_host: String::new(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        unsent: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        replayed: false,
        attribution: None,
        attribution_keys: Vec::new(),
        firewall: None,
        observed: None,
    };
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    hub.store.enqueue(record, caps).expect("io");
}
pub(super) fn logged_services(dir: &std::path::Path) -> Services {
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("log"),
    );
    Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: Some(log),
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }
}

pub(super) fn audit_actions(dir: &std::path::Path, action: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| r["action"] == action)
        .collect()
}

pub(super) fn config_default() -> crate::config::EventsConfig {
    crate::config::EventsConfig::default()
}

/// A source whose verdict admits the first `admits` asks and refuses (-32012)
/// every later one: a reload landing between two asks.
pub(super) struct Flipping {
    pub(super) admits: usize,
    pub(super) asked: std::sync::atomic::AtomicUsize,
    /// Event types the source exempts from the delivery charge.
    pub(super) free: &'static [&'static str],
}

#[async_trait::async_trait]
impl crate::events::EventSource for Flipping {
    fn kind(&self) -> crate::events::types::SourceKind {
        crate::events::types::SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        ["probe.flip", "probe.free"]
            .map(|name| descriptor(name, crate::events::types::SourceKind::RestWatch))
            .into()
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        true
    }
    fn charges(&self, name: &str) -> bool {
        !self.free.contains(&name)
    }
    async fn authorize(
        &self,
        _p: &str,
        _n: &str,
        _a: &serde_json::Value,
    ) -> Result<(), crate::events::types::RpcError> {
        let n = self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < self.admits {
            Ok(())
        } else {
            Err(crate::events::types::RpcError::forbidden())
        }
    }
}
/// A test catalogue entry for `name`.
pub(super) fn descriptor(
    name: &str,
    kind: crate::events::types::SourceKind,
) -> crate::events::types::EventDescriptor {
    crate::events::types::EventDescriptor {
        name: name.into(),
        description: "test source".into(),
        input_schema: serde_json::json!({"type": "object"}),
        payload_schema: serde_json::json!({"type": "object"}),
        scope: crate::events::types::Visibility::Owner,
        kind,
    }
}

/// A source of kind `kind` offering exactly `names` and admitting everyone.
pub(super) struct Offering {
    pub(super) kind: crate::events::types::SourceKind,
    pub(super) names: Vec<&'static str>,
}

#[async_trait::async_trait]
impl crate::events::EventSource for Offering {
    fn kind(&self) -> crate::events::types::SourceKind {
        self.kind
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        self.names
            .iter()
            .map(|name| descriptor(name, self.kind))
            .collect()
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        true
    }
}

/// Register a webhook-kind source offering `names`.
pub(super) fn offer(hub: &Arc<EventsHub>, names: &[&'static str]) {
    hub.register_source(Arc::new(Offering {
        kind: crate::events::types::SourceKind::Webhook,
        names: names.to_vec(),
    }));
}

/// A budget that records every charge; the registry it charges.
#[cfg(feature = "cost-governance")]
pub(super) fn budgeted(
    services: &mut Services,
) -> Arc<crate::cost_accounting::registry::CostRegistry> {
    use crate::cost_accounting::{
        config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
    };
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&registry)));
    services.budget = Some((enforcer, Arc::clone(&registry)));
    registry
}
