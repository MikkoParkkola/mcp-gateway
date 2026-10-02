// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T41 (SOURCE.3): a source plugs in through the trait alone. Crate-private
//! by design (I4 build notes): no public registration surface exists.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::records::{Credential, Subscription};
use super::rpc::Caller;
use super::types::{EventDescriptor, SourceKind, Visibility};
use super::*;

const NAME: &str = "probe.thing";

/// A source written against the trait only.
#[derive(Default)]
struct Probe {
    first: AtomicUsize,
    last: AtomicUsize,
}

#[async_trait::async_trait]
impl EventSource for Probe {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<EventDescriptor> {
        vec![EventDescriptor {
            name: NAME.into(),
            description: "test source".into(),
            input_schema: json!({"type": "object", "properties": {"k": {"type": "string"}}}),
            payload_schema: json!({"type": "object"}),
            scope: Visibility::Owner,
            kind: SourceKind::RestWatch,
        }]
    }
    fn matches(&self, _principal: &str, _arguments: &Value, _event: &SourceEvent) -> bool {
        true
    }
    async fn on_first_subscriber(
        &self,
        _key: &str,
        _principal: &str,
        _name: &str,
        _arguments: &Value,
    ) -> Result<(), RpcError> {
        self.first.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn on_last_subscriber(&self, _key: &str) {
        self.last.fetch_add(1, Ordering::SeqCst);
    }
}

fn caller(principal: &str) -> Caller {
    Caller {
        principal: Some(principal.to_owned()),
        credential: Credential {
            kind: crate::security::audit::CredentialKind::None,
            principal: String::new(),
            api_key: None,
            expires_at: None,
            binding: None,
        },
        visible_backends: std::collections::HashSet::new(),
    }
}

fn whsec() -> String {
    use base64::Engine as _;
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([7_u8; 32])
    )
}

fn services() -> Services {
    Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
    }
}

fn url(principal: &str) -> String {
    format!("https://{principal}.example/cb")
}

/// Seed a verified `(principal, url)` through a row of another event type,
/// so the subscribe under test needs no callback POST.
fn seed_verified(hub: &EventsHub, config: &crate::config::EventsConfig, principal: &str) {
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "id": format!("seed_{principal}"), "principal": principal,
        "url": url(principal), "name": "seed", "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    let caps = store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            row,
            true,
            caps,
            chrono::Duration::zero(),
            chrono::Utc::now(),
            tail_policy(config),
        )
        .expect("io")
        .expect("admitted");
}

async fn subscribe(hub: &Arc<EventsHub>, principal: &str) {
    let params = json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {
        "mode": "webhook", "url": url(principal), "secret": whsec()}});
    hub.subscribe(&caller(principal), Some(&params))
        .await
        .unwrap_or_else(|e| panic!("subscribe {principal}: {e:?}"));
}

async fn unsubscribe(hub: &Arc<EventsHub>, principal: &str) {
    let params =
        json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {"url": url(principal)}});
    hub.unsubscribe(&caller(principal), Some(&params))
        .await
        .expect("unsubscribe");
}

fn outbox_files(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir.join("outbox")).map_or(0, Iterator::count)
}

#[tokio::test]
async fn a_test_source_plugs_in_without_core_changes() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    assert!(
        hub.catalogue().iter().any(|d| d.name == NAME),
        "the descriptor is listed"
    );
    for p in ["p1", "p2"] {
        seed_verified(&hub, &config, p);
        subscribe(&hub, p).await;
    }
    assert_eq!(
        probe.first.load(Ordering::SeqCst),
        1,
        "on_first_subscriber once for two subscribers with the same arguments"
    );
    let event = SourceEvent {
        kind: SourceKind::RestWatch,
        name: NAME.into(),
        backend: "probe".into(),
        scope: Visibility::Owner,
        upstream_id: "u1".into(),
        occurred_at: chrono::Utc::now(),
        data: json!({"x": 1}),
    };
    // Through the runtime's own entry points: start, then the emit queue.
    hub.start(services());
    hub.emit(event);
    for _ in 0..100 {
        if outbox_files(dir.path()) == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(outbox_files(dir.path()), 2, "one record per subscriber");
    unsubscribe(&hub, "p1").await;
    assert_eq!(probe.last.load(Ordering::SeqCst), 0, "one subscriber left");
    unsubscribe(&hub, "p2").await;
    assert_eq!(
        probe.last.load(Ordering::SeqCst),
        1,
        "on_last_subscriber once"
    );

    // A restart replays the start once per distinct live key.
    subscribe(&hub, "p1").await;
    drop(hub);
    let hub = EventsHub::open(&config, dir.path()).expect("reopened hub");
    let again = Arc::new(Probe::default());
    hub.register_source(again.clone());
    hub.start(services());
    for _ in 0..100 {
        if again.first.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        again.first.load(Ordering::SeqCst),
        1,
        "replayed once by start"
    );
}
