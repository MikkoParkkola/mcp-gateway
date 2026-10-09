// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T34 (MIK-8194): a catalogue read that began before a renewal must not
//! revoke that renewal at delivery. Driven through the session's own read
//! (`State::maintain`) against a peer whose first resource list is held, and
//! the hub's real fan-out.

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::*;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// The first `resources/list` waits at `held` until `release`.
#[derive(Default)]
struct Gate {
    held: tokio::sync::Notify,
    release: tokio::sync::Notify,
    lists: AtomicUsize,
}

/// A peer listing only `file:///a`, its first list held at `gate`.
async fn upstream(gate: Arc<Gate>) -> String {
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let gate = Arc::clone(&gate);
        async move {
            let Some(id) = message.get("id").cloned() else {
                return StatusCode::ACCEPTED.into_response();
            };
            let body = match message["method"].as_str() {
                Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "b", "version": "0"}}}),
                Some("resources/list") => {
                    if gate.lists.fetch_add(1, Ordering::SeqCst) == 0 {
                        gate.held.notify_one();
                        gate.release.notified().await;
                    }
                    json!({"jsonrpc": "2.0", "id": id, "result": {
                        "resources": [{"uri": "file:///a", "name": "a"}]}})
                }
                _ => json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "method not found"}}),
            };
            axum::Json(body).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

/// Admit (or renew: same id, a new grant) `p`'s watch of `file:///x` on `b`.
fn subscribe(hub: &EventsHub) {
    let config = crate::config::EventsConfig::default();
    let row: crate::events::records::Subscription = serde_json::from_value(json!({
        "v": 1, "id": "sub_x", "principal": "p", "url": "https://h/x",
        "name": "backend.b.resource_updated", "arguments": {"uri": "file:///x"},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::None)
            .expect("kind"),
    }))
    .expect("row");
    hub.store
        .admit(
            row,
            true,
            crate::events::store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            chrono::Utc::now(),
            crate::events::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
}

#[tokio::test]
async fn t34_a_read_begun_before_a_renewal_does_not_revoke_it() {
    let gate = Arc::new(Gate::default());
    let url = upstream(Arc::clone(&gate)).await;
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["b".to_owned()]),
        Arc::clone(&registry),
        Arc::new(std::collections::BTreeSet::new),
    );
    subscribe(&hub);
    let source = hub
        .source(crate::events::types::SourceKind::BackendNotification)
        .expect("source");
    let listeners = source.upstream_listeners().expect("listeners");
    listeners.hold("b", &Interest::ResourceUpdated("file:///x".to_owned()));
    let shared = listeners.entry_of("b").expect("entry");
    let backend = registry.get("b").expect("b");
    let weak = Arc::downgrade(&hub);
    // The session's catalogue read begins, and its list is held.
    let read = tokio::spawn(async move {
        let mut state = State::new(&shared, Era::Modern);
        let handle: Weak<dyn UpstreamListen> = Weak::<crate::transport::HttpTransport>::new();
        state.maintain(&backend, &weak, &handle, true).await;
    });
    tokio::time::timeout(Duration::from_secs(10), gate.held.notified())
        .await
        .expect("the read began");
    // The subscriber renews meanwhile: the same id, a new grant.
    subscribe(&hub);
    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("the read finished")
        .expect("join");
    // A delivery to the renewal, judged against that older read.
    let event = crate::events::fanout::SourceEvent {
        kind: crate::events::types::SourceKind::BackendNotification,
        name: "backend.b.resource_updated".into(),
        backend: "b".into(),
        scope: crate::events::types::Visibility::Backend("b".into()),
        owner: None,
        upstream_id: "n1".into(),
        occurred_at: chrono::Utc::now(),
        data: json!({"uri": "file:///x"}),
        lifecycle_key: None,
    };
    let services = crate::events::Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
    };
    hub.fan_out(&services, &event).await;
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "the renewal survives a delivery judged against the older read"
    );
}

/// A peer whose first `resources/list` lists only `file:///a` and every later
/// one `file:///a` and `file:///x`: the URI appeared after the first read.
async fn upstream_x_appears() -> String {
    let lists = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let lists = Arc::clone(&lists);
        async move {
            let Some(id) = message.get("id").cloned() else {
                return StatusCode::ACCEPTED.into_response();
            };
            let body = match message["method"].as_str() {
                Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "b", "version": "0"}}}),
                Some("resources/list") => {
                    let mut listed = vec![json!({"uri": "file:///a", "name": "a"})];
                    if lists.fetch_add(1, Ordering::SeqCst) > 0 {
                        listed.push(json!({"uri": "file:///x", "name": "x"}));
                    }
                    json!({"jsonrpc": "2.0", "id": id, "result": {"resources": listed}})
                }
                _ => json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "method not found"}}),
            };
            axum::Json(body).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

/// MIK-8194, no-snapshot half (#3625 review CRITICAL): with no listener
/// snapshot, delivery reads the catalogue itself; a cached list from before
/// the renewal, without the URI, must not revoke it when the URI exists now.
#[tokio::test]
async fn t34_a_cached_list_from_before_a_renewal_does_not_revoke_it() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: upstream_x_appears().await,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    // An earlier read fills the shared catalogue cache, before the URI exists.
    let cached = registry
        .get("b")
        .expect("b")
        .read_resource_snapshot(false)
        .await
        .expect("first read");
    assert!(
        !cached.uris.contains("file:///x"),
        "premise: cached without x"
    );
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["b".to_owned()]),
        Arc::clone(&registry),
        Arc::new(std::collections::BTreeSet::new),
    );
    subscribe(&hub);
    let event = crate::events::fanout::SourceEvent {
        kind: crate::events::types::SourceKind::BackendNotification,
        name: "backend.b.resource_updated".into(),
        backend: "b".into(),
        scope: crate::events::types::Visibility::Backend("b".into()),
        owner: None,
        upstream_id: "n2".into(),
        occurred_at: chrono::Utc::now(),
        data: json!({"uri": "file:///x"}),
        lifecycle_key: None,
    };
    let services = crate::events::Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
    };
    hub.fan_out(&services, &event).await;
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "the renewal survives a delivery judged against the stale cache"
    );
}
