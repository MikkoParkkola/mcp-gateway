// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability reload that lands before the startup scan completes must
//! not be lost (MIK-7862, found in review of #2732).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::{EventsConfig, WebhookConfig};
use crate::gateway::WebhookRegistry;

fn capability(name: &str) -> String {
    format!(
        "name: {name}\ndescription: hooks\nschema:\n  input: {{ type: object, properties: {{}} }}\n  \
         output: {{ type: object }}\nproviders: {{}}\nwebhooks:\n  push:\n    path: /{name}/push\n    \
         method: POST\n    transform:\n      event_type: \"{name}.push\"\n      data: {{ ref: \"{{ref}}\" }}\n    \
         event:\n      description: \"A push.\"\n      filters: [ref]\n"
    )
}

fn routes(registry: &Arc<parking_lot::RwLock<WebhookRegistry>>) -> Vec<String> {
    let mut names: Vec<String> = registry
        .read()
        .event_routes()
        .into_iter()
        .map(|(cap, route, _)| format!("{cap}.{route}"))
        .collect();
    names.sort();
    names
}

/// Store a subscription to capability `cap`'s push event in the events store
/// at `store`, as an earlier run left it: the hub loads it when it opens.
fn seed_subscription(store: &std::path::Path, cap: &str) {
    let subs = store.join("subs");
    std::fs::create_dir_all(&subs).expect("subs dir");
    let row = serde_json::json!({
        "v": 1, "id": format!("sub_{cap}"), "principal": "p",
        "url": "https://p.example/cb", "name": format!("webhook.{cap}.push.received"),
        "arguments": {}, "secret": "whsec_x", "previous_secret": null,
        "previous_until": null, "granted_at": chrono::Utc::now(), "expires_at": null,
        "active": true, "failed_since": null, "last_delivery_at": null, "last_error": null
    });
    let file = subs.join(format!("sub_{cap}.json"));
    std::fs::write(&file, serde_json::to_vec(&row).expect("json")).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(0o700)).expect("mode");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
}

/// Whether the subscription [`seed_subscription`] stored for `cap` is still there.
fn subscribed(store: &std::path::Path, cap: &str) -> bool {
    store.join("subs").join(format!("sub_{cap}.json")).exists()
}

/// Poll `done` for up to 10 s.
async fn settled(mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The reload arrives while the scan is still running: it is held, then
/// applied once the scan completes, so the new route is registered.
#[tokio::test]
async fn a_reload_during_the_startup_scan_is_applied_when_it_completes() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    let caps = Arc::new(CapabilityBackend::new(
        "hooks",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.begin_initial_scan();
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("load");
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    )));
    for cap in caps.list_capabilities() {
        registry.write().register_capability(&cap);
    }
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));
    meta.set_webhook_registry(Arc::clone(&registry));
    let hub = EventsHub::open(&EventsConfig::default(), store.path()).expect("hub");
    hub.set_webhook_registry(Arc::clone(&registry));
    meta.set_events(hub);

    // The reload lands mid-scan: a second webhook capability appears.
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("reload");
    meta.events_capabilities_reloaded("hooks");
    assert_eq!(routes(&registry), ["alpha.push"], "held while scanning");

    caps.mark_initial_scan_complete();
    meta.reconcile_events_after_scan();
    let mut applied = false;
    for _ in 0..100 {
        if routes(&registry) == ["alpha.push", "beta.push"] {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        applied,
        "the held reload was applied: {:?}",
        routes(&registry)
    );
}

type Registry = Arc<parking_lot::RwLock<WebhookRegistry>>;

/// A capability backend that has scanned `dirs` and is still marked as
/// scanning, its routes registered from what that scan read, and a `MetaMcp`
/// wired to an events hub on `store` (which loads any seeded subscriptions).
async fn wired(
    dirs: &[&std::path::Path],
    store: &std::path::Path,
) -> (Arc<CapabilityBackend>, Registry, MetaMcp) {
    let caps = Arc::new(CapabilityBackend::new(
        "hooks",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.begin_initial_scan();
    for dir in dirs {
        caps.load_from_directory(dir.to_str().expect("utf8"))
            .await
            .expect("load");
    }
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    )));
    for cap in caps.list_capabilities() {
        registry.write().register_capability(&cap);
    }
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));
    meta.set_webhook_registry(Arc::clone(&registry));
    let hub = EventsHub::open(&EventsConfig::default(), store).expect("hub");
    hub.set_webhook_registry(Arc::clone(&registry));
    meta.set_events(hub);
    (caps, registry, meta)
}

/// MIK-7944 finding 1: a reload that lands during the startup scan, but
/// whose notice the drain has not handled yet, is still in the routes the
/// startup reconcile checks, so its type's subscriptions are kept.
#[tokio::test]
async fn an_unannounced_reload_during_the_scan_keeps_its_subscriptions() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    seed_subscription(store.path(), "beta");
    let (caps, registry, meta) = wired(&[dir.path()], store.path()).await;

    // The reload lands mid-scan; no notice reaches the drain.
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("reload");
    caps.mark_initial_scan_complete();
    meta.reconcile_events_after_scan();
    settled(|| !subscribed(store.path(), "beta") || routes(&registry).len() == 2).await;
    // Past any withdrawal the reconcile would make.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        subscribed(store.path(), "beta"),
        "the beta subscription survives the startup reconcile"
    );
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// MIK-8028 `PARTIAL.1`: a hot reload that cannot read one directory keeps
/// that directory's subscriptions; its routes go, so nothing is delivered.
#[tokio::test]
async fn a_reload_that_cannot_read_a_directory_keeps_its_subscriptions() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
        seed_subscription(store.path(), cap);
    }
    let (caps, registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();

    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        subscribed(store.path(), "beta"),
        "the unread directory's subscription is kept"
    );
    assert!(subscribed(store.path(), "alpha"));
    assert_eq!(routes(&registry), ["alpha.push"], "beta is unoffered");
}

/// MIK-8028 `PARTIAL.2`: the next complete reload withdraws a type that is
/// still absent, and keeps the rest.
#[tokio::test]
async fn the_next_complete_reload_withdraws_a_type_still_absent() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
        seed_subscription(store.path(), cap);
    }
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();

    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        subscribed(store.path(), "beta"),
        "kept through the partial reload"
    );

    // D2 is readable again, without beta: this load is complete.
    std::fs::create_dir_all(&d2).expect("restore d2");
    caps.reload().await.expect("complete reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        !subscribed(store.path(), "beta"),
        "withdrawn once a complete load still lacks it"
    );
    assert!(subscribed(store.path(), "alpha"));
}
