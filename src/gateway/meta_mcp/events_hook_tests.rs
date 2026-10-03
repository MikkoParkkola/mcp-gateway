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
