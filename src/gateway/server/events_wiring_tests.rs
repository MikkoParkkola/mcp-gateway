// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T28-T30: the kill switch and the breakers mark every chart in
//! every events configuration, the default (events on, operational off)
//! included.

use std::sync::Arc;
use std::time::Duration;

use super::install;
use crate::backend::{Backend, BackendRegistry};
use crate::config::Config;
use crate::counters::{CounterStore, MarkerKind};
use crate::gateway::WebhookRegistry;
use crate::gateway::meta_mcp::MetaMcp;

/// Wire a gateway's events as the server does, with `events.enabled` and
/// `events.sources.operational` as given.
type Wired = (
    Arc<MetaMcp>,
    Arc<BackendRegistry>,
    Arc<CounterStore>,
    Arc<tempfile::TempDir>,
    Arc<parking_lot::RwLock<WebhookRegistry>>,
);

fn wire(events: bool, operational: bool) -> Wired {
    // The gateway's events opener keeps the registered dir its store lives in.
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.events.enabled = events;
    config.events.sources.operational = operational;
    config.events.store_dir = dir.path().to_string_lossy().into_owned();
    let registry = Arc::new(BackendRegistry::new());
    let meta = Arc::new(MetaMcp::new(Arc::clone(&registry)));
    let store = Arc::new(CounterStore::new(0));
    let webhooks = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        crate::config::WebhookConfig::default(),
    )));
    let live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    install(
        &config,
        &meta,
        &registry,
        &webhooks,
        &live,
        crate::events::LiveCredentials::default(),
        &store,
    )
    .expect("wired");
    (meta, registry, store, dir, webhooks)
}

fn marks(store: &CounterStore) -> Vec<(MarkerKind, Option<String>)> {
    store
        .markers(0)
        .into_iter()
        .map(|m| (m.kind, m.subject))
        .collect()
}

/// T28, T29 and T30: a kill, a revive and a tripped breaker are three
/// markers, whatever the events configuration; a kill of a name nobody
/// configured is marked with no subject.
#[test]
fn t30_kill_switch_and_breaker_markers_in_every_events_configuration() {
    // The started hub's tasks hold it until their runtime is dropped, so the
    // runtime is owned here and the directories are checked after it goes.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let dirs = runtime.block_on(markers_in_every_events_configuration());
    drop(runtime);
    for (path, events, operational) in dirs {
        // The hub keeps its directory for as long as it lives, and it and the
        // webhook registry hold each other: with the loop broken, the directory
        // goes with the runtime instead of outliving the test binary.
        assert!(
            !path.exists(),
            "events {events}, operational {operational}: the store directory outlived its owners"
        );
    }
}

async fn markers_in_every_events_configuration() -> Vec<(std::path::PathBuf, bool, bool)> {
    let mut dirs = Vec::new();
    let backend = |name: &str| {
        Arc::new(Backend::new(
            name,
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(300),
        ))
    };
    for (events, operational) in [(false, false), (true, false), (true, true)] {
        let (meta, registry, store, dir, webhooks) = wire(events, operational);
        let path = dir.path().to_path_buf();
        assert!(registry.register(backend("alpha")));
        let kill = meta.kill_switch();
        kill.kill("alpha");
        kill.revive("alpha");
        kill.kill("sk-live-SENTINEL-8854");
        let beta = backend("beta");
        assert!(registry.register(Arc::clone(&beta)));
        beta.trip_circuit_breaker("test");
        assert_eq!(
            marks(&store),
            vec![
                (MarkerKind::SwitchOff, Some("alpha".to_owned())),
                (MarkerKind::SwitchOn, Some("alpha".to_owned())),
                (MarkerKind::SwitchOff, None),
                (MarkerKind::Pause, Some("beta".to_owned())),
            ],
            "events {events}, operational {operational}"
        );
        webhooks.write().clear_events();
        drop((meta, registry, store, dir, webhooks));
        dirs.push((path, events, operational));
    }
    dirs
}
