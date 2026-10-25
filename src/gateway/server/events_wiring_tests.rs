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
fn wire(
    events: bool,
    operational: bool,
) -> (
    Arc<MetaMcp>,
    Arc<BackendRegistry>,
    Arc<CounterStore>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("dir");
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
    (meta, registry, store, dir)
}

fn marks(store: &CounterStore) -> Vec<(MarkerKind, Option<String>)> {
    store
        .markers(0)
        .into_iter()
        .map(|m| (m.kind, m.subject))
        .collect()
}

/// T28, T29 and T30: a kill, a revive and a tripped breaker are three
/// markers, whatever the events configuration.
#[tokio::test]
async fn t30_kill_switch_and_breaker_markers_in_every_events_configuration() {
    for (events, operational) in [(false, false), (true, false), (true, true)] {
        let (meta, registry, store, _dir) = wire(events, operational);
        let kill = meta.kill_switch();
        kill.kill("alpha");
        kill.revive("alpha");
        let beta = Arc::new(Backend::new(
            "beta",
            crate::config::BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        assert!(registry.register(Arc::clone(&beta)));
        beta.trip_circuit_breaker("test");
        assert_eq!(
            marks(&store),
            vec![
                (MarkerKind::SwitchOff, Some("alpha".to_owned())),
                (MarkerKind::SwitchOn, Some("alpha".to_owned())),
                (MarkerKind::Pause, Some("beta".to_owned())),
            ],
            "events {events}, operational {operational}"
        );
    }
}
