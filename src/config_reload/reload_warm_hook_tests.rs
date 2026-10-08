// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8054` wiring: a config-file reload picked up by the watcher reports the
//! backends it registered and removed to the hook, with the published config.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{ConfigWatcher, OnRegistered, RegisteredChange};
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::gateway::test_helpers::write_owner_only;

fn yaml(backends: &str, warm: &str) -> String {
    format!("meta_mcp:\n  warm_start: [{warm}]\nbackends:{backends}\n")
}

const ONE: &str = "\n  x:\n    http_url: \"http://127.0.0.1:1/mcp\"\n";

#[tokio::test]
async fn a_watched_reload_reports_its_backends_to_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("gateway.yaml");
    write_owner_only(&cfg, &yaml(" {}", "")).unwrap();
    let seen: Arc<Mutex<Vec<(RegisteredChange, Vec<String>)>>> = Arc::default();
    let hook: OnRegistered = {
        let seen = Arc::clone(&seen);
        Arc::new(move |change: &RegisteredChange, config: &Config| {
            seen.lock()
                .unwrap()
                .push((change.clone(), config.meta_mcp.warm_start.clone()));
        })
    };
    let (_shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let initial = Config::load(Some(&cfg)).unwrap();
    let _watcher = ConfigWatcher::start_with_hook(
        cfg.clone(),
        Arc::new(super::LiveConfig::new(initial.clone())),
        Arc::new(crate::backend::BackendRegistry::new()),
        &initial,
        Arc::new(LiveEnv::new(
            Arc::new(EnvOverlay::none()),
            ResolvedEnvFiles::default(),
        )),
        None,
        shutdown_rx,
        Some(hook),
    )
    .expect("the watcher starts");

    write_owner_only(&cfg, &yaml(ONE, "x")).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let reported = loop {
        if let Some(entry) = seen.lock().unwrap().first().cloned() {
            break Some(entry);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let (change, warm) = reported.expect("the watcher's reload never reached the hook");
    assert_eq!(change.registered, ["x"]);
    assert!(change.removed.is_empty());
    // The published config, not the one the watcher started with.
    assert_eq!(warm, ["x"]);
}
