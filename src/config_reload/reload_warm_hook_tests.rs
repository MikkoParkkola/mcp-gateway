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

/// A reported change, the `meta_mcp.warm_start` the hook was handed, and the
/// one the live config held at that moment.
type Seen = (RegisteredChange, Vec<String>, Vec<String>);

const ONE: &str = "\n  x:\n    http_url: \"http://127.0.0.1:1/mcp\"\n";

/// The `n`th report (0-based), waiting up to 15 s for it.
async fn nth(seen: &Mutex<Vec<Seen>>, n: usize) -> Option<Seen> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(entry) = seen.lock().unwrap().get(n).cloned() {
            return Some(entry);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_watched_reload_reports_its_backends_to_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("gateway.yaml");
    write_owner_only(&cfg, yaml(" {}", "")).unwrap();
    let initial = Config::load(Some(&cfg)).unwrap();
    let live = Arc::new(super::LiveConfig::new(initial.clone()));
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let hook: OnRegistered = {
        let (seen, live) = (Arc::clone(&seen), Arc::clone(&live));
        Arc::new(move |change: &RegisteredChange, config: &Config| {
            let published = live.get().meta_mcp.warm_start.clone();
            seen.lock().unwrap().push((
                change.clone(),
                config.meta_mcp.warm_start.clone(),
                published,
            ));
            Vec::new()
        })
    };
    let (_shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let _watcher = ConfigWatcher::start_with_hook(
        cfg.clone(),
        Arc::clone(&live),
        Arc::new(crate::backend::BackendRegistry::new()),
        &initial,
        Arc::new(LiveEnv::new(
            Arc::new(EnvOverlay::none()),
            ResolvedEnvFiles::default(),
        )),
        None,
        None,
        shutdown_rx,
        Some(hook),
    )
    .expect("the watcher starts");

    write_owner_only(&cfg, yaml(ONE, "x")).unwrap();
    let (change, handed, published) = nth(&seen, 0)
        .await
        .expect("the watcher's reload never reached the hook");
    assert_eq!(change.registered, ["x"]);
    assert!(change.removed.is_empty());
    // The new config, and already published when the hook ran.
    assert_eq!(handed, ["x"]);
    assert_eq!(
        published,
        ["x"],
        "the hook ran before the config was published"
    );

    write_owner_only(&cfg, yaml(" {}", "")).unwrap();
    let (change, _, _) = nth(&seen, 1)
        .await
        .expect("the removal never reached the hook");
    assert!(change.registered.is_empty());
    assert_eq!(change.removed, ["x"]);
}
