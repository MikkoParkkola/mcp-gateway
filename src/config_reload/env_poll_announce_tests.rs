// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7940 finding 2: a key edit the file watcher picks up announces the
//! capability listing change, as the explicit reload does.

use std::sync::Arc;
use std::time::Duration;

use super::ConfigWatcher;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::gateway::test_helpers::write_owner_only;

const KEY: &str = "MCP_GW_MIK7940_KEY";

#[tokio::test]
async fn a_key_the_watcher_picks_up_announces_the_listing() {
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    let cfg = r.join("gateway.yaml");
    write_owner_only(&cfg, "routing_profiles:\n  p:\n    description: \"x\"\n").unwrap();
    let env_file = r.join(".env");
    write_owner_only(&env_file, "MCP_GW_MIK7940_OTHER=1\n").unwrap();
    let paths = vec![env_file.clone()];
    let env = Arc::new(LiveEnv::new(
        Arc::new(EnvOverlay::from_paths(&paths)),
        ResolvedEnvFiles::new(paths, false),
    ));
    let capabilities = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new().with_env(Arc::clone(&env))),
    ));
    let yaml = format!(
        "name: keyed\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: bearer\n  key: \"env:{KEY}\"\n"
    );
    capabilities
        .register_capability(crate::capability::parse_capability(&yaml).unwrap())
        .unwrap();
    assert!(capabilities.listed_names().is_empty(), "no key yet");
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let (tx, mut feed) = tokio::sync::mpsc::unbounded_channel();
    registry.set_change_feed(tx);
    let (_shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let _watcher = ConfigWatcher::start(
        cfg,
        Arc::new(super::LiveConfig::new(Config::default())),
        Arc::clone(&registry),
        &Config::default(),
        env,
        None,
        Some(Arc::clone(&capabilities)),
        shutdown_rx,
    )
    .expect("the watcher starts");

    write_owner_only(&env_file, format!("{KEY}=x\n")).unwrap();
    let announced = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match feed.recv().await {
                Some(crate::backend::tools_nudge::ToolsNudge::Catalogue { name })
                    if name == "caps" =>
                {
                    return true;
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await;
    assert_eq!(
        announced,
        Ok(true),
        "the watcher's reload announced the listing"
    );
    assert_eq!(capabilities.listed_names(), ["keyed"]);
}
