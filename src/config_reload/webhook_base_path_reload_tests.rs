// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8002 test 2 (I5): a reload whose `webhooks.base_path` overlaps a
//! gateway route is refused, and the running config keeps its path.

use std::sync::Arc;

use super::*;
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

fn write(path: &std::path::Path, base_path: &str) {
    write_owner_only(
        path,
        format!("webhooks:\n  enabled: true\n  base_path: '{base_path}'\n"),
    )
    .expect("write config");
}

#[test]
fn a_reload_onto_a_gateway_route_is_refused_and_the_running_path_stays() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write(&config, "/webhooks");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    write(&config, "/mcp/hooks");
    let refused = load_config_patch(&config, &live, &env)
        .err()
        .expect("a base_path under /mcp refuses the reload");
    assert!(refused.contains("webhooks.base_path"), "{refused}");
    assert_eq!(live.running().webhooks.base_path, "/webhooks");
}
