// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8298: a hot reload that adds a pattern its section cannot match is
//! refused, and the running config keeps its rules.

use std::sync::Arc;

use super::{LiveConfig, load_config_patch};
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

fn deny(pattern: &str) -> String {
    format!("security:\n  tool_policy:\n    enabled: true\n    deny: [{pattern:?}]\n")
}

#[test]
fn a_reload_that_adds_an_inert_deny_is_refused_and_the_running_rules_stay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, deny("fs_*")).expect("write config");
    let startup = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    write_owner_only(&path, deny("*_delete")).expect("rewrite config");
    let refused = load_config_patch(&path, &live, &env)
        .err()
        .expect("a reload adding '*_delete' to a prefix-only deny list must be refused");
    assert!(
        refused.contains("security.tool_policy.deny[0]"),
        "{refused}"
    );
    assert!(refused.contains("\"*_delete\""), "{refused}");
    assert_eq!(
        live.get().security.tool_policy.deny,
        vec!["fs_*".to_string()],
        "a refused reload keeps the running rules"
    );
}
