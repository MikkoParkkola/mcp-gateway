// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8375: a refused reload is logged, so its reason must not carry the
//! value the new config got wrong.

use std::sync::Arc;

use super::*;
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

#[test]
fn a_refused_reload_does_not_log_the_value() {
    let sentinel = "cfgleak-sentinel-r4";
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, "server:\n  port: 39400\n").expect("write config");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);

    write_owner_only(
        &config,
        format!("server:\n  port: 39400\nauth:\n  bearer_token: !!int {sentinel}\n"),
    )
    .expect("break it");
    let Err(reason) = load_config_patch(&config, &live, &env) else {
        panic!("the reload must be refused");
    };
    assert!(!reason.contains(sentinel), "the value leaked: {reason}");
    assert!(reason.contains("auth.bearer_token"), "{reason}");
}
