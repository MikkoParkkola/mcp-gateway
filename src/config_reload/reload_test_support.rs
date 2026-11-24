// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared setup for the reload tests: a started gateway from one file, then a reload of another against it. Moved
//! unchanged from `firewall_shape_reload_tests.rs` so the reload rows share one setup instead of retyping it.

use std::sync::Arc;

use super::{LiveConfig, load_config_patch};
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

/// A started gateway from `startup`, and a reload of `reload` against it.
pub(super) fn reload_after(startup: &str, reload: &str) -> (Result<(), String>, Arc<LiveConfig>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, startup).expect("write config");
    let started = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(started.config.clone()));
    let env = LiveEnv::new(started.overlay, started.env_paths);
    write_owner_only(&path, reload).expect("rewrite config");
    let outcome = load_config_patch(&path, &live, &env).map(|_| ());
    (outcome, live)
}
