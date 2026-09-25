// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4 / SECRET.1: a disabled backend keeps its `${VAR}` text unexpanded, so
//! enabling it is where the unset variable must be caught. The admin panel
//! enables through `mutate_and_reload_outcome`; its reload re-runs the
//! expander and must keep the running config when the variable is unset.

use std::{sync::Arc, time::Duration};

use super::*;
use crate::config::Config;
use crate::gateway::test_helpers::write_owner_only;

#[tokio::test]
async fn enabling_a_backend_with_an_unset_var_is_refused_and_running_config_kept() {
    // GIVEN: a gateway running a config whose only backend is disabled and
    // references a variable nobody set
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  x:\n    enabled: false\n    http_url: \"http://127.0.0.1:9/mcp\"\n    \
         headers:\n      Authorization: \"Bearer ${MCP_GW_C4_RELOAD_NOPE}\"\n",
    )
    .expect("write config");
    let running = Config::load(Some(&path)).expect("a disabled backend's reference loads");
    let ctx = ReloadContext::new(
        path.clone(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );

    // WHEN: the admin panel's write path enables it
    let result = ctx
        .mutate_and_reload_outcome(&path, |config: &mut Config| {
            config.backends.get_mut("x").expect("backend x").enabled = true;
            Ok::<(), ()>(())
        })
        .await;

    // THEN: the reload is refused, naming the variable, and nothing is published
    match result {
        Err(ConfigWriteError::Failed(message)) => assert!(
            message.contains("MCP_GW_C4_RELOAD_NOPE"),
            "the refusal must name the unset variable: {message}"
        ),
        Err(ConfigWriteError::Busy) => panic!("reload lock was busy"),
        Ok(_) => panic!("enabling a backend with an unset ${{VAR}} was applied"),
    }
    assert!(
        !ctx.live_config.get().backends["x"].enabled,
        "the running config must keep the backend disabled"
    );
}
