// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH475.CFG.5 / CFG.5b — a configured error budget DECIDES, it does not merely
//! arrive.
//!
//! `gh475_cfg_5_error_budget_section_reaches_running_meta_mcp` (in this
//! module's parent) reads the effective config back off the running meta-MCP,
//! so it proves the operator's YAML reached the budgets. It cannot fail on a
//! gateway that stores the value and then decides on something else. These two
//! cases take the config as the boot path applied it and drive the real
//! `KillSwitch` decision functions with it, at a sample count that only the
//! configured budget can act on: two failures. Both defaults need more samples
//! before they evaluate anything (backend `min_samples` 10, capability 5,
//! `src/kill_switch/budget.rs`), so a boot path that dropped either setter
//! leaves a budget that cannot kill or disable here, and the assertion fails.
//!
//! Seam, stated rather than implied: `MetaMcp::record_error_budget`
//! (`src/gateway/meta_mcp/invoke.rs`) is private to its own module, so it
//! cannot be called from here. What these cases drive is the pair of
//! `KillSwitch` methods that recorder calls, with the same fields from the same
//! config it reads. That the recorder reaches the kill switch at all is pinned
//! separately by `ordinary_dispatch_failure_still_counts_against_both_budgets`
//! in `invoke.rs`.

use super::Gateway;
use crate::config::Config;

/// Boot a gateway from a literal `gateway.yaml`, returning what the boot path
/// built. The tempdir goes out of scope with the config already parsed —
/// nothing downstream re-reads the file.
async fn built_from_yaml(yaml: &str) -> super::BuiltMetaMcp {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("the configured error_budget must load");
    let gateway = Gateway::new(config).await.expect("gateway boots");
    gateway.build_meta_mcp().await.expect("meta-MCP builds")
}

/// GH475.CFG.5 — the configured backend threshold is what decides the kill.
///
/// `min_samples: 2` with `threshold: 0.2` is unreachable under the shipped
/// defaults: 2 failures against `min_samples: 10` are not enough samples to
/// evaluate at all, so a gateway ignoring the section cannot kill here however
/// the failures fall.
#[tokio::test]
async fn gh475_cfg_5_configured_backend_threshold_decides_the_kill() {
    let built = built_from_yaml(
        "error_budget:\n  threshold: 0.2\n  window_size: 10\n  window_duration: 5m\n  \
         min_samples: 2\n",
    )
    .await;

    let (backend, _capability) = built.meta_mcp.budget_configs();
    let kill_switch = built.meta_mcp.kill_switch();
    let server = "gh475-decides-backend";

    assert!(
        !kill_switch.is_killed(server),
        "a backend with no samples must not start out killed"
    );
    for _ in 0..2 {
        kill_switch.record_failure(
            server,
            backend.window_size,
            backend.window_duration,
            backend.threshold,
            backend.min_samples,
        );
    }

    assert!(
        kill_switch.is_killed(server),
        "two failures must exhaust a budget configured with min_samples 2 and \
         threshold 0.2; the effective budget was {backend:?}"
    );
}

/// GH475.CFG.5b — the configured capability threshold is what decides the
/// disable. The capability setter is a separate call on the boot path, so this
/// case fails independently of the backend one when only that call is dropped.
#[tokio::test]
async fn gh475_cfg_5b_configured_capability_threshold_decides_the_disable() {
    let built = built_from_yaml(
        "error_budget:\n  capability:\n    threshold: 0.2\n    window_size: 10\n    \
         window_duration: 5m\n    min_samples: 2\n    cooldown: 5m\n",
    )
    .await;

    let (_backend, capability) = built.meta_mcp.budget_configs();
    let kill_switch = built.meta_mcp.kill_switch();
    let (backend_name, capability_name) = ("gh475-decides-cap-backend", "gh475-decides-cap");

    assert!(
        !kill_switch.is_capability_disabled(backend_name, capability_name),
        "a capability with no samples must not start out disabled"
    );
    for _ in 0..2 {
        kill_switch.record_capability_failure(backend_name, capability_name, &capability);
    }

    assert!(
        kill_switch.is_capability_disabled(backend_name, capability_name),
        "two failures must exhaust a capability budget configured with min_samples 2 \
         and threshold 0.2; the effective budget was {capability:?}"
    );
}
