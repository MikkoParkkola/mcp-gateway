// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The compacted meta-tool surface
//! (`docs/design/2026-09-16-meta-tool-surface-compaction.md`).
//!
//! Two questions, and the second is what makes the first safe to answer.
//! What does the shipped default gate configuration list to an admin caller,
//! and is every tool it stopped listing still callable by name? The cut moves
//! six tools from "listed for everyone" to "listed for the operators who
//! asked for them"; it deletes nothing, so a listing assertion on its own
//! would be satisfied just as well by a deletion.

use std::{path::PathBuf, sync::Arc, time::Duration};

use serde_json::json;

use super::MetaMcp;
use crate::{
    backend::BackendRegistry,
    config::{Config, FailsafeConfig, WebhookConfig},
    config_reload::{LiveConfig, ReloadContext},
    gateway::{WebhookRegistry, authz::AllowAll},
    protocol::{JsonRpcResponse, RequestId, ToolsListResult},
    stats::UsageStats,
};

/// The six tools the cut takes off the default listing, and the gate that
/// each one now waits for.
const CUT: [(&str, &str); 6] = [
    ("gateway_get_stats", "meta_mcp.expose_stats_tool"),
    ("gateway_cost_report", "cost_governance.enabled"),
    ("gateway_run_playbook", "a loaded playbook directory"),
    ("gateway_set_profile", "a configured routing profile"),
    ("gateway_get_profile", "a configured routing profile"),
    ("gateway_list_profiles", "a configured routing profile"),
];

/// The eleven names the headline figure counts.
const CEILING: [&str; 11] = [
    "gateway_list_servers",
    "gateway_list_tools",
    "gateway_search_tools",
    "gateway_invoke",
    "gateway_kill_server",
    "gateway_revive_server",
    "gateway_list_disabled_capabilities",
    "gateway_set_state",
    "gateway_reload_config",
    "gateway_reload_capabilities",
    "gateway_webhook_status",
];

fn make_reload_context(backends: Arc<BackendRegistry>) -> Arc<ReloadContext> {
    Arc::new(ReloadContext::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/gateway-full.yaml"),
        Arc::new(LiveConfig::new(Config::default())),
        backends,
        FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// A gateway in the shipped default gate configuration: a config file and a
/// webhook registry, no playbook directory, no routing profiles, cost
/// governance off, `meta_mcp.expose_stats_tool` off.
///
/// The usage-stats collector is attached deliberately. `serve` always passes
/// one (`src/gateway/server/mod.rs`), so a fixture without it would measure a
/// deployment that does not exist, and would let the stats gate look closed
/// for the wrong reason.
fn shipped_default() -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        Some(Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    meta_mcp.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    meta_mcp
}

fn listed(meta_mcp: &MetaMcp) -> Vec<String> {
    let response: JsonRpcResponse = meta_mcp.handle_tools_list(RequestId::Number(1));
    let result: ToolsListResult =
        serde_json::from_value(response.result.expect("tools/list returns a result"))
            .expect("tools/list result deserializes");
    result.tools.into_iter().map(|tool| tool.name).collect()
}

/// `NFR.PERF.4` headline: eleven at the admin ceiling in the shipped default
/// gate configuration.
#[test]
fn shipped_default_gate_configuration_lists_eleven_to_an_admin_caller() {
    let names = listed(&shipped_default());

    let mut expected: Vec<&str> = CEILING.to_vec();
    expected.sort_unstable();
    let mut actual: Vec<&str> = names.iter().map(String::as_str).collect();
    actual.sort_unstable();

    assert_eq!(
        actual, expected,
        "the shipped default gate configuration serves exactly the headline eleven"
    );
    assert_eq!(
        names.len(),
        11,
        "NFR.PERF.4 headline is 11 at the admin ceiling; served {names:?}"
    );
}

/// The other half of the cut, and the half a deletion would fail.
///
/// A gated-off tool is absent from `tools/list` and still answers
/// `tools/call`. `-32601` here would mean a gate leaked into dispatch and the
/// design is void (R6 in the design document).
#[tokio::test]
async fn every_tool_the_cut_stops_listing_is_still_callable_by_name() {
    let meta_mcp = shipped_default();
    let names = listed(&meta_mcp);
    let authorizer = AllowAll;

    for (tool, gate) in CUT {
        assert!(
            !names.contains(&tool.to_string()),
            "{tool} waits for {gate} and must not be listed without it: {names:?}"
        );

        let response = meta_mcp
            .handle_tools_call(
                RequestId::Number(2),
                tool,
                json!({}),
                None,
                super::authz_tests::ctx(&authorizer),
            )
            .await;
        if let Some(error) = response.error {
            assert_ne!(
                error.code, -32601,
                "{tool} is gated off the listing, not removed: tools/call answered \
                 unrecognised-tool ({})",
                error.message
            );
        }
    }
}
