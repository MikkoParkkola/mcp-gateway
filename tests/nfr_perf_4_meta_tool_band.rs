// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `NFR.PERF.4` — the Meta-MCP surface a model is shown stays inside 14..=16.
//!
//! Measured through `handle_tools_list`, never through builder arithmetic: the
//! served path pins `cost_report_enabled` on and appends surfaced tools, so a
//! count derived from `build_meta_tools` answers a different question than the
//! requirement asks.
use std::{path::PathBuf, sync::Arc, time::Duration};

use mcp_gateway::{
    backend::BackendRegistry,
    config::{Config, FailsafeConfig, WebhookConfig},
    config_reload::{LiveConfig, ReloadContext},
    gateway::{WebhookRegistry, test_helpers::MetaMcp},
    protocol::{JsonRpcResponse, RequestId, ToolsListResult},
    stats::UsageStats,
};

/// The band `NFR.PERF.4` states, as a range rather than a pinned number.
const BAND: std::ops::RangeInclusive<usize> = 14..=16;

fn decode_tools_list(response: JsonRpcResponse) -> ToolsListResult {
    serde_json::from_value(response.result.expect("tools/list should return a result"))
        .expect("tools/list result should deserialize")
}

fn make_reload_context(backends: Arc<BackendRegistry>) -> Arc<ReloadContext> {
    Arc::new(ReloadContext::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/gateway-full.yaml"),
        Arc::new(LiveConfig::new(Config::default())),
        backends,
        FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// Every gate the served path actually reads, at both settings.
fn meta_mcp_with(stats: bool, webhooks: bool, reload: bool) -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        stats.then(|| Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    if reload {
        meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    }
    if webhooks {
        meta_mcp.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
            WebhookConfig::default(),
        ))));
    }
    meta_mcp
}

#[test]
fn nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band() {
    for stats in [false, true] {
        for webhooks in [false, true] {
            for reload in [false, true] {
                let served = decode_tools_list(
                    meta_mcp_with(stats, webhooks, reload).handle_tools_list(RequestId::Number(1)),
                )
                .tools;
                assert!(
                    BAND.contains(&served.len()),
                    "served meta-tool surface must stay inside {BAND:?}: \
                     stats={stats} webhooks={webhooks} reload={reload} served {} tools: {:?}",
                    served.len(),
                    served.iter().map(|t| t.name.as_str()).collect::<Vec<_>>()
                );
            }
        }
    }
}
