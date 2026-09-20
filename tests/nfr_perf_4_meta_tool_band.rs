// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `NFR.PERF.4` — the Meta-MCP surface a model is shown stays inside 9..=17.
//!
//! Measured through `handle_tools_list`, never through builder arithmetic: the
//! served path appends surfaced tools and applies the operator allow-list, so
//! a count derived from `build_meta_tools` answers a different question than
//! the requirement asks.
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use mcp_gateway::{
    backend::BackendRegistry,
    config::{Config, FailsafeConfig, WebhookConfig},
    config_reload::{LiveConfig, ReloadContext},
    gateway::{WebhookRegistry, test_helpers::MetaMcp},
    playbook::{PlaybookDefinition, PlaybookEngine},
    protocol::{JsonRpcResponse, RequestId, ToolsListResult},
    routing_profile::{ProfileRegistry, RoutingProfileConfig},
    stats::UsageStats,
};

/// The band `NFR.PERF.4` states, as a range rather than a pinned number.
///
/// Quantified over **gate configuration at the admin ceiling**, and over
/// nothing else. Every count here is what an admin caller is served; a
/// Standard caller is served fewer, and that is a different question with a
/// different answer (`docs/design/2026-09-16-meta-tool-surface-compaction.md`
/// §7). Nine is every gate off. The top is 17, not 16, because
/// `webhooks.enabled` defaults to true, so an HTTP deployment serving
/// `gateway_webhook_status` is the shipped default rather than an exotic
/// combination. See
/// `docs/design/2026-09-08-perf4-webhook-status-restoration.md`.
const BAND: std::ops::RangeInclusive<usize> = 9..=17;

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

/// A one-step playbook, enough to make the engine non-empty.
fn one_playbook() -> PlaybookEngine {
    let definition: PlaybookDefinition =
        serde_yaml::from_str("name: probe\ndescription: makes the engine non-empty\nsteps: []\n")
            .expect("playbook fixture must parse");
    let mut engine = PlaybookEngine::new();
    engine.register(definition);
    engine
}

/// One configured routing profile, enough to give the profile tools something
/// to describe.
fn one_profile() -> ProfileRegistry {
    let mut configs = HashMap::new();
    configs.insert("probe".to_string(), RoutingProfileConfig::default());
    ProfileRegistry::from_config(&configs, "probe")
}

/// The gate settings a deployment can be in. Every field is one gate the
/// served path reads; each is set through the same entry point production
/// uses, so a combination here is a deployment that can exist.
#[derive(Clone, Copy)]
// Independent gates read from six different sources; an enum would only
// rename them, and the band is precisely the sweep over their product.
#[allow(clippy::struct_excessive_bools)]
struct Gates {
    stats: bool,
    webhooks: bool,
    reload: bool,
    /// Only read where the feature that attaches a cost registry is
    /// compiled in; the axis carries `false` alone otherwise.
    #[cfg_attr(not(feature = "cost-governance"), allow(dead_code))]
    cost_report: bool,
    playbooks: bool,
    profiles: bool,
}

/// Every gate the served path actually reads, at both settings.
///
/// The usage-stats collector is attached unconditionally because `serve`
/// attaches one unconditionally; `gates.stats` is the operator opt-in that
/// actually governs the listing.
///
/// Coverage boundary: the registry is empty, so the sweep measures the meta
/// surface alone. No backend tool is ever surfaced or promoted into the
/// listing, and the band this file pins is the meta-tool band, not a bound on
/// everything `tools/list` can return.
fn meta_mcp_with(gates: Gates) -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    #[allow(unused_mut)]
    let mut meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        Some(Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    )
    .with_expose_stats_tool(gates.stats);
    if gates.profiles {
        meta_mcp = meta_mcp.with_profile_registry(one_profile());
    }
    #[cfg(feature = "cost-governance")]
    if gates.cost_report {
        let cfg = mcp_gateway::cost_accounting::config::CostGovernanceConfig {
            enabled: true,
            ..Default::default()
        };
        let registry = Arc::new(mcp_gateway::cost_accounting::registry::CostRegistry::new(
            &cfg,
        ));
        let enforcer = Arc::new(mcp_gateway::cost_accounting::enforcer::BudgetEnforcer::new(
            cfg,
            Arc::clone(&registry),
        ));
        meta_mcp = meta_mcp.with_cost_governance(enforcer, registry);
    }
    if gates.playbooks {
        meta_mcp.set_playbook_engine(one_playbook());
    }
    if gates.reload {
        meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    }
    if gates.webhooks {
        meta_mcp.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
            WebhookConfig::default(),
        ))));
    }
    meta_mcp
}

/// Both settings of the cost gate, or only `false` where the feature that
/// attaches a registry is compiled out. Sweeping `true` without the feature
/// would sweep a duplicate of `false` and report a narrower band as passing.
#[cfg(feature = "cost-governance")]
const COST_AXIS: [bool; 2] = [false, true];
#[cfg(not(feature = "cost-governance"))]
const COST_AXIS: [bool; 1] = [false];

/// The highest count this build can reach, which is the band's ceiling only
/// where the cost gate can be turned on at all. Derived from the swept axes
/// rather than from `BAND`: asserting against `BAND.end()` in a build that
/// compiled the cost tool out would fail for the configuration rather than
/// for a regression.
#[cfg(feature = "cost-governance")]
const ATTAINABLE_CEILING: usize = 17;
#[cfg(not(feature = "cost-governance"))]
const ATTAINABLE_CEILING: usize = 16;

#[test]
fn nfr_perf_4_1_every_feature_combination_serves_a_surface_inside_the_band() {
    let mut seen: Vec<usize> = Vec::new();
    for stats in [false, true] {
        for webhooks in [false, true] {
            for reload in [false, true] {
                for cost_report in COST_AXIS {
                    for playbooks in [false, true] {
                        for profiles in [false, true] {
                            let gates = Gates {
                                stats,
                                webhooks,
                                reload,
                                cost_report,
                                playbooks,
                                profiles,
                            };
                            let served = decode_tools_list(
                                meta_mcp_with(gates).handle_tools_list(RequestId::Number(1)),
                            )
                            .tools;
                            let names: Vec<&str> = served.iter().map(|t| t.name.as_str()).collect();
                            seen.push(served.len());
                            assert!(
                                BAND.contains(&served.len()),
                                "served meta-tool surface must stay inside {BAND:?}: \
                                 stats={stats} webhooks={webhooks} reload={reload} \
                                 cost_report={cost_report} playbooks={playbooks} \
                                 profiles={profiles} served {} tools: {names:?}",
                                served.len()
                            );
                            // Widening the band alone would let the tool stay
                            // deleted and still pass every range assertion, so
                            // what reaches the model is pinned here rather than
                            // only how many things do.
                            assert_eq!(
                                names.contains(&"gateway_webhook_status"),
                                webhooks,
                                "the webhook diagnostic is served exactly when its \
                                 registry is attached: stats={stats} webhooks={webhooks} \
                                 reload={reload} served {names:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    // A band nothing reaches the ends of is a band that fits anything. Both
    // ends have to be attained by some deployment, or widening the range would
    // be free.
    assert_eq!(
        seen.iter().min().copied(),
        Some(*BAND.start()),
        "some gate configuration must attain the floor of {BAND:?}"
    );
    assert!(
        BAND.contains(&ATTAINABLE_CEILING),
        "the ceiling this build can reach must itself be inside {BAND:?}"
    );
    // Containment alone leaves the published ceiling free to move: a `BAND` of
    // `9..=18` satisfies every other assertion here untouched. Where the cost
    // gate can be compiled in at all, the highest attainable count IS the
    // published ceiling, so pin them together. Builds that compiled the cost
    // tool out keep the containment form above, for the reason given at
    // `ATTAINABLE_CEILING`.
    #[cfg(feature = "cost-governance")]
    assert_eq!(
        ATTAINABLE_CEILING,
        *BAND.end(),
        "the published ceiling of {BAND:?} must be the highest attainable count"
    );
    assert_eq!(
        seen.iter().max().copied(),
        Some(ATTAINABLE_CEILING),
        "some gate configuration must attain {ATTAINABLE_CEILING}, the highest \
         count this build's features allow"
    );
}
