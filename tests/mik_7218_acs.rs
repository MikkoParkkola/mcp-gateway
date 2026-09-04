// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7218 acceptance tests. Drive the shipped telemetry functions, not a copy.

use mcp_gateway::protocol_revision_telemetry::{
    ATTRIBUTION_FLOOR, CacheScope, ListFilters, META_CLIENT_INFO, META_PROTOCOL_VERSION,
    MIN_MEASUREMENT_WINDOW, RETIRE_BELOW_SHARE, Registry, Transport, attribution_rate,
    cache_scope_decision, client_identity, distribution_table, global_snapshot,
    observe_inbound_request, public_over_filtered, requested_revision, retire_revisions,
};
use serde_json::json;

#[test]
fn mcp728_u1_1_initialize_and_meta_paths_record_revision_and_client() {
    let init = json!({
        "protocolVersion": "2025-06-18",
        "clientInfo": {"name": "stdio-client"}
    });
    assert_eq!(
        requested_revision(Some(&init), None).as_deref(),
        Some("2025-06-18")
    );
    assert_eq!(client_identity(Some(&init), None), "stdio-client");

    let meta = json!({
        META_PROTOCOL_VERSION: "2026-07-28",
        META_CLIENT_INFO: {"name": "streamable-http-client"}
    });
    assert_eq!(
        requested_revision(None, Some(&meta)).as_deref(),
        Some("2026-07-28")
    );
    assert_eq!(client_identity(None, Some(&meta)), "streamable-http-client");

    let before = global_snapshot();
    let modern_request = json!({
        "jsonrpc": "2.0",
        "id": 7218,
        "method": "tools/list",
        "params": {"_meta": meta}
    });
    observe_inbound_request(
        &modern_request,
        modern_request.get("params"),
        "tools/list",
        None,
        None,
        Transport::Http,
    );
    let legacy_request = json!({"jsonrpc": "2.0", "id": 7219, "method": "tools/list"});
    observe_inbound_request(
        &legacy_request,
        None,
        "tools/list",
        Some("2025-06-18"),
        None,
        Transport::Http,
    );
    let after = global_snapshot();
    assert!(
        after.by_revision.get("2026-07-28").copied().unwrap_or(0)
            > before.by_revision.get("2026-07-28").copied().unwrap_or(0)
    );
    assert!(
        after.by_revision.get("2025-06-18").copied().unwrap_or(0)
            > before.by_revision.get("2025-06-18").copied().unwrap_or(0)
    );
}

#[test]
fn mcp728_u1_2_unattributed_is_own_series_not_hidden_in_total() {
    let mut reg = Registry::new();
    reg.observe_request(Some("2025-11-25"), "claude", Transport::Stdio);
    reg.observe_request(None, "", Transport::Http);
    let snap = reg.snapshot();
    assert_eq!(snap.total, 2);
    assert_eq!(snap.unattributed, 1);
    assert_eq!(snap.by_revision.values().sum::<u64>(), 1);
    assert!(
        !snap.by_revision.contains_key("unattributed"),
        "unattributed must not be a revision bucket"
    );
    let table = distribution_table(&snap);
    assert!(table.contains("| unattributed | 1 |"));
    assert!(table.contains("| total | 2 |"));
}

#[test]
fn mcp728_u1_3_tools_list_shadows_filters_and_would_be_cache_scope() {
    let mut reg = Registry::new();
    let filtered = ListFilters {
        principal: true,
        profile: false,
        session: true,
        request: false,
    };
    let shadow = reg.shadow_tools_list(filtered);
    assert!(shadow.principal && shadow.session);
    assert_eq!(shadow.would_emit_cache_scope, CacheScope::Private);
    assert_eq!(cache_scope_decision(filtered), CacheScope::Private);
    assert!(public_over_filtered(filtered, CacheScope::Public));
    assert!(!public_over_filtered(filtered, CacheScope::Private));
}

#[test]
fn mcp728_u1_4_measurement_window_table_and_stop_criterion() {
    let mut reg = Registry::new();
    // In-process window. Production week has not elapsed; empty production
    // snapshot must not freeze Decision 2.
    let production = Registry::new().snapshot();
    assert_eq!(production.total, 0);
    assert!(attribution_rate(&production).abs() <= f64::EPSILON);
    assert!(
        attribution_rate(&production) < ATTRIBUTION_FLOOR,
        "empty window is not fit to decide on"
    );
    assert!(retire_revisions(&production, MIN_MEASUREMENT_WINDOW).is_empty());

    for _ in 0..5 {
        reg.observe_request(Some("2025-11-25"), "test", Transport::Http);
    }
    let table = distribution_table(&reg.snapshot());
    assert!(table.contains("2025-11-25"));
    assert!(table.contains("| total | 5 |"));
}

#[test]
fn mcp728_u1_5_public_over_filtered_is_detectable() {
    let hazard = public_over_filtered(
        ListFilters {
            principal: true,
            profile: false,
            session: false,
            request: false,
        },
        CacheScope::Public,
    );
    assert!(hazard);
    let mut reg = Registry::new();
    let shadow = reg.shadow_tools_list(ListFilters {
        principal: true,
        profile: false,
        session: false,
        request: false,
    });
    assert!(!public_over_filtered(
        ListFilters {
            principal: shadow.principal,
            profile: shadow.profile,
            session: shadow.session,
            request: shadow.request,
        },
        shadow.would_emit_cache_scope
    ));
}

#[test]
fn mcp728_u1_6_two_percent_rule_unadjusted_and_blocked_when_underattributed() {
    assert!((RETIRE_BELOW_SHARE - 0.02).abs() <= f64::EPSILON);
    let mut under = Registry::new();
    under.observe_request(Some("2024-11-05"), "c", Transport::Http);
    under.observe_request(None, "c", Transport::Http);
    assert!(retire_revisions(&under.snapshot(), MIN_MEASUREMENT_WINDOW).is_empty());

    let mut full = Registry::new();
    for _ in 0..99 {
        full.observe_request(Some("2025-11-25"), "c", Transport::Http);
    }
    full.observe_request(Some("2024-11-05"), "c", Transport::Http);
    assert!(retire_revisions(&full.snapshot(), std::time::Duration::from_secs(1)).is_empty());
    let retired = retire_revisions(&full.snapshot(), MIN_MEASUREMENT_WINDOW);
    assert!(retired.iter().any(|r| r == "2024-11-05"));
    assert!(retired.iter().any(|r| r == "2024-10-07"));
    assert!(!retired.iter().any(|r| r == "2025-11-25"));
}
