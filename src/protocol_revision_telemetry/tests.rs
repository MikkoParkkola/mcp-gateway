// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the protocol-revision measurement.

use super::*;
use serde_json::json;

#[test]
fn initialize_protocol_version_is_attributed() {
    let params = json!({"protocolVersion": "2025-06-18", "clientInfo": {"name": "claude"}});
    assert_eq!(
        requested_revision(Some(&params), None).as_deref(),
        Some("2025-06-18")
    );
    assert_eq!(client_identity(Some(&params), None), "claude");
}

#[test]
fn missing_protocol_version_is_unattributed_not_defaulted() {
    let params = json!({"clientInfo": {"name": "old"}});
    assert_eq!(requested_revision(Some(&params), None), None);
    assert_eq!(requested_revision(None, None), None);
}

#[test]
fn meta_protocol_version_wins_over_initialize() {
    let params = json!({"protocolVersion": "2025-06-18"});
    let meta = json!({META_PROTOCOL_VERSION: "2026-07-28"});
    assert_eq!(
        requested_revision(Some(&params), Some(&meta)).as_deref(),
        Some("2026-07-28")
    );
}

#[test]
fn unattributed_is_its_own_series() {
    let mut reg = Registry::new();
    reg.observe_request(Some("2025-11-25"), "claude-desktop", Transport::Http);
    reg.observe_request(None, "unknown", Transport::Stdio);
    let snap = reg.snapshot();
    assert_eq!(snap.total, 2);
    assert_eq!(snap.unattributed, 1);
    assert_eq!(snap.by_revision.get("2025-11-25"), Some(&1));
    assert_eq!(snap.by_client.get("claude"), Some(&1));
    assert_eq!(snap.by_client.get("other"), Some(&1));
    assert_eq!(snap.by_transport.get("http"), Some(&1));
    assert_eq!(snap.by_transport.get("stdio"), Some(&1));
    assert!(!snap.by_revision.contains_key("unattributed"));
    assert!((attribution_rate(&snap) - 0.5).abs() < f64::EPSILON);
    let table = distribution_table(&snap);
    assert!(table.contains("| unattributed | 1 |"));
    assert!(!table.contains("| unattributed | 1 |\n| unattributed |"));
}

#[test]
fn arbitrary_labels_are_bounded() {
    let mut reg = Registry::new();
    for i in 0..100 {
        reg.observe_request(
            Some(&format!("attacker-revision-{i}")),
            &format!("attacker-client-{i}"),
            Transport::Http,
        );
    }
    let snapshot = reg.snapshot();
    assert_eq!(snapshot.by_revision.len(), 1);
    assert_eq!(snapshot.by_revision.get(OTHER_REVISION), Some(&100));
    assert_eq!(snapshot.by_client.len(), 1);
    assert_eq!(snapshot.by_client.get("other"), Some(&100));
}

#[test]
fn every_supported_revision_has_a_dedicated_metric_label() {
    for revision in crate::protocol::SUPPORTED_VERSIONS {
        assert!(
            MEASURED_REVISIONS.contains(revision),
            "supported revision {revision} would collapse into the other bucket"
        );
    }
}

#[test]
fn notifications_are_not_request_observations() {
    let before = global_snapshot()
        .by_revision
        .get(OTHER_REVISION)
        .copied()
        .unwrap_or(0);
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    observe_inbound_request(
        &notification,
        None,
        "notifications/initialized",
        Some("notification-only-test-revision"),
        None,
        Transport::Http,
    );
    let after = global_snapshot()
        .by_revision
        .get(OTHER_REVISION)
        .copied()
        .unwrap_or(0);
    assert_eq!(after, before);
}

#[test]
fn cache_scope_public_only_when_unfiltered() {
    assert_eq!(
        cache_scope_decision(ListFilters::default()),
        CacheScope::Public
    );
    let filtered = ListFilters {
        principal: true,
        profile: false,
        session: false,
        request: false,
    };
    assert_eq!(cache_scope_decision(filtered), CacheScope::Private);
    assert!(!public_over_filtered(filtered, CacheScope::Private));
    assert!(public_over_filtered(filtered, CacheScope::Public));
}

#[test]
fn two_percent_rule_does_not_fire_on_underattributed_or_empty() {
    let empty = Registry::new().snapshot();
    assert_eq!(
        retire_revisions(&empty, MIN_MEASUREMENT_WINDOW),
        Err(RetirementBlocked::NoObservations)
    );
    let mut low = Registry::new();
    low.observe_request(Some("2025-06-18"), "c", Transport::Http);
    low.observe_request(None, "c", Transport::Http);
    // 50% attributed < 80% floor
    assert_eq!(
        retire_revisions(&low.snapshot(), MIN_MEASUREMENT_WINDOW),
        Err(RetirementBlocked::AttributionBelowFloor)
    );

    let mut ambiguous = Registry::new();
    for _ in 0..95 {
        ambiguous.observe_request(Some("2025-11-25"), "c", Transport::Http);
    }
    for _ in 0..5 {
        ambiguous.observe_request(None, "c", Transport::Http);
    }
    assert_eq!(
        retire_revisions(&ambiguous.snapshot(), MIN_MEASUREMENT_WINDOW),
        Err(RetirementBlocked::UnattributedAtOrAboveRetirementThreshold)
    );
}

#[test]
fn two_percent_rule_retires_only_below_floor_when_attributed() {
    let mut reg = Registry::new();
    for _ in 0..99 {
        reg.observe_request(Some("2025-11-25"), "c", Transport::Http);
    }
    reg.observe_request(Some("2024-11-05"), "c", Transport::Http);
    assert_eq!(
        retire_revisions(&reg.snapshot(), Duration::from_secs(1)),
        Err(RetirementBlocked::WindowTooShort)
    );
    let retired = retire_revisions(&reg.snapshot(), MIN_MEASUREMENT_WINDOW)
        .expect("full attributed window is actionable");
    assert!(retired.iter().any(|r| r == "2024-11-05"));
    // A supported revision with no traffic at all is retirable too. 4.0.0
    // dropped `2024-10-07` from `SUPPORTED_VERSIONS`, so the zero-traffic
    // stand-in is a revision the server still offers.
    assert!(retired.iter().any(|r| r == "2025-03-26"));
    assert!(!retired.iter().any(|r| r == "2025-11-25"));
}

#[test]
fn modern_request_is_observed_without_initialize() {
    let before = global_snapshot();
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                META_PROTOCOL_VERSION: "2026-07-28",
                META_CLIENT_INFO: {"name": "Codex"}
            }
        }
    });
    observe_inbound_request(
        &request,
        request.get("params"),
        "tools/list",
        None,
        None,
        Transport::Http,
    );
    let after = global_snapshot();
    assert!(
        after.by_revision.get("2026-07-28").copied().unwrap_or(0)
            > before.by_revision.get("2026-07-28").copied().unwrap_or(0)
    );
    assert!(
        after.by_client.get("codex").copied().unwrap_or(0)
            > before.by_client.get("codex").copied().unwrap_or(0)
    );
}

#[test]
fn legacy_stdio_followup_reuses_bounded_initialize_attribution() {
    let session_id = "mik-7218-legacy-stdio";
    let before = global_snapshot();
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "Claude Desktop"}
        }
    });
    observe_inbound_request(
        &initialize,
        initialize.get("params"),
        "initialize",
        None,
        Some(session_id),
        Transport::Stdio,
    );
    let followup = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    observe_inbound_request(
        &followup,
        None,
        "tools/list",
        None,
        Some(session_id),
        Transport::Stdio,
    );
    let after = global_snapshot();
    assert!(
        after.by_revision.get("2025-06-18").copied().unwrap_or(0)
            >= before.by_revision.get("2025-06-18").copied().unwrap_or(0) + 2
    );
}

#[test]
fn http_request_without_revision_does_not_reuse_session_attribution() {
    let session_id = "mik-7218-http-is-request-scoped";
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "Claude Desktop"}
        }
    });
    observe_inbound_request(
        &initialize,
        initialize.get("params"),
        "initialize",
        None,
        Some(session_id),
        Transport::Stdio,
    );
    let before = global_snapshot();
    let request = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    observe_inbound_request(
        &request,
        None,
        "tools/list",
        None,
        Some(session_id),
        Transport::Http,
    );
    let after = global_snapshot();
    assert!(after.unattributed > before.unattributed);
}

#[test]
fn shadow_tools_list_records_filters_and_would_be_scope() {
    let mut reg = Registry::new();
    let shadow = reg.shadow_tools_list(ListFilters {
        principal: false,
        profile: true,
        session: true,
        request: false,
    });
    assert!(shadow.profile && shadow.session);
    assert_eq!(shadow.would_emit_cache_scope, CacheScope::Private);
    assert_eq!(
        reg.shadow_count(ListFilters {
            principal: false,
            profile: true,
            session: true,
            request: false,
        }),
        1
    );
}
