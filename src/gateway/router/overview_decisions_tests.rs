// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview`'s open-decisions row: the decision set's count and
//! revision, the same pair the count route serves; an unreadable source named
//! in `degraded`; no set adds nothing; the row never folds. The needs-you
//! helpers it shares live in overview_needs_you_tests.rs.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{Value, json};

use super::AppState;
use super::overview_needs_you_tests::{
    edited, needs_you_kinds, pairs, reload_refused, rows, with_reload,
};
use super::overview_sources_tests::{record, with_store};
use super::overview_tests::{ADMIN_KEY, fixture, get_at, overview};
use crate::clock::test_clock;
use crate::counters::Tally;
use crate::decisions::{AdoptFind, Health, Shared, Source, UnreadableFile, UnreadableReason};
use crate::discovery::DiscoverySource;
use crate::discovery::shadow::ShadowRiskSeverity;

/// An unmanaged client find called `name`.
fn adopt(name: &str) -> AdoptFind {
    AdoptFind {
        find_id: format!("find-{name}"),
        name: name.to_owned(),
        source: DiscoverySource::ClaudeDesktop,
        config_file: Some("client.json".to_owned()),
        transport: "http",
        command: None,
        url: Some(format!("https://{name}.example.invalid/mcp")),
        severity: ShadowRiskSeverity::High,
    }
}

/// A decision set attached to `state`: access, control plane and capability
/// absent, and one adopt item per name in `finds`.
pub(super) fn ready_set(state: &AppState, finds: &[&str]) -> Arc<Shared> {
    let set = Arc::new(Shared::with_key([9; 32]));
    set.update(|s| {
        for source in [Source::Access, Source::ControlPlane, Source::Capability] {
            s.set_health(source, Health::Absent);
        }
        let finds = finds.iter().map(|n| adopt(n)).collect();
        s.set_discovery(finds, vec![], 1, Utc::now());
    });
    state.meta_mcp.set_decisions(Arc::clone(&set));
    set
}

/// D1 (DEC.2): open decisions are one row with the set's count and
/// revision, the same pair the count route serves; it follows the set; a
/// count of zero is no row.
#[tokio::test]
async fn d1_open_decisions_are_one_row_with_count_and_revision() {
    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &["d1-a", "d1-b"]);
    let broken = || UnreadableFile {
        source: DiscoverySource::VsCode,
        file: "user.json".to_owned(),
        path_digest: "d1-u".to_owned(),
        reason: UnreadableReason::DidNotParse,
    };
    let two = || vec![adopt("d1-a"), adopt("d1-b")];
    set.update(|s| s.set_discovery(two(), vec![broken()], 2, Utc::now()));
    let view = set.view().expect("every source readable");
    let kinds: Vec<(&str, &str)> = view
        .decisions
        .iter()
        .map(|d| {
            (
                d["kind"].as_str().unwrap_or("?"),
                d["server"]["name"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    assert!(kinds.contains(&("adopt", "d1-a")) && kinds.contains(&("adopt", "d1-b")));
    assert!(kinds.iter().any(|(k, _)| *k == "client_config_unreadable"));
    let (count, revision) = set.snapshot().expect("readable");
    assert!(count == 3 && count as u64 != revision, "{count} {revision}");

    let body = overview(&state).await;

    let row = json!({"kind": "decisions", "subject": "decisions", "detail": {"count": 3, "revision": revision}});
    assert_eq!(rows(&body), [row], "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
    let uri = "/ui/api/decisions/count";
    let (status, raw) = get_at(&state, uri, Some(ADMIN_KEY)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{raw}");
    let served: Value = serde_json::from_str(&raw).expect("a JSON body");
    assert_eq!(served, json!({"count": 3, "revision": revision}));

    let mut three = two();
    three.push(adopt("d1-c"));
    set.update(|s| s.set_discovery(three, vec![broken()], 3, Utc::now()));
    let body = overview(&state).await;
    let detail = &rows(&body)[0]["detail"];
    assert_eq!(detail["count"], 4, "{body}");
    assert_ne!(detail["revision"], revision, "{body}");

    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &[]);
    assert!(matches!(set.snapshot(), Some((0, _))), "an empty set");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
}

/// D2 (DEC.2): an unreadable decision source is no row and a `degraded`
/// name, never a zero; it extends the other degraded names.
#[tokio::test]
async fn d2_an_unreadable_decision_source_is_degraded_never_zero() {
    let (state, _dir) = fixture(0, false).await;
    let set = ready_set(&state, &["d2-a"]);
    set.update(|s| s.discovery_down());
    assert_eq!(set.snapshot(), None, "unreadable");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert_eq!(body["degraded"], json!(["needs_you.decisions"]), "{body}");

    // Beside the counter fields an unreadable clock degrades.
    let (state, _dir) = fixture(1, false).await;
    let store = with_store(&state, 0);
    record(&store, "key:d2", "name-000", 1_000, Tally::default());
    let _clock = test_clock::before_epoch();
    ready_set(&state, &["d2-a"]).update(|s| s.discovery_down());
    let body = overview(&state).await;
    let mut names: Vec<&str> = body["degraded"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    names.sort_unstable();
    let mut want = [
        "checklist.tool_tried",
        "edges",
        "kpi.blocks_24h",
        "kpi.calls_24h",
        "kpi.errors_24h",
        "latency",
        "markers",
        "needs_you.decisions",
        "servers.calls_24h",
    ];
    want.sort_unstable();
    assert_eq!(names, want, "{body}");
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
}

/// D3: with no decision set the overview adds no row and no degraded name.
#[tokio::test]
async fn d3_no_decision_set_adds_nothing() {
    let (state, _dir) = fixture(0, false).await;
    assert!(state.meta_mcp.decisions().is_none(), "no set");
    let body = overview(&state).await;
    assert!(!needs_you_kinds(&body).contains(&"decisions"), "{body}");
    assert!(body.get("degraded").is_none(), "{body}");
}

/// D6: the decisions row sits right after the invalid config and never
/// folds, however many refusals follow.
#[tokio::test]
async fn d6_the_decisions_row_survives_a_full_list() {
    let (state, dir) = fixture(0, false).await;
    let (context, _path) = with_reload(&state, &dir);
    reload_refused(context.refusals(), "Failed to parse config: bad");
    for i in 0..30 {
        edited(&context, &format!("b{i:02}"));
    }
    let set = ready_set(&state, &["d6-a", "d6-b"]);
    let (_, revision) = set.snapshot().expect("readable");

    let body = overview(&state).await;

    let shown = rows(&body);
    assert_eq!(shown.len(), 20, "{body}");
    assert_eq!(shown[0]["kind"], "invalid_config", "{body}");
    let row = json!({"kind": "decisions", "subject": "decisions", "detail": {"count": 2, "revision": revision}});
    assert_eq!(shown[1], row, "{body}");
    assert!(shown[2..].iter().all(|r| r["kind"] == "refused"), "{body}");
    let subjects: Vec<&str> = pairs(&body)[2..].iter().map(|&(_, s)| s).collect();
    let want: Vec<String> = (12..30).rev().map(|i| format!("b{i:02}")).collect();
    assert_eq!(subjects, want, "{body}");
    let more = json!({"count": 12, "by_kind": {"refused": 12}});
    assert_eq!(body["needs_you"]["more"], more, "{body}");
}
