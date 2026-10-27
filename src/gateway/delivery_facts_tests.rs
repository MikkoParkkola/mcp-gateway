// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record fields a delivery's facts produce.

use serde_json::{Map, Value, json};

use super::{Part, ResponseEffect, found, raise, record_fields, scanned, scope, snapshot};
use crate::security::Severity;

/// The fields the open cell records, given the frame's refusal.
fn recorded(frame_refused: bool) -> Map<String, Value> {
    let mut fields = Map::new();
    record_fields(snapshot().as_ref(), frame_refused, &mut fields);
    fields
}

#[tokio::test]
async fn outside_a_cell_nothing_is_recorded() {
    let mut fields = Map::new();
    record_fields(snapshot().as_ref(), true, &mut fields);
    assert!(fields.is_empty(), "{fields:?}");
}

#[tokio::test]
async fn unscanned_is_null_findings_and_scanned_clean_is_empty() {
    scope(async {
        let fields = recorded(false);
        assert_eq!(fields["response_effect"], "delivered");
        assert_eq!(fields["response_findings"], Value::Null);
        scanned();
        assert_eq!(recorded(false)["response_findings"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn the_strongest_effect_wins_whatever_the_order() {
    scope(async {
        raise(ResponseEffect::Refused);
        raise(ResponseEffect::Rewritten);
        raise(ResponseEffect::Annotated);
        assert_eq!(recorded(false)["response_effect"], "refused");
    })
    .await;
    scope(async {
        raise(ResponseEffect::Annotated);
        assert_eq!(recorded(false)["response_effect"], "annotated");
        assert_eq!(recorded(true)["response_effect"], "refused");
    })
    .await;
}

#[tokio::test]
async fn findings_are_most_severe_first_capped_at_32_with_a_total() {
    scope(async {
        for i in 0..40 {
            found(format!("firewall:k{i:02}"), Severity::Low, Part::Result);
        }
        found("firewall:z".into(), Severity::Critical, Part::Error);
        let fields = recorded(false);
        let listed = fields["response_findings"].as_array().expect("a list");
        assert_eq!(listed.len(), 32);
        assert_eq!(
            listed[0],
            json!({"kind": "firewall:z", "severity": "critical", "where": "error"})
        );
        assert_eq!(fields["response_findings_total"], 41);
    })
    .await;
}

#[tokio::test]
async fn an_unvouched_delivery_records_only_a_refusal() {
    scope(async {
        found("firewall:k".into(), Severity::High, Part::Result);
        super::unvouched();
        assert!(recorded(false).is_empty());
        let fields = recorded(true);
        assert_eq!(fields["response_effect"], "refused");
        assert!(fields.get("response_findings").is_none(), "{fields:?}");
    })
    .await;
}

#[tokio::test]
async fn a_suspended_scan_writes_nothing_to_the_delivery() {
    scope(async {
        super::suspended(|| {
            raise(ResponseEffect::Refused);
            found("firewall:k".into(), Severity::High, Part::Result);
        });
        let fields = recorded(false);
        assert_eq!(fields["response_effect"], "delivered");
        assert_eq!(fields["response_findings"], Value::Null);
    })
    .await;
}

/// Every production site that reads an answer back out of a store, as
/// `(needle, file, occurrences, why its delivery cannot state "delivered"
/// with no findings)`. A served stored answer is not this request's, so it
/// must clear `vouched` (`unvouched()`, or `note_cached()` which calls it),
/// with a row that fails without that call. Definitions and inline tests are
/// listed too, so the counts are exact.
const STORED_READS: &[(&str, &str, usize, &str)] = &[
    ("get_read(", "src/cache.rs", 4, "the response cache itself"),
    (
        "get_read(",
        "src/capability/executor/mod.rs",
        1,
        "a capability backend's own cache: its answer meets this request's egress scan",
    ),
    (
        "get_read(",
        "src/gateway/meta_mcp/invoke/cache_reads.rs",
        2,
        "inline tests",
    ),
    (
        "get_read(",
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        1,
        "served through GuardedValue::from_cache, which calls note_cached",
    ),
    (
        "CachedResult(",
        "src/idempotency/guard.rs",
        2,
        "the idempotency guard's outcome",
    ),
    (
        "CachedResult(",
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        1,
        "served through GuardedValue::from_cache",
    ),
    (
        "CachedResult(",
        "src/gateway/router/backend_handlers/direct_idempotency.rs",
        2,
        "deliver_replay calls note_cached",
    ),
    (
        "CachedError(",
        "src/idempotency/guard.rs",
        2,
        "the idempotency guard's outcome",
    ),
    (
        "CachedError(",
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        1,
        "note_cached_failure",
    ),
    (
        "CachedError(",
        "src/gateway/router/backend_handlers/direct_idempotency.rs",
        2,
        "note_cached_failure",
    ),
    (
        "Admission::Replay(",
        "src/idempotency/admission.rs",
        1,
        "the execution store's outcome",
    ),
    (
        "Admission::Replay(",
        "src/gateway/meta_mcp/admission.rs",
        3,
        "the execution store's outcome",
    ),
    (
        "Admission::Replay(",
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        1,
        "audit_replay calls unvouched",
    ),
    (
        "Admission::Replay(",
        "src/gateway/server/stdio_dispatch.rs",
        1,
        "audit_replay calls unvouched",
    ),
    (
        "Admission::Replay(",
        "src/gateway/router/backend_handlers/direct_idempotency.rs",
        1,
        "deliver_replay calls note_cached, or refuses",
    ),
    (
        "tasks_get(",
        "src/gateway/router/handlers/tasks.rs",
        1,
        "its definition",
    ),
    (
        "tasks_get(",
        "src/gateway/router/handlers.rs",
        1,
        "the tasks/get arm calls unvouched",
    ),
    (
        "dispatch_get(",
        "src/gateway/server/stdio_tasks.rs",
        2,
        "the tasks/get arm calls unvouched",
    ),
];

/// Whether `path`, relative to the crate, is test-only source, which serves
/// nothing.
fn test_only(path: &std::path::Path) -> bool {
    path.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        let stem = part.strip_suffix(".rs").unwrap_or(&part);
        stem == "tests"
            || stem.ends_with("_tests")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || stem.contains("fixture")
    })
}

fn production_sources(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) {
    for entry in std::fs::read_dir(dir).expect("src reads") {
        let path = entry.expect("a directory entry").path();
        if test_only(path.strip_prefix(root).expect("under the crate")) {
            continue;
        }
        if path.is_dir() {
            production_sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The scan row (lead ruling): a new way to serve a stored answer would
/// record `delivered` with null findings for bytes this request did not
/// produce. It cannot land without being inventoried above.
#[test]
fn every_stored_answer_read_is_inventoried() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    production_sources(root, &root.join("src"), &mut files);
    let needles: std::collections::BTreeSet<&str> =
        STORED_READS.iter().map(|(needle, ..)| *needle).collect();
    let mut found = std::collections::BTreeMap::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file reads");
        let name = file
            .strip_prefix(root)
            .expect("under the crate")
            .to_string_lossy()
            .replace('\\', "/");
        for needle in &needles {
            let count = text.matches(needle).count();
            if count > 0 {
                found.insert((*needle, name.clone()), count);
            }
        }
    }
    let listed: std::collections::BTreeMap<_, _> = STORED_READS
        .iter()
        .map(|(needle, file, count, _)| ((*needle, (*file).to_owned()), *count))
        .collect();
    assert_eq!(
        found, listed,
        "a stored-answer read changed: unvouch its delivery, add a row that fails without it, then list it"
    );
}

/// How a caller of the context-integrity transform treats its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransformUse {
    /// The function itself, or a call inside the transform.
    Inside,
    /// The result is the answer delivered: its raises and notes count.
    Delivering,
    /// The result is a copy never delivered: it runs with the facts cell and
    /// the gateway-write notes suspended.
    Suspended,
}

/// Every production occurrence of the transform's three entry points.
const TRANSFORM_CALLS: &[(&str, &str, usize, TransformUse)] = &[
    (
        "apply_context_integrity(",
        "src/gateway/meta_mcp/invoke/budget.rs",
        1,
        TransformUse::Inside,
    ),
    (
        "apply_context_integrity(",
        "src/gateway/meta_mcp/invoke/policy.rs",
        1,
        TransformUse::Delivering,
    ),
    (
        "apply_context_integrity(",
        "src/gateway/meta_mcp/invoke/relay.rs",
        1,
        TransformUse::Suspended,
    ),
    (
        "context_integrity_delivered_result(",
        "src/gateway/meta_mcp/invoke/budget.rs",
        2,
        TransformUse::Inside,
    ),
    (
        "attach_context_integrity_metadata(",
        "src/gateway/meta_mcp/invoke/budget.rs",
        2,
        TransformUse::Inside,
    ),
];

/// The scan row (lead ruling): a new caller of the transform would raise
/// and note into whatever delivery is open. It cannot land unclassified,
/// and a suspended caller must hold both suspensions.
#[test]
fn every_context_integrity_caller_is_classified() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    production_sources(root, &root.join("src"), &mut files);
    let needles: std::collections::BTreeSet<&str> =
        TRANSFORM_CALLS.iter().map(|(needle, ..)| *needle).collect();
    let mut found = std::collections::BTreeMap::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file reads");
        let name = file
            .strip_prefix(root)
            .expect("under the crate")
            .to_string_lossy()
            .replace('\\', "/");
        for needle in &needles {
            let count = text.matches(needle).count();
            if count > 0 {
                found.insert((*needle, name.clone()), count);
            }
        }
    }
    let listed: std::collections::BTreeMap<_, _> = TRANSFORM_CALLS
        .iter()
        .map(|(needle, file, count, _)| ((*needle, (*file).to_owned()), *count))
        .collect();
    assert_eq!(
        found, listed,
        "a context-integrity caller changed: classify it as delivering or suspended, then list it"
    );
    // The suspensions must wrap the call itself: each opens in the few
    // lines just before it, so one elsewhere in the file cannot stand in.
    for (needle, file, _, class) in TRANSFORM_CALLS {
        if *class == TransformUse::Suspended {
            let text = std::fs::read_to_string(root.join(file)).expect("reads");
            let at = text.find(needle).expect("listed above");
            let lead_in = &text[text[..at].len().saturating_sub(300)..at];
            for guard in ["delivery_facts::suspended(", "gateway_writes::suspended("] {
                assert!(
                    lead_in.contains(guard),
                    "{file}: {needle} is not inside {guard}"
                );
            }
        }
    }
}
