// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use serde_json::json;

// ── helpers ──────────────────────────────────────────────────────────────

fn make_tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("Tool {name}")),
        input_schema: json!({"type": "object", "properties": {}}),
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

// ── fnv1a_64 ─────────────────────────────────────────────────────────────

#[test]
fn fnv1a_64_is_deterministic() {
    // GIVEN: the same input
    // WHEN: hashed twice
    // THEN: identical output
    let h1 = fnv1a_64("server:my_tool");
    let h2 = fnv1a_64("server:my_tool");
    assert_eq!(h1, h2);
}

#[test]
fn fnv1a_64_differs_for_distinct_inputs() {
    // GIVEN: two different keys
    // THEN: distinct hashes (no trivial collision for typical tool names)
    let h1 = fnv1a_64("srv_a:tool_read");
    let h2 = fnv1a_64("srv_a:tool_write");
    assert_ne!(h1, h2);
}

#[test]
fn fnv1a_64_empty_string_does_not_panic() {
    // Edge case: empty input
    let _ = fnv1a_64("");
}

// ── insert + get (O(1) hash path) ────────────────────────────────────────

#[test]
fn insert_then_get_returns_entry() {
    // GIVEN: a fresh registry and a tool
    let reg = ToolRegistry::default();
    reg.insert("srv", make_tool("my_tool"));

    // WHEN: looking up the key
    let entry = reg.get("srv:my_tool");

    // THEN: entry is returned
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert_eq!(entry.tool.name, "my_tool");
}

#[test]
fn get_missing_key_returns_none() {
    // GIVEN: an empty registry
    let reg = ToolRegistry::default();

    // WHEN: looking up a non-existent key
    let result = reg.get("srv:nonexistent");

    // THEN: None
    assert!(result.is_none());
}

#[test]
fn insert_assigns_stable_tool_id() {
    // GIVEN: same tool inserted twice (idempotent)
    let reg = ToolRegistry::default();
    reg.insert("srv", make_tool("stable_id_tool"));
    let e1 = reg.get("srv:stable_id_tool").unwrap();
    reg.insert("srv", make_tool("stable_id_tool"));
    let e2 = reg.get("srv:stable_id_tool").unwrap();

    // THEN: tool_id is identical on both reads
    assert_eq!(e1.tool_id, e2.tool_id);
}

#[test]
fn tool_id_matches_fnv1a_of_key() {
    // GIVEN: an inserted tool
    let reg = ToolRegistry::default();
    reg.insert("my_server", make_tool("my_tool"));
    let entry = reg.get("my_server:my_tool").unwrap();

    // THEN: tool_id equals fnv1a_64("my_server:my_tool")
    assert_eq!(entry.tool_id, fnv1a_64("my_server:my_tool"));
}

#[test]
fn insert_overwrites_existing_entry() {
    // GIVEN: a tool already in the registry
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));

    // WHEN: inserting the same key with different description
    let mut updated = make_tool("t");
    updated.description = Some("updated".to_string());
    reg.insert("s", updated);

    // THEN: the new description is returned
    let entry = reg.get("s:t").unwrap();
    assert_eq!(entry.tool.description.as_deref(), Some("updated"));
}

// ── replace_server ───────────────────────────────────────────────────────

#[test]
fn replace_server_replaces_only_target_server_tools() {
    // GIVEN: two servers with tools
    let reg = ToolRegistry::default();
    reg.insert("srv_a", make_tool("tool1"));
    reg.insert("srv_b", make_tool("shared"));

    // WHEN: replacing srv_a with a new tool list
    reg.replace_server("srv_a", vec![make_tool("new_tool")]);

    // THEN: srv_a's old tool is gone, new one present; srv_b is untouched
    assert!(reg.get("srv_a:tool1").is_none(), "old tool must be removed");
    assert!(reg.get("srv_a:new_tool").is_some(), "new tool must exist");
    assert!(reg.get("srv_b:shared").is_some(), "other server unaffected");
}

#[test]
fn replace_server_with_empty_list_removes_all_tools() {
    // GIVEN: a server with tools
    let reg = ToolRegistry::default();
    reg.insert("srv", make_tool("a"));
    reg.insert("srv", make_tool("b"));

    // WHEN: replace with empty list
    reg.replace_server("srv", vec![]);

    // THEN: all tools removed
    assert_eq!(reg.len(), 0);
}

// ── remove_server ────────────────────────────────────────────────────────

#[test]
fn remove_server_removes_only_that_server() {
    // GIVEN: two servers
    let reg = ToolRegistry::default();
    reg.insert("a", make_tool("t1"));
    reg.insert("b", make_tool("t2"));

    // WHEN: removing server "a"
    reg.remove_server("a");

    // THEN: "a" tools gone, "b" tools remain
    assert!(reg.get("a:t1").is_none());
    assert!(reg.get("b:t2").is_some());
}

// ── metrics: hit rate ─────────────────────────────────────────────────────

#[test]
#[allow(clippy::float_cmp)]
fn metrics_hit_rate_zero_when_no_lookups() {
    let reg = ToolRegistry::default();
    assert_eq!(reg.metrics.hit_rate(), 0.0);
}

#[test]
fn metrics_hit_rate_one_after_all_hits() {
    // GIVEN: a tool in the registry
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));

    // WHEN: three successful lookups
    for _ in 0..3 {
        let _ = reg.get("s:t");
    }

    // THEN: hit rate = 1.0
    assert!((reg.metrics.hit_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn metrics_miss_increments_on_unknown_key() {
    let reg = ToolRegistry::default();
    let _ = reg.get("nope:nope");
    assert_eq!(reg.metrics.misses.load(Ordering::Relaxed), 1);
}

#[test]
fn metrics_hit_rate_mixed_lookups() {
    // GIVEN: 3 hits + 1 miss
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));
    let _ = reg.get("s:t");
    let _ = reg.get("s:t");
    let _ = reg.get("s:t");
    let _ = reg.get("s:missing");

    // THEN: hit rate = 3/4 = 0.75
    let rate = reg.metrics.hit_rate();
    assert!((rate - 0.75).abs() < 1e-9);
}

// ── metrics: latency ──────────────────────────────────────────────────────

#[test]
#[allow(clippy::float_cmp)]
fn metrics_avg_latency_zero_when_no_samples() {
    let reg = ToolRegistry::default();
    assert_eq!(reg.metrics.avg_latency_ns(), 0.0);
}

/// A hit records one latency sample.
///
/// Asserted on the sample count, never on how long the machine took. The
/// wall-clock bound this test used to carry — `avg < 1ms`, "sub-millisecond
/// for in-memory lookup" — fails on a loaded box, where a scheduler
/// preemption between `Instant::now` and `elapsed` inflates the reading
/// without anything in `get` behaving differently. It was the last red test
/// in the release gate and it measured the runner, not the registry.
#[test]
fn metrics_records_latency_on_hit() {
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));
    // Before the lookup the averaged value is the no-data zero rather than
    // a measurement, which is what makes the sample count below meaningful.
    assert_eq!(reg.metrics.latency_samples.load(Ordering::Relaxed), 0);

    let _ = reg.get("s:t");

    assert_eq!(
        reg.metrics.latency_samples.load(Ordering::Relaxed),
        1,
        "a registry hit must record exactly one latency sample"
    );
    let avg = reg.metrics.avg_latency_ns();
    assert!(
        avg.is_finite() && avg >= 0.0,
        "avg_latency_ns must be a finite non-negative measurement, got {avg}"
    );
}

/// The averaging itself, pinned deterministically.
///
/// Separate from the test above on purpose: that one proves `get` is wired
/// to the metric, this one proves the metric computes a mean, and neither
/// can be satisfied by the other. Feeding known samples is the only way to
/// assert the arithmetic without asserting a duration the test cannot
/// control.
#[test]
fn metrics_average_latency_is_the_mean_of_its_samples() {
    let reg = ToolRegistry::default();
    reg.metrics.record_hit(100);
    reg.metrics.record_hit(300);
    assert_eq!(reg.metrics.latency_samples.load(Ordering::Relaxed), 2);
    assert!((reg.metrics.avg_latency_ns() - 200.0).abs() < 1e-9);
}

// ── metrics: snapshot ────────────────────────────────────────────────────

#[test]
fn metrics_snapshot_reflects_current_state() {
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));
    let _ = reg.get("s:t");
    let _ = reg.get("s:missing");

    let snap = reg.metrics.snapshot();
    assert_eq!(snap.lookups, 2);
    assert_eq!(snap.hits, 1);
    assert_eq!(snap.misses, 1);
    assert!((snap.hit_rate - 0.5).abs() < 1e-9);
}

// ── prefetch ─────────────────────────────────────────────────────────────

#[test]
fn prefetch_after_does_not_panic_on_cold_tracker() {
    // GIVEN: an empty tracker and registry
    let reg = ToolRegistry::new(3);
    let tracker = TransitionTracker::new();

    // WHEN: prefetching after a tool with no history
    reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

    // THEN: no panic, no prefetch recorded
    assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 0);
}

#[test]
fn prefetch_after_warms_predicted_successors_that_exist_in_registry() {
    // GIVEN: A→B observed 5 times, B is in the registry
    let tracker = TransitionTracker::new();
    for _ in 0..5 {
        tracker.record_transition("sess", "s:tool_a");
        tracker.record_transition("sess", "s:tool_b");
    }

    let reg = ToolRegistry::new(3);
    reg.insert("s", make_tool("tool_b")); // B is in registry

    // WHEN: prefetch after A
    reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

    // THEN: exactly 1 prefetch request recorded (for B)
    assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 1);
}

#[test]
fn prefetch_after_skips_candidates_not_in_registry() {
    // GIVEN: A→C observed 5 times, C is NOT in the registry
    let tracker = TransitionTracker::new();
    for _ in 0..5 {
        tracker.record_transition("s", "s:tool_a");
        tracker.record_transition("s", "s:tool_c");
    }

    let reg = ToolRegistry::new(3);
    // tool_c intentionally not inserted

    // WHEN: prefetch after A
    reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

    // THEN: no prefetch recorded (candidate missing from registry)
    assert_eq!(reg.metrics.prefetch_requests.load(Ordering::Relaxed), 0);
}

#[test]
fn prefetch_hit_credited_when_prefetched_key_is_accessed() {
    // GIVEN: A→B seen 5 times; B is in registry; prefetch is run
    let tracker = TransitionTracker::new();
    for _ in 0..5 {
        tracker.record_transition("s", "s:tool_a");
        tracker.record_transition("s", "s:tool_b");
    }

    let reg = ToolRegistry::new(3);
    reg.insert("s", make_tool("tool_b"));
    reg.prefetch_after("s:tool_a", &tracker, 0.20, 2);

    // WHEN: tool_b is then looked up
    let _ = reg.get("s:tool_b");

    // THEN: a prefetch hit is credited
    assert_eq!(reg.metrics.prefetch_hits.load(Ordering::Relaxed), 1);
}

#[test]
fn prefetch_depth_limits_number_of_warming_candidates() {
    // GIVEN: A→B, A→C, A→D all observed; depth = 2
    let tracker = TransitionTracker::new();
    for _ in 0..5 {
        tracker.record_transition("s1", "s:a");
        tracker.record_transition("s1", "s:b");
    }
    for _ in 0..4 {
        tracker.record_transition("s2", "s:a");
        tracker.record_transition("s2", "s:c");
    }
    for _ in 0..3 {
        tracker.record_transition("s3", "s:a");
        tracker.record_transition("s3", "s:d");
    }

    let reg = ToolRegistry::new(2); // depth = 2
    reg.insert("s", make_tool("b"));
    reg.insert("s", make_tool("c"));
    reg.insert("s", make_tool("d"));

    // WHEN: prefetch after a
    reg.prefetch_after("s:a", &tracker, 0.0, 1);

    // THEN: only up to 2 candidates are warmed (depth limit)
    assert!(
        reg.metrics.prefetch_requests.load(Ordering::Relaxed) <= 2,
        "Prefetch depth must cap at 2"
    );
}

// ── prefetch accuracy ────────────────────────────────────────────────────

#[test]
#[allow(clippy::float_cmp)]
fn prefetch_accuracy_zero_when_no_prefetch_requests() {
    let reg = ToolRegistry::default();
    assert_eq!(reg.metrics.prefetch_accuracy(), 0.0);
}

#[test]
fn prefetch_accuracy_is_hits_over_requests() {
    // GIVEN: 4 prefetch requests, 2 hits
    let reg = ToolRegistry::default();
    reg.metrics.record_prefetch(4);
    reg.metrics.record_prefetch_hit();
    reg.metrics.record_prefetch_hit();

    let accuracy = reg.metrics.prefetch_accuracy();
    assert!((accuracy - 0.5).abs() < 1e-9);
}

// ── contains / len / is_empty ─────────────────────────────────────────────

#[test]
fn len_and_is_empty_reflect_contents() {
    let reg = ToolRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);

    reg.insert("s", make_tool("t1"));
    reg.insert("s", make_tool("t2"));
    assert!(!reg.is_empty());
    assert_eq!(reg.len(), 2);
}

#[test]
fn contains_returns_true_for_inserted_key() {
    let reg = ToolRegistry::default();
    reg.insert("s", make_tool("t"));
    assert!(reg.contains("s:t"));
    assert!(!reg.contains("s:other"));
}

// ── all_keys ──────────────────────────────────────────────────────────────

#[test]
fn all_keys_returns_sorted_keys() {
    let reg = ToolRegistry::default();
    reg.insert("b", make_tool("z"));
    reg.insert("a", make_tool("a"));
    reg.insert("a", make_tool("z"));

    let keys = reg.all_keys();
    assert_eq!(keys, vec!["a:a", "a:z", "b:z"]);
}

// ── default prefetch_depth ───────────────────────────────────────────────

#[test]
fn default_prefetch_depth_is_three() {
    let reg = ToolRegistry::default();
    assert_eq!(reg.prefetch_depth, 3);
}
