//! Unit tests for `tool_profiles` (RFC-0073).

use super::*;

// ── ProfileRegistry::record_usage ─────────────────────────────────────────────

#[test]
fn record_usage_increments_counter_on_each_call() {
    // GIVEN: empty registry
    let registry = ProfileRegistry::new();

    // WHEN: same user calls same tool three times
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");

    // THEN: count is 3
    let suggestions = registry.suggest_tools("alice", 10);
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].tool_name, "search");
    assert_eq!(suggestions[0].call_count, 3);
}

#[test]
fn record_usage_tracks_multiple_tools_per_user() {
    // GIVEN: empty registry
    let registry = ProfileRegistry::new();

    // WHEN: alice calls two different tools
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "summarise");

    // THEN: two distinct tools are tracked
    let suggestions = registry.suggest_tools("alice", 10);
    assert_eq!(suggestions.len(), 2);
}

#[test]
fn record_usage_isolates_users() {
    // GIVEN: two users call the same tool
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");
    registry.record_usage("bob", "search");

    // WHEN: suggesting for alice
    let alice = registry.suggest_tools("alice", 10);

    // THEN: only alice's count (2) is returned, not bob's (1)
    assert_eq!(alice[0].call_count, 2);

    // AND: bob's count is independent
    let bob = registry.suggest_tools("bob", 10);
    assert_eq!(bob[0].call_count, 1);
}

// ── ProfileRegistry::suggest_tools ────────────────────────────────────────────

#[test]
fn suggest_tools_returns_sorted_by_frequency_descending() {
    // GIVEN: alice with 3 tools at different call counts
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search"); // 1 call
    for _ in 0..5 {
        registry.record_usage("alice", "translate");
    } // 5 calls
    for _ in 0..3 {
        registry.record_usage("alice", "summarise");
    } // 3 calls

    // WHEN: suggest with limit=10
    let suggestions = registry.suggest_tools("alice", 10);

    // THEN: sorted translate > summarise > search
    assert_eq!(suggestions[0].tool_name, "translate");
    assert_eq!(suggestions[0].call_count, 5);
    assert_eq!(suggestions[1].tool_name, "summarise");
    assert_eq!(suggestions[2].tool_name, "search");
}

#[test]
fn suggest_tools_respects_limit() {
    // GIVEN: 5 distinct tools
    let registry = ProfileRegistry::new();
    for tool in &["a", "b", "c", "d", "e"] {
        registry.record_usage("alice", tool);
    }

    // WHEN: limit=3
    let suggestions = registry.suggest_tools("alice", 3);

    // THEN: at most 3 suggestions returned
    assert_eq!(suggestions.len(), 3);
}

#[test]
fn suggest_tools_returns_empty_for_unknown_user() {
    // GIVEN: empty registry
    let registry = ProfileRegistry::new();

    // WHEN: suggesting for unknown user
    let suggestions = registry.suggest_tools("ghost", 10);

    // THEN: empty Vec
    assert!(suggestions.is_empty());
}

#[test]
fn suggest_tools_returns_empty_when_limit_is_zero() {
    // GIVEN: registry with data
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");

    // WHEN: limit=0
    let suggestions = registry.suggest_tools("alice", 0);

    // THEN: empty Vec
    assert!(suggestions.is_empty());
}

// ── ProfileRegistry::get_profile ──────────────────────────────────────────────

#[test]
fn get_profile_returns_none_for_unknown_user() {
    // GIVEN: empty registry
    let registry = ProfileRegistry::new();

    // THEN: None
    assert!(registry.get_profile("nobody").is_none());
}

#[test]
fn get_profile_returns_snapshot_with_correct_totals() {
    // GIVEN: alice with 4 total calls
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "summarise");

    // WHEN: profile retrieved
    let snapshot = registry.get_profile("alice").unwrap();

    // THEN: totals and favourite are correct
    assert_eq!(snapshot.user_id, "alice");
    assert_eq!(snapshot.total_calls, 4);
    assert_eq!(snapshot.favourite_tool.as_deref(), Some("search"));
    assert!(snapshot.last_active_secs.is_some());
}

#[test]
fn get_profile_top_tools_are_ordered_by_frequency() {
    // GIVEN: alice with search×3, summarise×1
    let registry = ProfileRegistry::new();
    for _ in 0..3 {
        registry.record_usage("alice", "search");
    }
    registry.record_usage("alice", "summarise");

    // WHEN: profile retrieved
    let snapshot = registry.get_profile("alice").unwrap();

    // THEN: first entry is "search"
    assert_eq!(snapshot.top_tools[0].tool_name, "search");
}

// ── ProfileRegistry::user_count ───────────────────────────────────────────────

#[test]
fn user_count_reflects_distinct_users() {
    // GIVEN: registry with 3 distinct users
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");
    registry.record_usage("bob", "search");
    registry.record_usage("carol", "search");

    // THEN: user_count == 3
    assert_eq!(registry.user_count(), 3);
}

#[test]
fn user_count_zero_for_empty_registry() {
    // GIVEN: empty registry
    let registry = ProfileRegistry::new();

    // THEN: 0
    assert_eq!(registry.user_count(), 0);
}

// ── ToolProfile internals via ProfileRegistry ─────────────────────────────────

#[test]
fn favourite_tool_is_most_frequently_called() {
    // GIVEN: two tools with different call frequencies
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "search");
    registry.record_usage("alice", "read");

    // WHEN: profile fetched
    let snapshot = registry.get_profile("alice").unwrap();

    // THEN: favourite is "search"
    assert_eq!(snapshot.favourite_tool.as_deref(), Some("search"));
}

#[test]
fn all_snapshots_returns_entry_per_user() {
    // GIVEN: 2 users
    let registry = ProfileRegistry::new();
    registry.record_usage("alice", "search");
    registry.record_usage("bob", "translate");

    // WHEN: all_snapshots called
    let snapshots = registry.all_snapshots();

    // THEN: 2 entries, one per user
    assert_eq!(snapshots.len(), 2);
    let ids: Vec<&str> = snapshots.iter().map(|s| s.user_id.as_str()).collect();
    assert!(ids.contains(&"alice"));
    assert!(ids.contains(&"bob"));
}

// ── ToolSuggestion equality ───────────────────────────────────────────────────

#[test]
fn tool_suggestion_equality_is_structural() {
    let a = ToolSuggestion {
        tool_name: "search".to_string(),
        call_count: 5,
        last_used_secs: 1_700_000_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}
