// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b rows B7, B7c, B7 persisted and B8: tool-profile times on a
//! dark clock. Each is read through the serialized form, which is the field's
//! wire contract (`null` when undated), so the rows compile against today's
//! `u64` fields and fail at their assertions.

use std::time::Duration;

use super::analytics::UsageAnalytics;
use super::persistence;
use super::*;
use crate::clock::test_clock;

/// A readable clock, seconds after the epoch.
const T: u64 = 1_000_000;

fn suggestion<'a>(suggestions: &'a [ToolSuggestion], tool: &str) -> &'a ToolSuggestion {
    suggestions
        .iter()
        .find(|s| s.tool_name == tool)
        .unwrap_or_else(|| panic!("{tool} in {suggestions:?}"))
}

fn last_used(suggestion: &ToolSuggestion) -> serde_json::Value {
    serde_json::to_value(suggestion).expect("a suggestion serializes")["last_used_secs"].clone()
}

/// MIK-8202 AC.2, P4b design r2/r3 B7 (kept by r4): a use on a dark clock
/// keeps the entry's last real time; an entry first made on a dark clock is
/// undated (`last_used_secs` null), and an undated entry never sorts as the
/// most recent.
///
/// Red on base: base reads the wall clock directly, so the forced clocks never
/// reach it; "search" carries the real time, not `T`, and the first assertion
/// fails ("fresh" would carry a number, not null).
///
/// Mutant B7m (`Some(0)` stored on Err): "fresh" serializes as 0, killed by
/// the `is_null` assertion. A mutant writing the dark use over the last real
/// time (`increment` storing on Err) is killed by the `== T` assertion.
#[test]
fn a_use_on_a_dark_clock_keeps_the_last_time_and_a_new_entry_is_undated() {
    let registry = ProfileRegistry::new();
    {
        let _clock = test_clock::at_secs(T);
        registry.record_usage("alice", "search");
        registry.record_usage("alice", "dated");
    }
    {
        let _clock = test_clock::before_epoch();
        registry.record_usage("alice", "search");
        registry.record_usage("alice", "fresh");
    }
    let suggestions = registry.suggest_tools("alice", 10);
    let search = suggestion(&suggestions, "search");
    assert_eq!(search.call_count, 2, "the dark use still counts");
    assert_eq!(
        last_used(search),
        serde_json::json!(T),
        "B7: a dark use keeps the last real time"
    );
    assert!(
        last_used(suggestion(&suggestions, "fresh")).is_null(),
        "B7: an entry made on a dark clock is undated"
    );
    let order: Vec<&str> = suggestions
        .iter()
        .filter(|s| s.call_count == 1)
        .map(|s| s.tool_name.as_str())
        .collect();
    assert_eq!(
        order,
        ["dated", "fresh"],
        "B7: at equal counts the undated entry sorts after the dated one"
    );
}

/// MIK-8202 AC.2, P4b design r3/r4 B7 (test plan r2 row B7c): a profile
/// created on a dark clock has `created_at` null; one created on a readable
/// clock carries its time.
///
/// Red on base: base reads the wall clock directly, so the dark profile carries
/// the real time and the `is_null` assertion fails.
///
/// Mutant B7m (`Some(0)` on Err, `created_at`): serializes 0, killed by the
/// `is_null` assertion.
#[test]
fn a_profile_created_on_a_dark_clock_has_no_creation_time() {
    let registry = ProfileRegistry::new();
    {
        let _clock = test_clock::before_epoch();
        registry.record_usage("bob", "search");
    }
    {
        let _clock = test_clock::at_secs(T);
        registry.record_usage("carol", "search");
    }
    let created_at = |user: &str| {
        let profile = registry.get_profile(user).expect("the profile exists");
        serde_json::to_value(profile).expect("a snapshot serializes")["created_at"].clone()
    };
    assert!(
        created_at("bob").is_null(),
        "B7c: a profile created dark is undated"
    );
    assert_eq!(created_at("carol"), serde_json::json!(T));
}

/// MIK-8202 AC.2, P4b design r3 B7 ("a persisted profile still deserializes a
/// number, and null when undated"): a profiles file holding null for
/// `created_at` and `last_used_secs` loads, and so does one holding numbers;
/// each round-trips its value.
///
/// Red on base: both persisted fields are `u64`, so `load` of the null file is
/// a parse error and the `expect` on it fails.
///
/// Mutant B7p (a persisted field left non-optional): the null file fails to
/// load, killed by the same `expect`.
#[test]
fn a_persisted_profile_loads_with_a_number_or_null_time() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let file = |name: &str, created_at: &str, used: &str| {
        let path = dir.path().join(name);
        let json = format!(
            r#"{{"saved_at":{T},"profiles":{{"alice":{{"user_id":"alice","created_at":{created_at},
            "tools":[{{"tool_name":"search","call_count":3,"last_used_secs":{used}}}]}}}}}}"#
        );
        std::fs::write(&path, json).expect("write the profiles file");
        path
    };
    for (name, created_at, used, expected) in [
        ("null.json", "null", "null", serde_json::Value::Null),
        ("number.json", "1000000", "1000000", serde_json::json!(T)),
    ] {
        let loaded = persistence::load(&file(name, created_at, used))
            .unwrap_or_else(|e| panic!("B7: the {name} profile loads: {e}"));
        let alice = serde_json::to_value(&loaded.profiles["alice"]).expect("serializes");
        assert_eq!(alice["created_at"], expected, "{name}");
        assert_eq!(alice["tools"][0]["last_used_secs"], expected, "{name}");
    }
}

/// MIK-8202 AC.2, P4b design r1 B8 (kept by r4): `active_users` on a clock
/// before 1970 returns 0, since no user can be judged active.
///
/// Red on base: base reads the wall clock directly, so the forced dark clock
/// does not reach it; with the real time as "now" both users (dated at `T`
/// on the fixed clock after the fix, at the real time on base) are counted
/// by the generous window and the `== 0` assertion fails.
///
/// Mutant B8m (cutoff 0 on Err, today's behaviour): every user with a dated
/// call counts (2), killed by the `== 0` assertion.
#[test]
fn no_user_is_active_on_a_dark_clock() {
    let registry = ProfileRegistry::new();
    {
        let _clock = test_clock::at_secs(T);
        registry.record_usage("alice", "search");
        registry.record_usage("bob", "search");
    }
    let analytics = UsageAnalytics::compute(&registry);
    {
        let _clock = test_clock::at_secs(T + 60);
        assert_eq!(
            analytics.active_users(Duration::from_secs(3_600)),
            2,
            "premise: on a readable clock both are active"
        );
    }
    let _clock = test_clock::before_epoch();
    assert_eq!(
        analytics.active_users(Duration::from_secs(3_600)),
        0,
        "B8: on a dark clock no user is judged active"
    );
}
