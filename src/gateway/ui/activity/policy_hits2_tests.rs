// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hits per rule, continued: an edited rule, a scoped caller, a dark clock,
//! the members already served, one pattern listed twice, the window's
//! edges, an inactive built-in, a rotation during the read, no log, a record
//! the list cannot show, and a read that fails.

use super::policy_hits_tests::{
    a_rows, cells, config, decided, entries, firewall_id, p1_config, p1_fixture, policy_id, read,
    read_with, rule, stripped, write_log,
};
use super::scan_window_tests::{
    MIB, ago, fill_past_one_pass, n, rotate_past_sealed, rotating_logger, wall_now,
};
use super::{
    access::Access,
    counts::{COUNT_SCAN_BYTES, count_rule_hits},
    decision_fixtures::decision,
    reader::{Limits, read_page},
    rows::{Check, Filter, NOT_A_CALL, kind_of, row},
};
use crate::config_reload::LiveConfig;
use crate::gateway::ui::policies::{Sources, read_model, read_model_with_hits};
use crate::security::{
    TransparencyLogger,
    audit::{AuditEnvelope, AuditWho, InvocationTarget},
    decision_record::Decision,
    transparency_log::{CorrelationKey, CorrelationSource},
};
use chrono::{DateTime, FixedOffset, TimeDelta};
use serde_json::{Map, Value, json};
use std::ops::ControlFlow;

#[test]
fn p5_an_edited_rule_starts_from_zero() {
    let live = LiveConfig::new(config(vec![rule("a_tool", "one")], &[], &[], false));
    let old = firewall_id(&live.generation(), "a_tool");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    write_log(&path, a_rows(&old, &[1, 2]));
    let text = std::fs::read_to_string(&path).expect("the log");
    assert_eq!(
        text.matches(&old).count(),
        2,
        "premise: two records name the old id"
    );
    live.set(config(vec![rule("a_tool", "two")], &[], &[], false));
    let new = firewall_id(&live.generation(), "a_tool");
    assert_ne!(new, old);
    let model = read(&live, &path);
    assert_eq!(cells(&model["finding_rules"][0]), json!([new, 0, 0, 0]));
}

#[test]
fn p6_a_scoped_caller_counts_only_its_backends_calls() {
    let live = LiveConfig::new(config(Vec::new(), &[], &["delete_x"], false));
    let g = live.generation();
    let id = policy_id(&g, "alpha", "delete_x");
    assert_eq!(id, policy_id(&g, "beta", "delete_x"));
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    let rows = ["alpha", "alpha", "beta", "beta", "beta"]
        .into_iter()
        .map(|s| decided(s, "delete_x", "tool_policy", &id, ago(1)))
        .collect();
    write_log(&path, rows);
    let scoped = Access::Scoped {
        owner: None,
        backends: vec!["alpha".to_owned()],
    };
    for (access, hits, scope) in [(scoped, 2, "scoped"), (Access::All, 5, "all")] {
        let model = read_with(&live, Some(&path), &access, Ok(n()), COUNT_SCAN_BYTES);
        assert_eq!(model["tool_policy"]["deny"][0]["hits_24h"], hits, "{scope}");
        assert_eq!(model["hits"]["scope"], scope);
    }
}

#[test]
fn p7_a_dark_clock_reads_null() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (live, ids, path) = p1_fixture(dir.path());
    let dark = read_with(
        &live,
        Some(&path),
        &Access::All,
        Err(crate::clock::ClockBeforeEpoch),
        COUNT_SCAN_BYTES,
    );
    for e in entries(&dark) {
        assert!(
            e["hits_24h"].is_null() && e["hits_prev_24h"].is_null(),
            "{e}"
        );
    }
    assert_eq!(
        (&dark["hits"]["complete"], &dark["hits"]["stopped"]),
        (&json!(false), &Value::Null)
    );
    let lit = read(&live, &path);
    assert_eq!(cells(&lit["finding_rules"][0]), json!([ids.a, 3, 2, 2]));
}

#[test]
fn p8_every_existing_member_is_unchanged() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (live, _, path) = p1_fixture(dir.path());
    let model = stripped(&read(&live, &path));
    assert_eq!(model, read_model(&Sources::of(&live)));
    assert_eq!(
        model["tool_policy"]["deny"][0],
        json!({
            "entry": "srv:delete_*", "path": "security.tool_policy.deny[0]",
            "overridden_by": [],
            "partly_overridden_by": [
                "security.tool_policy.allow[0]",
                "security.tool_policy.allow[1]",
                "security.tool_policy.allow[2]",
            ],
        })
    );
    assert_eq!(
        model["tool_policy"]["default_denies"][0]["partly_overridden_by"],
        json!([
            "security.tool_policy.allow[0]",
            "security.tool_policy.allow[2]"
        ])
    );
    assert_eq!(
        model["tool_policy"]["allow"][2],
        json!({ "entry": "srv:write_file", "path": "security.tool_policy.allow[2]" })
    );
}

#[test]
fn p9_two_entries_with_one_pattern_share_an_id_and_show_the_same_counts() {
    let live = LiveConfig::new(config(Vec::new(), &[], &["srv:x", "srv:x"], false));
    let id = policy_id(&live.generation(), "srv", "x");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    write_log(&path, vec![decided("srv", "x", "tool_policy", &id, ago(1))]);
    let model = read(&live, &path);
    for i in 0..2 {
        let e = &model["tool_policy"]["deny"][i];
        assert_eq!(
            (&e["rule_id"], &e["hits_24h"]),
            (&json!(id), &json!(1)),
            "deny[{i}]"
        );
    }
}

#[test]
fn p10_the_window_edges() {
    let live = LiveConfig::new(config(Vec::new(), &[], &["srv:x"], false));
    let id = policy_id(&live.generation(), "srv", "x");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    // An hour past `n()` lies in neither day.
    let rows = [
        n() + crate::duration_bound::delta!(hours, 1),
        n(),
        ago(24),
        ago(48),
    ]
    .into_iter()
    .map(|at| decided("srv", "x", "tool_policy", &id, at))
    .collect();
    write_log(&path, rows);
    let model = read(&live, &path);
    let deny = &model["tool_policy"]["deny"][0];
    assert_eq!(
        (&deny["hits_24h"], &deny["hits_prev_24h"]),
        (&json!(2), &json!(1))
    );
    let older_end = ago(24) - TimeDelta::nanoseconds(1);
    assert_eq!(
        model["hits"]["older_to"],
        "2026-11-23T11:59:59.999999999+00:00"
    );
    assert_eq!(listed(&path, &id, ago(24), n()).len(), 2);
    assert_eq!(listed(&path, &id, ago(48), older_end).len(), 1);
}

/// The stamps of the rows the Activity list gives for rule `id` over
/// `[from, to]`: its own filter, then its own `row()`, which drops a line it
/// cannot project.
fn listed(
    path: &std::path::Path,
    id: &str,
    from: DateTime<FixedOffset>,
    to: DateTime<FixedOffset>,
) -> Vec<String> {
    let filter = Filter {
        rule: Some(id.to_owned()),
        from: Some(from),
        to: Some(to),
        ..Filter::default()
    };
    let limits = Limits {
        matches: 100,
        bytes: MIB,
    };
    let page = read_page(path, None, None, limits, |line| {
        kind_of(line).is_some_and(|kind| filter.matches(line, kind, &NOT_A_CALL))
    })
    .expect("read");
    let check = Check::new(None, path, None);
    page.lines
        .iter()
        .filter_map(|l| row(l, &check, &NOT_A_CALL))
        .map(|r| r["timestamp"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn p10b_a_sub_second_record_before_the_split() {
    let live = LiveConfig::new(config(Vec::new(), &[], &["srv:x"], false));
    let id = policy_id(&live.generation(), "srv", "x");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    let late = ago(24) - crate::duration_bound::delta!(milliseconds, 500);
    write_log(&path, vec![decided("srv", "x", "tool_policy", &id, late)]);
    let model = read(&live, &path);
    let deny = &model["tool_policy"]["deny"][0];
    assert_eq!(
        (&deny["hits_24h"], &deny["hits_prev_24h"]),
        (&json!(0), &json!(1))
    );
    // The older day as the answer states it lists exactly that record; the
    // newer day from the split lists nothing.
    let older_to = model["hits"]["older_to"].as_str().expect("an end");
    let older_to = DateTime::parse_from_rfc3339(older_to).expect("a time");
    assert_eq!(listed(&path, &id, ago(48), older_to), [late.to_rfc3339()]);
    assert!(listed(&path, &id, ago(24), n()).is_empty());
}

#[test]
fn p11_an_inactive_built_in_deny() {
    let live = LiveConfig::new(config(Vec::new(), &[], &[], true));
    let id = policy_id(&live.generation(), "other", "write_file");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    write_log(
        &path,
        vec![decided("other", "write_file", "tool_policy", &id, ago(1))],
    );
    // While active, the built-in carries that id and its hit.
    let on = read(&live, &path);
    assert_eq!(
        cells(&on["tool_policy"]["default_denies"][0]),
        json!([id, 1, 0, 0])
    );
    live.set(config(Vec::new(), &[], &[], false));
    let off = read(&live, &path);
    for e in off["tool_policy"]["default_denies"]
        .as_array()
        .expect("built-ins")
    {
        assert_eq!(cells(e), json!([null, 0, 0, 0]), "{e}");
    }
}

/// A call on `srv/delete_x` decided by `decision`, through the logger.
fn deny_call(log: &TransparencyLogger, decision: &Decision) {
    log.log_invocation_attributed(
        CorrelationKey {
            id: "s",
            source: CorrelationSource::SessionId,
        },
        &AuditEnvelope::ok(AuditWho::from_actor_id("c")),
        InvocationTarget::meta("srv", "delete_x"),
        "sha256:aa",
        Some("sha256:bb"),
        Map::new(),
        Some(decision),
    )
    .expect("written");
}

#[test]
fn p12_a_rotated_read_keeps_the_rules_and_nulls_the_counts() {
    let live = LiveConfig::new(p1_config());
    let id = policy_id(&live.generation(), "srv", "delete_x");
    let mut raw = decision(Some(&id));
    raw.as_object_mut()
        .expect("a decision")
        .retain(|k, _| !k.starts_with("SENTINEL"));
    let decision: Decision = serde_json::from_value(raw).expect("a decision");
    for rotate in [true, false] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = dir.path().join("inv.jsonl");
        let log = rotating_logger(&path);
        let written = fill_past_one_pass(&path, |_| deny_call(&log, &decision));
        let mut hooks = 0;
        let model = read_model_with_hits(
            &Sources::of(&live),
            Some((&path, None)),
            &Access::All,
            Ok(wall_now()),
            COUNT_SCAN_BYTES,
            |_| {
                if rotate && hooks == 0 {
                    rotate_past_sealed(&path, |_| deny_call(&log, &decision));
                }
                hooks += 1;
                ControlFlow::Continue(())
            },
        );
        if rotate {
            assert_eq!(stripped(&model), read_model(&Sources::of(&live)));
            for e in entries(&model) {
                assert!(
                    e["hits_24h"].is_null() && e["hits_prev_24h"].is_null(),
                    "{e}"
                );
            }
            assert_eq!(
                (&model["hits"]["complete"], &model["hits"]["stopped"]),
                (&json!(false), &json!("rotated"))
            );
        } else {
            assert_eq!(model["hits"]["stopped"], "end");
            assert_eq!(model["tool_policy"]["deny"][0]["hits_24h"], written);
        }
    }
}

/// Lead ruling 2026-11-24 (b): no transparency log is kept.
#[test]
fn p13_no_log_serves_the_rules_with_every_count_null() {
    let live = LiveConfig::new(p1_config());
    let model = read_with(&live, None, &Access::All, Ok(n()), COUNT_SCAN_BYTES);
    assert_eq!(model["finding_rules"].as_array().map(Vec::len), Some(2));
    assert!(!entries(&model).is_empty());
    for e in entries(&model) {
        assert!(
            e["hits_24h"].is_null() && e["hits_prev_24h"].is_null(),
            "{e}"
        );
    }
    assert_eq!(
        (&model["hits"]["complete"], &model["hits"]["stopped"]),
        (&json!(false), &Value::Null)
    );
}

/// Code seat finding (count and list parity): a record the list cannot show
/// as a row (no counter) is not counted, so a count never exceeds the list.
#[test]
fn p14_a_record_the_list_cannot_show_is_not_counted() {
    let live = LiveConfig::new(config(Vec::new(), &[], &["srv:x"], false));
    let id = policy_id(&live.generation(), "srv", "x");
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("inv.jsonl");
    let rows = [ago(1), ago(2)]
        .into_iter()
        .map(|at| decided("srv", "x", "tool_policy", &id, at))
        .collect();
    write_log(&path, rows);
    let unlisted = ago(1).to_rfc3339();
    let text = std::fs::read_to_string(&path).expect("the log");
    let edited: String = text
        .lines()
        .map(|line| {
            let mut entry: Value = serde_json::from_str(line).expect("a record");
            if entry["timestamp"] == unlisted.as_str() {
                entry.as_object_mut().expect("an object").remove("counter");
            }
            entry.to_string() + "\n"
        })
        .collect();
    std::fs::write(&path, edited).expect("the log");
    // Premise: both records name the rule, and the list shows one of them.
    let text = std::fs::read_to_string(&path).expect("the log");
    assert_eq!(text.matches(&id).count(), 2);
    assert_eq!(listed(&path, &id, ago(24), n()).len(), 1);
    let model = read(&live, &path);
    assert_eq!(model["tool_policy"]["deny"][0]["hits_24h"], 1);
}

/// A read that fails for any reason but a rotation still serves the rules,
/// with every count unknown (the builder's rule; the spec names none).
#[test]
fn p15_a_failed_read_serves_the_rules_with_every_count_null() {
    let live = LiveConfig::new(p1_config());
    let dir = crate::test_dir_keep::kept_tempdir();
    // A folder where the log file should be: the read fails.
    let path = dir.path().join("inv.jsonl");
    std::fs::create_dir(&path).expect("a folder");
    let failed = count_rule_hits(Ok(n()), &path, None, &Access::All, COUNT_SCAN_BYTES, |_| {
        ControlFlow::Continue(())
    });
    let kind = failed.expect_err("premise: the read fails").kind();
    assert_ne!(
        kind,
        std::io::ErrorKind::Interrupted,
        "premise: not a rotation"
    );
    let model = read(&live, &path);
    assert_eq!(model["finding_rules"].as_array().map(Vec::len), Some(2));
    for e in entries(&model) {
        assert!(
            e["hits_24h"].is_null() && e["hits_prev_24h"].is_null(),
            "{e}"
        );
    }
    assert_eq!(
        (&model["hits"]["complete"], &model["hits"]["stopped"]),
        (&json!(false), &Value::Null)
    );
}
