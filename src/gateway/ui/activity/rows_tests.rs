// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R1, R2, R4 and R6 of the U2 test plan, at the row level, plus the
//! Developer join.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{FeedOutcome, Filter, Kind, kind_of, owned_by, row};
use crate::gateway::ui::activity::reader::{Line, Which};
use crate::security::decision_record::read::{
    NO_FINDINGS, NOT_RECORDED_BY_VERSION, NOT_RECORDED_FOR_CALL,
};

const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn line(log: Which, entry: Value) -> Line {
    Line {
        log,
        entry,
        segment: 0,
    }
}

fn call(outcome: &str) -> Value {
    json!({
        "counter": 7, "timestamp": "2026-10-26T10:00:00+00:00",
        "prev_entry_hash": HASH, "entry_hash": HASH,
        "outcome": outcome, "error_code": -32000,
        "server": "srv", "tool": "search_docs", "route": "meta_invoke",
        "trace_id": "t-1", "request_hash": "sha256:aa", "response_hash": "sha256:bb",
        "who": {"credential_kind": "oidc_bearer", "account": "acct", "authority": "https://x",
                "subject": "s", "principal": "abcdef012345"},
        "caller": "acct", "session_id": "sess", "correlation_source": "trace_id",
        "schema_version": 2, "sig": "hmac-sha256:00", "key_id": "k",
        "extra_field_never_named": "leak"
    })
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

const COMMON: [&str; 7] = [
    "id",
    "kind",
    "counter",
    "timestamp",
    "prev_entry_hash",
    "entry_hash",
    "signature",
];

#[test]
fn r1_each_kind_holds_exactly_its_allowlist() {
    let r = row(&line(Which::Invocation, call("ok")), None).unwrap();
    let mut want = set(&COMMON);
    want.extend(set(&[
        "outcome",
        "error_code",
        "server",
        "tool",
        "route",
        "trace_id",
        "request_hash",
        "response_hash",
        "who",
        "findings",
    ]));
    assert_eq!(keys(&r), want);
    assert_eq!(
        keys(&r["who"]),
        set(&["credential_kind", "account", "authority", "subject"]),
        "who.principal is never shown"
    );
    assert_eq!(r["findings"], NOT_RECORDED_BY_VERSION);
    assert_eq!(r["id"], "7-0123456789abcdef");

    let config = json!({
        "kind": "control_plane_audit", "counter": 3, "timestamp": null,
        "prev_entry_hash": HASH, "entry_hash": HASH,
        "event_id": "e1", "action": "mutate_grant", "actor_id": "alice", "target_id": "srv",
        "reason": "pasted secret", "rollback_summary": "r", "rollback_step": "s",
        "grant_change": {"x": 1}, "extra_field_never_named": "leak"
    });
    let r = row(&line(Which::Governance, config), None).unwrap();
    let mut want = set(&COMMON);
    want.extend(set(&["action", "actor_id", "target_id", "outcome"]));
    assert_eq!(keys(&r), want);
    assert_eq!(r["id"], "g3-0123456789abcdef");

    let admin = json!({
        "event": "admin_action", "counter": 4, "timestamp": "2026-10-26T10:00:00+00:00",
        "prev_entry_hash": HASH, "entry_hash": HASH,
        "surface": "ui", "route": "/ui/api/reload", "method": "POST", "http_status": 200,
        "tool": "t", "who": {"account": "a"}, "extra_field_never_named": "leak"
    });
    let r = row(&line(Which::Invocation, admin), None).unwrap();
    let mut want = set(&COMMON);
    want.extend(set(&[
        "surface",
        "route",
        "method",
        "http_status",
        "tool",
        "outcome",
    ]));
    assert_eq!(keys(&r), want);
}

#[test]
fn r2_outcomes_group_into_ok_failed_and_blocked() {
    for (recorded, feed) in [
        ("ok", "ok"),
        ("tool_error", "failed"),
        ("error", "failed"),
        ("denied", "blocked"),
        ("invalid", "blocked"),
    ] {
        let r = row(&line(Which::Invocation, call(recorded)), None).unwrap();
        assert_eq!(r["outcome"], feed, "{recorded}");
    }
    let only = |o| Filter {
        outcome: Some(o),
        ..Filter::default()
    };
    let blocked = line(Which::Invocation, call("denied"));
    assert!(only(FeedOutcome::Blocked).matches(&blocked, Kind::Call));
    assert!(!only(FeedOutcome::Ok).matches(&blocked, Kind::Call));
    let config = line(Which::Governance, json!({"kind": "control_plane_audit"}));
    assert!(!only(FeedOutcome::Ok).matches(&config, Kind::Config));
    assert!(Filter::default().matches(&config, Kind::Config));
}

#[test]
fn r4_each_filter_and_their_and() {
    let a = line(Which::Invocation, call("ok"));
    let mut other = call("ok");
    other["server"] = "other".into();
    other["who"]["account"] = "someone".into();
    let b = line(Which::Invocation, other);
    let f = |f: Filter| (f.matches(&a, Kind::Call), f.matches(&b, Kind::Call));
    let base = Filter::default;
    assert_eq!(
        f(Filter {
            server: Some("srv".into()),
            ..base()
        }),
        (true, false)
    );
    assert_eq!(
        f(Filter {
            caller: Some("someone".into()),
            ..base()
        }),
        (false, true)
    );
    for q in ["search_docs", "docs", "t-1"] {
        assert_eq!(
            f(Filter {
                q: Some(q.into()),
                ..base()
            }),
            (true, true),
            "{q}"
        );
    }
    assert_eq!(
        f(Filter {
            q: Some("t-".into()),
            ..base()
        }),
        (false, false),
        "a call id matches exactly, not as a substring"
    );
    // AND: server of a and caller of b match neither.
    assert_eq!(
        f(Filter {
            server: Some("srv".into()),
            caller: Some("someone".into()),
            ..base()
        }),
        (false, false)
    );
    let t = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok();
    assert!(
        Filter {
            from: t("2026-10-26T09:00:00Z"),
            to: t("2026-10-26T11:00:00Z"),
            ..base()
        }
        .matches(&a, Kind::Call)
    );
    assert!(
        !Filter {
            from: t("2026-10-26T10:00:01Z"),
            ..base()
        }
        .matches(&a, Kind::Call)
    );
    let mut untimed = call("ok");
    untimed["timestamp"] = Value::Null;
    let untimed = line(Which::Invocation, untimed);
    assert!(Filter::default().matches(&untimed, Kind::Call));
    assert!(
        !Filter {
            to: t("2030-01-01T00:00:00Z"),
            ..base()
        }
        .matches(&untimed, Kind::Call),
        "an untimed row is outside every time range"
    );
}

#[test]
fn r6_other_record_kinds_are_not_listed() {
    for entry in [
        json!({"action": "token_exchange", "subject": "s", "backend": "b", "request_hash": "x"}),
        json!({"event": "audit_segment_sealed"}),
        json!({"event": "response_delivery_attempt", "request_hash": "x"}),
        json!({"type": "audit_probe", "request_hash": "x"}),
        json!({"event": "tenant_read"}),
    ] {
        assert_eq!(
            kind_of(&line(Which::Invocation, entry.clone())),
            None,
            "{entry}"
        );
    }
    assert_eq!(
        kind_of(&line(Which::Governance, json!({"event": "x"}))),
        None
    );
}

#[test]
fn developer_rows_join_on_issuer_and_subject() {
    let mut e = call("ok");
    e["who"]["authority"] = "https://x".into();
    e["who"]["subject"] = "s".into();
    let mine = line(Which::Invocation, e);
    assert!(owned_by(&mine, Kind::Call, "https://x", "s"));
    assert!(
        !owned_by(&mine, Kind::Call, "https://y", "s"),
        "same subject, other issuer"
    );
    assert!(!owned_by(&mine, Kind::Call, "https://x", "t"));
    let mut no_subject = call("ok");
    no_subject["who"] = json!({"account": "bearer"});
    assert!(!owned_by(
        &line(Which::Invocation, no_subject),
        Kind::Call,
        "https://x",
        "s"
    ));
    assert!(!owned_by(&mine, Kind::Config, "https://x", "s"));
}

/// The row's `findings` for a call carrying `decision` (or none).
fn findings_of(decision: Option<Value>) -> Value {
    let mut e = call("ok");
    if let Some(d) = decision {
        e["decision"] = d;
    }
    row(&line(Which::Invocation, e), None).unwrap()["findings"].clone()
}

#[test]
fn row_findings_is_the_readers_line() {
    let kind = |v: u8| json!({"v": v, "kind": "tool_policy", "decided": "fresh"});
    let with_found = |found: Value| {
        let mut d = kind(2);
        d["request_findings"] = found;
        d
    };
    let one = json!({"scan_type": "pii", "severity": "high", "location": "arguments.q"});
    assert_eq!(findings_of(Some(with_found(json!([])))), NO_FINDINGS);
    assert_eq!(findings_of(Some(kind(2))), NOT_RECORDED_FOR_CALL);
    assert_eq!(
        findings_of(Some(with_found(json!([one.clone()])))),
        json!([one])
    );
    assert_eq!(findings_of(Some(kind(1))), NOT_RECORDED_BY_VERSION);
    assert_eq!(findings_of(None), NOT_RECORDED_BY_VERSION);
}
