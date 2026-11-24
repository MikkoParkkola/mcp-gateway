// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Outcome group's counts (UI6.3, UI6.4): each count is the number of
//! rows the Activity list shows for that value over the same window.

use std::ops::ControlFlow;
use std::path::Path;

use chrono::{DateTime, FixedOffset, TimeDelta};

use super::counts::{COUNT_SCAN_BYTES, CountsQuery, count_page};
use super::decision_fixtures::{call, decision};
use super::scan_window_tests::{
    MIB, depth, fill_past_one_pass, line_len, n, plain, rotate_past_sealed, rotating_log, stamped,
    wall_now,
};
use super::*;
use crate::security::transparency_log::recompute_entry_hash;

/// Marks a record that is written without its counter.
const NO_COUNTER: &str = "__no_counter";

/// `entry`, written with no counter: its hash holds and its delivery record
/// still joins, but the list cannot show it as a row.
fn unlisted(mut entry: Value) -> Value {
    entry[NO_COUNTER] = true.into();
    entry
}

/// Marks the time a record is stamped with, in place of its position.
const AT: &str = "__at";

/// `entry`, stamped `t` when it is written.
fn at(mut entry: Value, t: DateTime<FixedOffset>) -> Value {
    entry[AT] = t.to_rfc3339().into();
    entry
}

/// `m` minutes before `n()`.
fn minutes(m: i64) -> DateTime<FixedOffset> {
    n() - TimeDelta::try_minutes(m).expect("minutes in range")
}

/// Write `entries` oldest first, chained and hashed, unsigned. Entry `i` of
/// `len` is stamped `len - i` seconds before `n()`, inside the window,
/// unless [`at`] gave it a time.
fn write(path: &Path, entries: Vec<Value>) {
    let len = entries.len();
    let mut prev = "genesis".to_owned();
    let mut text = String::new();
    for (i, mut entry) in entries.into_iter().enumerate() {
        let seconds = i64::try_from(len - i).expect("a short log");
        let place = n() - TimeDelta::try_seconds(seconds).expect("seconds in range");
        let fields = entry.as_object_mut().expect("a record");
        if fields.remove(NO_COUNTER).is_none() {
            fields.insert("counter".into(), (i + 1).into());
        }
        let stamp = match fields.remove(AT) {
            Some(Value::String(t)) => t,
            _ => place.to_rfc3339(),
        };
        fields.insert("timestamp".into(), stamp.into());
        fields.insert("prev_entry_hash".into(), prev.into());
        let hash = recompute_entry_hash(&entry).expect("a hash");
        entry["entry_hash"] = hash.clone().into();
        text.push_str(&(entry.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, text).expect("the log");
}

/// The invocation log, and the governance log when it has records.
fn written(dir: &tempfile::TempDir, invocation: Vec<Value>, governance: Vec<Value>) -> Logs {
    let path = dir.path().join("inv.jsonl");
    write(&path, invocation);
    let governance = (!governance.is_empty()).then(|| {
        let gov = dir.path().join("gov.jsonl");
        write(&gov, governance);
        gov
    });
    Logs {
        invocation: path,
        governance,
        secret: None,
    }
}

/// A call on its own trace that ended in `outcome`.
fn ended(trace: &str, outcome: &str) -> Value {
    let mut e = call("srv", trace, None);
    e["outcome"] = outcome.into();
    e["trace_id"] = trace.into();
    e
}

/// The record that finalized `trace`'s answer with `effect`.
fn delivered(trace: &str, effect: &str) -> Value {
    json!({
        "event": "response_delivery_attempt", "response_stage": "transport_finalized",
        "response_effect": effect, "trace_id": trace,
    })
}

/// A call an identity grant refused, with no invocation record of its own.
fn refused(trace: &str) -> Value {
    json!({
        "kind": crate::decisions::GRANT_DECISION_KIND, "outcome": "denied",
        "invocation_recorded": false, "server": "srv", "tool": trace,
        "trace_id": trace, "who": {"account": "acct"},
    })
}

fn admin_action() -> Value {
    json!({
        "event": "admin_action", "surface": "ui", "route": "/ui/api/settings",
        "method": "PUT", "http_status": 200, "who": {"account": "acct"},
    })
}

fn config_change() -> Value {
    json!({
        "kind": "control_plane_audit", "action": "role_mapping.update",
        "actor_id": "acct", "target_id": "roles",
    })
}

/// The window every row reads: the hour ending at `n()`.
fn bounds() -> (Option<String>, Option<String>) {
    let hour = TimeDelta::try_hours(1).expect("an hour");
    (Some((n() - hour).to_rfc3339()), Some(n().to_rfc3339()))
}

fn window() -> CountsQuery {
    let (from, to) = bounds();
    CountsQuery {
        from,
        to,
        ..CountsQuery::default()
    }
}

fn list_window(outcome: Option<&str>) -> ListQuery {
    let (from, to) = bounds();
    ListQuery {
        outcome: outcome.map(str::to_owned),
        from,
        to,
        ..ListQuery::default()
    }
}

async fn parsed(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).expect("JSON")
}

async fn body(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    parsed(response).await
}

/// What one counts read gave back, and how many passes its scan reported.
struct Answer {
    status: StatusCode,
    body: Value,
    passes: usize,
}

async fn ask(logs: &Logs, access: &Access, query: &CountsQuery, cap: u64) -> Answer {
    let mut passes = 0;
    let response = count_page(logs, access, query, cap, |_| {
        passes += 1;
        ControlFlow::Continue(())
    });
    let status = response.status();
    let body = parsed(response).await;
    Answer {
        status,
        body,
        passes,
    }
}

/// The counts answer for `query`, read by an admin with the full cap.
async fn counts(logs: &Logs, query: CountsQuery) -> Value {
    let answer = ask(logs, &Access::All, &query, COUNT_SCAN_BYTES).await;
    assert_eq!(answer.status, StatusCode::OK);
    answer.body
}

/// The window's query with one more field set.
fn with(set: impl FnOnce(&mut CountsQuery)) -> CountsQuery {
    let mut query = window();
    set(&mut query);
    query
}

fn some(text: &str) -> Option<String> {
    Some(text.to_owned())
}

/// The window's query with a parameter the counts route does not take.
fn sent(name: &str, value: &str) -> CountsQuery {
    with(|q| {
        q.other.insert(name.to_owned(), value.to_owned());
    })
}

/// The rows the Activity list gives for `query`, paged to the end.
async fn listed(logs: &Logs, mut query: ListQuery) -> usize {
    query.limit = Some("200".to_owned());
    let mut rows = 0;
    loop {
        let page = body(list_page(logs, &Access::All, &query)).await;
        rows += page["rows"].as_array().expect("rows").len();
        match page["next_cursor"].as_str() {
            Some(next) => query.cursor = Some(next.to_owned()),
            None => return rows,
        }
    }
}

fn lines(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("the log");
    text.lines().map(str::to_owned).collect()
}

/// c1's logs: every class, two cleaned calls, a refusal, an admin action
/// and a config change.
fn mixed(dir: &tempfile::TempDir) -> Logs {
    let invocation = vec![
        ended("ok-1", "ok"),
        ended("ok-2", "ok"),
        ended("ok-3", "ok"),
        ended("annotated", "ok"),
        delivered("annotated", "annotated"),
        ended("rewritten", "ok"),
        delivered("rewritten", "rewritten"),
        ended("tool-error", "tool_error"),
        ended("error", "error"),
        ended("denied-1", "denied"),
        ended("denied-2", "denied"),
        ended("invalid", "invalid"),
        refused("refused"),
        admin_action(),
    ];
    written(dir, invocation, vec![config_change()])
}

#[tokio::test]
async fn c1_counts_equal_the_rows_the_list_returns_per_outcome() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let logs = mixed(&dir);
    // Premise: 15 lines are kept, 2 of them delivery records in no count.
    let gov = logs.governance.as_deref().expect("a governance log");
    let mut kept = lines(&logs.invocation);
    kept.extend(lines(gov));
    assert_eq!(kept.len(), 15);
    let deliveries = kept.iter().filter(|l| l.contains("delivery_attempt"));
    assert_eq!(deliveries.count(), 2);

    // Cleaned calls are ok calls too; blocked holds the grant refusal; all
    // holds the admin action and the config change.
    let got = counts(&logs, window()).await;
    assert_eq!(
        got["counts"],
        json!({"all": 13, "ok": 5, "failed": 2, "blocked": 4, "cleaned": 2})
    );
    let per_value = [
        (None, 13),
        (Some("ok"), 5),
        (Some("failed"), 2),
        (Some("blocked"), 4),
        (Some("cleaned"), 2),
    ];
    for (outcome, rows) in per_value {
        assert_eq!(
            listed(&logs, list_window(outcome)).await,
            rows,
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn c15_a_count_is_a_row_the_list_would_show() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let main = vec![
        ended("ok-1", "ok"),
        ended("ok-2", "ok"),
        ended("ok-3", "ok"),
        unlisted(ended("ok-4", "ok")),
        ended("failed-1", "tool_error"),
        ended("failed-2", "error"),
        ended("failed-3", "error"),
        ended("blocked-1", "denied"),
        ended("blocked-2", "invalid"),
        unlisted(ended("blocked-3", "denied")),
    ];
    let logs = written(&dir, main, Vec::new());
    // Premise: 10 records, 2 of them with no counter.
    let kept = lines(&logs.invocation);
    assert_eq!(kept.len(), 10);
    assert_eq!(kept.iter().filter(|l| l.contains("\"counter\"")).count(), 8);
    let got = counts(&logs, window()).await;
    assert_eq!(
        got["counts"],
        json!({"all": 8, "ok": 3, "failed": 3, "blocked": 2, "cleaned": 0})
    );
    let per_value = [
        (None, 8),
        (Some("ok"), 3),
        (Some("failed"), 3),
        (Some("blocked"), 2),
    ];
    for (outcome, rows) in per_value {
        assert_eq!(
            listed(&logs, list_window(outcome)).await,
            rows,
            "{outcome:?}"
        );
    }

    // (i) A rule filter.
    let dir = crate::test_dir_keep::kept_tempdir();
    let ruled = |trace: &str| {
        let mut e = ended(trace, "denied");
        e["decision"] = decision(Some("R"));
        e
    };
    let logs = written(&dir, vec![ruled("r-1"), unlisted(ruled("r-2"))], Vec::new());
    let rule = || Some("R".to_owned());
    let query = CountsQuery {
        rule: rule(),
        ..window()
    };
    assert_eq!(counts(&logs, query).await["counts"]["all"], 1);
    let query = ListQuery {
        rule: rule(),
        ..list_window(None)
    };
    assert_eq!(listed(&logs, query).await, 1);

    // (ii) An effect filter, and cleaned: the stripped call keeps its join.
    let dir = crate::test_dir_keep::kept_tempdir();
    let effects = vec![
        ended("a-1", "ok"),
        delivered("a-1", "annotated"),
        unlisted(ended("a-2", "ok")),
        delivered("a-2", "annotated"),
    ];
    let logs = written(&dir, effects, Vec::new());
    let annotated = || Some("annotated".to_owned());
    let query = CountsQuery {
        effect: annotated(),
        ..window()
    };
    assert_eq!(counts(&logs, query).await["counts"]["all"], 1);
    assert_eq!(counts(&logs, window()).await["counts"]["cleaned"], 1);
    let query = ListQuery {
        effect: annotated(),
        ..list_window(None)
    };
    assert_eq!(listed(&logs, query).await, 1);
    assert_eq!(listed(&logs, list_window(Some("cleaned"))).await, 1);

    // (iii) A grant refusal.
    let dir = crate::test_dir_keep::kept_tempdir();
    let refusals = vec![refused("g-1"), unlisted(refused("g-2"))];
    let logs = written(&dir, refusals, Vec::new());
    let got = counts(&logs, window()).await;
    assert_eq!(
        (&got["counts"]["blocked"], &got["counts"]["all"]),
        (&json!(1), &json!(1))
    );
    assert_eq!(listed(&logs, list_window(Some("blocked"))).await, 1);
}

#[tokio::test]
async fn c2_counts_span_more_than_one_page() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let blocked = (0..450)
        .map(|i| ended(&format!("blocked-{i}"), "denied"))
        .collect();
    let logs = written(&dir, blocked, Vec::new());
    let got = counts(&logs, window()).await;
    assert_eq!(
        (&got["counts"]["blocked"], &got["counts"]["all"]),
        (&json!(450), &json!(450))
    );
    // One list page holds 200 of them and points past itself.
    let mut query = list_window(Some("blocked"));
    query.limit = some("200");
    let page = body(list_page(&logs, &Access::All, &query)).await;
    assert_eq!(page["rows"].as_array().map(Vec::len), Some(200));
    assert!(page["next_cursor"].is_string(), "{}", page["next_cursor"]);
}

/// A call on `server` by `caller`, of `tool`.
fn by(server: &str, caller: &str, tool: &str) -> Value {
    let mut e = call(server, tool, None);
    e["who"]["account"] = caller.into();
    e
}

#[tokio::test]
async fn c3_filters_apply() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let hours = |h: i64| TimeDelta::try_hours(h).expect("hours in range");
    // Oldest first, so the recorded order is the time order.
    let mut entries = vec![at(by("c", "z", "old.one"), n() - hours(2))];
    let mut minute = 50;
    for (server, caller, tool, times) in [
        ("a", "x", "kb.search", 4),
        ("b", "y", "web.fetch", 3),
        ("a", "y", "rule.check", 2),
    ] {
        for _ in 0..times {
            let mut e = by(server, caller, tool);
            if tool == "rule.check" {
                e["decision"] = decision(Some("R"));
            }
            entries.push(at(e, minutes(minute)));
            minute -= 1;
        }
    }
    entries.push(at(by("d", "w", "edge.at"), n()));
    let second = TimeDelta::try_seconds(1).expect("a second");
    entries.push(at(by("d", "w", "edge.after"), n() + second));
    for (i, e) in entries.iter_mut().enumerate() {
        e["trace_id"] = format!("trace-{i}").into();
    }
    let logs = written(&dir, entries, Vec::new());
    let wide = with(|q| {
        q.from = Some((n() - hours(3)).to_rfc3339());
        q.to = Some((n() + hours(1)).to_rfc3339());
    });
    let legs = [
        ("server=a", with(|q| q.server = some("a")), 6),
        ("caller=y", with(|q| q.caller = some("y")), 5),
        ("q=kb.", with(|q| q.q = some("kb.")), 4),
        ("rule=R", with(|q| q.rule = some("R")), 2),
        // The record stamped `to` is counted; the one a second after is not.
        ("server=d", with(|q| q.server = some("d")), 1),
        ("no filter", window(), 10),
        ("wide window", wide, 12),
    ];
    for (leg, query, all) in legs {
        assert_eq!(counts(&logs, query).await["counts"]["all"], all, "{leg}");
    }

    // The effect filter, on its own log.
    let dir = crate::test_dir_keep::kept_tempdir();
    let effects = vec![
        ended("e-1", "ok"),
        delivered("e-1", "annotated"),
        ended("e-2", "ok"),
        delivered("e-2", "delivered"),
    ];
    let logs = written(&dir, effects, Vec::new());
    let annotated = with(|q| q.effect = some("annotated"));
    assert_eq!(counts(&logs, annotated).await["counts"]["all"], 1);
    assert_eq!(counts(&logs, window()).await["counts"]["all"], 2);
}

#[tokio::test]
async fn c4_a_member_counts_only_own_calls() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let issuer = "https://issuer";
    let of = |subject: &str, i: usize| {
        let mut e = ended(&format!("{subject}-{i}"), "ok");
        e["who"] = json!({"account": subject, "authority": issuer, "subject": subject});
        e
    };
    let entries = (0..3)
        .map(|i| of("s", i))
        .chain((0..4).map(|i| of("t", i)))
        .collect();
    let logs = written(&dir, entries, Vec::new());
    let own = Access::Own {
        issuer: issuer.to_owned(),
        subject: "s".to_owned(),
    };
    let mine = ask(&logs, &own, &window(), COUNT_SCAN_BYTES).await.body;
    assert_eq!(
        (&mine["counts"]["all"], &mine["access"]),
        (&json!(3), &json!("own"))
    );
    let every = counts(&logs, window()).await;
    assert_eq!(
        (&every["counts"]["all"], &every["access"]),
        (&json!(7), &json!("all"))
    );
}

/// `name` is refused by its name, before a byte is read.
async fn assert_not_taken(logs: &Logs, name: &str, value: &str) {
    let answer = ask(logs, &Access::All, &sent(name, value), COUNT_SCAN_BYTES).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{name}");
    let error = format!("`{name}` is not a counts parameter");
    assert_eq!(answer.body, json!({ "error": error }), "{name}");
    assert_eq!(answer.passes, 0, "{name}: nothing is read");
}

#[tokio::test]
async fn c5_outcome_cursor_or_limit_in_the_query_is_refused() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let logs = written(&dir, vec![ended("ok-1", "ok")], Vec::new());
    for (name, value) in [("outcome", "ok"), ("cursor", "x"), ("limit", "5")] {
        assert_not_taken(&logs, name, value).await;
    }
    let plain_read = ask(&logs, &Access::All, &window(), COUNT_SCAN_BYTES).await;
    assert_eq!(plain_read.status, StatusCode::OK);
}

/// More than `bytes` of padded ok calls on server `z`, stamped `t`.
fn filler(bytes: u64, t: DateTime<FixedOffset>) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut size = 0;
    while size <= bytes {
        let mut e = stamped(&format!("fill-{}", rows.len()), t);
        e["server"] = "z".into();
        size += line_len(&e);
        rows.push(at(e, t));
    }
    rows
}

/// How a read stopped, whether it says it is complete, and its blocked count.
fn stop(answer: &Value) -> (&Value, &Value, &Value) {
    (
        &answer["stopped"],
        &answer["complete"],
        &answer["counts"]["blocked"],
    )
}

#[tokio::test]
async fn c6_each_stop_reaches_the_answer() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let blocked = |tag: &str, i: usize, t| at(ended(&format!("{tag}-{i}"), "denied"), t);
    let mut entries: Vec<Value> = (0..2).map(|i| blocked("low", i, minutes(40))).collect();
    entries.extend(filler(3 * MIB, minutes(30)));
    entries.extend((0..6).map(|i| blocked("high", i, minutes(20))));
    let logs = written(&dir, entries, Vec::new());
    // Premise: the six lie in the first MiB read, the two over 3 MiB down.
    let path = &logs.invocation;
    assert!(depth(path, |l| l.contains("\"high-0\"")) < MIB);
    assert!(depth(path, |l| l.contains("\"low-1\"")) > 3 * MIB);

    let capped = ask(&logs, &Access::All, &window(), MIB).await.body;
    assert_eq!(stop(&capped), (&json!("cap"), &json!(false), &json!(6)));
    // Only the cap changes.
    let whole = ask(&logs, &Access::All, &window(), COUNT_SCAN_BYTES).await;
    assert_eq!(stop(&whole.body), (&json!("end"), &json!(true), &json!(8)));
    assert_eq!(COUNT_SCAN_BYTES, 64 << 20);

    // The window lies above more than two passes of older records.
    let dir = crate::test_dir_keep::kept_tempdir();
    let day = TimeDelta::try_days(1).expect("a day");
    let mut entries = filler(6 * MIB, n() - day);
    entries.extend((0..20).map(|i| blocked("new", i, minutes(10))));
    let logs = written(&dir, entries, Vec::new());
    let passed = ask(&logs, &Access::All, &window(), COUNT_SCAN_BYTES).await;
    assert_eq!(
        stop(&passed.body),
        (&json!("window_passed"), &json!(false), &json!(20))
    );
}

#[tokio::test]
async fn c8_the_answer_holds_only_numbers() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let got = counts(&mixed(&dir), window()).await;
    let keys = |v: &Value| {
        let mut names: Vec<String> = v
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        names.sort();
        names
    };
    assert_eq!(keys(&got), ["access", "complete", "counts", "stopped"]);
    assert_eq!(
        keys(&got["counts"]),
        ["all", "blocked", "cleaned", "failed", "ok"]
    );
    let counted = got["counts"].as_object().expect("the counts");
    for count in counted.values() {
        assert!(count.is_u64(), "{count}");
    }
    let stopped = got["stopped"].as_str().unwrap_or_default();
    let stops = ["end", "window_passed", "cap"];
    assert!(stops.contains(&stopped), "{stopped}");
    assert_eq!(got["complete"], json!(stopped == "end"));
    let access = got["access"].as_str().unwrap_or_default();
    assert!(["all", "own", "scoped"].contains(&access), "{access}");
}

#[tokio::test]
async fn c16_a_log_that_rotates_under_the_count_is_not_counted() {
    let (log, path, dir) = rotating_log();
    fill_past_one_pass(&path, |i| plain(&log, i));
    let logs = Logs {
        invocation: path.clone(),
        governance: None,
        secret: None,
    };
    // The logger stamps the real clock.
    let hour = TimeDelta::try_hours(1).expect("an hour");
    let around_now = with(|q| {
        q.from = Some((wall_now() - hour).to_rfc3339());
        q.to = Some((wall_now() + hour).to_rfc3339());
    });
    let mut hooks = 0;
    let response = count_page(&logs, &Access::All, &around_now, COUNT_SCAN_BYTES, |_| {
        if hooks == 0 {
            rotate_past_sealed(&path, |i| plain(&log, i));
        }
        hooks += 1;
        ControlFlow::Continue(())
    });
    let status = response.status();
    let answer = parsed(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        answer["error"],
        "the log rotated while it was being counted: try again"
    );
    assert!(answer.get("counts").is_none(), "{answer}");
    // Premise: the rotation ran once, after the first pass.
    assert_eq!(hooks, 1);

    // Control: with no log file yet, the first pass's reset is no error.
    let none = Logs {
        invocation: dir.path().join("none.jsonl"),
        governance: None,
        secret: None,
    };
    let got = counts(&none, window()).await;
    assert_eq!(
        got["counts"],
        json!({"all": 0, "ok": 0, "failed": 0, "blocked": 0, "cleaned": 0})
    );
    assert_eq!(
        (&got["stopped"], &got["complete"]),
        (&json!("end"), &json!(true))
    );
}

#[tokio::test]
async fn c18_no_buckets_parameter() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let logs = written(&dir, vec![ended("ok-1", "ok")], Vec::new());
    for (name, value) in [("bucket_secs", "3600"), ("zzz", "1")] {
        assert_not_taken(&logs, name, value).await;
    }
    let plain_read = ask(&logs, &Access::All, &window(), COUNT_SCAN_BYTES).await;
    assert_eq!(plain_read.status, StatusCode::OK);
}
