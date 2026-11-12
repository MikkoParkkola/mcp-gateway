// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call refused by an identity grant with no invocation record of its own
//! is one blocked row, read from its decision record: listed only when the
//! record is a denial that says no invocation record was written for the call.

use crate::gateway::ui::activity::rows::Check;
use std::path::Path;

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use super::access::Access;
use super::{ListQuery, Logs, list_page};
use crate::security::transparency_log::recompute_entry_hash;

const X: &str = "https://issuer-x";

/// Chain and hash `entries` as the logger does, unsigned.
fn write(path: &Path, entries: Vec<Value>) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, mut entry) in entries.into_iter().enumerate() {
        entry["counter"] = (i + 1).into();
        entry["prev_entry_hash"] = prev.clone().into();
        entry["timestamp"] = format!("2026-11-06T10:00:{i:02}+00:00").into();
        let hash = recompute_entry_hash(&entry).unwrap();
        entry["entry_hash"] = hash.clone().into();
        body.push_str(&(entry.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

/// A grant decision for `tool` by subject `s` under issuer X, as the writer
/// records it. `allowed`, `server` and `recorded` vary; `None` leaves a
/// field out, as a record written before it existed does.
fn decision(tool: &str, allowed: bool, server: Option<&str>, recorded: Option<bool>) -> Value {
    let mut e = json!({
        "kind": "identity_grant_decision",
        "reason": if allowed { "grant_matched" } else { "missing_grant" },
        "capability": "stripe.refunds", "scope": "execute", "tool": tool,
        "subject": {"authority": X, "subject": "s"},
        "outcome": if allowed { "ok" } else { "denied" },
        "trace_id": format!("trace-{tool}"),
        "who": {"account": "s", "authority": X, "subject": "s"},
    });
    if let Some(server) = server {
        e["server"] = server.into();
    }
    if let Some(recorded) = recorded {
        e["invocation_recorded"] = recorded.into();
    }
    e
}

/// A call record, so a page is never only decisions.
fn call(tool: &str) -> Value {
    json!({
        "outcome": "ok", "server": "srv", "tool": tool, "route": "meta_invoke",
        "request_hash": "sha256:aa", "trace_id": format!("trace-{tool}"),
        "who": {"account": "s", "authority": X, "subject": "s", "principal": "p"},
    })
}

fn logs(dir: &tempfile::TempDir, entries: Vec<Value>) -> Logs {
    let invocation = dir.path().join("inv.jsonl");
    write(&invocation, entries);
    Logs {
        invocation,
        governance: None,
        secret: None,
    }
}

async fn page(logs: &Logs, access: &Access, q: ListQuery) -> Value {
    let response: Response = list_page(logs, access, &q);
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn rows(logs: &Logs, access: &Access, q: ListQuery) -> Vec<Value> {
    page(logs, access, q).await["rows"]
        .as_array()
        .unwrap()
        .clone()
}

fn tools(rows: &[Value]) -> Vec<&str> {
    rows.iter().map(|r| r["tool"].as_str().unwrap()).collect()
}

/// The five decision shapes beside one call: only the denial that records
/// no invocation of its own is a row, and it reads as a blocked call.
fn mixed(dir: &tempfile::TempDir) -> Logs {
    logs(
        dir,
        vec![
            call("called"),
            decision("refused", false, Some("srv"), Some(false)),
            decision("has_record", false, Some("srv"), Some(true)),
            decision("allowed", true, Some("srv"), Some(false)),
            decision("old_record", false, Some("srv"), None),
        ],
    )
}

#[tokio::test]
async fn a_denial_with_no_invocation_record_is_one_blocked_row() {
    let dir = tempfile::tempdir().unwrap();
    let rows = rows(&mixed(&dir), &Access::All, ListQuery::default()).await;
    let mut listed = tools(&rows);
    listed.sort_unstable();
    assert_eq!(
        listed,
        vec!["called", "refused"],
        "a recorded denial, an allowed decision and an old record are not rows"
    );
    let refused = rows.iter().find(|r| r["tool"] == "refused").unwrap();
    assert_eq!(refused["outcome"], "blocked", "{refused}");
    assert_eq!(refused["server"], "srv", "{refused}");
    assert_eq!(refused["who"]["subject"], "s", "{refused}");
}

#[tokio::test]
async fn a_refusal_row_matches_the_outcome_server_caller_and_tool_filters() {
    let dir = tempfile::tempdir().unwrap();
    let logs = mixed(&dir);
    let q =
        |outcome: Option<&str>, server: Option<&str>, caller: Option<&str>, text: Option<&str>| {
            ListQuery {
                outcome: outcome.map(str::to_string),
                server: server.map(str::to_string),
                caller: caller.map(str::to_string),
                q: text.map(str::to_string),
                ..ListQuery::default()
            }
        };
    let blocked = rows(&logs, &Access::All, q(Some("blocked"), None, None, None)).await;
    assert_eq!(tools(&blocked), vec!["refused"], "outcome=blocked");
    let by_server = rows(
        &logs,
        &Access::All,
        q(Some("blocked"), Some("srv"), None, None),
    )
    .await;
    assert_eq!(tools(&by_server), vec!["refused"], "server=srv");
    let other = rows(
        &logs,
        &Access::All,
        q(Some("blocked"), Some("other"), None, None),
    )
    .await;
    assert!(other.is_empty(), "server=other: {other:?}");
    let by_caller = rows(
        &logs,
        &Access::All,
        q(Some("blocked"), None, Some("s"), None),
    )
    .await;
    assert_eq!(tools(&by_caller), vec!["refused"], "caller=s");
    let by_tool = rows(&logs, &Access::All, q(None, None, None, Some("refused"))).await;
    assert_eq!(tools(&by_tool), vec!["refused"], "q=refused");
}

#[tokio::test]
async fn a_refusal_with_no_server_never_matches_a_server_filter_or_a_scope() {
    let dir = tempfile::tempdir().unwrap();
    let logs = logs(&dir, vec![decision("no_server", false, None, Some(false))]);
    let all = rows(&logs, &Access::All, ListQuery::default()).await;
    assert_eq!(tools(&all), vec!["no_server"]);
    assert!(all[0].get("server").is_none(), "{}", all[0]);
    let q = ListQuery {
        server: Some("srv".into()),
        ..ListQuery::default()
    };
    assert!(rows(&logs, &Access::All, q).await.is_empty(), "server=srv");
    let scoped = Access::Scoped {
        owner: None,
        backends: vec!["srv".into()],
    };
    assert!(
        rows(&logs, &scoped, ListQuery::default()).await.is_empty(),
        "a row with no server is in no scope"
    );
}

#[tokio::test]
async fn a_scoped_or_own_caller_sees_only_its_own_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let mut other = decision("other_subject", false, Some("a"), Some(false));
    other["subject"]["subject"] = "t".into();
    other["who"] = json!({"account": "t", "authority": X, "subject": "t"});
    let logs = logs(
        &dir,
        vec![
            decision("on_a", false, Some("a"), Some(false)),
            decision("on_b", false, Some("b"), Some(false)),
            other,
        ],
    );
    let scoped = Access::Scoped {
        owner: None,
        backends: vec!["a".into()],
    };
    let mut seen = tools(&rows(&logs, &scoped, ListQuery::default()).await)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    seen.sort();
    assert_eq!(seen, vec!["on_a", "other_subject"], "scope a: not b");
    let own = Access::Own {
        issuer: X.into(),
        subject: "s".into(),
    };
    let mut mine = tools(&rows(&logs, &own, ListQuery::default()).await)
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    mine.sort();
    assert_eq!(mine, vec!["on_a", "on_b"], "own rows only, not subject t's");
}

#[tokio::test]
async fn a_refusal_appears_in_both_exports_and_its_receipt_shows_the_decision() {
    let dir = tempfile::tempdir().unwrap();
    let logs = mixed(&dir);
    let listed = rows(&logs, &Access::All, ListQuery::default()).await;
    let refused = listed.iter().find(|r| r["tool"] == "refused").unwrap();
    let id = super::receipt::parse_id(refused["id"].as_str().unwrap()).unwrap();
    let receipt = super::receipt::receipt(&logs.invocation, &id, &Access::All, &Check::bare(None))
        .unwrap()
        .expect("the refusal has a receipt");
    assert_eq!(receipt["decision"]["reason"], "missing_grant", "{receipt}");
    assert_eq!(receipt["decision"]["scope"], "execute", "{receipt}");
    assert_eq!(receipt["outcome"], "blocked", "{receipt}");
    // Both export formats are built from the one collection, then the CSV is
    // written from it: the row is in the collection and in the CSV text.
    let collected = super::export::collect(
        &logs.invocation,
        None,
        &super::rows::Filter::default(),
        &Access::All,
        &Check::bare(None),
        super::export::CAPS,
        super::export::csv_size,
    )
    .unwrap();
    assert!(
        collected
            .rows
            .iter()
            .any(|r| r["tool"] == "refused" && r["outcome"] == "blocked"),
        "{:?}",
        collected.rows
    );
    assert!(
        !collected.rows.iter().any(|r| r["tool"] == "has_record"),
        "a recorded denial is not exported"
    );
    let csv = super::export::csv(&collected);
    assert!(csv.contains("refused"), "{csv}");
}

/// A delivery record for `trace`, as the writer shapes it.
fn delivery(trace: &str) -> Value {
    json!({
        "event": "response_delivery_attempt", "response_stage": "transport_finalized",
        "trace_id": trace,
    })
}

#[tokio::test]
async fn an_effect_filter_never_lists_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let query = ListQuery {
        effect: Some("no_record".into()),
        ..ListQuery::default()
    };
    let rows = rows(&mixed(&dir), &Access::All, query).await;
    assert_eq!(tools(&rows), ["called"], "{rows:?}");
}

#[tokio::test]
async fn a_refusal_is_never_counted_in_the_answer_join() {
    let dir = tempfile::tempdir().unwrap();
    // Two delivery records under the refusal's trace read as a duplicate for a
    // call; a refusal is no call, so nothing is joined or counted for it.
    let entries = vec![
        decision("refused", false, Some("srv"), Some(false)),
        delivery("trace-refused"),
        delivery("trace-refused"),
    ];
    let page = page(&logs(&dir, entries), &Access::All, ListQuery::default()).await;
    assert_eq!(page["rows"].as_array().unwrap().len(), 1, "premise: {page}");
    assert_eq!(page["join_incomplete"], 0, "{page}");
    assert_eq!(page["answer_integrity_failed"], 0, "{page}");
}

#[tokio::test]
async fn a_refusal_receipt_has_no_answer_block() {
    let dir = tempfile::tempdir().unwrap();
    let logs = mixed(&dir);
    let listed = rows(&logs, &Access::All, ListQuery::default()).await;
    let refused = listed.iter().find(|r| r["tool"] == "refused").unwrap();
    let id = super::receipt::parse_id(refused["id"].as_str().unwrap()).unwrap();
    let receipt = super::receipt::receipt(&logs.invocation, &id, &Access::All, &Check::bare(None))
        .unwrap()
        .expect("the refusal has a receipt");
    assert!(receipt.get("answer").is_none(), "{receipt}");
}
