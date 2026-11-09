// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The list route's query and role matrix: R3, the page-size rules, a stale
//! page token, and L1-L5 of the U2 test plan.

use std::collections::BTreeSet;
use std::path::Path;

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use super::access::{self, Access, Refused};
use super::decision_fixtures::{
    assert_no_sentinel, call as dcall, decision, finding, write_chained as write_dec,
};
use super::{ListQuery, Logs, list_page};
use crate::control_plane::ControlPlaneRole;
use crate::control_plane::role_mapping::{ControlPlaneRoleMappingConfig, ControlPlaneRoleRule};
use crate::gateway::auth::AuthenticatedClient;
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::audit::CredentialKind;
use crate::security::transparency_log::recompute_entry_hash;

const X: &str = "https://issuer-x";
const Y: &str = "https://issuer-y";

/// Write call records, chained and hashed like the logger's, unsigned.
/// `who` is `(account, issuer, subject, principal)`.
/// A call: `(account, verified (issuer, subject), principal)`.
type Call<'a> = (&'a str, Option<(&'a str, &'a str)>, &'a str);

fn write_calls(path: &Path, calls: &[Call<'_>]) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, (account, verified, principal)) in calls.iter().enumerate() {
        let mut who = json!({"account": account, "principal": principal});
        if let Some((issuer, subject)) = verified {
            who["authority"] = (*issuer).into();
            who["subject"] = (*subject).into();
        }
        let mut entry = json!({
            "counter": i + 1, "prev_entry_hash": prev,
            "timestamp": format!("2026-10-26T10:00:{:02}+00:00", i),
            "outcome": "ok", "server": "srv", "tool": format!("tool_{i}"),
            "route": "meta_invoke", "request_hash": "sha256:aa", "who": who,
        });
        let hash = recompute_entry_hash(&entry).unwrap();
        entry["entry_hash"] = hash.clone().into();
        body.push_str(&(entry.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

fn logs(dir: &tempfile::TempDir) -> Logs {
    Logs {
        invocation: dir.path().join("inv.jsonl"),
        governance: None,
        secret: None,
    }
}

async fn body(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn tools(v: &Value) -> BTreeSet<String> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["tool"].as_str().unwrap().to_string())
        .collect()
}

fn query(pairs: &[(&str, &str)]) -> ListQuery {
    let mut q = ListQuery::default();
    for (k, v) in pairs {
        let v = Some((*v).to_string());
        match *k {
            "outcome" => q.outcome = v,
            "rule" => q.rule = v,
            "server" => q.server = v,
            "limit" => q.limit = v,
            "cursor" => q.cursor = v,
            other => panic!("no query field {other}"),
        }
    }
    q
}

fn client(admin: bool, authenticated: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "c".into(),
        rate_limit: 0,
        backends: vec!["*".into()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        principal: crate::gateway::auth::principal_of("activity-list-test"),
        quota_principal: None,
        authenticated,
        credential_kind: CredentialKind::ApiKey,
    }
}

fn identity(issuer: &str, subject: &str, group: &str) -> VerifiedIdentity {
    VerifiedIdentity::for_test(
        subject,
        format!("{subject}@corp"),
        None,
        vec![group.into()],
        issuer,
    )
}

fn mapping() -> ControlPlaneRoleMappingConfig {
    let rule = |issuer: &str, group: &str, role| ControlPlaneRoleRule {
        issuer: issuer.into(),
        group: Some(group.into()),
        email: None,
        domain: None,
        role,
    };
    ControlPlaneRoleMappingConfig {
        rules: vec![
            rule(X, "auditors", ControlPlaneRole::Auditor),
            rule(X, "devs", ControlPlaneRole::Developer),
            rule(Y, "devs", ControlPlaneRole::Developer),
        ],
    }
}

/// Calls by three callers: A (X, s), B (Y, s), C (X, t), a bearer with no
/// verified subject, and A again under a refreshed token (new principal).
fn fixture(dir: &tempfile::TempDir) -> Logs {
    let l = logs(dir);
    write_calls(
        &l.invocation,
        &[
            ("a", Some((X, "s")), "p-a1"),
            ("b", Some((Y, "s")), "p-b1"),
            ("c", Some((X, "t")), "p-c1"),
            ("bearer", None, ""),
            ("a", Some((X, "s")), "p-a2"),
        ],
    );
    l
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

#[tokio::test]
async fn l1_l2_admin_and_mapped_auditor_read_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let logs = fixture(&dir);
    let all = set(&["tool_0", "tool_1", "tool_2", "tool_3", "tool_4"]);
    let admin = access::resolve(Some(&client(true, true)), None, &mapping()).unwrap();
    assert_eq!(admin, Access::All);
    let auditor = access::resolve(
        Some(&client(false, true)),
        Some(&identity(X, "z", "auditors")),
        &mapping(),
    )
    .unwrap();
    assert_eq!(auditor, Access::All);
    for a in [admin, auditor] {
        let (status, v) = body(list_page(&logs, &a, &ListQuery::default())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tools(&v), all);
    }
}

#[tokio::test]
async fn l3_developers_see_exactly_their_own_rows_across_a_token_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let logs = fixture(&dir);
    let dev = |issuer, subject| {
        access::resolve(
            Some(&client(false, true)),
            Some(&identity(issuer, subject, "devs")),
            &mapping(),
        )
        .unwrap()
    };
    for (who, want) in [
        (dev(X, "s"), set(&["tool_0", "tool_4"])),
        (dev(Y, "s"), set(&["tool_1"])),
        (dev(X, "t"), set(&["tool_2"])),
    ] {
        let (status, v) = body(list_page(&logs, &who, &ListQuery::default())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tools(&v), want, "{who:?}");
    }
}

#[test]
fn l4_l5_other_credentials_are_refused() {
    let m = mapping();
    assert_eq!(
        access::resolve(Some(&client(false, true)), None, &m),
        Err(Refused::Forbidden),
        "a non-admin key"
    );
    assert_eq!(
        access::resolve(
            Some(&client(false, true)),
            Some(&identity(X, "s", "nobody")),
            &m
        ),
        Err(Refused::Forbidden),
        "an unmapped identity, which the control plane would treat as Auditor"
    );
    assert_eq!(
        access::resolve(None, None, &m),
        Err(Refused::Unauthenticated)
    );
    assert_eq!(
        access::resolve(Some(&client(true, false)), None, &m),
        Err(Refused::Unauthenticated),
        "an admin-named identity that presented no credential"
    );
}

#[tokio::test]
async fn r3_cleaned_is_no_longer_400_and_the_supported_list_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let logs = logs(&dir);
    let (status, v) = body(list_page(
        &logs,
        &Access::All,
        &query(&[("outcome", "cleaned")]),
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["rows"], json!([]));
    let (status, v) = body(list_page(
        &logs,
        &Access::All,
        &query(&[("outcome", "bogus")]),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        v["supported"],
        json!(["ok", "failed", "blocked", "cleaned"])
    );
}

/// Write decision-carrying calls, given newest first.
fn write_newest_first(l: &Logs, mut calls: Vec<Value>) {
    calls.reverse();
    write_dec(&l.invocation, &mut calls);
}

fn named(server: &str, tool: &str, rule: &str) -> Value {
    dcall(server, tool, Some(decision(Some(rule))))
}

#[tokio::test]
async fn list_rule_filter_returns_exactly_that_rules_rows() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    write_newest_first(
        &l,
        vec![
            named("srv", "t_r1", "r1"),
            named("srv", "t_r2", "r2"),
            dcall("srv", "t_norule", Some(decision(None))),
            dcall("srv", "t_nodec", None),
        ],
    );
    let (status, v) = body(list_page(&l, &Access::All, &query(&[("rule", "r1")]))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tools(&v), BTreeSet::from(["t_r1".to_string()]));
    assert_no_sentinel(&v.to_string());
}

/// Page with `limit=1` through `next_cursor`, collecting the tools in order.
async fn paged_tools(l: &Logs, pairs: &[(&str, &str)]) -> Vec<String> {
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let mut q = pairs.to_vec();
        q.push(("limit", "1"));
        if let Some(c) = &cursor {
            q.push(("cursor", c));
        }
        let (status, v) = body(list_page(l, &Access::All, &query(&q))).await;
        assert_eq!(status, StatusCode::OK);
        seen.extend(
            v["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["tool"].as_str().unwrap().to_string()),
        );
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return seen,
        }
    }
    panic!("the cursor never ended");
}

#[tokio::test]
async fn list_rule_filter_ands_with_server_and_pages() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    write_newest_first(
        &l,
        vec![
            named("srv", "a1", "r1"),
            named("srv", "x1", "r2"),
            named("other", "o1", "r1"),
            named("srv", "x2", "r2"),
            named("srv", "a2", "r1"),
            named("srv", "x3", "r2"),
            named("srv", "a3", "r1"),
        ],
    );
    let got = paged_tools(&l, &[("rule", "r1"), ("server", "srv")]).await;
    assert_eq!(got, ["a1", "a2", "a3"]);
}

#[tokio::test]
async fn list_sparse_rule_filter_resumes_past_scan_exhausted() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    let pad = "z".repeat(400);
    let mut calls = vec![named("srv", "needle", "r1")];
    for i in 0..25_000 {
        let mut c = named("srv", &format!("hay_{i}"), "r2");
        c["pad"] = pad.clone().into();
        calls.push(c);
    }
    write_dec(&l.invocation, &mut calls);
    assert!(std::fs::metadata(&l.invocation).unwrap().len() > 9 << 20);
    let (_, first) = body(list_page(&l, &Access::All, &query(&[("rule", "r1")]))).await;
    assert!(first["rows"].as_array().unwrap().is_empty());
    assert_eq!(first["scan_exhausted"], true);
    // The log is several page budgets long: follow the cursor until the needle.
    let mut cursor = first["next_cursor"].as_str().map(str::to_string);
    for _ in 0..8 {
        let c = cursor.as_deref().expect("a cursor to resume");
        let (_, next) = body(list_page(
            &l,
            &Access::All,
            &query(&[("rule", "r1"), ("cursor", c)]),
        ))
        .await;
        if !next["rows"].as_array().unwrap().is_empty() {
            assert_eq!(tools(&next), BTreeSet::from(["needle".to_string()]));
            return;
        }
        cursor = next["next_cursor"].as_str().map(str::to_string);
    }
    panic!("the cursor never reached the needle");
}

async fn rule_tools(l: &Logs, rule: &str) -> BTreeSet<String> {
    let (status, v) = body(list_page(l, &Access::All, &query(&[("rule", rule)]))).await;
    assert_eq!(status, StatusCode::OK);
    tools(&v)
}

#[tokio::test]
async fn rule_filter_ignores_the_id_in_another_field() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    let mut e = named("srv", "rule-1", "r2");
    e["payload"] = "rule-1".into();
    write_newest_first(&l, vec![e]);
    assert!(rule_tools(&l, "rule-1").await.is_empty());
}

#[tokio::test]
async fn rule_filter_has_no_prefix_collision() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    write_newest_first(
        &l,
        vec![
            named("srv", "t_one", "rule-1"),
            named("srv", "t_ten", "rule-10"),
        ],
    );
    assert_eq!(
        rule_tools(&l, "rule-1").await,
        BTreeSet::from(["t_one".to_string()])
    );
    assert_eq!(
        rule_tools(&l, "rule-10").await,
        BTreeSet::from(["t_ten".to_string()])
    );
}

/// Shared with the answer-findings change: it adds the `answer_findings`
/// half; this change pins that `findings` never reads the answer's.
#[tokio::test]
async fn field_split_findings_vs_answer_findings() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    let request = finding("pii", "high", "arguments.q");
    let answer = finding("injection", "critical", "response.text");
    let mut d = decision(Some("r1"));
    d["request_findings"] = json!([request.clone()]);
    let mut c = dcall("srv", "t", Some(d));
    c["trace_id"] = "trace-1".into();
    let delivery = json!({
        "event": "response_delivery_attempt", "trace_id": "trace-1", "tool": "t",
        "response_stage": "transport_finalized", "response_effect": "annotated",
        "response_findings": [answer.clone()],
    });
    write_dec(&l.invocation, &mut [c, delivery]);
    let (status, v) = body(list_page(&l, &Access::All, &ListQuery::default())).await;
    assert_eq!(status, StatusCode::OK);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["findings"], json!([request]));
    let text = rows[0]["findings"].to_string();
    assert!(!text.contains("injection") && !text.contains("response.text"));
    assert_eq!(rows[0]["answer_findings"], json!([answer]));
}

#[tokio::test]
async fn page_size_defaults_to_50_and_is_capped_at_200() {
    let dir = tempfile::tempdir().unwrap();
    let l = logs(&dir);
    let calls: Vec<Call<'_>> = vec![("a", None, ""); 210];
    write_calls(&l.invocation, &calls);
    let count = |v: &Value| v["rows"].as_array().unwrap().len();
    let (_, v) = body(list_page(&l, &Access::All, &ListQuery::default())).await;
    assert_eq!(count(&v), 50);
    let (_, v) = body(list_page(&l, &Access::All, &query(&[("limit", "200")]))).await;
    assert_eq!(count(&v), 200);
    for bad in ["201", "0", "x"] {
        let (status, _) = body(list_page(&l, &Access::All, &query(&[("limit", bad)]))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "limit={bad}");
    }
}

#[tokio::test]
async fn p4_a_token_this_process_did_not_issue_restarts_from_the_newest_row() {
    let dir = tempfile::tempdir().unwrap();
    let logs = fixture(&dir);
    let (_, first) = body(list_page(&logs, &Access::All, &query(&[("limit", "2")]))).await;
    let token = first["next_cursor"].as_str().unwrap().to_string();
    let (_, resumed) = body(list_page(
        &logs,
        &Access::All,
        &query(&[("limit", "2"), ("cursor", &token)]),
    ))
    .await;
    assert_eq!(resumed["cursor_reset"], false);
    assert_eq!(tools(&resumed), set(&["tool_1", "tool_2"]));
    let mut forged = token.into_bytes();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'Q' { b'R' } else { b'Q' };
    let forged = String::from_utf8(forged).unwrap();
    let (status, reset) = body(list_page(
        &logs,
        &Access::All,
        &query(&[("limit", "2"), ("cursor", &forged)]),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "never an error");
    assert_eq!(reset["cursor_reset"], true);
    assert_eq!(tools(&reset), set(&["tool_3", "tool_4"]));
}

/// A call signed by the real logger under `secret`.
fn signed_call(dir: &tempfile::TempDir, name: &str, secret: &str) -> Value {
    let path = dir.path().join(name);
    let l = crate::security::TransparencyLogger::open(std::sync::Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "k".into(),
            shared_secret: secret.into(),
            rotation: crate::security::audit_rotation_config::RotationConfig::default(),
        },
    ))
    .unwrap();
    l.log_invocation("s", "c", "srv", "t", "sha256:aa", "sha256:bb")
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(text.lines().last().unwrap()).unwrap()
}

#[test]
fn rows_are_checked_with_the_running_key_not_a_reloaded_one() {
    use crate::security::transparency_log::signature::{SignatureState, signature_state};
    const RUNNING: &str = "the-key-the-logger-started-with-0123456789";
    const RELOADED: &str = "a-key-loaded-but-not-yet-running-987654321";
    let with_key = |key: &str| {
        let mut c = crate::config::Config::default();
        c.security.transparency_log.shared_secret = key.into();
        c
    };
    let live = crate::config_reload::LiveConfig::new(with_key(RUNNING));
    live.set(with_key(RELOADED));
    let secret = super::verification_secret(&live).expect("a key is configured");
    assert_eq!(secret, RUNNING.as_bytes());

    let dir = tempfile::tempdir().unwrap();
    let by_running = signed_call(&dir, "a.jsonl", RUNNING);
    let by_reloaded = signed_call(&dir, "b.jsonl", RELOADED);
    assert_eq!(
        signature_state(&by_running, Some(&secret)),
        SignatureState::Valid
    );
    assert_eq!(
        signature_state(&by_reloaded, Some(&secret)),
        SignatureState::Invalid
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fifth_read_waits_until_one_of_four_finishes() {
    use axum::response::IntoResponse;
    use std::sync::mpsc;
    // Its own state's pool: another test's reads cannot fill or free these slots.
    let facts = crate::gateway::router::ProcessFacts::default();
    let reads = facts.activity_reads();
    assert_eq!(
        reads.available_permits(),
        4,
        "a state's pool holds four read slots"
    );
    // Four reads that hold their permit until released. Waiting on their own
    // start count, not on the permits, so a looser limit fails the assertion
    // below instead of hanging here.
    let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut releases = Vec::new();
    let mut held = Vec::new();
    for _ in 0..4 {
        let (tx, rx) = mpsc::channel::<()>();
        releases.push(tx);
        let started = std::sync::Arc::clone(&started);
        let reads = std::sync::Arc::clone(reads);
        held.push(tokio::spawn(async move {
            super::blocking(&reads, move || {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = rx.recv();
                StatusCode::OK.into_response()
            })
            .await
        }));
    }
    while started.load(std::sync::atomic::Ordering::SeqCst) < 4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(reads.available_permits(), 0, "four reads fill the limit");
    // The fifth does not start while four run.
    let (ran_tx, ran_rx) = mpsc::channel::<()>();
    let mut fifth = Box::pin(super::blocking(reads, move || {
        let _ = ran_tx.send(());
        StatusCode::OK.into_response()
    }));
    assert!(futures::poll!(&mut fifth).is_pending());
    assert!(ran_rx.try_recv().is_err(), "the fifth read ran early");
    // One finishes; its slot frees and the fifth runs.
    releases.remove(0).send(()).unwrap();
    held.remove(0).await.unwrap();
    assert_eq!(fifth.await.status(), StatusCode::OK);
    assert!(ran_rx.try_recv().is_ok());
    for tx in releases {
        tx.send(()).unwrap();
    }
    for h in held {
        h.await.unwrap();
    }
}

/// The shared-permit flake: one state's reads, on another runtime, hold every
/// slot of their pool; a paused-clock test waiting for a read of its own state
/// is not timed out by that hold. With one process-wide pool its idle clock
/// auto-advanced past its 20 s bound while the other runtime held the slots.
#[test]
fn a_paused_wait_for_a_read_permit_is_not_timed_out_by_another_states_hold() {
    use axum::response::IntoResponse;
    use std::sync::mpsc;
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let other = crate::gateway::router::ProcessFacts::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let reads = std::sync::Arc::clone(other.activity_reads());
            let limit = reads.available_permits();
            let release = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
            let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut held = Vec::new();
            for _ in 0..limit {
                let (reads, started, release) = (
                    std::sync::Arc::clone(&reads),
                    std::sync::Arc::clone(&started),
                    std::sync::Arc::clone(&release),
                );
                held.push(tokio::spawn(async move {
                    super::blocking(&reads, move || {
                        started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = release.lock().unwrap().recv();
                        StatusCode::OK.into_response()
                    })
                    .await
                }));
            }
            while started.load(std::sync::atomic::Ordering::SeqCst) < limit {
                tokio::task::yield_now().await;
            }
            held_tx.send(()).unwrap();
            for h in held {
                h.await.unwrap();
            }
        });
    });
    held_rx.recv().unwrap();
    let mine = crate::gateway::router::ProcessFacts::default();
    let limit = mine.activity_reads().available_permits();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let waited = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            super::blocking(mine.activity_reads(), || StatusCode::OK.into_response()),
        )
        .await
    });
    // The other state's reads end only after the observation: a handshake, not a sleep.
    for _ in 0..limit {
        let _ = release_tx.send(());
    }
    holder.join().unwrap();
    assert!(
        waited.is_ok(),
        "the paused clock jumped past its 20 s bound while another state held its slots"
    );
}

/// A read whose caller stops waiting keeps its permit until the read itself
/// finishes, so cancelled requests cannot run more reads than the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_read_keeps_its_permit_until_the_read_ends() {
    use axum::response::IntoResponse;
    use std::sync::mpsc;
    let facts = crate::gateway::router::ProcessFacts::default();
    let reads = std::sync::Arc::clone(facts.activity_reads());
    let before = reads.available_permits();
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let pool = std::sync::Arc::clone(&reads);
    let caller = tokio::spawn(async move {
        super::blocking(&pool, move || {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
            let _ = done_tx.send(());
            StatusCode::OK.into_response()
        })
        .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    caller.abort();
    let _ = caller.await;
    assert_eq!(
        reads.available_permits(),
        before - 1,
        "the cancelled caller's read is still running, so its permit stays taken"
    );
    release_tx.send(()).unwrap();
    tokio::task::spawn_blocking(move || done_rx.recv().unwrap())
        .await
        .unwrap();
    every_slot_returns(&reads, before).await;
}

/// Once its read ends, every slot of the pool comes back: a permit kept past
/// the read would leak a slot for good. The read signals before its closure
/// returns and drops the permit, so this waits (in real time) for all of them.
async fn every_slot_returns(reads: &tokio::sync::Semaphore, all: usize) {
    let all = u32::try_from(all).unwrap();
    let back =
        tokio::time::timeout(std::time::Duration::from_secs(5), reads.acquire_many(all)).await;
    assert!(
        matches!(back, Ok(Ok(_))),
        "a slot stayed taken after its read ended"
    );
}

/// Guard row: the live stream's read path holds its permit until the read
/// ends too, even when its caller stops waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_stream_read_keeps_its_permit_until_the_read_ends() {
    use std::sync::mpsc;
    let (state, _dir) = crate::gateway::router::tests::audience_state(
        &crate::config::AuthConfig::default(),
        (None, None),
        |meta| meta,
    )
    .await;
    let reads = std::sync::Arc::clone(state.process.activity_reads());
    let before = reads.available_permits();
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let reader = std::sync::Arc::clone(&state);
    let caller = tokio::spawn(async move {
        super::stream_read(&reader, move |_given| {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
            let _ = done_tx.send(());
            Ok(())
        })
        .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    caller.abort();
    let _ = caller.await;
    assert_eq!(
        reads.available_permits(),
        before - 1,
        "the cancelled caller's stream read is still running, so its permit stays taken"
    );
    release_tx.send(()).unwrap();
    tokio::task::spawn_blocking(move || done_rx.recv().unwrap())
        .await
        .unwrap();
    every_slot_returns(&reads, before).await;
}
