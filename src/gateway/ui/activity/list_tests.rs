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
use super::{ListQuery, Logs, list_page};
use crate::control_plane::ControlPlaneRole;
use crate::control_plane::role_mapping::{ControlPlaneRoleMappingConfig, ControlPlaneRoleRule};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::record_principal::InternalPrincipal;
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
        principal: InternalPrincipal::new("0123456789ab".into()),
        quota_principal: None,
        authenticated,
        credential_kind: CredentialKind::ApiKey,
    }
}

fn identity(issuer: &str, subject: &str, group: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@corp"),
        name: None,
        groups: vec![group.into()],
        issuer: issuer.into(),
    }
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
async fn r3_cleaned_answers_400_with_the_supported_list() {
    let dir = tempfile::tempdir().unwrap();
    let logs = fixture(&dir);
    let (status, v) = body(list_page(
        &logs,
        &Access::All,
        &query(&[("outcome", "cleaned")]),
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        v,
        json!({
            "error": "answer changes are not recorded by this gateway version",
            "supported": ["ok", "failed", "blocked"],
        })
    );
}

#[tokio::test]
async fn a_rule_filter_answers_400_until_rules_are_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let logs = fixture(&dir);
    let (status, v) = body(list_page(&logs, &Access::All, &query(&[("rule", "r1")]))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"], "rules are not recorded by this gateway version");
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
    assert_eq!(super::MAX_CONCURRENT_READS, 4);
    // Four reads that hold their permit until released.
    let mut releases = Vec::new();
    let mut held = Vec::new();
    for _ in 0..4 {
        let (tx, rx) = mpsc::channel::<()>();
        releases.push(tx);
        held.push(tokio::spawn(super::blocking(move || {
            let _ = rx.recv();
            StatusCode::OK.into_response()
        })));
    }
    while super::READS.available_permits() > 0 {
        tokio::task::yield_now().await;
    }
    // The fifth does not start while four run.
    let (ran_tx, ran_rx) = mpsc::channel::<()>();
    let mut fifth = Box::pin(super::blocking(move || {
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
