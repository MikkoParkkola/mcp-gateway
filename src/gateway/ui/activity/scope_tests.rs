// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend-scoped reader's rows: its backends' calls only. Config rows are
//! grant and policy changes and admin actions are gateway-wide, so a scoped
//! reader sees neither, even a grant whose id names one of its backends.

use crate::gateway::ui::activity::rows::Check;
use serde_json::{Value, json};

use super::access::Access;
use super::receipt::{parse_id, receipt};
use super::rows::row_id;
use super::{ListQuery, Logs, list_page};
use crate::gateway::ui::activity::reader::{Line, Which};
use crate::security::transparency_log::recompute_entry_hash;

const ISSUER: &str = "https://issuer-scope";

fn write(path: &std::path::Path, entries: &mut [Value]) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, e) in entries.iter_mut().enumerate() {
        e["counter"] = (i + 1).into();
        e["prev_entry_hash"] = prev.clone().into();
        e["timestamp"] = format!("2026-10-26T10:00:{i:02}+00:00").into();
        let hash = recompute_entry_hash(e).unwrap();
        e["entry_hash"] = hash.clone().into();
        body.push_str(&(e.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

fn call(server: &str, subject: &str) -> Value {
    json!({
        "outcome": "ok", "server": server, "tool": format!("{server}_{subject}"),
        "route": "meta_invoke", "request_hash": "sha256:aa",
        "who": {"account": "k", "authority": ISSUER, "subject": subject},
    })
}

/// Calls on alpha and beta by two subjects, an admin action, and Config rows
/// whose targets name `backend:alpha` (a grant id an operator chose) and
/// `backend:beta`.
fn fixture(dir: &tempfile::TempDir) -> (Logs, Vec<Value>, Vec<Value>) {
    let logs = Logs {
        invocation: dir.path().join("inv.jsonl"),
        governance: Some(dir.path().join("gov.jsonl")),
        secret: None,
    };
    let mut inv = vec![
        call("alpha", "dev"),
        call("alpha", "other"),
        call("beta", "dev"),
        json!({"event": "admin_action", "surface": "ui", "route": "/ui/api/config",
               "method": "PUT", "http_status": 200}),
    ];
    write(&logs.invocation, &mut inv);
    let mut gov = ["backend:alpha", "backend:beta"]
        .map(|target| {
            json!({"kind": "control_plane_audit", "actor_id": "alice",
                   "target_id": target, "action": "mutate_grant"})
        })
        .to_vec();
    write(logs.governance.as_ref().unwrap(), &mut gov);
    (logs, inv, gov)
}

async fn listed(logs: &Logs, access: &Access) -> Vec<String> {
    let response = list_page(logs, access, &ListQuery::default());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page: Value = serde_json::from_slice(&bytes).unwrap();
    let mut rows: Vec<String> = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "{}:{}",
                r["kind"].as_str().unwrap(),
                r["tool"].as_str().unwrap_or("-")
            )
        })
        .collect();
    rows.sort_unstable();
    rows
}

fn scoped(owner: Option<&str>) -> Access {
    Access::Scoped {
        owner: owner.map(|s| (ISSUER.to_string(), s.to_string())),
        backends: vec!["alpha".to_string()],
    }
}

#[tokio::test]
async fn a_scoped_reader_lists_its_backends_calls_only() {
    let dir = tempfile::tempdir().unwrap();
    let (logs, _, _) = fixture(&dir);
    assert_eq!(
        listed(&logs, &Access::All).await.len(),
        6,
        "premise: all rows"
    );
    assert_eq!(
        listed(&logs, &scoped(None)).await,
        ["call:alpha_dev", "call:alpha_other"]
    );
    assert_eq!(
        listed(&logs, &scoped(Some("dev"))).await,
        ["call:alpha_dev"]
    );
    let empty = Access::Scoped {
        owner: None,
        backends: Vec::new(),
    };
    assert!(
        listed(&logs, &empty).await.is_empty(),
        "an empty scope reads nothing"
    );
}

#[test]
fn a_scoped_receipt_answers_as_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    let (logs, inv, gov) = fixture(&dir);
    let read = |which, path: &std::path::Path, entry: &Value, access: &Access| {
        let line = Line {
            log: which,
            entry: entry.clone(),
            segment: 0,
            span: None,
        };
        let id = parse_id(&row_id(&line).unwrap()).unwrap();
        receipt(path, &id, access, &Check::bare(None)).unwrap()
    };
    let gov_path = logs.governance.clone().unwrap();
    assert!(read(Which::Invocation, &logs.invocation, &inv[0], &scoped(None)).is_some());
    for (which, path, entry) in [
        (Which::Invocation, &logs.invocation, &inv[2]),
        (Which::Invocation, &logs.invocation, &inv[3]),
        (Which::Governance, &gov_path, &gov[0]),
    ] {
        assert!(
            read(which, path, entry, &Access::All).is_some(),
            "premise: {entry} has a receipt"
        );
        assert!(
            read(which, path, entry, &scoped(None)).is_none(),
            "a scoped reader got {entry}'s receipt"
        );
    }
}
