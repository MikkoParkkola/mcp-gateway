// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X1-X3 of the U2 test plan: no secret, no call content and no unescaped
//! caller text in any read or export.

use base64::Engine as _;
use serde_json::{Value, json};

use super::access::Access;
use super::receipt::{parse_id, receipt};
use super::rows::row_id;
use super::{ExportQuery, ListQuery, Logs, export_response, list_page};
use crate::gateway::ui::activity::reader::{Line, Which};
use crate::security::transparency_log::recompute_entry_hash;
use crate::trust::provenance_public::ProvenancePublicSigner;

const SECRET: &str = "log-hmac-secret-9f2e7c1a-at-least-32-bytes";
const SEED: [u8; 32] = [7u8; 32];

/// Hash-chained entries, unsigned (the HMAC is not what these tests check).
fn write(path: &std::path::Path, entries: &mut [Value]) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, e) in entries.iter_mut().enumerate() {
        e["counter"] = (i + 1).into();
        e["prev_entry_hash"] = prev.clone().into();
        let hash = recompute_entry_hash(e).unwrap();
        e["entry_hash"] = hash.clone().into();
        body.push_str(&(e.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

async fn text(r: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Every list page, every receipt and both exports, as text.
async fn everything(logs: &Logs, inv: &[Value], gov: &[Value]) -> Vec<String> {
    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, "x-test");
    let mut out = vec![text(list_page(logs, &Access::All, &ListQuery::default())).await];
    for (which, path, entries) in [
        (Which::Invocation, &logs.invocation, inv),
        (Which::Governance, logs.governance.as_ref().unwrap(), gov),
    ] {
        for e in entries {
            let line = Line {
                log: which,
                entry: e.clone(),
                segment: 0,
            };
            let id = parse_id(&row_id(&line).unwrap()).unwrap();
            if let Some(body) = receipt(path, &id, &Access::All, logs.secret.as_deref()).unwrap() {
                out.push(body.to_string());
            }
        }
    }
    out.push(
        text(export_response(
            logs,
            &Access::All,
            &ExportQuery::default(),
            Some(&signer),
        ))
        .await,
    );
    let csv = ExportQuery {
        format: Some("csv".into()),
        ..ExportQuery::default()
    };
    out.push(text(export_response(logs, &Access::All, &csv, Some(&signer))).await);
    out
}

fn fixture(dir: &tempfile::TempDir, server: &str) -> (Logs, Vec<Value>, Vec<Value>) {
    let logs = Logs {
        invocation: dir.path().join("inv.jsonl"),
        governance: Some(dir.path().join("gov.jsonl")),
        secret: Some(SECRET.as_bytes().to_vec()),
    };
    let mut inv = vec![json!({
        "outcome": "ok", "server": server, "tool": server, "route": "meta_invoke",
        "request_hash": "sha256:aa", "timestamp": "2026-10-26T10:00:00+00:00",
        // Fields no writer sets today, planted to prove the allowlist: a
        // call's content never reaches a row.
        "arguments": {"q": "DISTINCT-ARG-7731"}, "result": "DISTINCT-RESULT-9134",
    })];
    write(&logs.invocation, &mut inv);
    let mut gov = vec![json!({
        "kind": "control_plane_audit", "actor_id": "alice", "target_id": "srv",
        "action": "mutate_grant", "timestamp": "2026-10-26T10:00:01+00:00",
        "reason": format!("pasted {SECRET}"), "rollback_summary": "DISTINCT-ROLLBACK-5521",
    })];
    write(logs.governance.as_ref().unwrap(), &mut gov);
    (logs, inv, gov)
}

#[tokio::test]
async fn x1_x2_no_secret_and_no_call_content_in_any_read_or_export() {
    let dir = tempfile::tempdir().unwrap();
    let (logs, inv, gov) = fixture(&dir, "srv");
    let seed_b64 = base64::engine::general_purpose::STANDARD.encode(SEED);
    let outputs = everything(&logs, &inv, &gov).await;
    assert!(outputs.len() >= 5, "list, two receipts, two exports");
    for out in &outputs {
        for planted in [
            SECRET,
            seed_b64.as_str(),
            "DISTINCT-ARG-7731",
            "DISTINCT-RESULT-9134",
            "DISTINCT-ROLLBACK-5521",
        ] {
            assert!(!out.contains(planted), "{planted} in {out}");
        }
    }
}

#[tokio::test]
async fn x3_caller_spelled_names_are_escaped_in_json_and_neutralised_in_csv() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = "=cmd|'/c calc'!A1 <script>\"x\"\n";
    let (logs, _, _) = fixture(&dir, hostile);
    let body = text(list_page(&logs, &Access::All, &ListQuery::default())).await;
    let v: Value = serde_json::from_str(&body).expect("valid JSON");
    let call = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "call")
        .unwrap();
    assert_eq!(call["server"], hostile, "round-trips as data");
    assert!(!body.contains('\n'), "the newline is escaped in JSON");

    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, "x-test");
    let csv = ExportQuery {
        format: Some("csv".into()),
        ..ExportQuery::default()
    };
    let out = text(export_response(&logs, &Access::All, &csv, Some(&signer))).await;
    let quoted = format!("\"'{}\"", hostile.replace('"', "\"\""));
    assert!(out.contains(&quoted), "guarded and quoted: {out}");
    assert!(!out.contains(",=cmd"), "never a bare formula cell");
}
