// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reader's half of the signing anchor: an unsigned record after signing
//! began reads `invalid` in every reader (list, receipt, NDJSON and CSV
//! export, live stream), and records from before it stay `unsigned` only
//! while the bytes they sit in are the ones the writer froze.

use axum::http::StatusCode;
use serde_json::Value;

use super::access::Access;
use super::receipt::{parse_id, receipt};
use super::{ExportQuery, ListQuery, Logs, export_response, list_page};
use crate::security::transparency_log::sigstart_fixture::{Fixture, SECRET};
use crate::trust::provenance_public::ProvenancePublicSigner;

fn logs(fx: &Fixture) -> Logs {
    Logs {
        invocation: fx.path.clone(),
        governance: None,
        secret: Some(SECRET.as_bytes().to_vec()),
    }
}

fn signer() -> ProvenancePublicSigner {
    ProvenancePublicSigner::from_seed_for_test([9u8; 32], "sigstate-test")
}

async fn json_body(r: axum::response::Response) -> Vec<u8> {
    assert_eq!(r.status(), StatusCode::OK);
    axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// What every reader says about the record whose `tool` is `tool`.
struct Seen {
    list: Value,
    receipt: Value,
    ndjson: Value,
    manifest: Value,
    csv_signature: String,
    csv_integrity: String,
}

async fn seen(fx: &Fixture, tool: &str) -> Seen {
    let logs = logs(fx);
    let list: Value =
        serde_json::from_slice(&json_body(list_page(&logs, &Access::All, &ListQuery::default())).await)
            .unwrap();
    let list = list["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tool"] == tool)
        .unwrap_or_else(|| panic!("{tool} not in the list"))
        .clone();
    let id = parse_id(list["id"].as_str().unwrap()).unwrap();
    let receipt = receipt(&fx.path, &id, &Access::All, logs.secret.as_deref())
        .unwrap()
        .expect("a receipt");
    let s = signer();
    let nd = json_body(export_response(&logs, &Access::All, &ExportQuery::default(), Some(&s))).await;
    let lines: Vec<Value> = String::from_utf8(nd)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let manifest = lines.last().unwrap().clone();
    let ndjson = lines
        .iter()
        .find(|r| r["tool"] == tool)
        .expect("row in the NDJSON export")
        .clone();
    let csv_q = ExportQuery {
        format: Some("csv".into()),
        ..ExportQuery::default()
    };
    let csv = String::from_utf8(json_body(export_response(&logs, &Access::All, &csv_q, None)).await).unwrap();
    let mut rows = csv.lines().filter(|l| !l.starts_with('#')).map(csv_fields);
    let header = rows.next().unwrap();
    let col = |name: &str| header.iter().position(|h| h == name).unwrap();
    let row = rows
        .find(|r| r.get(col("tool")).map(String::as_str) == Some(tool))
        .expect("row in the CSV export");
    Seen {
        list,
        receipt,
        ndjson,
        manifest,
        csv_signature: row[col("signature")].clone(),
        csv_integrity: row[col("integrity")].clone(),
    }
}

/// One CSV line's fields (RFC 4180 quoting; no field here spans lines).
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quoted = false;
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                out.last_mut().unwrap().push('"');
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(String::new()),
            (c, _) => out.last_mut().unwrap().push(c),
        }
    }
    out
}

/// Every reader says `invalid`, and the exports say why.
fn assert_invalid(s: &Seen, why: &str) {
    assert_eq!(s.list["signature"], "invalid", "list");
    assert_eq!(s.receipt["signature"], "invalid", "receipt");
    assert_eq!(s.ndjson["signature"], "invalid", "ndjson");
    assert_eq!(s.ndjson["integrity"], why, "ndjson integrity");
    assert_eq!(s.csv_signature, "invalid", "csv");
    assert_eq!(s.csv_integrity, why, "csv integrity");
    assert!(s.manifest["integrity_failed"].as_u64().unwrap() >= 1, "manifest");
}

/// A signed log of `n` calls, then `tool_<k>` edited, rehashed, stripped.
fn attacked(n: usize, k: usize, edit: impl FnOnce(&mut Value)) -> Fixture {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, n);
    drop(log);
    fx.strip(&format!("tool_{k}"), edit);
    fx
}

/// R1 (SIGSTATE.1): an edited, rehashed, sig-stripped record after signing
/// began reads `invalid` in list, receipt and both exports, never `unsigned`.
#[tokio::test]
async fn r1_stripped_after_signing_began_reads_invalid_everywhere() {
    let fx = attacked(3, 1, |v| v["response_hash"] = "sha256:ff".into());
    assert_invalid(&seen(&fx, "tool_1").await, "sig_missing");
}

/// R3 (SIGSTATE.3): an outcome edited from refused to delivered is never
/// served as a definitive effect: the receipt carries the integrity failure.
#[tokio::test]
async fn r3_an_edited_outcome_is_an_integrity_failure_not_an_effect() {
    let fx = attacked(3, 2, |v| {
        v["error_code"] = Value::Null;
        v.as_object_mut().unwrap().remove("error_code");
    });
    let s = seen(&fx, "tool_2").await;
    assert_invalid(&s, "sig_missing");
    assert_eq!(s.receipt["integrity"], "sig_missing", "receipt names the failure");
}

/// R4 (SIGSTATE.4): the stripped record's timestamp moved before the first
/// signed record changes nothing: position decides, not the timestamp.
#[tokio::test]
async fn r4_an_earlier_timestamp_does_not_rescue_a_stripped_record() {
    let fx = attacked(3, 2, |v| v["timestamp"] = "2000-01-01T00:00:00Z".into());
    assert_invalid(&seen(&fx, "tool_2").await, "sig_missing");
}

/// Every reader shows `state` for the row.
fn assert_state(s: &Seen, state: &str) {
    assert_eq!(s.list["signature"], state, "list");
    assert_eq!(s.receipt["signature"], state, "receipt");
    assert_eq!(s.ndjson["signature"], state, "ndjson");
    assert_eq!(s.csv_signature, state, "csv");
}

/// Two unsigned calls, then the secret, then two signed ones.
fn turned_on_midway() -> Fixture {
    let fx = Fixture::new();
    let plain = fx.open(false, 0);
    Fixture::calls(&plain, 0, 2);
    drop(plain);
    let log = fx.open(true, 0);
    Fixture::calls(&log, 2, 2);
    drop(log);
    fx
}

/// R2 (SIGSTATE.2): records written before signing began stay `unsigned`;
/// the later ones read `valid`. Green on the base; guards the false positive.
#[tokio::test]
async fn r2_records_before_signing_began_stay_unsigned() {
    let fx = turned_on_midway();
    for tool in ["tool_0", "tool_1"] {
        assert_state(&seen(&fx, tool).await, "unsigned");
    }
    for tool in ["tool_2", "tool_3"] {
        assert_state(&seen(&fx, tool).await, "valid");
    }
}

/// R11: without a secret the sidecar is never read: a stripped record and a
/// broken sidecar change nothing. Green on the base.
#[tokio::test]
async fn r11_no_secret_reads_as_before() {
    let fx = attacked(3, 1, |_| {});
    std::fs::write(fx.sidecar(), "garbage\n").unwrap();
    let mut l = logs(&fx);
    l.secret = None;
    let list: Value =
        serde_json::from_slice(&json_body(list_page(&l, &Access::All, &ListQuery::default())).await)
            .unwrap();
    let row = list["rows"].as_array().unwrap().iter().find(|r| r["tool"] == "tool_1").unwrap().clone();
    assert_eq!(row["signature"], "unsigned");
}

/// R18 (Q3 pin): a copy of a log without its sidecar, read with a secret:
/// its unsigned records read `invalid` and the export names the missing anchor.
#[tokio::test]
async fn r18_an_offline_copy_without_its_sidecar_fails_closed() {
    let fx = turned_on_midway();
    std::fs::remove_file(fx.sidecar()).ok();
    let s = seen(&fx, "tool_0").await;
    assert_invalid(&s, "sigstart_missing");
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "missing");
}

/// R19 (round 1 G1, round 2 H1, round 3 J1): edits to the bytes written
/// before signing began make that file's unsigned records `invalid`.
#[tokio::test]
async fn r19_edits_to_legacy_bytes_are_caught() {
    // (a) one legacy line deleted.
    let fx = turned_on_midway();
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let kept: String = text
        .lines()
        .filter(|l| !l.contains("\"tool_0\""))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&fx.path, kept).unwrap();
    assert_invalid(&seen(&fx, "tool_1").await, "legacy_edited");

    // (b) a legacy line replaced by a stripped signed record of the same
    // length (padded with spaces), P unchanged.
    let fx = turned_on_midway();
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let legacy = lines.iter().position(|l| l.contains("\"tool_1\"")).unwrap();
    let signed = lines.iter().position(|l| l.contains("\"tool_3\"")).unwrap();
    let mut forged: Value = serde_json::from_str(lines[signed]).unwrap();
    forged["tool"] = "tool_9".into();
    crate::security::transparency_log::sigstart_fixture::strip_sig(&mut forged);
    let mut forged = forged.to_string();
    assert!(forged.len() <= lines[legacy].len(), "the forged line fits");
    while forged.len() < lines[legacy].len() {
        forged.push(' ');
    }
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
    out[legacy] = forged;
    std::fs::write(&fx.path, out.join("\n") + "\n").unwrap();
    assert_invalid(&seen(&fx, "tool_9").await, "legacy_edited");

    // (c) a stripped record inserted inside the legacy range.
    let fx = turned_on_midway();
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut extra: Value = serde_json::from_str(&lines[1]).unwrap();
    extra["tool"] = "tool_8".into();
    crate::security::transparency_log::sigstart_fixture::strip_sig(&mut extra);
    // Between the two legacy lines, so it lies wholly below P.
    lines.insert(1, extra.to_string());
    std::fs::write(&fx.path, lines.join("\n") + "\n").unwrap();
    assert_invalid(&seen(&fx, "tool_8").await, "legacy_edited");
}

/// R21 (round 1 G6): a broken sidecar is reported log-wide even when every
/// row on the page is a valid signed one.
#[tokio::test]
async fn r21_an_anchor_fault_is_reported_with_no_failing_row() {
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 2);
    drop(log);
    let mut sc: Value =
        serde_json::from_str(std::fs::read_to_string(fx.sidecar()).unwrap().trim_end()).unwrap();
    sc["offset"] = (sc["offset"].as_u64().unwrap() + 1).into();
    std::fs::write(fx.sidecar(), sc.to_string() + "\n").unwrap();
    let s = seen(&fx, "tool_1").await;
    assert_state(&s, "valid");
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "mac");
    assert_eq!(s.manifest["anchor_faults"], 1);
    assert_eq!(s.receipt["signing_anchor"], "mac");
}
