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
use crate::security::transparency_log::segments::list_segments;
use crate::security::transparency_log::sigstart_fixture::{
    Fixture, SECRET, rewrite, strip_sig, write_v3,
};
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
    /// `Null` when the receipt's counter seek cannot find the record (an
    /// appended copy that repeats a counter); only R29 allows that.
    receipt: Value,
    ndjson: Value,
    manifest: Value,
    csv_signature: String,
    csv_integrity: String,
    csv_unanchored: String,
    /// The list page's log-wide anchor report.
    list_anchor: Value,
}

async fn seen(fx: &Fixture, tool: &str) -> Seen {
    let logs = logs(fx);
    let list: Value = serde_json::from_slice(
        &json_body(list_page(&logs, &Access::All, &ListQuery::default())).await,
    )
    .unwrap();
    let list_anchor = list["signing_anchor"].clone();
    let list = list["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tool"] == tool)
        .unwrap_or_else(|| panic!("{tool} not in the list"))
        .clone();
    let id = parse_id(list["id"].as_str().unwrap()).unwrap();
    let receipt = receipt(&fx.path, &id, &Access::All, &logs.check())
        .unwrap()
        .unwrap_or(Value::Null);
    let s = signer();
    let nd = json_body(export_response(
        &logs,
        &Access::All,
        &ExportQuery::default(),
        Some(&s),
    ))
    .await;
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
    let csv =
        String::from_utf8(json_body(export_response(&logs, &Access::All, &csv_q, None)).await)
            .unwrap();
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
        csv_unanchored: row[col("unanchored")].clone(),
        list_anchor,
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
    assert_invalid_unseekable(s, why);
}

/// As [`assert_invalid`], for a record the receipt's counter seek cannot
/// reach because the edit broke counter order.
fn assert_invalid_unseekable(s: &Seen, why: &str) {
    assert_eq!(s.list["signature"], "invalid", "list");
    assert_eq!(s.ndjson["signature"], "invalid", "ndjson");
    assert_eq!(s.ndjson["integrity"], why, "ndjson integrity");
    assert_eq!(s.csv_signature, "invalid", "csv");
    assert_eq!(s.csv_integrity, why, "csv integrity");
    assert!(
        s.manifest["integrity_failed"].as_u64().unwrap() >= 1,
        "manifest"
    );
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

/// R3 (SIGSTATE.3): a refused call edited to delivered (outcome `ok`, its
/// error code removed), rehashed and stripped, is an integrity failure in
/// every reader, the receipt included, never a plain delivered row.
#[tokio::test]
async fn r3_an_edited_outcome_is_an_integrity_failure_not_an_effect() {
    use crate::security::audit::{AuditEnvelope, AuditOutcome, AuditWho, InvocationTarget};
    use crate::security::transparency_log::{CorrelationKey, CorrelationSource};
    let fx = Fixture::new();
    let log = fx.open(true, 0);
    Fixture::calls(&log, 0, 2);
    let refused = AuditEnvelope {
        outcome: AuditOutcome::Denied(-32001),
        ..AuditEnvelope::ok(AuditWho::from_actor_id("c"))
    };
    log.log_invocation_correlated(
        CorrelationKey {
            id: "s",
            source: CorrelationSource::SessionId,
        },
        &refused,
        InvocationTarget::meta("srv", "tool_refused"),
        "sha256:aa",
        None,
    )
    .unwrap();
    drop(log);
    assert_eq!(
        seen(&fx, "tool_refused").await.list["outcome"],
        "blocked",
        "a refusal first"
    );
    fx.strip("tool_refused", |v| {
        v["outcome"] = "ok".into();
        v.as_object_mut().unwrap().remove("error_code");
    });
    let s = seen(&fx, "tool_refused").await;
    assert_invalid(&s, "sig_missing");
    assert_eq!(
        s.receipt["integrity"], "sig_missing",
        "receipt names the failure"
    );
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
    let list: Value = serde_json::from_slice(
        &json_body(list_page(&l, &Access::All, &ListQuery::default())).await,
    )
    .unwrap();
    let row = list["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tool"] == "tool_1")
        .unwrap()
        .clone();
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
        .flat_map(|l| [l, "\n"])
        .collect();
    std::fs::write(&fx.path, kept).unwrap();
    let s = seen(&fx, "tool_1").await;
    assert_invalid(&s, "legacy_edited");
    // The log-wide report names the legacy fault a row met (code review M3).
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "legacy_edited");
    assert_eq!(s.manifest["anchor_faults"], 1);

    // (b) a legacy line replaced by a stripped signed record of the same
    // length (padded with spaces), P unchanged.
    let fx = turned_on_midway();
    let text = std::fs::read_to_string(&fx.path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let legacy = lines.iter().position(|l| l.contains("\"tool_1\"")).unwrap();
    let signed = lines.iter().position(|l| l.contains("\"tool_3\"")).unwrap();
    let replaced: Value = serde_json::from_str(lines[legacy]).unwrap();
    let mut forged: Value = serde_json::from_str(lines[signed]).unwrap();
    forged["tool"] = "tool_9".into();
    // Chain-consistent where it sits, as a careful attacker would make it.
    forged["counter"] = replaced["counter"].clone();
    // The timestamp's printed length varies with the clock (3, 6 or 9 fractional
    // digits; Windows ticks in 100 ns), so a careful attacker copies it too.
    forged["timestamp"] = replaced["timestamp"].clone();
    forged["prev_entry_hash"] = replaced["prev_entry_hash"].clone();
    strip_sig(&mut forged);
    let mut forged = forged.to_string();
    assert!(
        forged.len() <= lines[legacy].len(),
        "the forged line fits: {} vs {} bytes",
        forged.len(),
        lines[legacy].len()
    );
    while forged.len() < lines[legacy].len() {
        forged.push(' ');
    }
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
    out[legacy] = forged;
    std::fs::write(&fx.path, out.join("\n") + "\n").unwrap();
    assert_invalid(&seen(&fx, "tool_9").await, "legacy_edited");

    // (c) a legacy record's content edited and its hash recomputed: it is
    // still unsigned and chain-shaped, but its bytes are not the frozen ones.
    let fx = turned_on_midway();
    rewrite(&fx.path, |v| {
        let hit = v["tool"] == "tool_1";
        if hit {
            v["response_hash"] = "sha256:ff".into();
            strip_sig(v);
        }
        hit
    });
    assert_invalid(&seen(&fx, "tool_1").await, "legacy_edited");
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
    // The list page reports it too (code review M2).
    assert_eq!(s.list_anchor["invocation"], "mac");
}

/// Strip `tool` wherever it is: the active file or a sealed segment.
fn strip_anywhere(fx: &Fixture, tool: &str) {
    let files: Vec<_> = list_segments(&fx.path)
        .unwrap()
        .into_iter()
        .map(|s| s.path)
        .chain([fx.path.clone()])
        .collect();
    let file = files
        .iter()
        .find(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .contains(&format!("\"{tool}\""))
        })
        .expect("the record is kept");
    rewrite(file, |v| {
        let hit = v["tool"] == tool;
        if hit {
            strip_sig(v);
        }
        hit
    });
}

/// R5 (SIGSTATE.5, condition 3): across rotated files, and after the
/// anchor's segment is gone, a stripped record still reads `invalid`, and
/// the anchor itself still reads `ok` (round 3 J8).
#[tokio::test]
async fn r5_rotation_and_retention_keep_the_anchor() {
    let fx = Fixture::new();
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 0, 16);
    drop(log);
    let sealed = list_segments(&fx.path).unwrap();
    assert!(sealed.len() >= 2, "the fixture rotated twice");
    // Retention removes the oldest file, the one P names.
    std::fs::remove_file(&sealed[0].path).unwrap();
    let oldest_kept = std::fs::read_to_string(&sealed[1].path).unwrap();
    let tool = serde_json::from_str::<Value>(
        oldest_kept
            .lines()
            .find(|l| l.contains("\"tool\""))
            .unwrap(),
    )
    .unwrap()["tool"]
        .as_str()
        .unwrap()
        .to_string();
    strip_anywhere(&fx, &tool);
    let s = seen(&fx, &tool).await;
    assert_invalid(&s, "sig_missing");
    assert_eq!(s.manifest["signing_anchor"]["invocation"], "ok");
    // A stripped record in the active file too.
    strip_anywhere(&fx, "tool_15");
    assert_invalid(&seen(&fx, "tool_15").await, "sig_missing");
}

/// R27 (lead ruling): unanchored legacy: records before the first surviving
/// signed record read `unsigned` with the flag; a stripped one after it
/// reads `invalid` (lead condition on the residual).
#[tokio::test]
async fn r27_unanchored_legacy_flags_only_the_earliest_records() {
    let fx = Fixture::new();
    write_v3(&fx.path, 40, 5, 6);
    drop(fx.open(true, 0));
    let s = seen(&fx, "tool_1").await;
    assert_state(&s, "unsigned");
    assert_eq!(s.list["unanchored"], true);
    assert_eq!(s.ndjson["unanchored"], true);
    assert_eq!(s.csv_unanchored, "true", "csv (code review M4)");
    fx.strip("tool_7", |_| {});
    assert_invalid(&seen(&fx, "tool_7").await, "sig_missing");
}

/// R33 (J2 residual pin): signatures stripped from the first signed v3
/// records before the upgrade read `unsigned` after migration; an edit to
/// one of them breaks the next signed record's chain link in the receipt.
#[tokio::test]
async fn r33_pre_upgrade_stripping_downgrades_but_an_edit_breaks_the_chain() {
    let fx = Fixture::new();
    write_v3(&fx.path, 1, 2, 4);
    for tool in ["tool_2", "tool_3"] {
        rewrite(&fx.path, |v| {
            let hit = v["tool"] == tool;
            if hit {
                let o = v.as_object_mut().unwrap();
                o.remove("sig");
                o.remove("key_id");
            }
            hit
        });
    }
    drop(fx.open(true, 0));
    assert_state(&seen(&fx, "tool_3").await, "unsigned");
    assert_eq!(
        seen(&fx, "tool_4").await.receipt["chain"]["link"],
        "verified"
    );

    let fx = Fixture::new();
    write_v3(&fx.path, 1, 2, 4);
    fx.strip("tool_3", |v| v["response_hash"] = "sha256:ff".into());
    drop(fx.open(true, 0));
    assert_eq!(seen(&fx, "tool_4").await.receipt["chain"]["link"], "broken");
}

/// R32 (lead condition on J4): binding to this log without legacy history.
#[tokio::test]
async fn r32_coverage_binds_the_sidecar_to_this_log() {
    // (a) two logs signed from their start; B's sidecar copied into A.
    let a = attacked(3, 1, |_| {});
    let b = Fixture::new();
    let log = b.open(true, 0);
    Fixture::calls(&log, 0, 5);
    drop(log);
    std::fs::copy(b.sidecar(), a.sidecar()).unwrap();
    assert_invalid(&seen(&a, "tool_1").await, "sig_missing");

    // (b) P past the start with an empty legacy list: tampering. The MAC is
    // not re-signed here, so this checks the loader reads coverage, not only
    // the MAC: the implementation row adds a re-signed variant.
    let fx = turned_on_midway();
    let mut sc: Value =
        serde_json::from_str(std::fs::read_to_string(fx.sidecar()).unwrap().trim_end()).unwrap();
    sc["legacy"] = Value::Array(vec![]);
    std::fs::write(fx.sidecar(), sc.to_string() + "\n").unwrap();
    let s = seen(&fx, "tool_0").await;
    assert_eq!(s.list["signature"], "invalid");
    assert_ne!(s.manifest["signing_anchor"]["invocation"], "ok");
}

/// R12: the live stream's announced record is the newest one: signed, it
/// reads `valid`; an unsigned announced record reads `invalid` with the
/// reason (round 3 J8: q13 needs the reason, not only the state).
#[test]
fn r12_the_live_frame_is_placed_after_every_anchor() {
    use super::forward::{Log, StreamKind, frame};
    // Unsigned history in earlier files, so the anchor sits past segment 0:
    // a frame misplaced at (0, 0) would then read as legacy (q13).
    let fx = Fixture::new();
    let plain = fx.open(false, 1024);
    Fixture::calls(&plain, 0, 8);
    drop(plain);
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 8, 4);
    drop(log);
    let newest = fx.records().last().unwrap().1.clone();
    let live = Log {
        path: &fx.path,
        kind: StreamKind::Activity,
        generation: 0,
        secret: Some(SECRET.as_bytes()),
    };
    let served = frame(&live, &Access::All, &newest).expect("a call row");
    assert_eq!(served.row["signature"], "valid");
    let mut forged = newest.clone();
    strip_sig(&mut forged);
    let served = frame(&live, &Access::All, &forged).expect("a call row");
    assert_eq!(served.row["signature"], "invalid");
    assert_eq!(served.row["integrity"], "sig_missing");
}

/// R16: the governance log has its own anchor: a stripped governance
/// record reads `invalid` in the list and the export.
#[tokio::test]
async fn r16_the_governance_log_is_anchored_too() {
    // The invocation log's anchor sits past legacy bytes; a governance row
    // judged against it (the wrong log's anchor) would not read `sig_missing`.
    let inv = turned_on_midway();
    let gov = Fixture::new();
    let log = gov.open(true, 0);
    for target in ["backend:alpha", "backend:beta"] {
        let mut f = serde_json::Map::new();
        f.insert("kind".into(), "control_plane_audit".into());
        f.insert("actor_id".into(), "alice".into());
        f.insert("target_id".into(), target.into());
        f.insert("action".into(), "mutate_grant".into());
        log.append_event(f, &crate::security::audit::AuditEnvelope::gateway())
            .unwrap();
    }
    drop(log);
    rewrite(&gov.path, |v| {
        let hit = v["target_id"] == "backend:alpha";
        if hit {
            v["action"] = "read_grant".into();
            strip_sig(v);
        }
        hit
    });
    let logs = Logs {
        invocation: inv.path.clone(),
        governance: Some(gov.path.clone()),
        secret: Some(SECRET.as_bytes().to_vec()),
    };
    let page: Value = serde_json::from_slice(
        &json_body(list_page(&logs, &Access::All, &ListQuery::default())).await,
    )
    .unwrap();
    let row = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["target_id"] == "backend:alpha")
        .expect("the governance row")
        .clone();
    assert_eq!(row["signature"], "invalid");
    let s = signer();
    let nd = json_body(export_response(
        &logs,
        &Access::All,
        &ExportQuery::default(),
        Some(&s),
    ))
    .await;
    let text = String::from_utf8(nd).unwrap();
    let exported: Value = text
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|r| r["target_id"] == "backend:alpha")
        .expect("exported");
    assert_eq!(exported["integrity"], "sig_missing");
}

/// R29 (round 3 J1): a stripped record appended after a sealed legacy
/// file's digested length reads `invalid`, not legacy `unsigned`.
#[tokio::test]
async fn r29_bytes_past_a_legacy_files_length_are_not_legacy() {
    let fx = Fixture::new();
    let plain = fx.open(false, 1024);
    Fixture::calls(&plain, 0, 12);
    drop(plain);
    let sealed = list_segments(&fx.path).unwrap();
    assert!(!sealed.is_empty(), "legacy history rotated");
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 12, 2);
    drop(log);
    // A sealed legacy file holding a call record (the first may hold only
    // housekeeping).
    let (legacy, text) = sealed
        .iter()
        .map(|s| (s.path.clone(), std::fs::read_to_string(&s.path).unwrap()))
        .find(|(_, t)| t.contains("\"tool\""))
        .expect("a sealed legacy file with a call");
    let legacy = &legacy;
    let last = text.lines().rev().find(|l| l.contains("\"tool\"")).unwrap();
    let mut extra: Value = serde_json::from_str(last).unwrap();
    extra["tool"] = "tool_99".into();
    strip_sig(&mut extra);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(legacy)
        .unwrap();
    std::io::Write::write_all(&mut f, (extra.to_string() + "\n").as_bytes()).unwrap();
    drop(f);
    // Its copied counter repeats one, so the receipt's seek cannot reach it.
    assert_invalid_unseekable(&seen(&fx, "tool_99").await, "legacy_edited");
}

/// R15 (a): a v3 log with no open record holds the anchor, then rotates: the
/// sealed file keeps the anchor's seq, its legacy records still read
/// `unsigned`, and a stripped signed record in it reads `invalid`.
#[tokio::test]
async fn r15_a_pre_open_record_file_keeps_its_anchor_after_rotation() {
    let fx = Fixture::new();
    write_v3(&fx.path, 1, 2, 3);
    drop(fx.open(true, 0));
    let log = fx.open(true, 1024);
    Fixture::calls(&log, 10, 8);
    drop(log);
    assert!(!list_segments(&fx.path).unwrap().is_empty(), "it rotated");
    assert_state(&seen(&fx, "tool_1").await, "unsigned");
    strip_anywhere(&fx, "tool_3");
    assert_invalid(&seen(&fx, "tool_3").await, "sig_missing");
}

/// R34: with history from before signing, a record stripped after signing
/// began reads `invalid` in every reader; the receipt must place it at its
/// own offset, not at the file's start, which holds legacy bytes (q14).
#[tokio::test]
async fn r34_stripped_after_a_midway_start_reads_invalid_everywhere() {
    let fx = turned_on_midway();
    fx.strip("tool_3", |v| v["response_hash"] = "sha256:ff".into());
    assert_invalid(&seen(&fx, "tool_3").await, "sig_missing");
}

// The rows the code review added, kept in their own file for size.
#[path = "sigstate_review_tests.rs"]
mod review;
