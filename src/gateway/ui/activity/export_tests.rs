// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E1-E6 of the U2 test plan: the signed NDJSON bundle and its offline check,
//! domain separation, integrity marks, caps, and the exported field set.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::{CAPS, Caps, Collected, collect, csv, csv_size, ndjson, ndjson_size};
use crate::gateway::ui::activity::access::Access;
use crate::gateway::ui::activity::rows::Filter;
use crate::gateway::ui::activity::{ExportQuery, Logs, export_response};
use crate::security::audit_rotation_config::RotationConfig;
use crate::security::{TransparencyLogConfig, TransparencyLogger};
use crate::trust::export_verify::{ExportRefusal, verify_export};
use crate::trust::provenance_public::{ACTIVITY_EXPORT_DOMAIN, ProvenancePublicSigner, TrustSet};

const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";

fn signer() -> ProvenancePublicSigner {
    ProvenancePublicSigner::from_seed_for_test([7u8; 32], "export-test-1")
}

fn trust(s: &ProvenancePublicSigner) -> TrustSet {
    TrustSet::from_json(&s.public_jwk().to_string()).unwrap()
}

/// A signed log of `n` calls written by the real logger.
fn log(dir: &tempfile::TempDir, n: usize) -> std::path::PathBuf {
    let path = dir.path().join("inv.jsonl");
    let l = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: SECRET.into(),
        rotation: RotationConfig::default(),
    }))
    .unwrap();
    for i in 0..n {
        l.log_invocation(
            "s",
            "c",
            "srv",
            &format!("tool_{i}"),
            "sha256:aa",
            "sha256:bb",
        )
        .unwrap();
    }
    path
}

fn all(path: &Path, caps: Caps, size: fn(&Value) -> usize) -> Collected {
    collect(
        path,
        None,
        &Filter::default(),
        &Access::All,
        Some(SECRET.as_bytes()),
        caps,
        size,
    )
    .unwrap()
}

fn bundle(path: &Path) -> Vec<u8> {
    ndjson(&all(path, CAPS, ndjson_size), json!({}), &signer())
}

#[test]
fn e1_a_valid_export_verifies_and_every_edit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = log(&dir, 5);
    let good = bundle(&path);
    let t = trust(&signer());
    let report = verify_export(&good, &t).expect("valid");
    assert_eq!(report.rows, 5);
    assert_eq!(report.truncated, "none");

    let text = String::from_utf8(good.clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let manifest: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    let rejoin = |ls: &[String]| -> Vec<u8> {
        ls.iter()
            .map(|l| l.clone() + "\n")
            .collect::<String>()
            .into_bytes()
    };
    let owned: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();

    // A changed field in one row.
    let mut edited = owned.clone();
    edited[0] = edited[0].replace("tool_4", "tool_X");
    assert_eq!(
        verify_export(&rejoin(&edited), &t),
        Err(ExportRefusal::DigestMismatch)
    );

    // The same change with the digest recomputed and the old signature kept.
    let rows: String = edited[..edited.len() - 1]
        .iter()
        .map(|l| l.clone() + "\n")
        .collect();
    let mut m = manifest.clone();
    m["sha256"] = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(rows.as_bytes())).into();
    let mut forged = edited.clone();
    *forged.last_mut().unwrap() = m.to_string();
    assert_eq!(
        verify_export(&rejoin(&forged), &t),
        Err(ExportRefusal::BadSignature)
    );

    // A changed manifest field.
    for (field, value) in [
        ("rows", json!(4)),
        ("truncated", json!("rows")),
        ("filters", json!({"server": "x"})),
    ] {
        let mut m = manifest.clone();
        m[field] = value;
        let mut changed = owned.clone();
        *changed.last_mut().unwrap() = m.to_string();
        assert_eq!(
            verify_export(&rejoin(&changed), &t),
            Err(ExportRefusal::BadSignature),
            "{field}"
        );
    }

    // Another key under the same key id, and a key id not trusted.
    let other = ProvenancePublicSigner::from_seed_for_test([9u8; 32], "export-test-1");
    assert_eq!(
        verify_export(&good, &trust(&other)),
        Err(ExportRefusal::BadSignature)
    );
    let stranger = ProvenancePublicSigner::from_seed_for_test([9u8; 32], "someone-else");
    let refused = verify_export(&good, &trust(&stranger)).unwrap_err();
    assert!(matches!(refused, ExportRefusal::UnknownKid), "{refused:?}");

    // Empty, manifest removed, manifest cut half-way.
    assert_eq!(verify_export(b"", &t), Err(ExportRefusal::Empty));
    assert_eq!(
        verify_export(&rejoin(&owned[..owned.len() - 1]), &t),
        Err(ExportRefusal::NoManifest)
    );
    let cut = &good[..good.len() - lines.last().unwrap().len() / 2];
    assert_eq!(verify_export(cut, &t), Err(ExportRefusal::Torn));
}

#[test]
fn e3_export_and_receipt_signatures_are_separate_domains() {
    let s = signer();
    let t = trust(&s);
    let message = b"{\"kind\":\"manifest\"}";
    let receipt_domain = b"mcp-gateway-provenance-ed25519-v1\0";
    let as_receipt = s.sign_bytes(receipt_domain, message);
    assert!(
        t.verify_bytes(s.kid(), ACTIVITY_EXPORT_DOMAIN, message, &as_receipt)
            .is_err()
    );
    let as_export = s.sign_bytes(ACTIVITY_EXPORT_DOMAIN, message);
    assert!(
        t.verify_bytes(s.kid(), receipt_domain, message, &as_export)
            .is_err()
    );
    assert!(
        t.verify_bytes(s.kid(), ACTIVITY_EXPORT_DOMAIN, message, &as_export)
            .is_ok()
    );
}

#[test]
fn e4_tampered_rows_are_marked_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let path = log(&dir, 3);
    let mut text: Vec<Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let calls: Vec<usize> = (0..text.len())
        .filter(|i| text[*i].get("tool").is_some())
        .collect();
    // A field edited with the stored hash kept: the hash fails.
    text[calls[0]]["tool"] = "edited".into();
    // A hash recomputed after an edit, the old HMAC kept: the signature fails.
    text[calls[1]]["tool"] = "rehashed".into();
    let h = crate::security::transparency_log::recompute_entry_hash(&text[calls[1]]).unwrap();
    text[calls[1]]["entry_hash"] = h.into();
    let body: String = text.iter().map(|v| v.to_string() + "\n").collect();
    std::fs::write(&path, body).unwrap();

    let c = all(&path, CAPS, ndjson_size);
    let mark = |tool: &str| {
        c.rows
            .iter()
            .find(|r| r["tool"] == tool)
            .and_then(|r| r.get("integrity").cloned())
    };
    assert_eq!(mark("edited"), Some(json!("hash_failed")));
    assert_eq!(mark("rehashed"), Some(json!("sig_failed")));
    assert_eq!(mark("tool_2"), None);
    let out = String::from_utf8(ndjson(&c, json!({}), &signer())).unwrap();
    let manifest: Value = serde_json::from_str(out.lines().last().unwrap()).unwrap();
    assert_eq!(manifest["integrity_failed"], 2);
}

#[test]
fn e5_each_cap_cuts_where_it_says_and_names_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = log(&dir, 12);
    let tools = |c: &Collected| -> Vec<String> {
        c.rows
            .iter()
            .map(|r| r["tool"].as_str().unwrap().to_string())
            .collect()
    };
    let newest =
        |n: usize| -> Vec<String> { (12 - n..12).rev().map(|i| format!("tool_{i}")).collect() };

    let below = all(&path, CAPS, ndjson_size);
    assert_eq!(tools(&below), newest(12));
    assert!(matches!(below.truncated, super::Truncated::None));

    let rows = all(&path, Caps { rows: 5, ..CAPS }, ndjson_size);
    assert_eq!(tools(&rows), newest(5));
    assert!(matches!(rows.truncated, super::Truncated::Rows));

    for size in [ndjson_size as fn(&Value) -> usize, csv_size] {
        let one = size(&below.rows[0]);
        // Room for three rows and part of a fourth: exactly three, no partial row.
        let cap = one * 3 + one / 2;
        let bytes = all(&path, Caps { bytes: cap, ..CAPS }, size);
        assert_eq!(tools(&bytes), newest(3));
        assert!(matches!(bytes.truncated, super::Truncated::Bytes));
        assert!(bytes.rows.iter().map(size).sum::<usize>() <= cap);
    }

    // A filter nothing matches, over a scan cap smaller than the log: the
    // log must exceed one read window, which is always read.
    let big = dir.path().join("big.jsonl");
    let pad = "p".repeat(400);
    let lines: String = (0..5_000)
        .map(|i| {
            json!({"tool": format!("t{i}"), "request_hash": "x", "pad": pad}).to_string() + "\n"
        })
        .collect();
    std::fs::write(&big, lines).unwrap();
    let sparse = collect(
        &big,
        None,
        &Filter {
            server: Some("absent".into()),
            ..Filter::default()
        },
        &Access::All,
        None,
        Caps {
            scan: 1 << 20,
            ..CAPS
        },
        ndjson_size,
    )
    .unwrap();
    assert!(sparse.rows.is_empty());
    assert!(matches!(sparse.truncated, super::Truncated::Scan));
    assert!(csv(&sparse).ends_with("#end rows=0 truncated=scan\r\n"));
    assert_eq!(CAPS.rows, 10_000);
    assert_eq!(CAPS.bytes, 64 << 20);
    assert_eq!(CAPS.scan, 512 << 20);
}

#[test]
fn e6_rows_carry_the_entry_chain_and_hmac_fields_as_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = log(&dir, 2);
    let source: Vec<Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v.get("tool").is_some())
        .collect();
    let c = all(&path, CAPS, ndjson_size);
    for r in &c.rows {
        let src = source
            .iter()
            .find(|s| s["counter"] == r["counter"])
            .unwrap();
        for k in ["entry_hash", "prev_entry_hash", "counter", "sig", "key_id"] {
            assert_eq!(r[k], src[k], "{k}");
        }
        assert_eq!(r["decision"], "not recorded by this gateway version");
        assert_eq!(r["reach"], "not recorded by this gateway version");
        assert!(r.get("integrity").is_none());
    }
}

#[tokio::test]
async fn e2_ndjson_without_a_key_is_409_and_csv_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let logs = Logs {
        invocation: log(&dir, 2),
        governance: None,
        secret: None,
    };
    let ndjson_q = ExportQuery::default();
    let r = export_response(&logs, &Access::All, &ndjson_q, None);
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("GATEWAY_PROVENANCE_SIGNING_SEED")
    );
    assert_eq!(v["csv"], "CSV is unsigned: evidence to read, not to verify");

    let csv_q = ExportQuery {
        format: Some("csv".into()),
        ..ExportQuery::default()
    };
    let r = export_response(&logs, &Access::All, &csv_q, None);
    assert_eq!(r.status(), StatusCode::OK);
    let s = signer();
    let r = export_response(&logs, &Access::All, &ndjson_q, Some(&s));
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(verify_export(&body, &trust(&s)).is_ok());
}
