// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8236: no audit row carries caller or backend content. Every writer is
//! fed a finding whose `matched` fragment and description carry markers; its
//! row must hold each finding as exactly its scan type, severity and location,
//! with `schema_version` 3, and neither marker anywhere.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use tempfile::NamedTempFile;

use super::super::{Finding, FindingLocation, FirewallAction, FirewallVerdict, ScanType, Severity};
use super::AuditLogger;
use crate::security::response_policy::{
    ResponseArtifactKind, ResponseCorrelation, ResponsePolicyTarget,
};

const FRAGMENT: &str = "MARK-FRAGMENT";
const KEY: &str = "mark_key";

/// A blocking verdict whose one finding carries both markers.
fn marked() -> FirewallVerdict {
    FirewallVerdict {
        allowed: false,
        action: FirewallAction::Block,
        findings: vec![Finding {
            scan_type: ScanType::ShellInjection,
            severity: Severity::High,
            description: format!("Shell injection pattern in argument '{KEY}'"),
            matched: FRAGMENT.to_owned(),
            location: FindingLocation::RequestArgs,
        }],
        anomaly_score: None,
    }
}

fn correlation() -> ResponseCorrelation<'static> {
    ResponseCorrelation {
        session_id: "s",
        caller: "c",
        external_server: "srv",
        external_tool: "t",
        subject: None,
    }
}

/// The one row `write` puts in a fresh log.
fn row(write: impl FnOnce(&AuditLogger)) -> Value {
    let tmp = NamedTempFile::new().unwrap();
    let logger = AuditLogger::new(tmp.path()).unwrap();
    write(&logger);
    let text = std::fs::read_to_string(tmp.path()).unwrap();
    let line = text.lines().find(|l| !l.is_empty()).expect("one row");
    serde_json::from_str(line).unwrap()
}

/// The content-free shape: the finding is exactly {scan_type, severity,
/// location} with the source's values, the count is kept, the row is
/// `schema_version` 3, and neither marker appears anywhere in it.
fn assert_content_free(writer: &str, row: &Value) {
    let text = row.to_string();
    assert!(
        !text.contains(FRAGMENT),
        "{writer}: a fragment was logged: {text}"
    );
    assert!(
        !text.contains(KEY),
        "{writer}: an argument key was logged: {text}"
    );
    assert_eq!(row["findings_count"], 1, "{writer}: {text}");
    assert_eq!(row["schema_version"], 3, "{writer}: {text}");
    let finding = row["findings"][0]
        .as_object()
        .unwrap_or_else(|| panic!("{writer}: one finding kept: {text}"));
    let keys: BTreeSet<&str> = finding.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from(["location", "scan_type", "severity"]),
        "{writer}: {text}"
    );
    assert_eq!(
        (
            &finding["scan_type"],
            &finding["severity"],
            &finding["location"]
        ),
        (
            &json!("shell_injection"),
            &json!("high"),
            &json!("request_args")
        ),
        "{writer}: {text}"
    );
}

/// C1.
#[test]
fn c1_a_request_row_carries_no_content() {
    let row = row(|log| log.log_request("s", "srv", "t", "c", &json!({KEY: "x"}), &marked()));
    assert_content_free("log_request", &row);
}

/// C2.
#[test]
fn c2_an_attributed_request_row_carries_no_content() {
    let tenants = BTreeSet::from(["tenant-a".to_owned()]);
    let row = row(|log| {
        log.log_request_attributed(&correlation(), &json!({KEY: "x"}), &marked(), &tenants)
    });
    assert_content_free("log_request_attributed", &row);
}

/// C3.
#[test]
fn c3_a_response_row_carries_no_content() {
    let row = row(|log| log.log_response("s", "srv", "t", "c", &marked()));
    assert_content_free("log_response", &row);
}

/// C4.
#[test]
fn c4_a_response_artifact_row_carries_no_content() {
    let targets = [ResponsePolicyTarget {
        server: "srv".to_owned(),
        tool: "t".to_owned(),
    }];
    let row = row(|log| {
        log.log_response_artifact(
            &correlation(),
            &targets,
            ResponseArtifactKind::FinalResponse,
            &marked(),
        );
    });
    assert_content_free("log_response_artifact", &row);
}

/// C5.
#[test]
fn c5_a_dispatch_row_carries_no_content() {
    let row = row(|log| log.log_dispatch(&correlation(), &json!({KEY: "x"}), &marked(), "step"));
    assert_content_free("log_dispatch", &row);
}
