// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential the gateway never injected reaches the response firewall
//! whole, so its finding drives the decision and the audit entry. The executor
//! removes only injected literals; the scanner pass belongs to the firewall.
//!
//! Each case runs what production composes: `interpret`'s output (an error
//! wrapped as `dispatch_error_result` wraps it) through
//! `check_response_artifact` exactly as `response_pass` calls it.

use std::process::ExitStatus;

use serde_json::{Value, json};

use super::{CliOutcome, interpret};
use crate::capability::definition::CliOutput;
use crate::capability::executor::cli_argv::CliInvocation;
use crate::security::firewall::{
    Firewall, FirewallAction, FirewallConfig, FirewallVerdict, ScanType,
};
use crate::security::response_policy::{
    ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
};

/// AWS-key shaped, assembled so the repository holds no literal key.
const KEY: &str = concat!("AK", "IAIOSFODNN7", "EXAMPLE");
/// A second, distinct key.
const OTHER_KEY: &str = concat!("AK", "IAZZZZQQQQ7", "WXYZABC");

fn invocation() -> CliInvocation {
    CliInvocation {
        command: "tool".into(),
        args: Vec::new(),
        stdin: None,
    }
}

fn outcome(success: bool, stdout: &str, stderr: &str) -> CliOutcome {
    let status = if success {
        ExitStatus::default()
    } else {
        failed()
    };
    CliOutcome {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[cfg(unix)]
fn failed() -> ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(1 << 8)
}

#[cfg(windows)]
fn failed() -> ExitStatus {
    std::os::windows::process::ExitStatusExt::from_raw(1)
}

/// What the caller would receive for this outcome, before the firewall: the
/// result, or the error in the shape `dispatch_error_result` gives it.
fn artifact(output: CliOutput, outcome: &CliOutcome, secrets: &[String]) -> Value {
    match interpret(&invocation(), output, outcome, secrets, &json!({})) {
        Ok(value) => value,
        Err(e) => json!({"isError": true, "content": [{"type": "text", "text": e.to_string()}]}),
    }
}

/// The router's response pass on `artifact`, and the audit entries it wrote.
fn firewall_pass(mut artifact: Value) -> (FirewallVerdict, Value, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("fw.ndjson");
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            audit_log: Some(log.clone()),
            ..FirewallConfig::default()
        },
        None,
    );
    let verdict = firewall
        .check_response_artifact(
            &mut artifact,
            &[ResponsePolicyTarget {
                server: "cap".into(),
                tool: "tool".into(),
            }],
            &ResponseCorrelation {
                session_id: "s",
                caller: "c",
                external_server: "cap",
                external_tool: "tool",
                subject: None,
            },
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::Redact,
        )
        .expect("one policy target");
    let entries = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (verdict, artifact, entries)
}

/// The firewall saw the credential: a Credentials finding, the default Block
/// for its severity, the finding in the audit entry, and no key left behind.
fn assert_blocked_and_audited(output: CliOutput, outcome: &CliOutcome) {
    let before = artifact(output, outcome, &[]);
    let (verdict, after, entries) = firewall_pass(before.clone());
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials),
        "no credential finding; the firewall saw {before}"
    );
    assert_eq!(verdict.action, FirewallAction::Block, "{before}");
    assert!(!verdict.allowed);
    let audited = entries
        .iter()
        .filter(|e| e["event"] == "response")
        .flat_map(|e| e["findings"].as_array().cloned().unwrap_or_default())
        .any(|f| f["scan_type"] == "credentials");
    assert!(
        audited,
        "no credential finding in the audit log: {entries:?}"
    );
    assert!(!after.to_string().contains(KEY), "{after}");
}

#[test]
fn a_json_result_credential_reaches_the_firewall() {
    let stdout = json!({"note": format!("key {KEY} end")}).to_string();
    assert_blocked_and_audited(CliOutput::Json, &outcome(true, &stdout, ""));
}

#[test]
fn a_text_result_credential_reaches_the_firewall() {
    let stdout = format!("key {KEY} end");
    assert_blocked_and_audited(CliOutput::Text, &outcome(true, &stdout, ""));
}

#[test]
fn an_error_excerpt_credential_reaches_the_firewall() {
    let stderr = format!("failed: key {KEY} end");
    assert_blocked_and_audited(CliOutput::Json, &outcome(false, "", &stderr));
}

/// An MCP child's result goes through the same `redact_value` (mcp.rs).
#[test]
fn an_mcp_result_credential_reaches_the_firewall() {
    let mut result = json!({"content": [{"type": "text", "text": format!("key {KEY} end")}]});
    super::redact_value(&mut result, &[]);
    let (verdict, after, _) = firewall_pass(result);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials),
        "{:?}",
        verdict.findings
    );
    assert_eq!(verdict.action, FirewallAction::Block);
    assert!(!after.to_string().contains(KEY), "{after}");
}

/// Control: an injected credential is still removed by the executor, so the
/// firewall has nothing to find.
#[test]
fn an_injected_credential_is_removed_before_the_firewall() {
    let stdout = json!({"note": format!("key {KEY} end")}).to_string();
    let before = artifact(
        CliOutput::Json,
        &outcome(true, &stdout, ""),
        &[KEY.to_owned()],
    );
    assert!(!before.to_string().contains(KEY), "{before}");
    let (verdict, _, _) = firewall_pass(before);
    assert!(
        !verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials),
        "{:?}",
        verdict.findings
    );
    assert!(verdict.allowed);
}

/// The excerpt keeps the last 2 KiB. A credential the cut would split goes
/// whole (its tail alone is recognisable by nobody); one wholly inside the
/// tail stays for the firewall.
#[test]
fn a_credential_split_by_the_excerpt_cut_leaves_no_fragment() {
    let tail = format!(" then {OTHER_KEY} end");
    // The last 2048 bytes start 10 bytes into KEY.
    let filler = "b".repeat(2048 - (KEY.len() - 10) - 1 - tail.len());
    let stderr = format!("{} {KEY} {filler}{tail}", "a".repeat(100));
    let Err(e) = interpret(
        &invocation(),
        CliOutput::Json,
        &outcome(false, "", &stderr),
        &[],
        &json!({}),
    ) else {
        panic!("a failed child is an error");
    };
    let text = e.to_string();
    assert!(!text.contains(&KEY[10..]), "{text}");
    assert!(text.contains(OTHER_KEY), "{text}");
}

/// A credential that begins exactly at the cut lies wholly inside the
/// excerpt: it stays for the firewall, which only a whole credential reaches.
#[test]
fn a_credential_starting_at_the_excerpt_cut_stays_for_the_firewall() {
    // The last 2048 bytes start at KEY.
    let filler = "b".repeat(2048 - KEY.len() - 1);
    let stderr = format!("{} {KEY} {filler}", "a".repeat(100));
    let Err(e) = interpret(
        &invocation(),
        CliOutput::Json,
        &outcome(false, "", &stderr),
        &[],
        &json!({}),
    ) else {
        panic!("a failed child is an error");
    };
    let text = e.to_string();
    assert!(text.contains(KEY), "{text}");
}
