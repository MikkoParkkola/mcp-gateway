//! Integration tests for RFC-0071 Security Firewall.
//!
//! These tests exercise the full `Firewall` pipeline:
//! - Pre-invocation request scanning (shell injection, path traversal, SQL)
//! - Post-invocation response scanning (credential redaction, prompt injection)
//! - Audit log writing (NDJSON format, args hashed not raw)

#![cfg(feature = "firewall")]

use mcp_gateway::security::firewall::{
    Firewall, FirewallAction, FirewallConfig, FirewallRule, ScanType,
};
use serde_json::json;
use tempfile::NamedTempFile;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn default_fw() -> Firewall {
    Firewall::from_config(FirewallConfig::default(), None)
}

fn fw_with_audit(path: &std::path::Path) -> Firewall {
    let cfg = FirewallConfig {
        audit_log: Some(path.to_path_buf()),
        ..FirewallConfig::default()
    };
    Firewall::from_config(cfg, None)
}

// ─── T1: Shell injection blocks the request ──────────────────────────────────

#[test]
fn firewall_blocks_shell_injection_in_request() {
    let fw = default_fw();
    let args = json!({ "command": "; rm -rf / " });
    let verdict = fw.check_request("sess-1", "backend", "exec_tool", &args, "caller");

    assert!(!verdict.allowed, "Shell injection must be blocked");
    assert_eq!(
        verdict.action,
        FirewallAction::Block,
        "Action must be Block for shell injection"
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::ShellInjection),
        "Must report ShellInjection finding"
    );
}

// ─── T2: Credential redaction in response ────────────────────────────────────

#[test]
fn firewall_redacts_credential_in_response() {
    let fw = default_fw();
    let mut response =
        json!({ "output": "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890 completed" });

    let verdict = fw.check_response("sess-2", "backend", "my_tool", &mut response, "caller");

    // Credential must be redacted in-place.
    let output = response["output"].as_str().unwrap();
    assert!(
        output.contains("[REDACTED:credential]"),
        "GitHub token must be redacted, got: {output}"
    );
    assert!(
        !output.contains("ghp_"),
        "Raw token must not remain: {output}"
    );

    // Surrounding text preserved.
    assert!(output.contains("token: "), "Prefix should remain");
    assert!(output.contains(" completed"), "Suffix should remain");

    // Finding reported.
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials),
        "Must report Credentials finding"
    );
}

// ─── T3: Audit log written in NDJSON format ──────────────────────────────────

#[test]
fn firewall_audit_log_written_on_request() {
    let tmp = NamedTempFile::new().unwrap();
    let fw = fw_with_audit(tmp.path());

    let args = json!({ "query": "normal search" });
    let _verdict = fw.check_request("sess-3", "srv", "search_tool", &args, "api-key-abc");

    // File must have at least one line.
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "Audit log must have at least one entry");

    // Each line must be valid JSON with required fields.
    for line in &lines {
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("each audit line must be valid JSON");

        assert!(entry.get("timestamp").is_some(), "Missing timestamp");
        assert!(entry.get("tool").is_some(), "Missing tool");
        assert!(entry.get("action").is_some(), "Missing action");
        assert!(entry.get("session_id").is_some(), "Missing session_id");

        // Raw argument values must NOT appear in the log.
        assert!(
            !line.contains("normal search"),
            "Raw arg value must not appear in audit log"
        );
    }
}

// ─── T4: Path traversal blocked ──────────────────────────────────────────────

#[test]
fn firewall_blocks_path_traversal_in_request() {
    let fw = default_fw();
    let args = json!({ "file": "../../../etc/passwd" });
    let verdict = fw.check_request("sess-4", "backend", "read_file", &args, "caller");

    assert!(!verdict.allowed, "Path traversal must be blocked");
    assert_eq!(verdict.action, FirewallAction::Block);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::PathTraversal),
        "Must report PathTraversal finding"
    );
}

// ─── T5: SQL injection warns but allows ──────────────────────────────────────

#[test]
fn firewall_warns_on_sql_injection() {
    let fw = default_fw();
    let args = json!({ "query": "' OR 1=1" });
    let verdict = fw.check_request("sess-5", "backend", "search", &args, "caller");

    // SQL injection is MEDIUM severity → Warn, not Block.
    assert!(verdict.allowed, "SQL injection should warn, not block");
    assert_eq!(verdict.action, FirewallAction::Warn);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::SqlInjection),
        "Must report SqlInjection finding"
    );
}

// ─── T6: Disabled firewall passes everything ─────────────────────────────────

#[test]
fn disabled_firewall_passes_shell_injection() {
    let cfg = FirewallConfig {
        enabled: false,
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, None);

    let args = json!({ "cmd": "; rm -rf / " });
    let verdict = fw.check_request("sess-6", "srv", "exec", &args, "caller");
    assert!(verdict.allowed);
    assert_eq!(verdict.action, FirewallAction::Allow);
    assert!(verdict.findings.is_empty());
}

// ─── T7: Exec_* rule blocks even MEDIUM-severity findings ────────────────────

#[test]
fn exec_rule_elevates_sql_injection_to_block() {
    let cfg = FirewallConfig {
        rules: vec![FirewallRule {
            tool_match: "exec_*".to_string(),
            action: FirewallAction::Block,
            reason: Some("All exec tools blocked".to_string()),
            scan: vec![],
        }],
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, None);

    // SQL injection alone is MEDIUM (→ warn), but the exec_* rule → block.
    let args = json!({ "q": "' OR 1=1" });
    let verdict = fw.check_request("sess-7", "srv", "exec_query", &args, "caller");
    assert!(!verdict.allowed);
    assert_eq!(verdict.action, FirewallAction::Block);
}

// ─── T8: Response scan disabled ──────────────────────────────────────────────

#[test]
fn response_scan_disabled_skips_credential_detection() {
    let cfg = FirewallConfig {
        scan_responses: false,
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, None);

    let mut response = json!({ "key": "AKIAIOSFODNN7EXAMPLE12345" });
    let verdict = fw.check_response("sess-8", "srv", "tool", &mut response, "caller");
    assert!(verdict.allowed);
    assert!(verdict.findings.is_empty());
    // Value should NOT be redacted when scan_responses is false.
    assert_eq!(
        response["key"].as_str().unwrap(),
        "AKIAIOSFODNN7EXAMPLE12345"
    );
}

// ─── T9: Audit log written for both request and response ─────────────────────

#[test]
fn audit_log_written_for_both_request_and_response() {
    let tmp = NamedTempFile::new().unwrap();
    let fw = fw_with_audit(tmp.path());

    let args = json!({ "x": "value" });
    fw.check_request("sess-9", "srv", "tool", &args, "caller");

    let mut response = json!({ "result": "ok" });
    fw.check_response("sess-9", "srv", "tool", &mut response, "caller");

    let content = std::fs::read_to_string(tmp.path()).unwrap();
    let lines: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    assert_eq!(lines.len(), 2, "Expected one request + one response entry");

    let events: Vec<&str> = lines.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert!(events.contains(&"request"), "Missing request audit entry");
    assert!(events.contains(&"response"), "Missing response audit entry");
}
