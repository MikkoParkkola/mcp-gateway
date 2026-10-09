// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// #2145: a credential finding's excerpt is the redacted text, so a bare
/// 40-char token value cannot survive the 40-char cut into the audit log.
#[test]
fn a_redacted_value_leaves_no_part_of_the_secret_in_the_audit_log() {
    let (firewall, _dir, path) = response_fixture(FirewallConfig {
        rules: vec![response_rule("inspect_me", FirewallAction::Allow)],
        ..FirewallConfig::default()
    });
    let mut response = json!({ "content": [{ "type": "text", "text": CANARY }] });
    let verdict = inspected_response(&firewall, &mut response);
    assert!(verdict.allowed);
    assert_eq!(response["content"][0]["text"], "[REDACTED:credential]");
    let log = std::fs::read_to_string(&path).expect("configured audit file was opened");
    assert!(!log.contains("ghp_"), "{log}");
    let events = audit_entries(&path);
    let findings = events[0]["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "{log}");
    // MIK-8236: the audit row carries the finding's kind only; the redacted
    // excerpt stays in-process, on the verdict.
    for finding in findings {
        assert_eq!(finding["scan_type"], "credentials", "{log}");
        assert!(finding.get("matched").is_none(), "{log}");
    }
    for finding in &verdict.findings {
        assert_eq!(finding.matched, "[REDACTED:credential]");
    }
}
