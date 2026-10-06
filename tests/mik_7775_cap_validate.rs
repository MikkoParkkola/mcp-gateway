// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7775: `mcp-gateway cap validate` runs the structural checks the loader
//! runs, so an author sees a warning (CAP-011, CAP-012) before deploying and a
//! structural error fails the command.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::{Output, Stdio};

const VALID: &str = "name: probe_cap
description: Reads one endpoint.
providers:
  primary:
    config:
      base_url: https://api.example.com
      path: /v1
";

fn cap_validate(yaml: &str) -> (Output, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("probe_cap.yaml");
    std::fs::write(&file, yaml).expect("write capability");
    let mut command = gateway_bin::command(dir.path(), gateway_bin::Inherit::Environment);
    command
        .stdin(Stdio::null())
        .arg("cap")
        .arg("validate")
        .arg(&file);
    let out = command.output().expect("run mcp-gateway");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, text)
}

#[test]
fn a_declared_fallback_is_reported_and_the_file_still_validates() {
    let yaml = format!(
        "{VALID}  fallback:\n    - config:\n        base_url: https://backup.example.com\n"
    );
    let (out, text) = cap_validate(&yaml);
    assert!(text.contains("CAP-011"), "CAP-011 is shown: {text}");
    assert!(out.status.success(), "a warning does not fail: {text}");
}

#[test]
fn an_unread_provider_key_is_reported() {
    let (out, text) = cap_validate(&format!("{VALID}      methd: POST\n"));
    assert!(text.contains("CAP-012"), "CAP-012 is shown: {text}");
    assert!(
        text.contains("providers.primary.config.methd"),
        "the key is named: {text}"
    );
    assert!(out.status.success(), "a warning does not fail: {text}");
}

#[test]
fn a_structural_error_fails_the_command() {
    // A REST provider with a relative path and no base URL cannot be called (CAP-005).
    let yaml = VALID.replace("      base_url: https://api.example.com\n", "");
    let (out, text) = cap_validate(&yaml);
    assert!(text.contains("CAP-005"), "CAP-005 is shown: {text}");
    assert!(!out.status.success(), "a structural error fails: {text}");
}

#[test]
fn a_clean_file_validates_with_no_issue_codes() {
    let (out, text) = cap_validate(VALID);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains("CAP-0"), "no issue codes: {text}");
}
