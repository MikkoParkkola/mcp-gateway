// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365 through `audit verify`'s config step: the key it verifies with is
//! the resolved one, and a key that did not resolve is refused.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_gateway::security::TransparencyLogger;
use mcp_gateway::security::transparency_log::{
    TransparencyLogConfig, VerifyMode, verify_audit_log,
};

use mcp_gateway::config::Config;

const FIELD: &str = "security.transparency_log.shared_secret";
const VAR: &str = "MCP_GW_8365_VERIFY_KEY";
const KEY: &str = "tlog-8365-verify-key-0123456789abcdefghij";

fn write_0600(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn config(dir: &Path, enabled: bool, env_body: &str) -> PathBuf {
    let env = dir.join("gateway.env");
    write_0600(&env, env_body);
    let path = dir.join("gateway.yaml");
    write_0600(
        &path,
        &format!(
            "env_files:\n  - \"{}\"\nsecurity:\n  transparency_log:\n    enabled: {enabled}\n    \
             path: \"{}\"\n    shared_secret: \"env:{VAR}\"\n",
            env.display(),
            dir.join("unused.jsonl").display()
        ),
    );
    path
}

/// Three entries signed with `key`.
fn write_log(path: &Path, key: &str) {
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "default".into(),
        shared_secret: key.into(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    for i in 0..3 {
        log.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .expect("append");
    }
}

/// T6: a log signed with the resolved key verifies; one forged with the
/// reference's literal text is a signature mismatch, not a load failure.
#[test]
fn audit_verify_uses_the_resolved_key_and_rejects_the_reference_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(dir.path(), true, &format!("{VAR}={KEY}\n"));
    let verify_config = Config::audit_verify_config(Some(&path)).expect("the config loads");
    assert_eq!(verify_config.shared_secret, KEY);

    let honest = dir.path().join("honest.jsonl");
    write_log(&honest, KEY);
    let result = verify_audit_log(&honest, &verify_config, VerifyMode::Live, None).expect("verify");
    assert!(
        result.ok,
        "the honest log failed: {:?}",
        result.error_message
    );
    // The log's own open record, then the three entries.
    assert_eq!(result.entries_checked, 4);

    let forged = dir.path().join("forged.jsonl");
    write_log(&forged, &format!("env:{VAR}"));
    let result = verify_audit_log(&forged, &verify_config, VerifyMode::Live, None).expect("verify");
    assert!(!result.ok, "a log signed with the reference text verified");
}

/// T3e: with the log off and the reference unset, the gateway's config loads
/// but `audit verify` refuses, naming the field.
#[test]
fn audit_verify_refuses_a_key_that_did_not_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(dir.path(), false, "MCP_GW_8365_OTHER=1\n");
    mcp_gateway::config::Config::load(Some(&path)).expect("a disabled log loads");
    let error = Config::audit_verify_config(Some(&path)).expect_err("verify refuses");
    assert!(error.to_string().contains(FIELD), "{error}");
}
