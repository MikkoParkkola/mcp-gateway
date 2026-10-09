// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1-T3 — with auth on, an audit log that cannot open stops the gateway.
//!
//! Drives `build_meta_mcp`, the step both `run` and `run_stdio` take before
//! they bind or read anything.

use super::Gateway;
use crate::config::Config;

/// Auth on, and the log path's parent is a regular file, so the open fails
/// for every user including root.
async fn gateway(auth: bool, dir: &tempfile::TempDir) -> Gateway {
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("blocker file");
    let mut config = Config::default();
    config.auth.enabled = auth;
    config.auth.bearer_token = Some("d1-start-test-token-0123456789abcdef".to_string());
    config.security.transparency_log.enabled = Some(true);
    config.security.transparency_log.path =
        blocker.join("audit.jsonl").to_string_lossy().into_owned();
    Gateway::new(config)
        .await
        .expect("the config itself is valid")
}

#[tokio::test]
async fn audit_log_open_failure_refuses_serve_with_auth() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(true, &dir).await;
    assert!(
        gateway.build_meta_mcp().await.is_err(),
        "auth is on and the audit log cannot open, so the gateway must not start"
    );
}

/// MIK-8044 P2c2: with the switch unset and auth on, startup opens the log
/// all the same. The path cannot open, so a start that skipped the log would
/// succeed and this would fail.
#[tokio::test]
async fn an_unset_audit_switch_opens_the_log_with_auth() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("blocker file");
    let mut config = Config::default();
    config.auth.enabled = true;
    config.auth.bearer_token = Some("d1-start-test-token-0123456789abcdef".to_string());
    assert_eq!(config.security.transparency_log.enabled, None, "left unset");
    config.security.transparency_log.path =
        blocker.join("audit.jsonl").to_string_lossy().into_owned();
    let gateway = Gateway::new(config).await.expect("the config is valid");
    assert!(
        gateway.build_meta_mcp().await.is_err(),
        "auth is on and the switch unset, so the log must open (and fail here)"
    );
}

/// Positive control: auth off keeps today's warn-and-continue.
#[tokio::test]
async fn audit_log_open_failure_with_auth_off_still_starts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway(false, &dir).await;
    assert!(gateway.build_meta_mcp().await.is_ok());
}

/// R3: another gateway already writes the log. The start is refused whatever
/// the auth setting, with the lease refusal named (not the generic
/// "audit log must open" error), because two writers fork the chain.
async fn refused_while_leased(auth: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let held = crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let _holder =
        crate::security::transparency_log::TransparencyLogger::open(std::sync::Arc::new(held))
            .expect("the first writer opens");
    let mut config = Config::default();
    config.auth.enabled = auth;
    config.auth.bearer_token = Some("d1-start-test-token-0123456789abcdef".to_string());
    config.security.transparency_log.enabled = Some(true);
    config.security.transparency_log.path = path.to_string_lossy().into_owned();
    let gateway = Gateway::new(config).await.expect("the config is valid");
    let err = match gateway.build_meta_mcp().await {
        Ok(_) => panic!("auth={auth}: started beside another writer of the log"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("another gateway process") && err.contains(&path.display().to_string()),
        "auth={auth}: {err}"
    );
    assert!(
        !err.contains("auth is enabled, so the audit log"),
        "auth={auth}: reported as a generic open failure: {err}"
    );
}

#[tokio::test]
async fn a_leased_log_refuses_start_with_auth_on() {
    refused_while_leased(true).await;
}

#[tokio::test]
async fn a_leased_log_refuses_start_with_auth_off() {
    refused_while_leased(false).await;
}
