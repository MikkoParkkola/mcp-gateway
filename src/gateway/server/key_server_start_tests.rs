// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The key server needs the audit log: it records the email-hash key there,
//! so a lost key file is refused instead of replaced. Drives
//! `start_key_server`, the step `run` takes after the audit log opened.

use std::sync::Arc;

use super::Gateway;
use crate::config::Config;

fn config(dir: &tempfile::TempDir) -> Config {
    let mut config = Config::default();
    config.auth.enabled = false;
    config.key_server.enabled = true;
    config.security.transparency_log.enabled = Some(false);
    config.security.transparency_log.path = dir
        .path()
        .join("audit.jsonl")
        .to_string_lossy()
        .into_owned();
    config
}

/// No audit log: refused, naming the setting to change.
#[tokio::test]
async fn an_enabled_key_server_without_the_audit_log_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::new(config(&dir))
        .await
        .expect("the config is valid");
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let err = match gateway.start_key_server(&tx, dir.path(), None) {
        Ok(_) => panic!("started a key server with no audit log"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("key_server.enabled") && err.contains("security.transparency_log.enabled"),
        "{err}"
    );
    assert!(
        !dir.path()
            .join(crate::key_server::email_hmac_store::FILE)
            .exists(),
        "no key file is created before the refusal"
    );
}

/// With the audit log: the key server starts, the key file is created and
/// the log holds exactly one creation record; a second start adds none.
#[tokio::test]
async fn with_the_audit_log_the_key_is_created_and_recorded_once() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let log_path = dir.path().join("audit.jsonl");
    let log_config = crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: log_path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let logger = Arc::new(
        crate::security::transparency_log::TransparencyLogger::open(Arc::new(log_config))
            .expect("the log opens"),
    );
    // The log's late writes land in a directory the test still holds.
    logger.keep_test_dir(Arc::clone(&dir));
    let gateway = Gateway::new(config(&dir))
        .await
        .expect("the config is valid");
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    for _ in 0..2 {
        let started = gateway
            .start_key_server(&tx, dir.path(), Some(&logger))
            .expect("starts");
        assert!(started.is_some());
    }
    let created = std::fs::read_to_string(&log_path)
        .expect("log")
        .lines()
        .filter(|l| l.contains(crate::key_server::email_hmac_store::CREATED_EVENT))
        .count();
    assert_eq!(created, 1, "one creation record across two starts");
    assert!(
        dir.path()
            .join(crate::key_server::email_hmac_store::FILE)
            .exists()
    );
}

/// The key server off: no audit log needed, no key file, no refusal.
#[tokio::test]
async fn a_disabled_key_server_needs_no_audit_log_and_makes_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.key_server.enabled = false;
    let gateway = Gateway::new(cfg).await.expect("the config is valid");
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let started = gateway
        .start_key_server(&tx, dir.path(), None)
        .expect("no refusal");
    assert!(started.is_none());
    assert!(
        !dir.path()
            .join(crate::key_server::email_hmac_store::FILE)
            .exists()
    );
}

/// A crash after the creation record but before the file was marked
/// recorded: the next start finds the record and appends no second one.
#[tokio::test]
async fn a_crash_between_record_and_flag_appends_no_second_record() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let log_path = dir.path().join("audit.jsonl");
    let logger = Arc::new(
        crate::security::transparency_log::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        ))
        .expect("the log opens"),
    );
    logger.keep_test_dir(Arc::clone(&dir));
    let gateway = Gateway::new(config(&dir))
        .await
        .expect("the config is valid");
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    gateway
        .start_key_server(&tx, dir.path(), Some(&logger))
        .expect("first start");
    let file = dir.path().join(crate::key_server::email_hmac_store::FILE);
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).expect("read")).expect("json");
    envelope["creation_recorded"] = serde_json::json!(false);
    std::fs::write(&file, serde_json::to_vec(&envelope).expect("json")).expect("write");
    gateway
        .start_key_server(&tx, dir.path(), Some(&logger))
        .expect("restart");
    let created = std::fs::read_to_string(&log_path)
        .expect("log")
        .lines()
        .filter(|l| l.contains(crate::key_server::email_hmac_store::CREATED_EVENT))
        .count();
    assert_eq!(created, 1, "one creation record after the crash window");
}
