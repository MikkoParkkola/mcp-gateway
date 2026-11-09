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
    let dir = tempfile::tempdir().unwrap();
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
