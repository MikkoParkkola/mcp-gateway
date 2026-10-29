// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` without a key: a signed record written between its
//! signed-log check and its verifying pass must still refuse the run.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use mcp_gateway::security::TransparencyLogger;
use mcp_gateway::security::transparency_log::TransparencyLogConfig;

thread_local! {
    static BETWEEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

/// Runs once between the signed-log check and the verifying pass.
pub(super) fn between_passes() {
    if let Some(hook) = BETWEEN.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

fn logger(path: &Path, key: &str) -> TransparencyLogger {
    TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "default".into(),
        shared_secret: key.into(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log")
}

fn append(log: &TransparencyLogger, n: usize) {
    for i in 0..n {
        log.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .expect("append");
    }
}

/// A gateway config with a transparency log and no shared secret.
fn keyless_config(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("gateway.yaml");
    std::fs::write(
        &path,
        format!(
            "security:\n  transparency_log:\n    enabled: true\n    path: \"{}\"\n",
            dir.join("unused.jsonl").display()
        ),
    )
    .expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    path
}

/// The log is unsigned when checked, and signed records land before the
/// verifying pass reads it: the run is refused, not passed hash-only.
#[test]
fn a_signed_record_written_between_the_passes_refuses_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    append(&logger(&log, ""), 3);
    let config = keyless_config(dir.path());
    let target = log.clone();
    BETWEEN.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            append(&logger(&target, "tlog-9060-race-key-0123456789abcdef"), 2);
        }));
    });

    let exit = super::run_audit_verify(&log, true, None, Some(&config));

    assert_eq!(exit, ExitCode::FAILURE, "a signed record passed hash-only");
}

/// The control: an unsigned log verifies without a key, as before.
#[test]
fn an_unsigned_log_verifies_without_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    append(&logger(&log, ""), 3);
    let config = keyless_config(dir.path());

    assert_eq!(
        super::run_audit_verify(&log, true, None, Some(&config)),
        ExitCode::SUCCESS
    );
}
