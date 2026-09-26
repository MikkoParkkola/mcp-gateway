// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fail-closed audit hardening: `audit_identity_propagation` unit tests.
use std::sync::Arc;

use tempfile::NamedTempFile;

use super::*;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

fn open_logger() -> (NamedTempFile, Arc<TransparencyLogger>) {
    let file = NamedTempFile::new().expect("tempfile");
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    let logger = Arc::new(TransparencyLogger::open(cfg).expect("logger opens"));
    (file, logger)
}

// `logger = None` (transparency log disabled) is a no-op success, not
// a failure — the mint path must not be blocked when the operator has
// not configured a transparency log at all.
#[tokio::test]
async fn logger_disabled_is_ok_noop() {
    let result = audit_identity_propagation(
        None,
        "idp_mint",
        "alice",
        "github",
        Some("https://github.test.invalid/api"),
        None,
    )
    .await;
    assert_eq!(result, Ok(()));
}

// A durable write succeeds and reports `Ok(())`.
#[tokio::test]
async fn mint_write_success_is_ok() {
    let (_file, logger) = open_logger();
    let result = audit_identity_propagation(
        Some(&logger),
        "idp_mint",
        "alice",
        "github",
        Some("https://github.test.invalid/api"),
        None,
    )
    .await;
    assert_eq!(result, Ok(()));
}

// F20 T6: the mint audit goes through the bounded append, so a
// stalled disk refuses the mint within the bound (no durable record,
// no credential) instead of pinning a runtime worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_audit_on_a_stalled_disk_is_bounded_and_fail_closed() {
    let (_file, logger) = open_logger();
    let bound = std::time::Duration::from_millis(200);
    let release = logger.stall_next_write_for_test(bound);
    let start = std::time::Instant::now();
    let result = audit_identity_propagation(
        Some(&logger),
        "idp_mint",
        "alice",
        "github",
        Some("https://github.test.invalid/api"),
        None,
    )
    .await;
    assert!(
        start.elapsed() < bound * 5,
        "bounded: {:?}",
        start.elapsed()
    );
    assert!(
        matches!(result, Err(PropagationError::AuditFailed(_))),
        "{result:?}"
    );
    assert!(logger.is_stalled());
    release.release();
}

// Fail-closed contract: a genuine transparency-log write failure MUST
// surface as `Err(PropagationError::AuditFailed)`, never be swallowed.
//
// Failure-injection technique: POSIX only checks file permissions at
// `open(2)`, not at each `write(2)` — verified empirically (chmod and
// `chflags uchg` on an already-open fd do NOT make subsequent writes
// fail on macOS/Linux). A real write failure is therefore forced with
// `RLIMIT_FSIZE=0` (every write becomes `EFBIG`), which is
// process-wide and would corrupt any other test in this binary that
// touches a file concurrently — so the limited write happens in a
// *child process* only. A POSIX shell wrapper (`ulimit -f 0; trap ''
// XFSZ; exec ...`) sets the limit and ignores `SIGXFSZ` (whose
// default disposition is to kill the process) before re-`exec`ing
// this exact test binary/test with an env var that makes the child
// branch run the actual assertion and report its outcome over
// stdout — no `unsafe` code, no new dependency, isolated to the
// child only. Unix-only (the technique is POSIX shell + rlimit).
#[cfg(unix)]
#[tokio::test]
async fn mint_write_failure_is_fail_closed() {
    const ENV_VAR: &str = "IDP_AUDIT_FSIZE_CHILD_PATH";
    const MARK_OK: &str = "AUDIT_WRITE_FAILED_AS_EXPECTED";
    const TEST_PATH: &str =
        "identity_propagation::audit_fail_closed::mint_write_failure_is_fail_closed";

    if let Ok(path) = std::env::var(ENV_VAR) {
        // Child process: RLIMIT_FSIZE=0 + SIGXFSZ ignored are already
        // active (set by the parent's shell wrapper below), so any
        // write here returns `Err` (`EFBIG`), never panics/aborts.
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path,
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        });
        // `open()` performs no write (only reads an existing tail, if
        // any), so it must still succeed under the zero file-size
        // limit — only the append write below is expected to fail.
        let logger =
            Arc::new(TransparencyLogger::open(cfg).expect("open() writes nothing, must succeed"));
        let result = audit_identity_propagation(
            Some(&logger),
            "idp_mint",
            "alice",
            "github",
            Some("https://github.test.invalid/api"),
            None,
        )
        .await;
        match result {
            Err(PropagationError::AuditFailed(_)) => println!("{MARK_OK}"),
            other => println!("UNEXPECTED_RESULT:{other:?}"),
        }
        return;
    }

    // Parent: re-exec this exact test in an RLIMIT_FSIZE=0 child and
    // assert on what it observed.
    let exe = std::env::current_exe().expect("current test binary path");
    let file = NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    let script =
        format!("ulimit -f 0; trap '' XFSZ; exec \"$0\" '{TEST_PATH}' --exact --nocapture");
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(&exe)
        .env(ENV_VAR, &path)
        .output()
        .expect("spawn fsize-limited child process");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(MARK_OK),
        "child did not observe a fail-closed AuditFailed error \
         (status={:?}, stdout={stdout}, stderr={})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // The child must also EXIT cleanly: a child that prints the marker
    // and then aborts (panic/abort after the observation) must not read
    // as a pass.
    assert!(
        output.status.success(),
        "child printed the marker but did not exit successfully \
         (status={:?}, stderr={})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
