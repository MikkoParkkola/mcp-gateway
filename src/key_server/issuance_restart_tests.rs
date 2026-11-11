// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The restart promise of a confirmed issuance row: a mint acknowledged with
//! 200 has its row on retained storage after the process dies with no clean
//! shutdown, across a segment rotation, and a high-water-mark write that
//! fails only warns. Each case mints in a child that aborts afterwards (no
//! destructor runs, the lease is released only by the death), and the parent
//! reads the retained files.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use super::issuance_row_tests::{bearer_of, mint};
use crate::key_server::KeyServer;
use crate::key_server::email_hash::EmailHashKey;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::{Malformed, RotationConfig, log_contains_entry};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const CASE: &str = "MCP_GW_TEST_ISSUANCE_RESTART_CASE";
const DIR: &str = "MCP_GW_TEST_ISSUANCE_RESTART_DIR";
const JTI_FILE: &str = "jti.txt";

fn log_config(dir: &Path, rotating: bool) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        // Small enough that the mint's row forces a rotation.
        rotation: RotationConfig {
            max_segment_bytes: if rotating {
                700
            } else {
                RotationConfig::default().max_segment_bytes
            },
            ..RotationConfig::default()
        },
    })
}

/// Run `case` in a child that mints, records the JTI, and aborts.
fn run_child(dir: &Path, case: &str) -> String {
    let out = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "key_server::issuance_restart_tests::restart_child",
            "--ignored",
            "--nocapture",
        ])
        .env(CASE, case)
        .env(DIR, dir)
        // The parent keeps the directory, so the child reports no unkept log.
        .env("MCP_GATEWAY_TEST_KEPT_DIRS", dir)
        .output()
        .expect("the child runs");
    assert!(
        !out.status.success(),
        "the child must abort, not exit cleanly"
    );
    std::fs::read_to_string(dir.join(JTI_FILE)).unwrap_or_else(|_| {
        panic!(
            "the child never minted:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn row_present(dir: &Path, jti: &str) -> bool {
    log_contains_entry(
        &dir.join("audit.jsonl"),
        "restart row check",
        Malformed::Refuse,
        |e| {
            e.get("event").and_then(|v| v.as_str()) == Some("token.issued")
                && e.get("token_jti").and_then(|v| v.as_str()) == Some(jti)
        },
    )
    .expect("the retained log reads")
}

#[tokio::test]
#[ignore = "run by the restart rows, in a child that aborts"]
async fn restart_child() {
    let (Ok(case), Ok(dir)) = (std::env::var(CASE), std::env::var(DIR)) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let log = Arc::new(
        TransparencyLogger::open(log_config(&dir, case == "rotation"))
            .expect("opens")
            .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    if case == "hwm_write_fails" {
        // A directory where the mark file goes: its write fails.
        let hwm = dir.join("audit.jsonl.hwm");
        let _ = std::fs::remove_file(&hwm);
        std::fs::create_dir(&hwm).expect("a directory in the mark's place");
    }
    let ks = KeyServer::new(
        crate::config::KeyServerConfig::default(),
        EmailHashKey::for_test(),
    )
    .with_issuance_log(Arc::clone(&log));
    let response = mint(&ks).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK, "{case}");
    let bearer = bearer_of(response).await;
    let jti = ks.store.get(&bearer).await.expect("valid bearer").jti;
    let written = std::fs::File::create(dir.join(JTI_FILE)).and_then(|mut f| {
        use std::io::Write as _;
        f.write_all(jti.as_bytes())?;
        f.sync_all()
    });
    assert!(written.is_ok());
    // No destructor, no clean shutdown: the process just dies.
    std::process::abort();
}

/// NEW.W.1: the row survives the process dying, across a rotation, and the
/// log reopens on the retained files.
/// Mutant: skip the append (the row is then missing after the death).
#[test]
fn a_confirmed_row_survives_an_abrupt_death_across_a_rotation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let jti = run_child(dir.path(), "rotation");
    assert!(
        row_present(dir.path(), &jti),
        "the row is on retained storage"
    );
    let sealed = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("audit.jsonl.")
                && name.chars().last().is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert!(sealed >= 1, "the mint's row crossed a segment rotation");
    let reopened = TransparencyLogger::open(log_config(dir.path(), true));
    assert!(
        reopened.is_ok(),
        "the log reopens after the death: {:?}",
        reopened.err()
    );
}

/// NEW.W.1: a failed high-water-mark write only warns: the mint is still
/// acknowledged and its row is retained.
/// Mutant: treat a mark-write failure as an append failure (the mint then
/// answers 503 and the child's own 200 assertion fails).
#[test]
fn a_failed_high_water_mark_write_does_not_lose_the_confirmed_row() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let jti = run_child(dir.path(), "hwm_write_fails");
    assert!(
        row_present(dir.path(), &jti),
        "the row is on retained storage"
    );
}
