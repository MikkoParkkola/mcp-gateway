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
fn run_child(dir: &Path, case: &str) -> Vec<String> {
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
    let text = std::fs::read_to_string(dir.join(JTI_FILE)).unwrap_or_else(|_| {
        panic!(
            "the child never minted:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    text.lines().map(str::to_owned).collect()
}

fn sealed_segments(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("audit.jsonl.")
                && name.chars().last().is_some_and(|c| c.is_ascii_digit())
        })
        .count()
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

/// Make the mark file refuse writes while it stays readable, as a full or
/// failing volume does. The premise is checked: a process that can still
/// write it (root) cannot show the fault.
#[cfg(unix)]
fn make_mark_unwritable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let hwm = dir.join("audit.jsonl.hwm");
    assert!(hwm.is_file(), "the log wrote its mark when it opened");
    std::fs::set_permissions(&hwm, std::fs::Permissions::from_mode(0o444)).expect("read-only");
    assert!(
        std::fs::OpenOptions::new().write(true).open(&hwm).is_err(),
        "the mark file must refuse writes for this row to mean anything"
    );
}

#[cfg(not(unix))]
fn make_mark_unwritable(_dir: &Path) {
    panic!("the mark-fault rows are Unix-only");
}

#[tokio::test]
#[ignore = "run by the restart rows, in a child that aborts"]
async fn restart_child() {
    let (Ok(case), Ok(dir)) = (std::env::var(CASE), std::env::var(DIR)) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let log = Arc::new(
        TransparencyLogger::open(log_config(&dir, case.contains("rotat")))
            .expect("opens")
            .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    if case.starts_with("hwm_write_fails") {
        make_mark_unwritable(&dir);
    }
    let ks = KeyServer::new(
        crate::config::KeyServerConfig::default(),
        EmailHashKey::for_test(),
    )
    .with_issuance_log(Arc::clone(&log));
    if case == "mark_unreadable_rotating" {
        // A directory where the mark file goes: unreadable and unwritable.
        let hwm = dir.join("audit.jsonl.hwm");
        let _ = std::fs::remove_file(&hwm);
        std::fs::create_dir(&hwm).expect("a directory in the mark's place");
        let mut lines = Vec::new();
        for _ in 0..3 {
            let response = mint(&ks).await;
            let status = response.status().as_u16();
            let jti = if status == 200 {
                let bearer = bearer_of(response).await;
                ks.store.get(&bearer).await.expect("valid bearer").jti
            } else {
                "-".to_owned()
            };
            lines.push(format!("{status} {jti}"));
        }
        let written = std::fs::File::create(dir.join(JTI_FILE)).and_then(|mut f| {
            use std::io::Write as _;
            f.write_all(lines.join("\n").as_bytes())?;
            f.sync_all()
        });
        assert!(written.is_ok());
        std::process::abort();
    }
    // Two mints: the second shows later appends still land after the fault.
    let mut jtis = Vec::new();
    for _ in 0..2 {
        let response = mint(&ks).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK, "{case}");
        let bearer = bearer_of(response).await;
        jtis.push(ks.store.get(&bearer).await.expect("valid bearer").jti);
    }
    let written = std::fs::File::create(dir.join(JTI_FILE)).and_then(|mut f| {
        use std::io::Write as _;
        f.write_all(jtis.join("\n").as_bytes())?;
        f.sync_all()
    });
    assert!(written.is_ok());
    // No destructor, no clean shutdown: the process just dies.
    std::process::abort();
}

/// NEW.W.1: the rows survive the process dying, across a rotation, and the
/// log reopens on the retained files.
/// Mutant: skip the append (the rows are then missing after the death).
#[test]
fn a_confirmed_row_survives_an_abrupt_death_across_a_rotation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let jtis = run_child(dir.path(), "rotation");
    assert_eq!(jtis.len(), 2);
    for jti in &jtis {
        assert!(
            row_present(dir.path(), jti),
            "the row is on retained storage"
        );
    }
    assert!(
        sealed_segments(dir.path()) >= 1,
        "the rows crossed a rotation"
    );
    let reopened = TransparencyLogger::open(log_config(dir.path(), true));
    assert!(reopened.is_ok(), "the log reopens: {:?}", reopened.err());
}

/// NEW.W.1: a mark write that fails (the file refuses writes) only warns:
/// both mints are acknowledged and both rows are retained, and the log
/// reopens (the designed answer: the mark may lag the log, never the reverse).
/// Mutant: treat a mark-write failure as an append failure (the mint then
/// answers 503 and the child's own 200 assertion fails).
#[cfg(unix)]
#[test]
fn a_failed_high_water_mark_write_does_not_lose_the_confirmed_row() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let jtis = run_child(dir.path(), "hwm_write_fails");
    assert_eq!(jtis.len(), 2);
    for jti in &jtis {
        assert!(
            row_present(dir.path(), jti),
            "the row is on retained storage"
        );
    }
    assert!(TransparencyLogger::open(log_config(dir.path(), false)).is_ok());
}

/// NEW.W.1: the same fault while the first mint rotates the log: the seal,
/// the rename and the new segment complete, later appends still land, and
/// the log reopens on the stale mark.
/// Mutant: a mark failure inside the rotation aborts it or loses a row.
#[cfg(unix)]
#[test]
fn a_failed_high_water_mark_write_during_a_rotation_loses_no_row() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let jtis = run_child(dir.path(), "hwm_write_fails_rotating");
    assert_eq!(jtis.len(), 2);
    for jti in &jtis {
        assert!(
            row_present(dir.path(), jti),
            "the row is on retained storage"
        );
    }
    assert!(
        sealed_segments(dir.path()) >= 1,
        "the rows crossed a rotation"
    );
    let reopened = TransparencyLogger::open(log_config(dir.path(), true));
    assert!(
        reopened.is_ok(),
        "the log reopens on the stale mark: {:?}",
        reopened.err()
    );
}

/// An unreadable and unwritable mark at a rotation (a directory in its
/// place): what the key server answers is whatever the log does, but a mint
/// answered 200 must never lack its row, and a refused one must say so with
/// a 503. Prints nothing on its own; the observed answers are the finding.
/// Mutant: skip the append (200 without a row).
#[test]
fn an_unreadable_mark_at_a_rotation_never_acknowledges_a_mint_without_its_row() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let lines = run_child(dir.path(), "mark_unreadable_rotating");
    assert_eq!(lines.len(), 3, "{lines:?}");
    for line in &lines {
        let (status, jti) = line.split_once(' ').expect("status and jti");
        match status {
            "200" => assert!(
                row_present(dir.path(), jti),
                "acknowledged without a row: {line}"
            ),
            "503" => {}
            other => panic!("unexpected answer {other}: {lines:?}"),
        }
    }
    eprintln!("MARK-UNREADABLE-ANSWERS {lines:?}");
}
