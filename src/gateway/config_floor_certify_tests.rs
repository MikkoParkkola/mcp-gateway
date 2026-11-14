// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Certify rows C1 to C5: what the config checkpoint refuses, what it
//! certifies, and that it never writes a byte. Every Ok row compares the
//! certification with a hash computed here from literal bytes.

use std::sync::{Arc, Mutex};

use tokio::time::Instant;

use super::seams::{CheckHook, CheckStep};
use super::support::{self, BASE, BOUND, Booted};
use super::{ConfigFloor, FloorAdapter, FloorFault};

/// Pause then checkpoint on one real-time deadline, as the coordinator does.
async fn certify(floor: &mut ConfigFloor) -> Result<(), FloorFault> {
    let deadline = Instant::now() + BOUND;
    floor.pause(deadline).await?;
    floor.checkpoint(deadline).await
}

/// The sha256 the last checkpoint certified, or empty when none.
fn certified_sha(floor: &ConfigFloor) -> String {
    floor
        .certification()
        .map(|c| c.sha256.clone())
        .unwrap_or_default()
}

/// What a row compares before and after: bytes, mtime and inode of a file.
#[derive(Debug, PartialEq, Eq)]
struct FileState {
    bytes: Vec<u8>,
    mtime: std::time::SystemTime,
    inode: u64,
}

fn inode_of(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::ino(meta)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

fn file_state(path: &std::path::Path) -> FileState {
    let meta = std::fs::metadata(path).expect("file metadata");
    FileState {
        bytes: std::fs::read(path).expect("file bytes"),
        mtime: meta.modified().expect("mtime"),
        inode: inode_of(&meta),
    }
}

/// Install a check hook that records every step it sees; returns the record.
fn record_steps(floor: &mut ConfigFloor) -> Arc<Mutex<Vec<CheckStep>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let hook: CheckHook = Arc::new(move |_, step| sink.lock().unwrap().push(step));
    floor.set_check_hook(Some(hook));
    seen
}

/// The refusal contract of C1: SaveFailed, no read or validation after the
/// refusal, and the config file untouched. `unsettle` arranges one form.
async fn refuses_unsettled(
    row: &str,
    unsettle: impl FnOnce(&Booted, &mut ConfigFloor) -> Option<std::path::PathBuf>,
) {
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    let steps = record_steps(&mut floor);
    let sidecar = unsettle(&booted, &mut floor);
    let before = file_state(&booted.cfg.path);
    let sidecar_before = sidecar
        .as_ref()
        .map(|p| std::fs::read(p).expect("sidecar bytes"));

    let result = certify(&mut floor).await;

    assert_eq!(
        result,
        Err(FloorFault::SaveFailed),
        "{row} unsettled write must refuse"
    );
    let seen = steps.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|s| *s != CheckStep::Start),
        "{row} no read or validation after the refusal, saw {seen:?}"
    );
    assert_eq!(
        file_state(&booted.cfg.path),
        before,
        "{row} config file untouched"
    );
    if let (Some(path), Some(bytes)) = (sidecar, sidecar_before) {
        assert_eq!(
            std::fs::read(&path).ok(),
            Some(bytes),
            "{row} the evidence file still exists, unchanged"
        );
    }
}

#[tokio::test]
async fn c1_v1_journal_refuses() {
    const ROW: &str = "c1_v1_journal_refuses";
    refuses_unsettled(ROW, |b, _| {
        let path = b.cfg.beside(".gateway.yaml.replace-journal");
        std::fs::write(&path, r#"{"version":1}"#).expect("journal");
        Some(path)
    })
    .await;
}

#[tokio::test]
async fn c1_v2_journal_refuses() {
    const ROW: &str = "c1_v2_journal_refuses";
    refuses_unsettled(ROW, |b, _| {
        let path = b.cfg.beside(".gateway.yaml.replace-journal");
        std::fs::write(&path, r#"{"version":2}"#).expect("journal");
        Some(path)
    })
    .await;
}

#[tokio::test]
async fn c1_malformed_journal_refuses() {
    const ROW: &str = "c1_malformed_journal_refuses";
    refuses_unsettled(ROW, |b, _| {
        let path = b.cfg.beside(".gateway.yaml.replace-journal");
        std::fs::write(&path, b"not json at all {").expect("journal");
        Some(path)
    })
    .await;
}

#[tokio::test]
async fn c1_abandoned_file_refuses() {
    const ROW: &str = "c1_abandoned_file_refuses";
    refuses_unsettled(ROW, |b, _| {
        let path = b.cfg.beside("gateway.yaml.abandoned");
        std::fs::write(&path, b"left behind").expect("abandoned");
        Some(path)
    })
    .await;
}

#[tokio::test]
async fn c1_abandoned_metadata_error_refuses() {
    const ROW: &str = "c1_abandoned_metadata_error_refuses";
    refuses_unsettled(ROW, |_, floor| {
        floor.set_meta_hook(Some(Arc::new(|_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })));
        None
    })
    .await;
}

#[tokio::test]
async fn c1_nothing_unsettled_certifies_literal_hash() {
    const ROW: &str = "c1_nothing_unsettled_certifies_literal_hash";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Ok(()), "{ROW} a settled config certifies");
    assert_eq!(
        certified_sha(&floor),
        support::sha256_hex(BASE.as_bytes()),
        "{ROW} hash"
    );
}

#[tokio::test]
async fn c2_cli_write_between_pause_and_certify_certifies_new_bytes() {
    const ROW: &str = "c2_cli_write_between_pause_and_certify_certifies_new_bytes";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();
    let deadline = Instant::now() + BOUND;
    assert_eq!(floor.pause(deadline).await, Ok(()), "{ROW} pause");

    let cli = support::spawn_cli_writer(&booted.gate, &booted.cfg.path, "cli-edit");
    assert_eq!(
        support::join_bounded(cli.join, "cli writer"),
        Ok(()),
        "{ROW} cli write"
    );
    let after_cli = file_state(&booted.cfg.path);
    assert!(
        String::from_utf8_lossy(&after_cli.bytes).contains("cli-edit"),
        "{ROW} premise: the new bytes carry the value the cli set"
    );
    assert_ne!(
        after_cli.bytes,
        BASE.as_bytes(),
        "{ROW} the cli changed the file"
    );
    let result = floor.checkpoint(deadline).await;

    assert_eq!(result, Ok(()), "{ROW} certify after the cli write");
    assert_eq!(
        certified_sha(&floor),
        support::sha256_hex(&after_cli.bytes),
        "{ROW} hash of the new bytes"
    );
    assert_eq!(
        file_state(&booted.cfg.path).mtime,
        after_cli.mtime,
        "{ROW} mtime"
    );
}

/// C3 refusal contract: SaveFailed and no read or validation step after it.
fn assert_refused(
    row: &str,
    result: Result<(), FloorFault>,
    seen: &Mutex<Vec<CheckStep>>,
    late: &[CheckStep],
) {
    assert_eq!(result, Err(FloorFault::SaveFailed), "{row} must refuse");
    let seen = seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|s| late.contains(s)),
        "{row} late steps ran: {seen:?}"
    );
}

#[tokio::test]
async fn c3_invalid_yaml_refuses() {
    const ROW: &str = "c3_invalid_yaml_refuses";
    let booted = Booted::new(BASE);
    booted.cfg.rewrite("backends: [unclosed\n");
    let before = file_state(&booted.cfg.path);
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Err(FloorFault::SaveFailed), "{ROW} invalid yaml");
    assert_eq!(
        file_state(&booted.cfg.path),
        before,
        "{ROW} bytes, mtime and inode unchanged"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn c3_group_writable_file_refuses() {
    use std::os::unix::fs::PermissionsExt;
    const ROW: &str = "c3_group_writable_file_refuses";
    let booted = Booted::new(BASE);
    std::fs::set_permissions(&booted.cfg.path, std::fs::Permissions::from_mode(0o660))
        .expect("chmod");
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Err(FloorFault::SaveFailed), "{ROW} group-writable");
}

#[cfg(unix)]
#[tokio::test]
async fn c3_symlink_repointed_and_restored_refuses_at_identity() {
    const ROW: &str = "c3_symlink_repointed_and_restored_refuses_at_identity";
    let booted = Booted::new(BASE);
    let dir = booted.cfg.dir.path().to_path_buf();
    let (real, other) = (dir.join("real.yaml"), dir.join("other.yaml"));
    crate::gateway::test_helpers::write_owner_only(&real, BASE).expect("real target");
    crate::gateway::test_helpers::write_owner_only(&other, BASE.replace("  a:", "  b:"))
        .expect("other target");
    let link = booted.cfg.path.clone();
    std::fs::remove_file(&link).expect("remove file");
    std::os::unix::fs::symlink(&real, &link).expect("link to real");

    let mut floor = booted.floor();
    let steps = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&steps);
    let (to_other, to_real, link2) = (other.clone(), real.clone(), link.clone());
    floor.set_check_hook(Some(Arc::new(move |_, step| {
        sink.lock().unwrap().push(step);
        let target = match step {
            CheckStep::BeforeRead => &to_other,
            CheckStep::AfterValidation => &to_real,
            _ => return,
        };
        let _ = std::fs::remove_file(&link2);
        std::os::unix::fs::symlink(target, &link2).expect("repoint");
    })));

    let result = certify(&mut floor).await;

    assert_refused(
        ROW,
        result,
        &steps,
        &[CheckStep::AfterRead, CheckStep::AfterValidation],
    );
}

#[tokio::test]
async fn c3_in_place_rewrite_after_validation_refuses() {
    const ROW: &str = "c3_in_place_rewrite_after_validation_refuses";
    let booted = Booted::new(BASE);
    let path = booted.cfg.path.clone();
    let inode = file_state(&path).inode;
    let mut floor = booted.floor();
    let rewritten = format!("{BASE}environment: rewritten\n");
    floor.set_check_hook(Some(Arc::new(move |_, step| {
        if step == CheckStep::AfterValidation {
            std::fs::write(&path, &rewritten).expect("in-place rewrite");
        }
    })));

    let result = certify(&mut floor).await;

    assert_eq!(
        result,
        Err(FloorFault::SaveFailed),
        "{ROW} rewrite between validation and re-check"
    );
    assert_eq!(
        file_state(&booted.cfg.path).inode,
        inode,
        "{ROW} same inode"
    );
}

#[tokio::test]
async fn c3_good_file_certifies_literal_hash() {
    const ROW: &str = "c3_good_file_certifies_literal_hash";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Ok(()), "{ROW} good file");
    assert_eq!(
        certified_sha(&floor),
        support::sha256_hex(BASE.as_bytes()),
        "{ROW} hash"
    );
}

#[tokio::test]
async fn c4_identical_bytes_certify_twice_without_a_write() {
    const ROW: &str = "c4_identical_bytes_certify_twice_without_a_write";
    let booted = Booted::new(BASE);
    let before = file_state(&booted.cfg.path);
    let mut floor = booted.floor();
    let literal = support::sha256_hex(BASE.as_bytes());

    assert_eq!(certify(&mut floor).await, Ok(()), "{ROW} first");
    assert_eq!(certified_sha(&floor), literal, "{ROW} first hash");
    floor.resume();
    assert_eq!(certify(&mut floor).await, Ok(()), "{ROW} second");
    assert_eq!(certified_sha(&floor), literal, "{ROW} second hash");

    assert_eq!(
        file_state(&booted.cfg.path),
        before,
        "{ROW} bytes, mtime and inode unchanged"
    );
}

#[tokio::test]
async fn c5_reload_owed_flag_refuses() {
    const ROW: &str = "c5_reload_owed_flag_refuses";
    let booted = Booted::new(BASE);
    booted.ctx.owe_reload_for_test();
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Err(FloorFault::SaveFailed), "{ROW} owed reload");
}

#[tokio::test]
async fn c5_watcher_failed_retry_flag_refuses() {
    const ROW: &str = "c5_watcher_failed_retry_flag_refuses";
    let booted = Booted::new(BASE);
    let watcher = support::WatcherFixture::new(&booted);
    booted.cfg.rewrite("backends: [unclosed\n");
    // The test plays the OS delivering the notify event; the real reload fails.
    booted.gate.record_file_event();
    support::tick(&watcher).await;
    booted.cfg.rewrite(BASE);
    let text = String::from_utf8(booted.cfg.bytes()).expect("utf8");
    assert!(
        crate::config::Config::load_evaluated_text(&booted.cfg.path, &text).is_ok(),
        "{ROW} premise: the file is valid at certify"
    );
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Err(FloorFault::SaveFailed), "{ROW} failed retry");
}

#[tokio::test]
async fn c5_both_flags_clear_certifies_literal_hash() {
    const ROW: &str = "c5_both_flags_clear_certifies_literal_hash";
    let booted = Booted::new(BASE);
    let mut floor = booted.floor();

    let result = certify(&mut floor).await;

    assert_eq!(result, Ok(()), "{ROW} flags clear");
    assert_eq!(
        certified_sha(&floor),
        support::sha256_hex(BASE.as_bytes()),
        "{ROW} hash"
    );
}
