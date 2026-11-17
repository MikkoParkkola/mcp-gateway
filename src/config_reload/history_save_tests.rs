// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design D-2 rows: one bounded save, and what a failed or late save leaves.
//!
//! "Byte-identical" compares the history file's raw bytes before and after,
//! read by its literal name. Rows that need the deadline run on a
//! current-thread runtime with a paused clock: a running `spawn_blocking` task
//! holds the clock's auto-advance there, so the deadline fires only when the
//! test advances it, after the job has arrived where the row parked it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::record_tests::{ONE_BACKEND, TWO_BACKENDS, rig, rig_in};
use super::seams::{self, Fault};
use super::{Outcome, StoredFile};
use crate::gateway::test_helpers::write_owner_only;

const REFUSED_PORT: &str = "server:\n  port: not-a-number\n";
/// Real time, the outer bound of every row: a paused clock cannot guard a hang.
const HANG: Duration = Duration::from_secs(30);

fn history_file(dir: &Path) -> PathBuf {
    dir.join("config-history.json")
}

fn bytes_of(dir: &Path) -> Vec<u8> {
    std::fs::read(history_file(dir)).expect("the history file reads")
}

/// Run `body` on a current-thread runtime with a paused clock, on its own
/// thread, and fail the row if it has not finished within [`HANG`] of real time.
pub(super) fn paused<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let (done, finished) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime")
            .block_on(body());
        let _ = done.send(());
    });
    match finished.recv_timeout(HANG) {
        Ok(()) => worker.join().expect("the row's thread"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // The body panicked: re-raise its panic as this row's failure.
            if let Err(panic) = worker.join() {
                std::panic::resume_unwind(panic);
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the row hung for {HANG:?}"),
    }
}

/// C4: a failed read during a refused reload's record (an I/O error, then bytes
/// that do not parse) is never taken as an empty store: the record is kept in
/// memory, complete, and the file is left byte-identical.
#[tokio::test]
async fn c4_a_failed_read_keeps_the_record_in_memory_and_the_file_as_it_was() {
    for fault in [Fault::ReadIo, Fault::Unparseable] {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = seams::install(dir.path());
        let rig = rig_in(dir, ONE_BACKEND);
        let before = bytes_of(rig.dir.path());
        installed.seams.fail(fault);
        write_owner_only(&rig.path, REFUSED_PORT).expect("break the config");
        assert!(
            rig.ctx.reload_outcome().await.is_err(),
            "the reload is refused"
        );
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "{fault:?}: the file must be left byte-identical"
        );
        let events = rig.store.events();
        // Memory-only from this record: the refused event alone, complete.
        assert_eq!(events.len(), 1, "{fault:?}: {events:?}");
        assert_eq!(events[0].outcome, Outcome::Refused, "{fault:?}");
        assert!(
            events[0].still_running.is_some(),
            "{fault:?}: the served revision is named"
        );
    }
}

/// C5: a history file made unreadable after open is left byte-identical and
/// the record is kept in memory. A regression row: today's record refuses a
/// failed read already. Skipped where the process can read a mode-000 file.
#[cfg(unix)]
#[tokio::test]
async fn c5_an_unreadable_file_is_left_as_it_is_and_the_record_kept() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = rig(ONE_BACKEND);
    let file = history_file(rig.dir.path());
    let before = bytes_of(rig.dir.path());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    if std::fs::read(&file).is_ok() {
        // root reads it anyway; the row cannot stage an unreadable file.
        return;
    }
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
    rig.ctx.reload_outcome().await.expect("the reload applies");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod back");
    assert_eq!(
        bytes_of(rig.dir.path()),
        before,
        "the file is left byte-identical"
    );
    let events = rig.store.events();
    assert_eq!(events.len(), 1, "memory-only from this record: {events:?}");
    assert_eq!(events[0].outcome, Outcome::Applied);
}

/// C6: a stored file's Debug names its path and byte count, never its bytes.
#[test]
fn c6_stored_file_debug_prints_the_path_and_the_byte_count() {
    let present = StoredFile {
        path: "/x/gateway.yaml".to_string(),
        bytes: Some(b"secret-9f2e".to_vec()),
    };
    let absent = StoredFile {
        path: "/x/.env".to_string(),
        bytes: None,
    };
    assert_eq!(
        format!("{present:?}"),
        r#"StoredFile { path: "/x/gateway.yaml", bytes: Some(11) }"#
    );
    assert_eq!(
        format!("{absent:?}"),
        r#"StoredFile { path: "/x/.env", bytes: None }"#
    );
}

/// C10a-c: a save that fails on the reload path leaves the file
/// byte-identical and the store memory-only: with the state the job sent back
/// when the write failed after it, with this record alone when the job died
/// before sending.
#[tokio::test]
async fn c10_a_failed_save_leaves_the_file_and_keeps_what_it_can() {
    // (fault, events held afterwards: the sent-back state is start + this reload)
    for (fault, held) in [
        (Fault::Write, 2),
        (Fault::PanicBeforeSend, 1),
        (Fault::DropSender, 1),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = seams::install(dir.path());
        let rig = rig_in(dir, ONE_BACKEND);
        let before = bytes_of(rig.dir.path());
        installed.seams.fail(fault);
        write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
        rig.ctx.reload_outcome().await.expect("the reload applies");
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "{fault:?}: byte-identical"
        );
        let events = rig.store.events();
        assert_eq!(events.len(), held, "{fault:?}: {events:?}");
        assert!(
            events.iter().all(|event| event.outcome == Outcome::Applied),
            "{fault:?}: {events:?}"
        );
        // Memory-only from here: the next record does not touch the file.
        write_owner_only(&rig.path, ONE_BACKEND).expect("drop the backend");
        rig.ctx
            .reload_outcome()
            .await
            .expect("the next reload applies");
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "{fault:?}: still byte-identical"
        );
        assert_eq!(
            rig.store.events().len(),
            held + 1,
            "{fault:?}: kept in memory"
        );
    }
}
