// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record-FIFO regression (W-L8, MIK-8182), moved out of `store_tests.rs`
//! unchanged so that file keeps room under the 800-line ceiling.

use super::{
    AccountLookup, PersonalAccountStore, committed_fixture, config, install_committed_fixture,
};

// A record FIFO cannot be observed in-process: an implementation that opens it
// without O_NONBLOCK blocks forever, which is the defect under test. The bounded
// child process is the oracle. Unix: `mkfifo(1)` exists on Linux and macOS
// (MIK-8182); Windows has no FIFO path to guard.
#[cfg(unix)]
const RECORD_CHILD_ROOT: &str = "MCP_ACCOUNTS_RECORD_FIFO_TEST_ROOT";
#[cfg(unix)]
const RECORD_CHILD_TEST: &str = "personal_accounts::tests::store::record_fifo::record_lookup_child";

/// Private test-binary entrypoint; no daemon or real credentials are involved.
#[cfg(unix)]
#[test]
#[ignore = "private child entrypoint; exercised by the bounded record-FIFO regression"]
fn record_lookup_child() {
    use std::io::Write as _;

    let root =
        std::env::var_os(RECORD_CHILD_ROOT).expect("child requires its synthetic fixture root");
    let fixture = committed_fixture();
    let case = &fixture.cases[0];
    let key = case.account_key();
    let settings = config(std::path::Path::new(&root));
    println!("ACCOUNT_RECORD_READY");
    std::io::stdout().flush().unwrap();
    let outcome = match PersonalAccountStore::open(settings).map(|store| store.lookup(&key)) {
        Ok(Ok(AccountLookup::Connected(record))) if record == case.record => "CONNECTED".to_owned(),
        Ok(Ok(other)) => format!("STATE:{other:?}"),
        Ok(Err(error)) => format!("LOOKUP:{error:?}"),
        Err(error) => format!("OPEN:{error:?}"),
    };
    println!("ACCOUNT_RECORD_RESULT:{outcome}");
    std::io::stdout().flush().unwrap();
}

/// Always reap the owned child, including an implementation that never returns.
#[cfg(unix)]
struct RecordProbe {
    child: std::process::Child,
    reader: Option<std::thread::JoinHandle<()>>,
    events: std::sync::mpsc::Receiver<String>,
}

// Unix (W-L8, MIK-8182): the record-FIFO regression needs `mkfifo` and a bounded child.
#[cfg(unix)]
impl Drop for RecordProbe {
    fn drop(&mut self) {
        super::super::probe::reap(&mut self.child);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

// Unix (W-L8, MIK-8182): the record-FIFO regression needs `mkfifo` and a bounded child.
#[cfg(unix)]
fn probe_record_lookup(
    root: &std::path::Path,
) -> Result<String, std::sync::mpsc::RecvTimeoutError> {
    use std::io::BufRead as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            RECORD_CHILD_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(RECORD_CHILD_ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Inherited, so a child panic is visible in the log rather than being
        // silently indistinguishable from the blocking failure this bounds.
        .stderr(Stdio::inherit());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command.spawn().expect("spawn isolated record-lookup child");
    let output = child.stdout.take().unwrap();
    let (sender, events) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            let event = if line.contains("ACCOUNT_RECORD_READY") {
                "READY".to_owned()
            } else if let Some((_, result)) = line.split_once("ACCOUNT_RECORD_RESULT:") {
                result.trim().to_owned()
            } else {
                continue;
            };
            if sender.send(event).is_err() {
                break;
            }
        }
    });
    let probe = RecordProbe {
        child,
        reader: Some(reader),
        events,
    };
    assert_eq!(
        probe.events.recv_timeout(Duration::from_secs(10)),
        Ok("READY".to_owned()),
        "child readiness is a harness precondition"
    );
    probe.events.recv_timeout(Duration::from_secs(1))
}

// Unix (W-L8, MIK-8182): the record-FIFO regression needs `mkfifo` and a bounded child.
#[cfg(unix)]
#[test]
fn s03_fifo_record_refuses_promptly_without_blocking_lookup() {
    use std::os::unix::fs::FileTypeExt as _;

    let (root, settings, fixture) = install_committed_fixture();
    let case = &fixture.cases[0];
    // The parent never opens the store: both directory locks belong to the child.
    assert_eq!(
        probe_record_lookup(root.path()),
        Ok("CONNECTED".to_owned()),
        "the unmutated fixture must resolve through the child before any fault"
    );
    let path = settings.store_dir.join(&case.basename);
    let original = std::fs::read(&path).unwrap();
    let backup = settings.store_dir.join("saved-valid-ciphertext");
    std::fs::rename(&path, &backup).unwrap();
    crate::test_fifo::make_fifo(&path);
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    // Capture the result while the FIFO is present, then restore the untouched
    // ciphertext and prove it still reads before asserting the refusal.
    let observed = probe_record_lookup(root.path());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(probe_record_lookup(root.path()), Ok("CONNECTED".to_owned()));
    assert_eq!(
        observed,
        Ok("LOOKUP:StorageUnavailable".to_owned()),
        "a record FIFO must refuse as physical-storage failure within one second of readiness"
    );
}
