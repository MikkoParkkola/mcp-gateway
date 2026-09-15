// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S03: malformed authority must refuse without blocking an opening process.

use super::{PersonalAccountStore, config};
use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const CHILD_ROOT: &str = "MCP_ACCOUNTS_FIFO_TEST_ROOT";
const CHILD_TEST: &str = "personal_accounts::tests::fifo::authority_open_child";

#[derive(Debug, Eq, PartialEq)]
enum OpenEvent {
    Ready,
    Opened,
    Refused,
}

/// Private test-binary entrypoint; no daemon or real credentials are involved.
#[test]
#[ignore = "private child entrypoint; exercised by the bounded FIFO regression"]
fn authority_open_child() {
    let root = std::env::var_os(CHILD_ROOT).expect("child requires its synthetic fixture root");
    let settings = config(Path::new(&root));
    println!("ACCOUNT_AUTHORITY_READY");
    std::io::stdout().flush().unwrap();
    let result = PersonalAccountStore::open(settings);
    if result.is_ok() {
        println!("ACCOUNT_AUTHORITY_OPENED");
    } else {
        println!("ACCOUNT_AUTHORITY_REFUSED");
    }
    std::io::stdout().flush().unwrap();
}

/// Always reap the owned child, including the intentionally hanging old code.
struct AuthorityProbe {
    child: Child,
    reader: Option<JoinHandle<()>>,
    events: Receiver<OpenEvent>,
}

impl AuthorityProbe {
    fn spawn(root: &Path) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(CHILD_ROOT, root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        let mut child = command.spawn().expect("spawn isolated store-open child");
        let output = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                let event = if line.contains("ACCOUNT_AUTHORITY_READY") {
                    OpenEvent::Ready
                } else if line.contains("ACCOUNT_AUTHORITY_OPENED") {
                    OpenEvent::Opened
                } else if line.contains("ACCOUNT_AUTHORITY_REFUSED") {
                    OpenEvent::Refused
                } else {
                    continue;
                };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            reader: Some(reader),
            events,
        }
    }

    fn finish_successfully(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "store-open child exited unsuccessfully");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit after its result"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for AuthorityProbe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn probe_open(root: &Path) -> Result<OpenEvent, RecvTimeoutError> {
    let mut probe = AuthorityProbe::spawn(root);
    assert_eq!(
        probe.events.recv_timeout(Duration::from_secs(10)),
        Ok(OpenEvent::Ready),
        "child readiness is a harness precondition"
    );
    let result = probe.events.recv_timeout(Duration::from_secs(1));
    if result.is_ok() {
        probe.finish_successfully();
    }
    result
}

#[test]
fn s03_fifo_authority_refuses_promptly_and_preserves_original() {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    let initialized = PersonalAccountStore::initialize(settings.clone());
    assert!(initialized.is_ok(), "valid authority setup is required");
    drop(initialized);
    assert_eq!(probe_open(root.path()), Ok(OpenEvent::Opened));
    let path = settings.authority_dir.join("authority.json");
    let original = std::fs::read(&path).unwrap();
    let backup = root.path().join("saved-authority.json");
    std::fs::rename(&path, &backup).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("create actual FIFO in private fixture root");
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    // Capture the result while the FIFO is present. Only then remove the FIFO
    // and restore the untouched authority, keeping its original owner-only mode.
    let observed = probe_open(root.path());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "restored authority retains owner-only permissions"
    );
    assert_eq!(probe_open(root.path()), Ok(OpenEvent::Opened));
    assert_eq!(
        observed,
        Ok(OpenEvent::Refused),
        "authority FIFO must refuse within one second after child readiness"
    );
}
