// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One bounded child-process harness for every account restart and crash case.
//!
//! A store holds both directory locks for its lifetime, so "restart" can only
//! be observed from a separate process; and an operation that never returns
//! cannot be bounded in-process at all. Both reviewers raised the copied probe
//! in `store_tests.rs` as a finding. This module is the single owner. The two
//! existing copies adopt it once the frozen lookup mutation run resolves —
//! editing them now would race a source the supervisor owns.
//!
//! Every outcome is explicit. A child that dies announces the named boundary it
//! died at, so "it ended" is never mistaken for "it ended where I meant".

use std::io::{BufRead as _, Write as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(super) const ROOT: &str = "MCP_ACCOUNTS_CHILD_ROOT";
pub(super) const ACTION: &str = "MCP_ACCOUNTS_CHILD_ACTION";
const READY: &str = "ACCOUNT_CHILD_READY";
const RESULT: &str = "ACCOUNT_CHILD_RESULT:";

/// What the child did, from the parent's side of the pipe.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// It answered. `clean_exit` separates a deliberate abort from a normal end.
    Answered { text: String, clean_exit: bool },
    /// It ended without answering. `checkpoint` names the boundary it announced
    /// before dying; `None` means it died somewhere nobody asked it to.
    Died { checkpoint: Option<String> },
    /// It was still alive at the deadline. This is the blocking failure.
    Silent,
}

enum Event {
    Ready,
    Checkpoint(String),
    Result(String),
}

/// The child's fixture root and requested action.
pub(super) fn assignment() -> (std::path::PathBuf, String) {
    let root = std::env::var_os(ROOT).expect("child requires its synthetic fixture root");
    let action = std::env::var(ACTION).expect("child requires an action");
    (std::path::PathBuf::from(root), action)
}

/// Announce readiness. The parent's answer deadline starts here, so setup cost
/// is never mistaken for a blocked operation.
pub(super) fn ready() {
    println!("{READY}");
    std::io::stdout().flush().unwrap();
}

pub(super) fn report(outcome: &str) {
    println!("{RESULT}{outcome}");
    std::io::stdout().flush().unwrap();
}

/// Always reap the owned child, including one that never returns.
struct Probe {
    child: Child,
    reader: Option<JoinHandle<()>>,
    events: Receiver<Event>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Run `test_name` in a fresh process over `root` with `action`, bounded by
/// `answer`. `abort_at` names a persistence boundary at which the child dies;
/// the parent supplies it because a child cannot set its own environment
/// without `unsafe`, which this crate denies. The child is always reaped.
pub(super) fn run(
    test_name: &str,
    root: &Path,
    action: &str,
    abort_at: Option<&str>,
    answer: Duration,
) -> Outcome {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(ROOT, root)
        .env(ACTION, action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Inherited, so a child panic is readable instead of being silently
        // indistinguishable from the blocking failure this bounds.
        .stderr(Stdio::inherit());
    if let Some(boundary) = abort_at {
        command.env(super::faults::ABORT_AT, boundary);
    }
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command.spawn().expect("spawn isolated account child");
    let output = child.stdout.take().unwrap();
    let (sender, events) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            let event = if line.contains(READY) {
                Event::Ready
            } else if let Some((_, name)) = line.split_once(super::faults::CHECKPOINT) {
                Event::Checkpoint(name.trim().to_owned())
            } else if let Some((_, text)) = line.split_once(RESULT) {
                Event::Result(text.trim().to_owned())
            } else {
                continue;
            };
            if sender.send(event).is_err() {
                break;
            }
        }
    });
    let mut probe = Probe {
        child,
        reader: Some(reader),
        events,
    };
    assert!(
        matches!(
            probe.events.recv_timeout(Duration::from_secs(20)),
            Ok(Event::Ready)
        ),
        "child readiness is a harness precondition, not the measurement"
    );
    await_answer(&mut probe, answer)
}

fn await_answer(probe: &mut Probe, answer: Duration) -> Outcome {
    let deadline = Instant::now() + answer;
    let mut checkpoint = None;
    loop {
        match probe.events.try_recv() {
            Ok(Event::Result(text)) => {
                return Outcome::Answered {
                    text,
                    clean_exit: exited_cleanly(probe),
                };
            }
            Ok(Event::Checkpoint(name)) => {
                checkpoint = Some(name);
                continue;
            }
            Ok(Event::Ready) => continue,
            Err(_) => {}
        }
        // Exit without an answer is a real result, not a timeout: an aborted or
        // panicking child must never be reported as a hang. But the child
        // exiting does not mean the reader has finished queueing what it
        // flushed, so JOIN the reader before draining. Without this the race is
        // between the child's exit and its own last line, and a correct crash
        // test fails nondeterministically. The join terminates because the exit
        // closed the pipe's write end.
        if let Some(status) = probe.child.try_wait().unwrap() {
            if let Some(reader) = probe.reader.take() {
                let _ = reader.join();
            }
            while let Ok(event) = probe.events.try_recv() {
                match event {
                    Event::Result(text) => {
                        return Outcome::Answered {
                            text,
                            clean_exit: status.success(),
                        };
                    }
                    Event::Checkpoint(name) => checkpoint = Some(name),
                    Event::Ready => {}
                }
            }
            return Outcome::Died { checkpoint };
        }
        if Instant::now() >= deadline {
            return Outcome::Silent;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn exited_cleanly(probe: &mut Probe) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = probe.child.try_wait().unwrap() {
            return status.success();
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
