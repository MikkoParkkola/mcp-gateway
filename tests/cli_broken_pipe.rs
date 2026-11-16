// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway list --available | head` exits cleanly, through the shipped
//! binary.
//!
//! Rust ignores SIGPIPE, so once the reader of stdout is gone `println!`
//! panics with "failed printing to stdout: Broken pipe" and the release build
//! (`panic = "abort"`) dumps core. A CLI whose reader has left has nothing more
//! to say: it should exit quietly and successfully.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::BufRead as _;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Each wait on a child (its first line, its exit, the end of its output)
/// gets this long. The commands print a fixed text and exit well inside a
/// second, so only a hang reaches it, and it fails in seconds where an
/// unbounded wait held a Windows runner until the job's own limit.
const BOUND: Duration = Duration::from_secs(30);

/// How a bounded child ended: its status and all it wrote.
struct Ended {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// `from` read to its end on a thread; the text arrives on the receiver.
fn read_on_thread(mut from: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sent, text) = mpsc::channel();
    std::thread::spawn(move || {
        let mut all = String::new();
        let _ = from.read_to_string(&mut all);
        let _ = sent.send(all);
    });
    text
}

/// Kills `child` and reaps it within [`BOUND`]: true once it is gone. The
/// cleanup is bounded too, so a child that survives its kill is reported,
/// never waited on forever.
fn kill_and_reap(child: &mut Child) -> bool {
    let _ = child.kill();
    let deadline = Instant::now() + BOUND;
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Kills `child` and fails `case`, naming the wait that timed out.
fn hung(child: &mut Child, case: &str, wait: &str) -> ! {
    let after = if kill_and_reap(child) {
        "killed"
    } else {
        "killed but still not reaped"
    };
    panic!("{case}: {wait} did not happen within {BOUND:?}; the child was {after}");
}

/// A spawned child whose every wait is bounded by [`BOUND`]. Dropped before
/// it was reaped (a test that failed first), it is killed and waited for, so
/// its temporary home is never removed under a live process.
struct Bounded(Child);

impl Bounded {
    /// The child's first stdout line, read through a reader dropped as soon
    /// as it has the line (as `| head -1` leaves).
    fn first_line(&mut self, case: &str) -> String {
        let stdout = self.0.stdout.take().expect("stdout");
        let (sent, line) = mpsc::channel();
        std::thread::spawn(move || {
            let mut first = String::new();
            let read = std::io::BufReader::new(stdout).read_line(&mut first);
            let _ = sent.send(read.map(|_| first));
        });
        match line.recv_timeout(BOUND) {
            Ok(read) => read.expect("read the first line"),
            Err(_) => hung(&mut self.0, case, "the first stdout line"),
        }
    }

    /// Reaps the child: waits for its exit, then for each piped output to
    /// end; a wait that times out fails `case` naming that wait.
    fn reap(mut self, case: &str) -> Ended {
        let stdout = self.0.stdout.take().map(read_on_thread);
        let stderr = self.0.stderr.take().map(read_on_thread);
        let deadline = Instant::now() + BOUND;
        let status = loop {
            if let Some(status) = self.0.try_wait().expect("poll the child") {
                break status;
            }
            if Instant::now() >= deadline {
                hung(&mut self.0, case, "the child's exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let collect = |text: Option<mpsc::Receiver<String>>, which: &str| {
            text.map_or_else(String::new, |text| {
                text.recv_timeout(BOUND).unwrap_or_else(|_| {
                    panic!(
                        "{case}: the child exited ({status}) but its {which} did not end within {BOUND:?}: another process holds the pipe"
                    )
                })
            })
        };
        Ended {
            stdout: collect(stdout, "stdout"),
            stderr: collect(stderr, "stderr"),
            status,
        }
    }
}

impl Drop for Bounded {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = kill_and_reap(&mut self.0);
        }
    }
}

/// A stdout whose reader is closed before the child starts, so its first
/// write fails however quickly the command runs.
fn gone_reader() -> Stdio {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    Stdio::from(writer)
}

/// Run the binary with its stdout's read end already closed, so the first
/// write fails with a broken pipe whatever the output's size.
fn run_with_reader_gone(args: &[&str]) -> (std::process::ExitStatus, String) {
    let home = tempfile::tempdir().expect("home");
    let child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(args)
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(gone_reader())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-gateway");
    let ended = Bounded(child).reap(&format!("{args:?} with its reader gone"));
    (ended.status, ended.stderr)
}

#[test]
fn a_closed_stdout_is_a_clean_exit() {
    for args in [
        &["list", "--available"][..],
        &["list", "--available", "--json"][..],
    ] {
        let (status, stderr) = run_with_reader_gone(args);
        assert!(
            !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
            "{args:?} panicked on a closed stdout:\n{stderr}"
        );
        assert!(status.success(), "{args:?} exited {status}:\n{stderr}");
    }
}

/// The shape the bug was found in: `| head -1`, a reader that takes one line
/// and leaves while the command is still writing.
#[test]
fn a_reader_that_takes_one_line_and_leaves_is_a_clean_exit() {
    let home = tempfile::tempdir().expect("home");
    let spawned = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["list", "--available"])
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-gateway");
    let mut child = Bounded(spawned);
    let case = "a reader that takes one line";
    let first = child.first_line(case);
    let ended = child.reap(case);
    assert!(!first.is_empty(), "the command printed nothing");
    let stderr = &ended.stderr;
    assert!(!stderr.contains("panicked"), "panicked:\n{stderr}");
    assert!(ended.status.success(), "exited {}:\n{stderr}", ended.status);
}

/// Only `BrokenPipe` is a clean exit. A write that fails any other way (here
/// ENOSPC from `/dev/full`) must still fail loudly, as std's `println!` does.
#[cfg(target_os = "linux")]
#[test]
fn any_other_stdout_error_still_fails() {
    let home = tempfile::tempdir().expect("home");
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["list", "--available"])
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(full)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-gateway");
    let output = Bounded(child).reap("a full disk");
    let stderr = &output.stderr;
    assert!(
        !output.status.success(),
        "a full disk was swallowed:\n{stderr}"
    );
    assert!(
        stderr.contains("failed printing to stdout"),
        "the failure must be reported:\n{stderr}"
    );
}

/// Commands whose output the library prints (`tool list` through
/// `cli::output`, `validate` through the validator) take the same macros:
/// a closed stdout leaves their exit status as it is with a reader, and
/// nothing panics.
#[test]
fn library_printed_output_exits_as_with_a_reader() {
    let capabilities = concat!(env!("CARGO_MANIFEST_DIR"), "/capabilities");
    let capability = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capabilities/automation/agent_search.yaml"
    );
    for args in [
        &["tool", "list", "-C", capabilities][..],
        &["validate", capability][..],
    ] {
        let home = tempfile::tempdir().expect("home");
        let child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
            .args(args)
            .current_dir(home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp-gateway");
        let read = Bounded(child).reap(&format!("{args:?} with a reader"));
        assert!(!read.stdout.is_empty(), "{args:?} printed nothing");
        // A clean exit with a reader, so an exit without one that fails
        // (a broken pipe reported as an error) cannot hide behind it.
        assert!(
            read.status.success(),
            "{args:?} must succeed with a reader; pick a fixture that does: {:?}",
            read.status
        );
        let (status, stderr) = run_with_reader_gone(args);
        assert!(
            !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
            "{args:?} panicked on a closed stdout:\n{stderr}"
        );
        assert_eq!(
            status.code(),
            read.status.code(),
            "{args:?} exited differently without a reader:\n{stderr}"
        );
    }
}
