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

use std::process::Stdio;

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
    let output = child.wait_with_output().expect("wait for mcp-gateway");
    (
        output.status,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
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
    use std::io::BufRead;
    let home = tempfile::tempdir().expect("home");
    let mut child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["list", "--available"])
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-gateway");
    let mut first = String::new();
    std::io::BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut first)
        .expect("read the first line");
    assert!(!first.is_empty(), "the command printed nothing");
    let output = child.wait_with_output().expect("wait for mcp-gateway");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "panicked:\n{stderr}");
    assert!(
        output.status.success(),
        "exited {}:\n{stderr}",
        output.status
    );
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
    let output = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
        .args(["list", "--available"])
        .current_dir(home.path())
        .stdin(Stdio::null())
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .expect("run mcp-gateway");
    let stderr = String::from_utf8_lossy(&output.stderr);
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
        let read = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
            .args(args)
            .current_dir(home.path())
            .stdin(Stdio::null())
            .output()
            .expect("run mcp-gateway");
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
