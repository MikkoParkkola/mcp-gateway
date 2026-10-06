// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway list --available | head` exits cleanly, through the shipped
//! binary.
//!
//! Rust ignores SIGPIPE, so once the reader of stdout is gone `println!`
//! panics with "failed printing to stdout: Broken pipe" and the release build
//! (`panic = "abort"`) dumps core. A CLI whose reader has left has nothing more
//! to say: it should exit quietly and successfully.

use std::process::{Command, Stdio};

/// Run the binary with its stdout's read end already closed, so the first
/// write fails with a broken pipe whatever the output's size.
fn run_with_reader_gone(args: &[&str]) -> (std::process::ExitStatus, String) {
    let home = tempfile::tempdir().expect("home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(args)
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("MCP_GATEWAY_TEST_HOME_DIR", home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-gateway");
    drop(child.stdout.take());
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
