// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Executable stubs for tests, written so that the test process never holds a
//! stub's write descriptor. Std only and naming no `crate::` item, so the
//! library's tests use it as a module and the integration tests through
//! `#[path]`.
//!
//! A test that writes a stub and then runs it can fail with ETXTBSY ("Text
//! file busy") when another test thread forks while the write is open: the
//! forked child keeps a copy of the descriptor until its own exec. Here a
//! short-lived `/bin/sh` writes the file and sets its mode, and has exited
//! before this returns, so no thread of the test process ever has it open.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Write `contents` to `path` as a program anyone may run (mode 0755).
///
/// # Panics
///
/// When the writer cannot start or does not succeed (a missing directory,
/// say). The message names `path`, the writer's exit status and its stderr.
pub(crate) fn write_executable(path: &Path, contents: &str) {
    let mut child = Command::new("/bin/sh")
        // Full paths: a test may have replaced PATH.
        .args(["-c", r#"/bin/cat > "$1" && /bin/chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("starting /bin/sh to write {}: {e}", path.display()));
    // The pipe closes when `stdin` drops at the end of the closure: cat's EOF.
    let sent = child
        .stdin
        .take()
        .map_or(Ok(()), |mut stdin| stdin.write_all(contents.as_bytes()));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("waiting for the writer of {}: {e}", path.display()));
    assert!(
        out.status.success() && sent.is_ok(),
        "writing {} failed ({}, input {sent:?}): {}",
        path.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
}
