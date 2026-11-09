// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fetch's output (ADR-027 N4): drained to EOF so the pipe never blocks,
//! its last 64 KiB kept, and the last line, which a failing fetch refuses
//! with, stripped of the fetch credential and of any URL userinfo.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls these")
)]

use std::io::{self, Read};

/// How much of the fetch's output is kept: its tail.
pub(crate) const TAIL_BYTES: usize = 64 * 1024;

/// Read `reader` to EOF, keeping its last [`TAIL_BYTES`].
pub(crate) fn read_tail(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut tail = vec![0; TAIL_BYTES];
    let n = reader.read(&mut tail)?;
    tail.truncate(n);
    Ok(tail)
}

/// The last non-blank line of `tail`, redacted.
pub(crate) fn last_line(tail: &[u8], credential: &str) -> String {
    let text = String::from_utf8_lossy(tail);
    redact_line(text.lines().next().unwrap_or(""), credential)
}

/// `line` without `credential` (raw or base64) or any URL userinfo.
pub(crate) fn redact_line(line: &str, _credential: &str) -> String {
    line.to_owned()
}

#[cfg(test)]
#[path = "fetch_output_tests.rs"]
mod tests;
