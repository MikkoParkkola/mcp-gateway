// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sandbox helper's side of the control socket (ADR-027 step 6). The
//! helper has no async runtime, so this is blocking: every read has one
//! absolute deadline per frame, the socket timeout set to the time left
//! before each read, and the same 1 KiB cap as the gateway's reader.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the helper's fetch step wires it")
)]

use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::preview_sandbox::control_msg::{Expired, FetchDone, FetchStart, Issued};

/// The helper's bounds: the first byte of each answer, the rest of a frame
/// once its first byte came, and each write.
#[derive(Clone, Copy, Debug)]
pub(super) struct HelperBounds {
    pub(super) first: Duration,
    pub(super) frame: Duration,
    pub(super) write: Duration,
}

/// The design's helper bounds: 5 s each.
pub(super) const HELPER_BOUNDS: HelperBounds = HelperBounds {
    first: Duration::from_secs(5),
    frame: Duration::from_secs(5),
    write: Duration::from_secs(5),
};

/// One control line, without its newline: the first byte within `first`,
/// the rest within `frame` from that byte. Over the cap, EOF before the
/// newline, a missed deadline or non-UTF-8 refuses.
pub(super) fn read_line(
    stream: &mut UnixStream,
    _first: Duration,
    _frame: Duration,
) -> Result<String, String> {
    // Red stub: a naive reader with no cap, no deadline and lossy UTF-8.
    use std::io::BufRead as _;
    let mut line = Vec::new();
    std::io::BufReader::new(stream)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Write one control line within `bound`.
pub(super) fn write_line(
    _stream: &mut UnixStream,
    _line: &str,
    _bound: Duration,
) -> Result<(), String> {
    Ok(())
}

/// Parse one control line as `T`, refusing anything else.
pub(super) fn parse<T: serde::de::DeserializeOwned>(_line: &str, what: &str) -> Result<T, String> {
    Err(format!("the gateway sent something other than {what}"))
}

/// Ask for the fetch and return the gateway's credential and deadline.
pub(super) fn start_fetch(stream: &mut UnixStream, bounds: HelperBounds) -> Result<Issued, String> {
    // Red stub: answers without asking.
    let _ = (stream, bounds, FetchStart { fetch_start: true });
    Ok(Issued {
        credential: String::new(),
        deadline_ms: 0,
    })
}

/// Report the fetch done and wait for `expired`: returns only once the
/// gateway says every tunnel of the credential is shut.
pub(super) fn finish_fetch(stream: &mut UnixStream, bounds: HelperBounds) -> Result<(), String> {
    let _ = (stream, bounds, FetchDone { fetch_done: true });
    let _: Option<Expired> = None;
    Ok(())
}

#[cfg(test)]
#[path = "control_client_tests.rs"]
mod tests;
