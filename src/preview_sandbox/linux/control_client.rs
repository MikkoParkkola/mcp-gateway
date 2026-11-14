// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sandbox helper's side of the control socket (ADR-027 step 6). The
//! helper has no async runtime, so this is blocking: every read has one
//! absolute deadline per frame, the socket timeout set to the time left
//! before each read, and the same 1 KiB cap as the gateway's reader.

use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::preview_sandbox::control_msg::{Expired, FetchDone, FetchStart, Issued, MAX_LINE};

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
///
/// One byte per read, so nothing past the newline is ever taken from the
/// socket and the next call starts exactly at the next frame.
pub(super) fn read_line(
    stream: &mut UnixStream,
    first: Duration,
    frame: Duration,
) -> Result<String, String> {
    let mut line = Vec::new();
    let mut deadline = Instant::now() + first;
    let mut started = false;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(if started {
                "the gateway's control line stalled before its end".into()
            } else {
                "the gateway's control line never came".into()
            });
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|e| format!("setting the control socket's timeout ({e})"))?;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return Err("the gateway's control line was cut off by a close".into()),
            Ok(_) => {}
            // A timeout or a signal: the loop checks the deadline again.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(format!("reading the control socket ({e})")),
        }
        if !started {
            started = true;
            deadline = Instant::now() + frame;
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line)
                .map_err(|_| "the gateway's control line is not UTF-8".into());
        }
        // The cap is checked before the buffer grows; the newline counts.
        if line.len() + 1 >= MAX_LINE {
            return Err("the gateway's control line is over 1 KiB".into());
        }
        line.push(byte[0]);
    }
}

/// Write one control line within `bound`.
pub(super) fn write_line(
    stream: &mut UnixStream,
    line: &str,
    bound: Duration,
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(bound))
        .map_err(|e| format!("setting the control socket's timeout ({e})"))?;
    let mut frame = String::with_capacity(line.len() + 1);
    frame.push_str(line);
    frame.push('\n');
    stream
        .write_all(frame.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("writing the control socket ({e})"))
}

/// Parse one control line as `T`, refusing anything else.
pub(super) fn parse<T: serde::de::DeserializeOwned>(line: &str, what: &str) -> Result<T, String> {
    serde_json::from_str(line).map_err(|_| format!("the gateway sent something other than {what}"))
}

fn encode<T: serde::Serialize>(message: &T) -> Result<String, String> {
    serde_json::to_string(message).map_err(|e| format!("encoding a control line ({e})"))
}

/// Ask for the fetch and return the gateway's credential and deadline. The
/// credential must be 64 lowercase hex characters, as the gateway makes it.
pub(super) fn start_fetch(stream: &mut UnixStream, bounds: HelperBounds) -> Result<Issued, String> {
    write_line(
        stream,
        &encode(&FetchStart { fetch_start: true })?,
        bounds.write,
    )?;
    let issued: Issued = parse(
        &read_line(stream, bounds.first, bounds.frame)?,
        "the credential",
    )?;
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if issued.credential.len() != 64 || !issued.credential.bytes().all(hex) {
        return Err("the gateway's credential is malformed".into());
    }
    Ok(issued)
}

/// Report the fetch done and wait for `expired`: returns only once the
/// gateway says every tunnel of the credential is shut.
pub(super) fn finish_fetch(stream: &mut UnixStream, bounds: HelperBounds) -> Result<(), String> {
    write_line(
        stream,
        &encode(&FetchDone { fetch_done: true })?,
        bounds.write,
    )?;
    let expired: Expired = parse(&read_line(stream, bounds.first, bounds.frame)?, "expired")?;
    if !expired.expired {
        return Err("the gateway sent expired false".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "control_client_tests.rs"]
mod tests;
