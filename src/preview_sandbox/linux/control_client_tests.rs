// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the helper's side of the control socket (FETCH.2a R2, R4b, R5).

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

use super::{HELPER_BOUNDS, HelperBounds, finish_fetch, parse, read_line, start_fetch};
use crate::preview_sandbox::control_msg::{Expired, Issued, MAX_LINE};

/// A hang guard for rows that block: generous, so only a real hang trips it.
const GUARD: Duration = Duration::from_secs(30);

/// The bound under test where a row needs one to run out.
const SHORT: Duration = Duration::from_secs(1);

/// Run `f` on its own thread and return its result, failing the row if it
/// has not finished within the guard.
fn within_guard<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(GUARD)
        .expect("the row did not finish within the guard")
}

fn read(bytes: &'static [u8], first: Duration, frame: Duration) -> Result<String, String> {
    let (mut helper, mut gateway) = UnixStream::pair().expect("pair");
    gateway.write_all(bytes).expect("write");
    drop(gateway);
    within_guard(move || read_line(&mut helper, first, frame))
}

/// R5, kills "the cap is off by one" (a full-size line is read).
#[test]
fn r5_a_line_at_the_cap_is_read() {
    let line: &'static [u8] = format!("{}\n", "x".repeat(MAX_LINE - 1)).leak().as_bytes();
    assert_eq!(read(line, SHORT, SHORT), Ok("x".repeat(MAX_LINE - 1)));
}

/// R5, kills "a line over the cap is read".
#[test]
fn r5_a_line_one_byte_over_the_cap_is_refused() {
    let line: &'static [u8] = format!("{}\n", "x".repeat(MAX_LINE)).leak().as_bytes();
    assert!(read(line, SHORT, SHORT).is_err());
}

/// R5, kills "a close mid-line is taken as a line".
#[test]
fn r5_eof_before_the_newline_is_refused() {
    assert!(read(b"{\"expired\":true}", SHORT, SHORT).is_err());
}

/// R5, kills "a non-UTF-8 line is read".
#[test]
fn r5_a_non_utf8_line_is_refused() {
    assert!(read(b"\xff\xfe\n", SHORT, SHORT).is_err());
}

/// R5, kills "the reader takes more than one line per call" and "bytes after
/// the newline are lost": two lines in one write are read one at a time.
#[test]
fn r5_a_frame_after_a_consumed_newline_is_read() {
    let (mut helper, mut gateway) = UnixStream::pair().expect("pair");
    gateway.write_all(b"first\nsecond\n").expect("write");
    let lines = within_guard(move || {
        let a = read_line(&mut helper, SHORT, SHORT);
        let b = read_line(&mut helper, SHORT, SHORT);
        (a, b)
    });
    assert_eq!(lines, (Ok("first".into()), Ok("second".into())));
}

/// R5, kills "the first byte may wait forever": a silent gateway is cut off
/// at the bound (the guard only catches a reader with no bound at all).
#[test]
fn r5_no_first_byte_within_its_bound_is_refused() {
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let read = within_guard(move || read_line(&mut helper, SHORT, SHORT));
    drop(gateway);
    assert!(read.is_err());
}

/// R5, kills "each read resets the frame deadline": a gateway that sends one
/// byte at a time, never a newline, is cut off at the frame bound.
#[test]
fn r5_a_drip_fed_frame_past_its_deadline_is_refused() {
    let (mut helper, mut gateway) = UnixStream::pair().expect("pair");
    let (stop, stopped) = mpsc::channel::<()>();
    // Pacing, not a wait-and-see window: the drip runs until the reader is
    // done, and the row asserts on the reader's answer alone.
    let drip = std::thread::spawn(move || {
        while stopped.recv_timeout(SHORT / 4) == Err(mpsc::RecvTimeoutError::Timeout) {
            if gateway.write_all(b"x").is_err() {
                break;
            }
        }
    });
    let read = within_guard(move || read_line(&mut helper, SHORT, SHORT));
    let _ = stop.send(());
    drip.join().expect("drip");
    assert!(read.is_err());
}

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A fake gateway on the other end: reads one line, answers with `reply`
/// (unless `None`), and returns the line it read.
fn gateway_once(stream: UnixStream, reply: Option<String>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        if let Some(reply) = reply {
            (&stream).write_all(reply.as_bytes()).expect("reply");
        }
        line
    })
}

/// R2, kills "the helper's lines differ from what the gateway parses" and
/// "the helper cannot parse what the gateway writes": the exact lines each
/// side writes are read by the other side's parser.
#[test]
fn r2_each_side_reads_the_others_lines() {
    let issued = format!("{{\"credential\":\"{SECRET}\",\"deadline_ms\":1500}}");
    assert_eq!(
        parse::<Issued>(&issued, "the credential"),
        Ok(Issued {
            credential: SECRET.into(),
            deadline_ms: 1500
        })
    );
    assert_eq!(
        parse::<Expired>("{\"expired\":true}", "expired"),
        Ok(Expired { expired: true })
    );
    assert!(parse::<Issued>("{\"expired\":true}", "the credential").is_err());
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let seen = gateway_once(gateway, Some(format!("{issued}\n")));
    let got = within_guard(move || start_fetch(&mut helper, HELPER_BOUNDS));
    assert_eq!(seen.join().expect("gateway"), "{\"fetch_start\":true}\n");
    assert_eq!(got.map(|i| i.credential), Ok(SECRET.to_owned()));
}

/// R2, kills "a malformed credential is used": anything but 64 lowercase hex
/// characters refuses.
#[test]
fn r2_a_malformed_credential_is_refused() {
    for credential in ["", "ABCDEF", &SECRET[1..], &SECRET.replace('a', "g")] {
        let (mut helper, gateway) = UnixStream::pair().expect("pair");
        let line = format!("{{\"credential\":\"{credential}\",\"deadline_ms\":1}}\n");
        let seen = gateway_once(gateway, Some(line));
        let got = within_guard(move || start_fetch(&mut helper, HELPER_BOUNDS));
        seen.join().expect("gateway");
        assert!(got.is_err(), "{credential:?}");
    }
}

/// R4b, kills "the helper goes on before `expired`": `finish_fetch` returns
/// only after the gateway has written `expired`, so `supervise` (which runs
/// after it) can never overlap a live credential.
#[test]
fn r4b_finish_fetch_returns_only_after_expired() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let expired_sent = Arc::new(AtomicBool::new(false));
    let flag = expired_sent.clone();
    let fake = std::thread::spawn(move || {
        let mut reader = BufReader::new(gateway.try_clone().expect("clone"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        flag.store(true, Ordering::SeqCst);
        (&gateway)
            .write_all(b"{\"expired\":true}\n")
            .expect("expired");
        line
    });
    let returned = within_guard(move || {
        let done = finish_fetch(&mut helper, HELPER_BOUNDS);
        (done, expired_sent.load(Ordering::SeqCst))
    });
    assert_eq!(fake.join().expect("gateway"), "{\"fetch_done\":true}\n");
    assert_eq!(returned, (Ok(()), true));
}

/// R4b, kills "a withheld `expired` is taken as done" and "`expired:false`
/// is taken as done".
#[test]
fn r4b_a_withheld_or_false_expired_refuses() {
    let bounds = HelperBounds {
        first: SHORT,
        ..HELPER_BOUNDS
    };
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let seen = gateway_once(gateway.try_clone().expect("clone"), None);
    let got = within_guard(move || finish_fetch(&mut helper, bounds));
    seen.join().expect("gateway");
    drop(gateway);
    assert!(got.is_err());
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let seen = gateway_once(gateway, Some("{\"expired\":false}\n".into()));
    let got = within_guard(move || finish_fetch(&mut helper, bounds));
    seen.join().expect("gateway");
    assert!(got.is_err());
}

/// R2, kills "a spent deadline starts a fetch": `deadline_ms` of 0 refuses.
#[test]
fn r2_a_spent_deadline_is_refused() {
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    let line = format!("{{\"credential\":\"{SECRET}\",\"deadline_ms\":0}}\n");
    let seen = gateway_once(gateway, Some(line));
    let got = within_guard(move || start_fetch(&mut helper, HELPER_BOUNDS));
    seen.join().expect("gateway");
    assert!(got.is_err());
}

/// Kills "a debug print shows the credential" (CWE-532): `Issued`'s Debug
/// output never holds the secret.
#[test]
fn r2_a_debug_print_never_shows_the_credential() {
    let issued = Issued {
        credential: SECRET.into(),
        deadline_ms: 1,
    };
    assert!(!format!("{issued:?}").contains(SECRET));
}
