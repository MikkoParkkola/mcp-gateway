// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the fetch's loopback relay (R-relay).

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use super::{MAX_PAIRS, Relay};

/// Hang guard for every blocking read and the stop's own bound.
const GUARD: Duration = Duration::from_secs(30);
/// The bound the helper gives `stop`.
const STOP_BOUND: Duration = Duration::from_secs(2);

/// A proxy socket in a fresh directory; the directory lives as long as it.
fn proxy() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("proxy.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    (dir, path, listener)
}

fn client(relay: &Relay) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", relay.port())).expect("connect");
    stream.set_read_timeout(Some(GUARD)).expect("timeout");
    stream
}

/// Kills "the relay copies one way only": bytes go to the proxy and back.
#[test]
fn the_relay_copies_both_ways() {
    let (_dir, path, listener) = proxy();
    let echo = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).expect("read");
        stream.write_all(&got).expect("echo");
    });
    let relay = Relay::start(&path, MAX_PAIRS).expect("relay");
    let mut stream = client(&relay);
    stream.write_all(b"ping").expect("write");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half close");
    let mut back = Vec::new();
    stream.read_to_end(&mut back).expect("read back");
    assert_eq!(back, b"ping");
    echo.join().expect("echo thread");
    relay.stop(STOP_BOUND).expect("stop");
}

/// Kills "stop leaves the listener or a pair open" and "a copy thread blocked
/// reading never wakes": with a pair idle on both sides, stop returns within
/// its bound, the client reads EOF and the port refuses.
#[test]
fn stop_closes_the_port_and_every_pair() {
    let (_dir, path, listener) = proxy();
    let relay = Relay::start(&path, MAX_PAIRS).expect("relay");
    let port = relay.port();
    let mut stream = client(&relay);
    let (_held, _) = listener.accept().expect("the pair reached the proxy");
    relay.stop(STOP_BOUND).expect("stop within its bound");
    let mut rest = Vec::new();
    assert_eq!(stream.read_to_end(&mut rest).expect("EOF, not a hang"), 0);
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "the port still accepts"
    );
}

/// Kills "a copy thread blocked writing never wakes": the proxy accepts and
/// never reads, the client writes until the relay's write to the proxy
/// blocks; stop still returns within its bound and the client's writes fail.
#[test]
fn a_copy_thread_blocked_writing_wakes_on_stop() {
    let (_dir, path, listener) = proxy();
    let relay = Relay::start(&path, MAX_PAIRS).expect("relay");
    let mut stream = client(&relay);
    let (never_read, _) = listener.accept().expect("the pair reached the proxy");
    stream.set_write_timeout(Some(GUARD)).expect("timeout");
    let writer = std::thread::spawn(move || {
        let chunk = vec![7u8; 64 * 1024];
        // Ends once the relay's side is shut: a write error, never a hang.
        while stream.write_all(&chunk).is_ok() {}
    });
    // The proxy never reads, so the relay's write to it blocks once the
    // socket holds a send buffer's worth; wait for that much unread.
    while !writer.is_finished() && unread(&never_read) < BACKED_UP {
        std::thread::yield_now();
    }
    relay.stop(STOP_BOUND).expect("stop within its bound");
    writer.join().expect("the writer ended");
}

/// Unread bytes past which the relay's 64 KiB writes to a proxy that never
/// reads are blocked (the default Unix send buffer is about 208 KiB).
const BACKED_UP: usize = 100 * 1024;

/// Bytes queued on `side` and not yet read.
fn unread(side: &UnixStream) -> usize {
    rustix::io::ioctl_fionread(side).map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
}

/// Kills "the accept thread blocks on a stalled proxy" and "a stuck pair is
/// ignored": the proxy listens with a backlog of one and never accepts, so a
/// held connection fills it and the pair's connect blocks; stop still returns
/// within its bound, as an error.
#[test]
fn a_stalled_proxy_fails_the_stop_within_its_bound() {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket};
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("proxy.sock");
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None).expect("socket");
    bind(&fd, &SocketAddrUnix::new(&path).expect("address")).expect("bind");
    listen(&fd, 0).expect("listen");
    let _queued = UnixStream::connect(&path).expect("fills the backlog");
    let relay = Relay::start(&path, MAX_PAIRS).expect("relay");
    let _stream = client(&relay);
    // The accept loop polls, so wait for the pair to exist (its connect is
    // what blocks); a stop before that has no pair to report.
    let deadline = std::time::Instant::now() + GUARD;
    while relay.pair_count() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the relay never took the client"
        );
        std::thread::yield_now();
    }
    // On its own thread, so a stop that ignores its bound fails the row at
    // the guard instead of hanging it.
    let (sent, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || sent.send(relay.stop(STOP_BOUND)));
    let stopped = stopped
        .recv_timeout(GUARD)
        .expect("stop returned within the guard");
    assert!(stopped.is_err(), "a pair stuck in connect was not reported");
}

/// Kills "the pair cap is not enforced": with a cap of one, a second client
/// is closed at once while the first pair is open.
#[test]
fn an_accept_past_the_cap_is_closed() {
    let (_dir, path, listener) = proxy();
    let relay = Relay::start(&path, 1).expect("relay");
    let _first = client(&relay);
    let (_held, _) = listener.accept().expect("the first pair reached the proxy");
    let mut second = client(&relay);
    let mut rest = Vec::new();
    assert_eq!(
        second.read_to_end(&mut rest).expect("closed, not a hang"),
        0
    );
    relay.stop(STOP_BOUND).expect("stop");
}
