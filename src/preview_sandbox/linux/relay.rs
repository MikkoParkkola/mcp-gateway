// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fetch's loopback relay (ADR-027 step 6): npm and uv take a TCP proxy
//! URL, and the gateway's proxy serves a Unix socket, so the helper listens
//! on 127.0.0.1 inside the preview's network namespace and copies each
//! stream to its own connection to the proxy socket.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the npm fetch step, a later commit, starts it")
)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The relay's pairs at once; an accept past it is closed at once. The
/// proxy's own connection limit.
pub(super) const MAX_PAIRS: usize = 64;
/// Each direction's copy buffer.
const BUFFER: usize = 64 * 1024;
/// How often the accept thread checks for a connection and for `stop`.
const POLL: Duration = Duration::from_millis(50);

/// One relayed stream: duplicates of both ends, so `stop` can shut them, and
/// the thread that serves the pair (it joins its reverse copier).
struct Pair {
    tcp: TcpStream,
    unix: Arc<Mutex<Option<UnixStream>>>,
    thread: JoinHandle<()>,
}

/// A running relay: its port and the threads that serve it.
pub(super) struct Relay {
    port: u16,
    stop: Arc<AtomicBool>,
    accept: JoinHandle<()>,
    pairs: Arc<Mutex<Vec<Pair>>>,
}

impl Relay {
    /// Listen on 127.0.0.1 (a free port) and relay each accepted stream to a
    /// fresh connection to `proxy`, at most `max_pairs` at a time.
    pub(super) fn start(proxy: &Path, max_pairs: usize) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let pairs = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let (stop, pairs) = (Arc::clone(&stop), Arc::clone(&pairs));
            let proxy = proxy.to_path_buf();
            std::thread::Builder::new()
                .name("preview-relay".into())
                .spawn(move || accept_loop(&listener, &proxy, max_pairs, &stop, &pairs))?
        };
        Ok(Self {
            port,
            stop,
            accept,
            pairs,
        })
    }

    /// The port npm and uv are told to use.
    pub(super) fn port(&self) -> u16 {
        self.port
    }

    /// Stop accepting, shut both ends of every pair and join every thread
    /// within `bound`; a thread still running after it is an error.
    pub(super) fn stop(self, bound: Duration) -> Result<(), String> {
        let deadline = Instant::now() + bound;
        self.stop.store(true, Ordering::SeqCst);
        // The accept thread polls the flag; the listener closes with it.
        if !finished_by(&self.accept, deadline) {
            return Err("stopping the relay (its accept thread did not end)".into());
        }
        let _ = self.accept.join();
        let pairs = std::mem::take(&mut *lock(&self.pairs));
        for pair in &pairs {
            let _ = pair.tcp.shutdown(Shutdown::Both);
            if let Some(unix) = lock(&pair.unix).as_ref() {
                let _ = unix.shutdown(Shutdown::Both);
            }
        }
        for pair in pairs {
            if !finished_by(&pair.thread, deadline) {
                return Err("stopping the relay (a relayed stream did not end)".into());
            }
            let _ = pair.thread.join();
        }
        Ok(())
    }
}

/// Accept until `stop`, pruning pairs whose thread has ended, closing an
/// accept past `max` at once, and giving each other stream its own pair.
fn accept_loop(
    listener: &TcpListener,
    proxy: &Path,
    max: usize,
    stop: &Arc<AtomicBool>,
    pairs: &Mutex<Vec<Pair>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let mut held = lock(pairs);
                held.retain(|pair| !pair.thread.is_finished());
                if held.len() >= max {
                    // Closed at once: the client reads EOF.
                    continue;
                }
                if let Some(pair) = start_pair(tcp, proxy, stop) {
                    held.push(pair);
                }
            }
            // Nothing pending, or a failed accept: wait, then look again.
            Err(_) => std::thread::sleep(POLL),
        }
    }
}

/// The pair's thread does the Unix connect, so a stalled proxy blocks that
/// pair alone, never the accept thread.
fn start_pair(tcp: TcpStream, proxy: &Path, stop: &Arc<AtomicBool>) -> Option<Pair> {
    tcp.set_nonblocking(false).ok()?;
    let kept = tcp.try_clone().ok()?;
    let unix = Arc::new(Mutex::new(None));
    let (slot, stop, proxy) = (Arc::clone(&unix), Arc::clone(stop), proxy.to_path_buf());
    let thread = std::thread::Builder::new()
        .name("preview-relay-pair".into())
        .spawn(move || serve(tcp, &proxy, &slot, &stop))
        .ok()?;
    Some(Pair {
        tcp: kept,
        unix,
        thread,
    })
}

/// Connect to the proxy, keep a duplicate of that end where `stop` finds it,
/// then copy both ways until each side ends.
fn serve(tcp: TcpStream, proxy: &Path, slot: &Mutex<Option<UnixStream>>, stop: &AtomicBool) {
    let Ok(unix) = UnixStream::connect(proxy) else {
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    };
    let (Ok(kept), Ok(unix_in), Ok(tcp_out)) =
        (unix.try_clone(), unix.try_clone(), tcp.try_clone())
    else {
        return;
    };
    {
        let mut held = lock(slot);
        // A stop that read the slot before this store has set the flag first.
        if stop.load(Ordering::SeqCst) {
            let _ = kept.shutdown(Shutdown::Both);
        }
        *held = Some(kept);
    }
    let back = std::thread::Builder::new()
        .name("preview-relay-back".into())
        .spawn(move || copy(unix_in, &tcp_out));
    copy(tcp, &unix);
    if let Ok(back) = back {
        let _ = back.join();
    }
}

/// Copy `from` into `to` through a 64 KiB buffer until `from` ends or either
/// side fails, then half-close `to` so its reader sees EOF.
fn copy<W: HalfClose>(mut from: impl Read, to: &W)
where
    for<'a> &'a W: Write,
{
    let mut buffer = vec![0u8; BUFFER];
    let mut out = to;
    loop {
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if out.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    to.half_close();
}

/// Shut the write half of a relayed stream.
trait HalfClose {
    fn half_close(&self);
}

impl HalfClose for TcpStream {
    fn half_close(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

impl HalfClose for UnixStream {
    fn half_close(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// Whether `thread` has ended by `deadline`, looking every 10 ms.
fn finished_by(thread: &JoinHandle<()>, deadline: Instant) -> bool {
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
