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

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

/// The relay's pairs at once; an accept past it is closed at once. The
/// proxy's own connection limit.
pub(super) const MAX_PAIRS: usize = 64;

/// A running relay: its port and the threads that serve it.
pub(super) struct Relay {
    listener: TcpListener,
}

impl Relay {
    /// Listen on 127.0.0.1 (a free port) and relay each accepted stream to a
    /// fresh connection to `proxy`, at most `max_pairs` at a time.
    pub(super) fn start(proxy: &Path, max_pairs: usize) -> io::Result<Self> {
        let _ = (proxy, max_pairs);
        Err(io::Error::other("the relay is not built yet"))
    }

    /// The port npm and uv are told to use.
    pub(super) fn port(&self) -> u16 {
        self.listener.local_addr().map_or(0, |a| a.port())
    }

    /// Stop accepting, shut both ends of every pair and join every thread
    /// within `bound`; a thread still running after it is an error.
    pub(super) fn stop(self, bound: Duration) -> Result<(), String> {
        let _ = bound;
        Ok(())
    }
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
