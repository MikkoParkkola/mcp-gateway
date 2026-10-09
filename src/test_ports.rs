// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixed test ports that no parallel bind can take (MIK-8211).
//!
//! A test that must name a port before something else binds it cannot bind
//! port 0 and hand over the listener. Taking a port from the OS and releasing
//! it lets a parallel test's port-0 bind take it in between. Ports here come
//! from a range below every OS's ephemeral range (Linux 32768-60999, Windows
//! and macOS 49152-65535), so no port-0 bind can be given one. Each call in
//! this process gets a different port.
//!
//! The one residual is two test processes picking the same port at the same
//! time. CI runs test binaries one after another (no nextest), and
//! `scripts/ci/check_pick_then_bind.py` fails if nextest is ever introduced
//! without revisiting this.

use std::sync::atomic::{AtomicU16, Ordering};

/// First port of the reserved range.
const FIRST: u16 = 20_000;
/// Ports in the reserved range.
const SPAN: u16 = 10_000;

/// Ports handed out by this process so far.
static HANDED_OUT: AtomicU16 = AtomicU16::new(0);

/// A loopback port from the reserved range, never handed out before in this
/// process, and free when returned (a port some long-lived process already
/// holds is skipped).
///
/// Assumes each OS's default ephemeral range: Linux 32768-60999, macOS and
/// Windows 49152-65535. A host whose range was lowered into 20000-29999 could
/// give a port-0 bind one of these ports. On Linux the test below reads the
/// live range and fails if it overlaps.
///
/// # Panics
/// When every port in the range is taken.
pub(crate) fn reserved_port() -> u16 {
    // Start where the process id points, so two processes rarely overlap.
    let offset = u16::try_from(std::process::id() % u32::from(SPAN)).unwrap_or(0);
    for _ in 0..SPAN {
        let n = HANDED_OUT.fetch_add(1, Ordering::Relaxed);
        let port = FIRST + offset.wrapping_add(n) % SPAN;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in {FIRST}..{}", FIRST + SPAN);
}

#[cfg(test)]
mod tests {
    use super::{FIRST, SPAN, reserved_port};

    /// The reserved range sits outside this host's ephemeral range, so no
    /// port-0 bind can be given a reserved port. Linux only: it is the one
    /// OS whose live range a test can read without privileges.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_reserved_range_is_outside_the_ephemeral_range() {
        let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("the ephemeral range is readable");
        let bounds: Vec<u16> = text
            .split_whitespace()
            .map(|n| n.parse().expect("a port number"))
            .collect();
        let (low, high) = (bounds[0], bounds[1]);
        let last = FIRST + SPAN - 1;
        assert!(
            high < FIRST || low > last,
            "this host's ephemeral range {low}-{high} overlaps the reserved \
             range {FIRST}-{last}: port-0 binds can take reserved ports"
        );
    }

    /// Ports come from the reserved range, and two calls never share one.
    #[test]
    fn reserved_ports_are_in_range_and_distinct() {
        let a = reserved_port();
        let b = reserved_port();
        assert!((FIRST..FIRST + SPAN).contains(&a), "{a}");
        assert!((FIRST..FIRST + SPAN).contains(&b), "{b}");
        assert_ne!(a, b, "each call gets its own port");
    }
}
