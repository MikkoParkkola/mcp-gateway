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
//! Residuals: two test processes picking the same port at the same time (CI
//! runs test binaries one after another, no nextest, and
//! `scripts/ci/check_pick_then_bind.py` fails if nextest is ever introduced
//! without revisiting this); and an unexplained address conflict seen on macOS
//! (MIK-8242): about 1 in 100 runs of the whole test binary, a reserved port
//! returned free was in use (AddrInUse) a moment later, with no listener
//! visible to lsof. The macOS dynamic range is the default 49152-65535, so it
//! is not range overlap; holder and socket state were not identified.

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

    /// Whether the dynamic range `a`-`b` (either order: XNU accepts a
    /// descending pair) misses the reserved range entirely.
    fn outside(a: u16, b: u16) -> bool {
        let (low, high) = (a.min(b), a.max(b));
        high < FIRST || low > FIRST + SPAN - 1
    }

    fn assert_outside(a: u16, b: u16, source: &str) {
        let last = FIRST + SPAN - 1;
        assert!(
            outside(a, b),
            "{source}: dynamic range {a}-{b} overlaps the reserved range \
             {FIRST}-{last}: port-0 binds can take reserved ports"
        );
    }

    /// The overlap check itself, on every OS (MIK-8242).
    #[test]
    fn the_overlap_check_reads_ranges_either_way_round() {
        assert!(outside(49152, 65535));
        assert!(outside(65535, 49152), "a descending pair");
        assert!(outside(32768, 60999));
        assert!(!outside(15000, 25000), "straddles the start");
        assert!(!outside(29999, 40000), "touches the end");
        assert!(!outside(40000, 10000), "a descending pair over the range");
    }

    /// The reserved range sits outside this host's ephemeral range, so no
    /// port-0 bind can be given a reserved port.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_reserved_range_is_outside_the_ephemeral_range() {
        let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("the ephemeral range is readable");
        let bounds: Vec<u16> = text
            .split_whitespace()
            .map(|n| n.parse().expect("a port number"))
            .collect();
        assert_eq!(bounds.len(), 2, "{text:?}");
        assert_outside(bounds[0], bounds[1], "ip_local_port_range");
    }

    /// The same on macOS, from both of its dynamic ranges (MIK-8242).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_reserved_range_is_outside_the_macos_dynamic_ranges() {
        let out = std::process::Command::new("sysctl")
            .args([
                "-n",
                "net.inet.ip.portrange.first",
                "net.inet.ip.portrange.last",
                "net.inet.ip.portrange.hifirst",
                "net.inet.ip.portrange.hilast",
            ])
            .output()
            .expect("run sysctl");
        assert!(out.status.success(), "sysctl failed: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        let bounds: Vec<u16> = text
            .split_whitespace()
            .map(|n| n.parse().expect("a port number"))
            .collect();
        assert_eq!(bounds.len(), 4, "{text:?}");
        assert_outside(bounds[0], bounds[1], "portrange.first/last");
        assert_outside(bounds[2], bounds[3], "portrange.hifirst/hilast");
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
