// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One upper bound for every duration taken from input (MIK-8207).
//!
//! A duration read from a config file, a capability definition or a remote
//! token answer reaches arithmetic that panics on overflow (`Instant +
//! Duration`, chrono's constructors and `DateTime + TimeDelta`), and release
//! builds abort on a panic. 100 years is far above any real setting and safe
//! to add to an `Instant` or a `DateTime` on every supported platform.

use std::time::Duration;

/// The longest duration accepted from input: 100 years.
#[allow(dead_code)] // red seam: used by the fix
pub(crate) const MAX_DURATION: Duration = Duration::from_secs(3_155_760_000);

/// The expiry, in seconds since the epoch, of a token issued at `now_secs`
/// whose answer said `expires_in`.
#[allow(dead_code, clippy::unnecessary_wraps)] // red seam: replaced by the fix
pub(crate) fn expiry_from_expires_in(now_secs: u64, expires_in: u64) -> Option<u64> {
    Some(now_secs.wrapping_add(expires_in))
}

#[cfg(test)]
#[path = "duration_bound_tests.rs"]
mod tests;
