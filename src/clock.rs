// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The wall clock, read in one place (MIK-8202).
//!
//! A host clock earlier than 1970 makes `SystemTime::duration_since(UNIX_EPOCH)`
//! fail and makes chrono's `Utc::now()` a 1969 date. Code that fell back to 0,
//! or compared against that date, read every real deadline as still ahead and
//! served what had expired. Here a clock before the epoch is an error, never a
//! value: each caller decides what it means, at the call.
//!
//! - An access check (a credential, grant, session, lease or deadline that
//!   admits something) asks [`expired_by`]; a clock it cannot read answers
//!   [`Validity::Expired`].
//! - A recorder (minting, issuing, stamping a time) propagates
//!   [`ClockBeforeEpoch`] and writes nothing.
//! - A retention sweep skips its pass on `Err`: deleting what it cannot date
//!   is the dangerous answer there.
//!
//! Design: `docs/internal/design/2026-10-09-mik-8202-clock-before-epoch.md`.
#![allow(
    clippy::disallowed_methods,
    reason = "the one place the wall clock is read"
)]
#![cfg_attr(
    not(test),
    allow(dead_code, reason = "MIK-8202: call sites migrate later in this PR")
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

/// The host clock reads earlier than 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockBeforeEpoch;

impl std::fmt::Display for ClockBeforeEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("system clock reads before 1970")
    }
}

impl std::error::Error for ClockBeforeEpoch {}

/// Whether something an access check judges may still be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Validity {
    /// Still within its window.
    Live,
    /// Past its window, or judged on a clock that could not be read.
    Expired,
}

/// Time since the epoch, or the error. Every public reader goes through here,
/// so a test override reaches all of them.
fn since_epoch() -> Result<Duration, ClockBeforeEpoch> {
    #[cfg(test)]
    if let Some(forced) = test_clock::forced() {
        return forced;
    }
    // A child process's clock, for a test that runs the binary. Debug builds
    // only: release compiles it out, and the release job greps the binary for
    // the name, as it does for MCP_GATEWAY_TEST_HOME_DIR.
    #[cfg(debug_assertions)]
    if std::env::var_os("MCP_GATEWAY_TEST_CLOCK").is_some_and(|v| v == "before-epoch") {
        return Err(ClockBeforeEpoch);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockBeforeEpoch)
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_secs() -> Result<u64, ClockBeforeEpoch> {
    since_epoch().map(|d| d.as_secs())
}

/// Milliseconds since the Unix epoch.
pub(crate) fn unix_millis() -> Result<u64, ClockBeforeEpoch> {
    since_epoch().map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Now as a chrono time: `Err` where chrono would give a 1969 date.
pub(crate) fn utc_now() -> Result<DateTime<Utc>, ClockBeforeEpoch> {
    let since = since_epoch()?;
    let secs = i64::try_from(since.as_secs()).map_err(|_| ClockBeforeEpoch)?;
    DateTime::from_timestamp(secs, since.subsec_nanos()).ok_or(ClockBeforeEpoch)
}

/// An access check: `check` is the site's own comparison against now in
/// seconds. A clock that cannot be read answers [`Validity::Expired`].
pub(crate) fn expired_by(check: impl FnOnce(u64) -> Validity) -> Validity {
    unix_secs().map_or(Validity::Expired, check)
}

/// [`expired_by`] against a chrono now.
pub(crate) fn expired_by_utc(check: impl FnOnce(DateTime<Utc>) -> Validity) -> Validity {
    utc_now().map_or(Validity::Expired, check)
}

/// The JWT time window judged on one clock sample, in place of the decoder's
/// own (which reads the clock again and panics before 1970). Expired when
/// `exp + leeway < now`, immature when `nbf > now + leeway`; adding instead of
/// subtracting keeps a clock near the epoch from underflowing. An overflow, an
/// unreadable clock or a malformed claim answers [`Validity::Expired`].
pub(crate) fn jwt_window(exp: JwtClaimTime, nbf: JwtClaimTime, leeway: u64) -> Validity {
    expired_by(|now| {
        let late = match exp {
            JwtClaimTime::Absent => false,
            JwtClaimTime::Malformed => true,
            JwtClaimTime::At(exp) => exp.checked_add(leeway).is_none_or(|end| end < now),
        };
        let early = match nbf {
            JwtClaimTime::Absent => false,
            JwtClaimTime::Malformed => true,
            JwtClaimTime::At(nbf) => now.checked_add(leeway).is_none_or(|start| nbf > start),
        };
        if late || early {
            Validity::Expired
        } else {
            Validity::Live
        }
    })
}

/// A JWT `exp` or `nbf` claim as decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwtClaimTime {
    /// Not in the token.
    Absent,
    /// Present but not a non-negative number of seconds.
    Malformed,
    /// Seconds since the epoch.
    At(u64),
}

impl JwtClaimTime {
    /// The claim `name` of decoded `claims`.
    pub(crate) fn of(claims: &serde_json::Value, name: &str) -> Self {
        match claims.get(name) {
            None | Some(serde_json::Value::Null) => Self::Absent,
            // Whole seconds, or a fractional number the decoder also
            // accepted: its whole part.
            Some(value) => value
                .as_u64()
                .or_else(|| {
                    value
                        .as_f64()
                        .filter(|secs| secs.is_finite() && *secs >= 0.0)
                        .map(|secs| {
                            #[allow(
                                clippy::cast_possible_truncation,
                                clippy::cast_sign_loss,
                                reason = "finite and non-negative; a value past u64::MAX saturates, which reads as far future"
                            )]
                            let whole = secs.trunc() as u64;
                            whole
                        })
                })
                .map_or(Self::Malformed, Self::At),
        }
    }
}

/// A test's own clock, for this thread: before the epoch, or a fixed time.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    use std::time::Duration;

    use super::ClockBeforeEpoch;

    thread_local! {
        static FORCED: Cell<Option<Result<Duration, ClockBeforeEpoch>>> = const { Cell::new(None) };
    }

    pub(super) fn forced() -> Option<Result<Duration, ClockBeforeEpoch>> {
        FORCED.with(Cell::get)
    }

    /// Restores the real clock when dropped.
    #[must_use]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED.with(|f| f.set(None));
        }
    }

    /// This thread's clock reads before 1970 until the guard drops.
    pub(crate) fn before_epoch() -> Forced {
        FORCED.with(|f| f.set(Some(Err(ClockBeforeEpoch))));
        Forced(())
    }

    /// This thread's clock reads `secs` after the epoch until the guard drops.
    pub(crate) fn at_secs(secs: u64) -> Forced {
        FORCED.with(|f| f.set(Some(Ok(Duration::from_secs(secs)))));
        Forced(())
    }
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod tests;
