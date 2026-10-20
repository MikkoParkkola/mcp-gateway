// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The wall clock, read in one place (MIK-8202).
//!
//! Twin-copy invariant: this file compiles into two crates, the library
//! (`lib.rs`) and the binary (`main.rs`, `#[path = "clock.rs"]`, for the CLI
//! commands). Any state in it exists twice: each copy has its own statics and
//! thread-locals, and an override set through one copy never reaches the
//! other. The only override both copies see is the environment's
//! `MCP_GATEWAY_TEST_CLOCK` (debug builds only). So mutable shared state
//! (a `static` outside the `test_clock` thread-locals, a `Mutex`, `RwLock`,
//! `Atomic*`, `OnceLock` or `LazyLock`) may never be added here; a lexical
//! test in `clock_tests.rs` holds that line.
//!
//! A host clock earlier than 1970 makes `SystemTime::duration_since(UNIX_EPOCH)`
//! fail and makes chrono's `Utc::now()` panic (chrono 0.4.45 `utc.rs`,
//! "system time before Unix epoch"), which the release profile's
//! `panic = "abort"` turns into a dead process. Code that fell back to 0
//! read every real deadline as still ahead and served what had expired. Here
//! a clock before the epoch is an error, never a value: each caller decides
//! what it means, at the call.
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

/// Milliseconds since the Unix epoch (MIK-8202 P4b: health and breaker stamps).
pub(crate) fn unix_millis() -> Result<u64, ClockBeforeEpoch> {
    since_epoch().map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether a wall-clock reading is at or after the epoch, hence usable
/// (MIK-8202 P4b: the auth dashboard's injected `Now` judges this through
/// the clock module rather than comparing against `UNIX_EPOCH` itself).
pub(crate) fn wall_readable(wall: SystemTime) -> bool {
    wall.duration_since(UNIX_EPOCH).is_ok()
}

/// Now as a `SystemTime`, for a site that compares against stored
/// `SystemTime`s. A clock that cannot be read gives a time before the
/// epoch, which such a site already refuses (`duration_since(UNIX_EPOCH)`
/// fails): the reading is never a plausible present.
pub(crate) fn system_time_or_before_epoch() -> SystemTime {
    since_epoch().map_or_else(
        |_| UNIX_EPOCH - std::time::Duration::from_secs(1),
        |since| UNIX_EPOCH + since,
    )
}

/// Now as a chrono time: `Err` where chrono's `Utc::now()` would panic.
pub(crate) fn utc_now() -> Result<DateTime<Utc>, ClockBeforeEpoch> {
    let since = since_epoch()?;
    let secs = i64::try_from(since.as_secs()).map_err(|_| ClockBeforeEpoch)?;
    DateTime::from_timestamp(secs, since.subsec_nanos()).ok_or(ClockBeforeEpoch)
}

/// Stamp an audit row's `timestamp`. A recorder whose row must not vanish:
/// on a clock that cannot be read the row is kept undated, with `timestamp`
/// `null` and `clock_invalid` `true`, the marker the firewall audit uses.
pub(crate) fn stamp_audit_row(fields: &mut serde_json::Map<String, serde_json::Value>) {
    if let Ok(now) = utc_now() {
        fields.insert("timestamp".into(), now.to_rfc3339().into());
    } else {
        fields.insert("timestamp".into(), serde_json::Value::Null);
        fields.insert("clock_invalid".into(), true.into());
    }
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

/// A test's own clock, for this thread: before the epoch, or a fixed time.
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    use std::time::Duration;

    use super::ClockBeforeEpoch;

    thread_local! {
        static FORCED: Cell<Option<Result<Duration, ClockBeforeEpoch>>> = const { Cell::new(None) };
        static QUEUED: std::cell::RefCell<std::collections::VecDeque<Result<Duration, ClockBeforeEpoch>>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    }

    pub(super) fn forced() -> Option<Result<Duration, ClockBeforeEpoch>> {
        QUEUED
            .with(|queued| queued.borrow_mut().pop_front())
            .or_else(|| FORCED.with(Cell::get))
    }

    /// Restores the real clock when dropped.
    #[must_use]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED.with(|f| f.set(None));
            QUEUED.with(|queued| queued.borrow_mut().clear());
        }
    }

    /// This thread's clock reads before 1970 until the guard drops.
    pub(crate) fn before_epoch() -> Forced {
        FORCED.with(|f| f.set(Some(Err(ClockBeforeEpoch))));
        Forced(())
    }

    /// This thread's next clock reads, one each in order: `Some(secs)` reads
    /// `secs` after the epoch, `None` before 1970. Once they are used up the
    /// real clock reads again. A clock that fails and recovers inside one
    /// check is laid out this way.
    pub(crate) fn queued(reads: &[Option<u64>]) -> Forced {
        QUEUED.with(|queued| {
            *queued.borrow_mut() = reads
                .iter()
                .map(|read| read.map(Duration::from_secs).ok_or(ClockBeforeEpoch))
                .collect();
        });
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
pub(crate) mod tests;
