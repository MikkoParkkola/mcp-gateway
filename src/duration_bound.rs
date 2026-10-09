// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One upper bound for every duration taken from input (MIK-8207).
//!
//! A duration read from a config file, a capability definition or a remote
//! token answer reaches arithmetic that panics on overflow: adding it to an
//! `Instant` or a `DateTime`, or chrono's constructors. Release builds abort
//! on a panic. 100 years is far above any real setting and safe
//! to add to an `Instant` or a `DateTime` on every supported platform.

use std::time::Duration;

use serde::{Deserialize, Deserializer};

/// The longest duration accepted from input: 100 years.
pub(crate) const MAX_DURATION: Duration = Duration::from_secs(3_155_760_000);

/// Why an input duration was refused, worded for the operator.
pub(crate) fn too_long(what: &str) -> String {
    format!("{what} is longer than 100 years, the most any duration may be")
}

/// The expiry, in seconds since the epoch, of a token issued at `now_secs`
/// whose answer said `expires_in`. `None` when `expires_in` is above the
/// bound: such an answer is malformed, and trusting it would keep a token
/// for centuries without a refresh (MIK-8207).
pub(crate) fn expiry_from_expires_in(now_secs: u64, expires_in: u64) -> Option<u64> {
    (expires_in <= MAX_DURATION.as_secs())
        .then(|| now_secs.checked_add(expires_in))
        .flatten()
}

/// `serde(deserialize_with)` for a whole number of seconds: refused above the
/// bound at load, wherever the field sits (inside a map or a list as well).
pub(crate) fn secs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let secs = u64::deserialize(deserializer)?;
    if secs > MAX_DURATION.as_secs() {
        return Err(serde::de::Error::custom(too_long(&format!(
            "{secs} seconds"
        ))));
    }
    Ok(secs)
}

/// As [`secs`], for a field that also may not be zero.
pub(crate) fn nonzero_secs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let secs = secs(deserializer)?;
    if secs == 0 {
        return Err(serde::de::Error::custom("a duration of 0 seconds"));
    }
    Ok(secs)
}

/// As [`secs`], for a whole number of milliseconds.
pub(crate) fn millis<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let millis = u64::deserialize(deserializer)?;
    if Duration::from_millis(millis) > MAX_DURATION {
        return Err(serde::de::Error::custom(too_long(&format!("{millis} ms"))));
    }
    Ok(millis)
}

/// A chrono [`TimeDelta`](chrono::TimeDelta) from a constant, checked when
/// the crate compiles (MIK-8207): `delta!(seconds, 30)`, `delta!(days, 1)`.
///
/// The constructors it replaces (`TimeDelta::seconds` and the like) panic
/// out of range, and clippy refuses them (`clippy.toml`). Here the value is
/// built in a `const` block, so an out-of-range constant fails the build and
/// a runtime value does not compile at all: that one goes through
/// `TimeDelta::try_seconds` and the like, which return `None`.
macro_rules! delta {
    (weeks, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_weeks, $n)
    };
    (days, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_days, $n)
    };
    (hours, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_hours, $n)
    };
    (minutes, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_minutes, $n)
    };
    (seconds, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_seconds, $n)
    };
    (milliseconds, $n:expr) => {
        $crate::duration_bound::delta!(@checked try_milliseconds, $n)
    };
    (@checked $try:ident, $n:expr) => {
        const {
            match ::chrono::TimeDelta::$try($n) {
                Some(delta) => delta,
                None => panic!(concat!(
                    "delta!: ",
                    stringify!($try),
                    "(",
                    stringify!($n),
                    ") is out of chrono's range"
                )),
            }
        }
    };
}
pub(crate) use delta;

#[cfg(test)]
#[path = "duration_bound_tests.rs"]
mod tests;
