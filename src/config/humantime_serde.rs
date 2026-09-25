// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Custom humantime serde module for `Duration`.

use std::time::Duration;

use serde::{self, Deserialize, Deserializer, Serializer};

/// Parse a human-readable duration such as `"30s"`, `"5m"`, `"100ms"`.
///
/// NOTE: `"ms"` is tested BEFORE `"s"`. The previous implementation tested
/// `"s"` first, so `"100ms"` took the seconds branch and failed to parse
/// `"100m"` as an integer — every `ms` value in every duration field was
/// rejected. Bare integers are seconds.
fn parse(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if let Some(ms) = text.strip_suffix("ms") {
        ms.parse::<u64>().map(Duration::from_millis)
    } else if let Some(secs) = text.strip_suffix('s') {
        secs.parse::<u64>().map(Duration::from_secs)
    } else if let Some(mins) = text.strip_suffix('m') {
        mins.parse::<u64>().map(|m| Duration::from_secs(m * 60))
    } else if let Some(hours) = text.strip_suffix('h') {
        hours.parse::<u64>().map(|h| Duration::from_secs(h * 3600))
    } else {
        text.parse::<u64>().map(Duration::from_secs)
    }
    .map_err(|e| format!("invalid duration {text:?}: {e}"))
}

/// Serialize `Duration` to a human-readable string (e.g., `"30s"`).
///
/// # Errors
///
/// Returns a serialization error if the serializer fails, the duration has
/// sub-millisecond precision, or its millisecond total exceeds `u64` when
/// fractional seconds require the millisecond encoding.
pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if duration.subsec_nanos() == 0 {
        return serializer.serialize_str(&format!("{}s", duration.as_secs()));
    }
    if !duration.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(serde::ser::Error::custom(
            "duration has sub-millisecond precision",
        ));
    }
    let millis = u64::try_from(duration.as_millis())
        .map_err(|_| serde::ser::Error::custom("duration millisecond total exceeds u64"))?;
    serializer.serialize_str(&format!("{millis}ms"))
}

/// Deserialize a human-readable duration string.
///
/// # Errors
///
/// Returns a deserialization error if the string cannot be parsed.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    parse(&text).map_err(serde::de::Error::custom)
}

/// Same encoding for an optional duration. A missing key deserialises to
/// `None`, so "unset" stays distinguishable from any real value — no magic
/// zero standing in for "never".
pub mod option {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    /// # Errors
    ///
    /// Returns a serialization error if the serializer fails.
    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(d) => super::serialize(d, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// # Errors
    ///
    /// Returns a deserialization error if the string cannot be parsed.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(text) => super::parse(&text)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}
