// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: `security.transparency_log.rotation`, the audit log's segment size,
//! retention and disk-full behaviour. There is no "off" switch: with auth on
//! the log is required (UPGRADING item 43), and an unrotated required log is
//! the outage D6 removes (UPGRADING item 49).

use serde::{Deserialize, Serialize};

/// Smallest accepted `max_segment_bytes` (1 MiB).
pub const MIN_SEGMENT_BYTES: u64 = 1024 * 1024;
/// Largest accepted `max_segment_bytes` (128 MiB): half the 256 MiB bound of
/// the audit reader, so a full segment plus its seal plus one oversized record
/// (itself capped at 4 MiB) stays readable.
pub const MAX_SEGMENT_BYTES: u64 = 128 * 1024 * 1024;

/// What an append does when the volume returns ENOSPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDiskFull {
    /// Record, then delete, the oldest sealed segment and retry the append
    /// once, writing the record from a 1 MiB reserve file.
    #[default]
    ExpireOldest,
    /// Keep every record; the log stays degraded (the item 43 behaviour).
    Refuse,
}

/// Rotation settings. A plain nested struct (never flattened), so the
/// generic strict-keys walk rejects a misspelt key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RotationConfig {
    /// Rotate before a write would take the active segment past this size.
    pub max_segment_bytes: u64,
    /// Also rotate once the active segment is this old; 0 = off.
    pub max_segment_age_secs: u64,
    /// Sealed segments kept; older ones are recorded and deleted.
    pub retain_segments: u32,
    /// The ENOSPC emergency path.
    pub on_disk_full: OnDiskFull,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_segment_bytes: 64 * 1024 * 1024,
            max_segment_age_secs: 0,
            retain_segments: 12,
            on_disk_full: OnDiskFull::ExpireOldest,
        }
    }
}

impl RotationConfig {
    /// The governance log's fixed rotation (D6 section 2.12): 16 MiB x 4,
    /// at most 80 MiB, inheriting the operator's `on_disk_full`.
    #[must_use]
    pub fn governance(on_disk_full: OnDiskFull) -> Self {
        Self {
            max_segment_bytes: 16 * 1024 * 1024,
            max_segment_age_secs: 0,
            retain_segments: 4,
            on_disk_full,
        }
    }

    /// Refuse a segment size outside 1 MiB..=128 MiB or zero retention.
    ///
    /// # Errors
    ///
    /// [`crate::Error::ConfigValidation`] naming the offending key.
    pub fn validate(&self) -> crate::Result<()> {
        if !(MIN_SEGMENT_BYTES..=MAX_SEGMENT_BYTES).contains(&self.max_segment_bytes) {
            return Err(crate::Error::ConfigValidation(format!(
                "security.transparency_log.rotation.max_segment_bytes must be between \
                 {MIN_SEGMENT_BYTES} and {MAX_SEGMENT_BYTES}, got {} \
                 (docs/UPGRADING-4.0.md section 49)",
                self.max_segment_bytes
            )));
        }
        if self.retain_segments == 0 {
            return Err(crate::Error::ConfigValidation(
                "security.transparency_log.rotation.retain_segments must be at least 1 \
                 (docs/UPGRADING-4.0.md section 49)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 128 MiB loads, one byte more does not; the floor is exact too.
    #[test]
    fn segment_bytes_bound_is_exact() {
        let at = |b| RotationConfig {
            max_segment_bytes: b,
            ..RotationConfig::default()
        };
        assert!(at(134_217_728).validate().is_ok());
        assert!(at(134_217_729).validate().is_err());
        assert!(at(1_048_576).validate().is_ok());
        assert!(at(1_048_575).validate().is_err());
        let zero = RotationConfig {
            retain_segments: 0,
            ..RotationConfig::default()
        };
        assert!(zero.validate().is_err());
    }

    #[test]
    fn on_disk_full_parses_both_arms() {
        let r: RotationConfig =
            serde_yaml::from_str("on_disk_full: refuse\nretain_segments: 3\n").unwrap();
        assert_eq!(r.on_disk_full, OnDiskFull::Refuse);
        assert_eq!(r.retain_segments, 3);
        assert_eq!(r.max_segment_bytes, 64 * 1024 * 1024);
    }
}
