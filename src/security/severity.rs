// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared severity for security findings.

use serde::{Deserialize, Serialize};

/// Severity of a security finding, shared by the firewall, response inspection and context integrity.
/// Each scanner maps it to an action where that mapping lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational finding.
    Low,
    /// Suspicious pattern.
    Medium,
    /// Likely malicious content.
    High,
    /// Confirmed or deterministic threat.
    Critical,
}

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn severity_serializes_to_snake_case_and_round_trips() {
        for (severity, expected) in [
            (Severity::Low, "\"low\""),
            (Severity::Medium, "\"medium\""),
            (Severity::High, "\"high\""),
            (Severity::Critical, "\"critical\""),
        ] {
            assert_eq!(
                serde_json::to_string(&severity).expect("severity must serialize"),
                expected
            );
            assert_eq!(
                serde_json::from_str::<Severity>(expected).expect("snake_case must parse"),
                severity
            );
        }
    }

    #[test]
    fn severity_rejects_non_snake_case() {
        assert!(serde_json::from_str::<Severity>("\"High\"").is_err());
        assert!(serde_json::from_str::<Severity>("\"CRITICAL\"").is_err());
    }

    #[test]
    fn severity_orders_low_below_medium_below_high_below_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
