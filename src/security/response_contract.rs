// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-tool response contract validator (issue #133, D1).
//!
//! Implements the fail-closed policy gate from arXiv:2604.08407.
//! Each tool may declare:
//! - A maximum response size (`max_bytes`)
//! - A set of forbidden regex patterns that must NOT appear in the response
//! - Whether violations should block (`action_mode = true`) or be observed only
//!
//! Default: no contract → pass-through (unless `fail_closed` is set on the
//! [`crate::config::features::security::ResponseContractConfig`]).

use regex::RegexSet;

/// A compiled per-tool response contract.
///
/// Build once and reuse; [`RegexSet`] compilation is expensive.
pub struct ToolResponseContract {
    /// Maximum allowed response text size in bytes. `None` means unlimited.
    pub max_bytes: Option<usize>,
    /// Pre-compiled set of patterns that must NOT appear in the response.
    pub forbidden_patterns: RegexSet,
    /// When `true`, a violation will set [`ContractViolation::should_block`].
    /// When `false`, violations are recorded for logging only.
    pub action_mode: bool,
}

/// A single contract violation found during validation.
#[derive(Debug, Clone)]
pub struct ContractViolation {
    /// Short machine-readable reason code.
    pub reason: &'static str,
    /// Human-readable detail (e.g., which byte limit was exceeded).
    pub detail: String,
    /// Whether the caller should block the response.
    pub should_block: bool,
}

impl ToolResponseContract {
    /// Validate `text` against this contract.
    ///
    /// Returns `Some(violation)` on the first violation found, `None` when the
    /// response is compliant.
    #[must_use]
    pub fn validate(&self, text: &str) -> Option<ContractViolation> {
        // 1. Size check
        if let Some(max) = self.max_bytes {
            if text.len() > max {
                return Some(ContractViolation {
                    reason: "max_bytes_exceeded",
                    detail: format!(
                        "Response size {} bytes exceeds declared limit of {} bytes",
                        text.len(),
                        max
                    ),
                    should_block: self.action_mode,
                });
            }
        }

        // 2. Forbidden pattern check
        if !self.forbidden_patterns.is_empty() {
            let matches = self.forbidden_patterns.matches(text);
            if matches.matched_any() {
                // Report the index of the first matching pattern.
                let idx = matches.iter().next().unwrap_or(0);
                return Some(ContractViolation {
                    reason: "forbidden_pattern_matched",
                    detail: format!("Response matched forbidden pattern at index {idx}"),
                    should_block: self.action_mode,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contract(
        max_bytes: Option<usize>,
        patterns: &[&str],
        action_mode: bool,
    ) -> ToolResponseContract {
        let forbidden_patterns = if patterns.is_empty() {
            RegexSet::empty()
        } else {
            RegexSet::new(patterns).expect("test patterns must compile")
        };
        ToolResponseContract {
            max_bytes,
            forbidden_patterns,
            action_mode,
        }
    }

    #[test]
    fn clean_response_passes() {
        let contract = make_contract(Some(1024), &[r"sk-[a-zA-Z0-9]{48}"], false);
        assert!(contract.validate("Hello, world!").is_none());
    }

    #[test]
    fn max_bytes_violation_detected() {
        let contract = make_contract(Some(10), &[], false);
        let violation = contract.validate("This response is longer than ten bytes");
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_eq!(v.reason, "max_bytes_exceeded");
    }

    #[test]
    fn forbidden_pattern_violation_detected() {
        let contract = make_contract(None, &[r"BEGIN PRIVATE KEY"], false);
        let violation = contract.validate("-----BEGIN PRIVATE KEY-----\nMIIE...");
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_eq!(v.reason, "forbidden_pattern_matched");
    }

    #[test]
    fn action_mode_false_does_not_block() {
        let contract = make_contract(Some(5), &[], false);
        let violation = contract.validate("This is too long").unwrap();
        assert!(
            !violation.should_block,
            "observe mode must never set should_block"
        );
    }

    #[test]
    fn action_mode_true_blocks_on_violation() {
        let contract = make_contract(Some(5), &[], true);
        let violation = contract.validate("This is too long").unwrap();
        assert!(violation.should_block, "action mode must set should_block");
    }

    #[test]
    fn no_violation_when_exactly_at_limit() {
        let contract = make_contract(Some(5), &[], true);
        assert!(contract.validate("hello").is_none());
    }

    #[test]
    fn forbidden_pattern_in_action_mode_blocks() {
        let contract = make_contract(None, &[r"AKIA[0-9A-Z]{16}"], true);
        let violation = contract
            .validate("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
            .unwrap();
        assert_eq!(violation.reason, "forbidden_pattern_matched");
        assert!(violation.should_block);
    }

    #[test]
    fn multiple_patterns_first_match_reported() {
        let contract = make_contract(None, &[r"alpha", r"beta"], false);
        let violation = contract.validate("alpha and beta are here").unwrap();
        assert_eq!(violation.reason, "forbidden_pattern_matched");
    }

    #[test]
    fn empty_patterns_never_triggers_forbidden() {
        let contract = make_contract(None, &[], true);
        assert!(contract.validate("anything goes here").is_none());
    }
}
