//! Action policy classifier (SLACKCTL.AUTH.4).
//!
//! An explicit allow/deny classifier decides which instruction classes execute
//! vs require human confirm-in-thread. Destructive/irreversible operations
//! ALWAYS require explicit in-thread confirmation.

/// Result of a policy classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Instruction is safe to execute immediately.
    Execute,
    /// Instruction requires in-thread human confirmation before execution.
    RequireConfirmation {
        /// Reason the instruction requires confirmation.
        reason: String,
    },
    /// Instruction is unconditionally denied.
    Denied {
        /// Reason the instruction was denied.
        reason: String,
    },
}

/// Action policy classifier for Slack-triggered instructions.
#[derive(Debug, Clone)]
pub struct ActionPolicy {
    /// Patterns that indicate destructive/irreversible operations.
    destructive_patterns: Vec<String>,
    /// Patterns that indicate safe read-only operations.
    safe_patterns: Vec<String>,
    /// Maximum instruction length.
    max_instruction_length: usize,
}

impl ActionPolicy {
    /// Create a new action policy from configuration.
    pub fn new(
        destructive_patterns: Vec<String>,
        safe_patterns: Vec<String>,
        max_instruction_length: usize,
    ) -> Self {
        Self {
            destructive_patterns,
            safe_patterns,
            max_instruction_length,
        }
    }

    /// Classify an instruction and return the policy decision.
    ///
    /// Classification priority:
    /// 1. Empty or over-length instructions are denied.
    /// 2. If any destructive pattern matches → RequireConfirmation.
    /// 3. If any safe pattern matches → Execute.
    /// 4. Unknown instructions default to RequireConfirmation (fail-safe).
    pub fn classify(&self, instruction: &str) -> PolicyDecision {
        let trimmed = instruction.trim();

        if trimmed.is_empty() {
            return PolicyDecision::Denied {
                reason: "empty instruction".to_string(),
            };
        }

        if trimmed.len() > self.max_instruction_length {
            return PolicyDecision::Denied {
                reason: format!(
                    "instruction exceeds maximum length ({} > {})",
                    trimmed.len(),
                    self.max_instruction_length
                ),
            };
        }

        let lower = trimmed.to_lowercase();

        for pattern in &self.destructive_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return PolicyDecision::RequireConfirmation {
                    reason: format!(
                        "instruction matches destructive pattern '{pattern}'; \
                         in-thread confirmation required"
                    ),
                };
            }
        }

        for pattern in &self.safe_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return PolicyDecision::Execute;
            }
        }

        PolicyDecision::RequireConfirmation {
            reason: "unknown instruction class; in-thread confirmation required (fail-safe)"
                .to_string(),
        }
    }

    /// Return the destructive patterns.
    pub fn destructive_patterns(&self) -> &[String] {
        &self.destructive_patterns
    }

    /// Return the safe patterns.
    pub fn safe_patterns(&self) -> &[String] {
        &self.safe_patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> ActionPolicy {
        ActionPolicy::new(
            vec![
                "delete".to_string(),
                "destroy".to_string(),
                "force".to_string(),
                "rm ".to_string(),
            ],
            vec![
                "what is".to_string(),
                "list".to_string(),
                "show".to_string(),
                "status".to_string(),
            ],
            4096,
        )
    }

    #[test]
    fn safe_instruction_executes() {
        let policy = test_policy();
        assert_eq!(policy.classify("what is 2+2"), PolicyDecision::Execute);
    }

    #[test]
    fn destructive_instruction_requires_confirmation() {
        let policy = test_policy();
        let decision = policy.classify("delete all issues in the project");
        assert!(matches!(decision, PolicyDecision::RequireConfirmation { .. }));
    }

    #[test]
    fn unknown_instruction_requires_confirmation() {
        let policy = test_policy();
        let decision = policy.classify("deploy to production");
        assert!(matches!(decision, PolicyDecision::RequireConfirmation { .. }));
    }

    #[test]
    fn empty_instruction_denied() {
        let policy = test_policy();
        assert!(matches!(
            policy.classify(""),
            PolicyDecision::Denied { .. }
        ));
    }

    #[test]
    fn over_length_instruction_denied() {
        let policy = ActionPolicy::new(vec![], vec!["ok".to_string()], 10);
        assert!(matches!(
            policy.classify("this is way too long"),
            PolicyDecision::Denied { .. }
        ));
    }

    #[test]
    fn case_insensitive_matching() {
        let policy = test_policy();
        assert!(matches!(
            policy.classify("DELETE everything"),
            PolicyDecision::RequireConfirmation { .. }
        ));
    }
}
