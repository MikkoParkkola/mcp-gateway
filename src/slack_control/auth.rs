//! Command authorization gate (SLACKCTL.AUTH.3).
//!
//! Only an allowlisted Slack user-ID set (config-driven) can trigger actions.
//! Non-allowlisted posts are ignored AND logged.

use std::collections::HashSet;

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// User is allowlisted; instruction may proceed.
    Allowed {
        /// The authorized Slack user ID.
        user_id: String,
    },
    /// User is not allowlisted; instruction is rejected.
    Denied {
        /// The rejected Slack user ID.
        user_id: String,
        /// Reason for denial.
        reason: String,
    },
}

/// User-ID allowlist authorization gate.
#[derive(Debug, Clone)]
pub struct AuthGate {
    /// Set of Slack user IDs permitted to trigger actions.
    allowed_users: HashSet<String>,
}

impl AuthGate {
    /// Create a new auth gate from the configured allowlist.
    pub fn new(allowed_users: HashSet<String>) -> Self {
        Self { allowed_users }
    }

    /// Check whether the given Slack user ID is authorized.
    ///
    /// Returns `AuthDecision::Allowed` if the user is in the allowlist,
    /// `AuthDecision::Denied` otherwise.
    pub fn check(&self, user_id: &str) -> AuthDecision {
        if self.allowed_users.contains(user_id) {
            AuthDecision::Allowed {
                user_id: user_id.to_string(),
            }
        } else {
            AuthDecision::Denied {
                user_id: user_id.to_string(),
                reason: format!("user {user_id} is not in the allowlist"),
            }
        }
    }

    /// Return a reference to the allowlist.
    pub fn allowed_users(&self) -> &HashSet<String> {
        &self.allowed_users
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_gate() -> AuthGate {
        let mut users = HashSet::new();
        users.insert("U0B6UUVKGAC".to_string());
        users.insert("U1234567890".to_string());
        AuthGate::new(users)
    }

    #[test]
    fn allowlisted_user_is_allowed() {
        let gate = test_gate();
        let decision = gate.check("U0B6UUVKGAC");
        assert_eq!(
            decision,
            AuthDecision::Allowed {
                user_id: "U0B6UUVKGAC".to_string()
            }
        );
    }

    #[test]
    fn non_allowlisted_user_is_denied() {
        let gate = test_gate();
        let decision = gate.check("UEVIL_HACKER");
        assert!(matches!(decision, AuthDecision::Denied { .. }));
    }

    #[test]
    fn empty_user_is_denied() {
        let gate = test_gate();
        let decision = gate.check("");
        assert!(matches!(decision, AuthDecision::Denied { .. }));
    }
}
