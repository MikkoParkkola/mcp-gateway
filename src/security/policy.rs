//! Tool allow/deny policies for the gateway.
//!
//! Provides configurable per-tool access control that blocks high-risk
//! tools by default and allows operators to customize access.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Default tools blocked for security reasons.
/// These are tools commonly associated with filesystem write access,
/// arbitrary code execution, or destructive operations.
const DEFAULT_DENIED_PATTERNS: &[&str] = &[
    // Filesystem mutation tools (common in MCP servers)
    "write_file",
    "delete_file",
    "move_file",
    "create_directory",
    // Shell/code execution
    "run_command",
    "execute_command",
    "shell_exec",
    "run_script",
    "eval",
    // Database mutation
    "drop_table",
    "drop_database",
    "truncate_table",
    // System administration
    "kill_process",
    "shutdown",
    "reboot",
];

/// Tool access policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolPolicyConfig {
    /// Enable tool policy enforcement.
    pub enabled: bool,
    /// Default action when a tool matches neither allow nor deny.
    pub default_action: PolicyAction,
    /// Explicit allow list (takes precedence over deny).
    /// Supports exact names and glob-like `*` suffix patterns.
    pub allow: Vec<String>,
    /// Explicit deny list.
    /// Supports exact names and glob-like `*` suffix patterns.
    pub deny: Vec<String>,
    /// Whether to include default deny patterns for high-risk tools.
    pub use_default_deny: bool,
    /// Log denied tool invocations (for auditing).
    pub log_denied: bool,
}

impl Default for ToolPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: PolicyAction::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
            use_default_deny: true,
            log_denied: true,
        }
    }
}

/// What to do when a tool is not explicitly allowed or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Allow the tool invocation.
    Allow,
    /// Deny the tool invocation.
    Deny,
}

/// Compiled tool policy for efficient runtime evaluation.
#[derive(Debug)]
pub struct ToolPolicy {
    /// Whether policy enforcement is active.
    enabled: bool,
    /// Default action for unmatched tools.
    default_action: PolicyAction,
    /// Exact allow set.
    allow_exact: HashSet<String>,
    /// Allow prefix patterns (from `pattern*` entries).
    allow_prefixes: Vec<String>,
    /// Exact deny set.
    deny_exact: HashSet<String>,
    /// Deny prefix patterns (from `pattern*` entries).
    deny_prefixes: Vec<String>,
    /// Whether to log denied invocations.
    log_denied: bool,
}

impl ToolPolicy {
    /// Compile a policy from configuration.
    #[must_use]
    pub fn from_config(config: &ToolPolicyConfig) -> Self {
        let mut deny_exact = HashSet::new();
        let mut deny_prefixes = Vec::new();
        let mut allow_exact = HashSet::new();
        let mut allow_prefixes = Vec::new();

        // Add default deny patterns if enabled
        if config.use_default_deny {
            for pattern in DEFAULT_DENIED_PATTERNS {
                deny_exact.insert((*pattern).to_string());
            }
        }

        // Add configured deny patterns
        for pattern in &config.deny {
            if let Some(prefix) = pattern.strip_suffix('*') {
                deny_prefixes.push(prefix.to_string());
            } else {
                deny_exact.insert(pattern.clone());
            }
        }

        // Add configured allow patterns
        for pattern in &config.allow {
            if let Some(prefix) = pattern.strip_suffix('*') {
                allow_prefixes.push(prefix.to_string());
            } else {
                allow_exact.insert(pattern.clone());
            }
        }

        Self {
            enabled: config.enabled,
            default_action: config.default_action,
            allow_exact,
            allow_prefixes,
            deny_exact,
            deny_prefixes,
            log_denied: config.log_denied,
        }
    }

    /// Check whether a tool invocation is allowed.
    ///
    /// Evaluation order:
    /// 1. If policy is disabled, always allow.
    /// 2. If tool is in explicit allow list, allow (takes precedence).
    /// 3. If tool is in deny list, deny.
    /// 4. Fall back to default action.
    ///
    /// # Errors
    ///
    /// Returns `Error::Protocol` if the tool is denied by policy.
    pub fn check(&self, server: &str, tool: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let qualified = format!("{server}:{tool}");

        // Check allow list first (takes precedence)
        if self.is_allowed(tool, &qualified) {
            return Ok(());
        }

        // Check deny list
        if self.is_denied(tool, &qualified) {
            if self.log_denied {
                tracing::warn!(
                    server = server,
                    tool = tool,
                    "Tool invocation denied by policy"
                );
            }
            return Err(Error::Protocol(format!(
                "Tool '{tool}' on server '{server}' is blocked by security policy"
            )));
        }

        // Apply default action
        match self.default_action {
            PolicyAction::Allow => Ok(()),
            PolicyAction::Deny => {
                if self.log_denied {
                    tracing::warn!(
                        server = server,
                        tool = tool,
                        "Tool invocation denied by default policy"
                    );
                }
                Err(Error::Protocol(format!(
                    "Tool '{tool}' on server '{server}' is not in the allow list"
                )))
            }
        }
    }

    /// Check if a tool is explicitly allowed.
    fn is_allowed(&self, tool: &str, qualified: &str) -> bool {
        if self.allow_exact.contains(tool) || self.allow_exact.contains(qualified) {
            return true;
        }
        self.allow_prefixes
            .iter()
            .any(|prefix| tool.starts_with(prefix) || qualified.starts_with(prefix))
    }

    /// Check if a tool is denied.
    fn is_denied(&self, tool: &str, qualified: &str) -> bool {
        if self.deny_exact.contains(tool) || self.deny_exact.contains(qualified) {
            return true;
        }
        self.deny_prefixes
            .iter()
            .any(|prefix| tool.starts_with(prefix) || qualified.starts_with(prefix))
    }
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self::from_config(&ToolPolicyConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> ToolPolicy {
        ToolPolicy::default()
    }

    fn custom_policy(
        allow: &[&str],
        deny: &[&str],
        default: PolicyAction,
        use_defaults: bool,
    ) -> ToolPolicy {
        let config = ToolPolicyConfig {
            enabled: true,
            default_action: default,
            allow: allow.iter().map(|s| (*s).to_string()).collect(),
            deny: deny.iter().map(|s| (*s).to_string()).collect(),
            use_default_deny: use_defaults,
            log_denied: false,
        };
        ToolPolicy::from_config(&config)
    }

    // ── Default policy ────────────────────────────────────────────────

    #[test]
    fn default_policy_blocks_write_file() {
        let policy = default_policy();
        assert!(policy.check("server", "write_file").is_err());
    }

    #[test]
    fn default_policy_blocks_delete_file() {
        let policy = default_policy();
        assert!(policy.check("server", "delete_file").is_err());
    }

    #[test]
    fn default_policy_blocks_run_command() {
        let policy = default_policy();
        assert!(policy.check("server", "run_command").is_err());
    }

    #[test]
    fn default_policy_blocks_execute_command() {
        let policy = default_policy();
        assert!(policy.check("server", "execute_command").is_err());
    }

    #[test]
    fn default_policy_blocks_drop_table() {
        let policy = default_policy();
        assert!(policy.check("server", "drop_table").is_err());
    }

    #[test]
    fn default_policy_blocks_kill_process() {
        let policy = default_policy();
        assert!(policy.check("server", "kill_process").is_err());
    }

    #[test]
    fn default_policy_allows_read_file() {
        let policy = default_policy();
        assert!(policy.check("server", "read_file").is_ok());
    }

    #[test]
    fn default_policy_allows_search() {
        let policy = default_policy();
        assert!(policy.check("server", "search").is_ok());
    }

    #[test]
    fn default_policy_allows_list_directory() {
        let policy = default_policy();
        assert!(policy.check("server", "list_directory").is_ok());
    }

    // ── Allow overrides deny ──────────────────────────────────────────

    #[test]
    fn allow_overrides_default_deny() {
        let policy = custom_policy(
            &["write_file"],
            &[],
            PolicyAction::Allow,
            true,
        );
        assert!(policy.check("server", "write_file").is_ok());
    }

    #[test]
    fn allow_overrides_explicit_deny() {
        let policy = custom_policy(
            &["my_tool"],
            &["my_tool"],
            PolicyAction::Allow,
            false,
        );
        assert!(policy.check("server", "my_tool").is_ok());
    }

    // ── Prefix patterns ───────────────────────────────────────────────

    #[test]
    fn deny_prefix_pattern() {
        let policy = custom_policy(
            &[],
            &["dangerous_*"],
            PolicyAction::Allow,
            false,
        );
        assert!(policy.check("server", "dangerous_operation").is_err());
        assert!(policy.check("server", "dangerous_write").is_err());
        assert!(policy.check("server", "safe_operation").is_ok());
    }

    #[test]
    fn allow_prefix_pattern() {
        let policy = custom_policy(
            &["safe_*"],
            &[],
            PolicyAction::Deny,
            false,
        );
        assert!(policy.check("server", "safe_read").is_ok());
        assert!(policy.check("server", "safe_list").is_ok());
        assert!(policy.check("server", "unsafe_write").is_err());
    }

    // ── Qualified names (server:tool) ─────────────────────────────────

    #[test]
    fn allow_qualified_name() {
        let policy = custom_policy(
            &["filesystem:write_file"],
            &[],
            PolicyAction::Allow,
            true,
        );
        // Qualified match overrides default deny
        assert!(policy.check("filesystem", "write_file").is_ok());
        // Different server still denied
        assert!(policy.check("other", "write_file").is_err());
    }

    #[test]
    fn deny_qualified_name() {
        let policy = custom_policy(
            &[],
            &["my_server:my_tool"],
            PolicyAction::Allow,
            false,
        );
        assert!(policy.check("my_server", "my_tool").is_err());
        assert!(policy.check("other", "my_tool").is_ok());
    }

    // ── Default action ────────────────────────────────────────────────

    #[test]
    fn default_deny_blocks_unknown_tools() {
        let policy = custom_policy(
            &["known_tool"],
            &[],
            PolicyAction::Deny,
            false,
        );
        assert!(policy.check("server", "known_tool").is_ok());
        assert!(policy.check("server", "unknown_tool").is_err());
    }

    #[test]
    fn default_allow_permits_unknown_tools() {
        let policy = custom_policy(
            &[],
            &[],
            PolicyAction::Allow,
            false,
        );
        assert!(policy.check("server", "anything").is_ok());
    }

    // ── Disabled policy ───────────────────────────────────────────────

    #[test]
    fn disabled_policy_allows_everything() {
        let config = ToolPolicyConfig {
            enabled: false,
            ..Default::default()
        };
        let policy = ToolPolicy::from_config(&config);
        assert!(policy.check("server", "write_file").is_ok());
        assert!(policy.check("server", "drop_database").is_ok());
    }

    // ── Default deny disabled ─────────────────────────────────────────

    #[test]
    fn no_default_deny_allows_previously_blocked() {
        let policy = custom_policy(
            &[],
            &[],
            PolicyAction::Allow,
            false,
        );
        assert!(policy.check("server", "write_file").is_ok());
        assert!(policy.check("server", "run_command").is_ok());
    }

    // ── Error messages ────────────────────────────────────────────────

    #[test]
    fn error_message_contains_tool_and_server() {
        let policy = default_policy();
        let err = policy.check("my_server", "write_file").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("write_file"));
        assert!(msg.contains("my_server"));
    }

    // ── All default deny patterns ─────────────────────────────────────

    #[test]
    fn all_default_deny_patterns_are_blocked() {
        let policy = default_policy();
        for pattern in DEFAULT_DENIED_PATTERNS {
            assert!(
                policy.check("server", pattern).is_err(),
                "Expected '{pattern}' to be blocked by default policy"
            );
        }
    }
}
