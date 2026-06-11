//! Slack control plane configuration.
//!
//! All token values use `env:` references resolved at runtime from
//! `~/.claude/secrets.env` or the process environment — never literal secrets.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Slack control plane configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackControlConfig {
    /// Enable the Slack control plane listener.
    pub enabled: bool,

    /// App-level token reference for Socket Mode (xapp-...).
    /// Must be an `env:` reference (e.g. `env:SLACK_APP_TOKEN`).
    pub app_token: String,

    /// Bot token reference for API calls (xoxb-...).
    /// Must be an `env:` reference (e.g. `env:SLACK_BOT_TOKEN`).
    pub bot_token: String,

    /// Allowlisted channel IDs. Events from other channels are ignored.
    pub allowed_channels: HashSet<String>,

    /// Allowlisted Slack user IDs. Only these users may trigger actions.
    pub allowed_users: HashSet<String>,

    /// Path to the JSONL audit log file.
    pub audit_log_path: String,

    /// Path to the instruction checkpoint file for restart durability.
    pub checkpoint_path: String,

    /// Action policy: instruction patterns that require in-thread confirmation.
    pub destructive_patterns: Vec<String>,

    /// Action policy: instruction patterns that execute without confirmation.
    pub safe_patterns: Vec<String>,

    /// Maximum instruction length in characters.
    pub max_instruction_length: usize,
}

impl Default for SlackControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_token: "env:SLACK_APP_TOKEN".to_string(),
            bot_token: "env:SLACK_BOT_TOKEN".to_string(),
            allowed_channels: HashSet::new(),
            allowed_users: HashSet::new(),
            audit_log_path: "~/.mcp-gateway/slack-control/audit.jsonl".to_string(),
            checkpoint_path: "~/.mcp-gateway/slack-control/checkpoints.jsonl".to_string(),
            destructive_patterns: vec![
                "delete".to_string(),
                "destroy".to_string(),
                "drop".to_string(),
                "remove".to_string(),
                "rm ".to_string(),
                "force".to_string(),
                "push --force".to_string(),
                "reset --hard".to_string(),
            ],
            safe_patterns: vec![
                "what is".to_string(),
                "list".to_string(),
                "show".to_string(),
                "status".to_string(),
                "help".to_string(),
            ],
            max_instruction_length: 4096,
        }
    }
}

impl SlackControlConfig {
    /// Validate that token fields use `env:` references, not literal values.
    ///
    /// Returns an error message if a literal token is detected.
    pub fn validate_no_literal_secrets(&self) -> Result<(), String> {
        for (field, value) in [("app_token", &self.app_token), ("bot_token", &self.bot_token)] {
            if !value.starts_with("env:") {
                return Err(format!(
                    "slack_control.{field} must use an env: reference, not a literal value"
                ));
            }
            if value.contains("xapp-") || value.contains("xoxb-") {
                return Err(format!(
                    "slack_control.{field} contains a literal secret token"
                ));
            }
        }
        Ok(())
    }

    /// Resolve the app token variable name from the `env:` reference.
    pub fn app_token_var(&self) -> Option<&str> {
        self.app_token.strip_prefix("env:")
    }

    /// Resolve the bot token variable name from the `env:` reference.
    pub fn bot_token_var(&self) -> Option<&str> {
        self.bot_token.strip_prefix("env:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_env_references() {
        let cfg = SlackControlConfig::default();
        assert!(cfg.validate_no_literal_secrets().is_ok());
    }

    #[test]
    fn literal_token_rejected() {
        let mut cfg = SlackControlConfig::default();
        cfg.app_token = "xapp-1-abc123".to_string();
        assert!(cfg.validate_no_literal_secrets().is_err());
    }
}
