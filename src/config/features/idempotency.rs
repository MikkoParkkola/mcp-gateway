// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Operator-owned exceptions to mandatory modern execution admission.

use serde::{Deserialize, Serialize};

/// Explicit read-only targets. An omitted section permits no exceptions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdempotencyConfig {
    /// Exact backend/tool pairs; backend-reported annotations are not authority.
    pub read_only_tools: Vec<IdempotencyReadOnlyTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One operator-authorized read-only backend tool, matched byte for byte.
pub struct IdempotencyReadOnlyTool {
    /// Exact configured backend name.
    pub server: String,
    /// Exact backend tool name.
    pub tool: String,
}

impl IdempotencyConfig {
    pub(crate) fn is_read_only(&self, server: &str, tool: &str) -> bool {
        self.read_only_tools
            .iter()
            .any(|target| target.server == server && target.tool == tool)
    }

    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self
            .read_only_tools
            .iter()
            .any(|target| target.server.is_empty() || target.tool.is_empty())
        {
            return Err(crate::Error::ConfigValidation(
                "idempotency.read_only_tools requires nonempty server and tool names".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod idempotency_config_tests {
    use super::*;

    fn listed() -> IdempotencyConfig {
        IdempotencyConfig {
            read_only_tools: vec![IdempotencyReadOnlyTool {
                server: "files".into(),
                tool: "read_file".into(),
            }],
        }
    }

    /// MIK-7216.IDEM.1 — admission's read-only check for a backend tool is
    /// this operator list alone; backend annotations are never consulted.
    #[test]
    fn only_an_operator_listed_pair_is_read_only_for_admission() {
        let config = listed();
        assert!(config.is_read_only("files", "read_file"));
        assert!(!config.is_read_only("files", "get_and_increment"));
        assert!(!config.is_read_only("other", "read_file"));
        assert!(!IdempotencyConfig::default().is_read_only("files", "read_file"));
    }
}
