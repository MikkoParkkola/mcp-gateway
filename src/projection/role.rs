// SPDX-License-Identifier: MIT

//! Tool role taxonomy for the projection layer (MIK-3530 / MIK-3531).
//!
//! Every gateway-advertised tool can be tagged with the role it plays in an
//! agent workflow. `list_tools` discovery filtering (MIK-3532) uses this so a
//! caller can request, for example, only `selector` tools instead of the full
//! union of backend surfaces.

use serde::{Deserialize, Serialize};

/// The role a tool plays in an agent workflow.
///
/// Untagged tools default to [`Role::Action`], which preserves full backward
/// compatibility: a tool with no declared role behaves exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Finds or lists candidate subjects (e.g. `search`, `list`).
    Selector,
    /// Pulls detail for a known subject (e.g. `get`, `read`).
    Extractor,
    /// Adds derived or contextual data to a subject (e.g. `enrich`, `annotate`).
    Enricher,
    /// Mutates external state (e.g. `create`, `update`, `delete`).
    ///
    /// This is the default for untagged tools — the safe assumption is that a
    /// tool may have side effects.
    #[default]
    Action,
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn default_role_is_action() {
        assert_eq!(Role::default(), Role::Action);
    }

    #[test]
    fn role_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Role::Selector).unwrap(),
            "\"selector\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Extractor).unwrap(),
            "\"extractor\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Enricher).unwrap(),
            "\"enricher\""
        );
        assert_eq!(serde_json::to_string(&Role::Action).unwrap(), "\"action\"");
    }

    #[test]
    fn role_round_trips() {
        for role in [
            Role::Selector,
            Role::Extractor,
            Role::Enricher,
            Role::Action,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let back: Role = serde_json::from_str(&json).unwrap();
            assert_eq!(role, back);
        }
    }
}
