//! `TrustCard` generation facade.
//!
//! Generation currently reuses the canonical `TrustCard` constructors. The
//! facade keeps CLI, docs, tests, and future registry/live metadata adapters on
//! one import path instead of binding them to constructor placement.

use crate::{capability::CapabilityDefinition, protocol::Tool};

use super::TrustCard;

/// Generate a `TrustCard` from a live or fixture MCP tool descriptor.
#[must_use]
pub fn trust_card_from_tool(server_name: impl Into<String>, tool: &Tool) -> TrustCard {
    TrustCard::from_tool(server_name, tool)
}

/// Generate a `TrustCard` from a local capability definition.
#[must_use]
pub fn trust_card_from_capability(capability: &CapabilityDefinition) -> TrustCard {
    TrustCard::from_capability(capability)
}
