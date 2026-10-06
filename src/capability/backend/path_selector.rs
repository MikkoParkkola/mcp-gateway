// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A path-selector argument must be a string: refused before any request.

use serde_json::Value;

use crate::capability::CapabilityDefinition;
use crate::protocol::{Content, ToolsCallResult};

pub(super) fn path_selector_type_error(
    capability: &CapabilityDefinition,
    arguments: &Value,
) -> Option<ToolsCallResult> {
    let selector = capability
        .primary_provider()?
        .config
        .path_selector
        .as_ref()?;
    let value = arguments.get(&selector.parameter)?;
    if value.is_null() || value.is_string() {
        return None;
    }

    Some(ToolsCallResult {
        content: vec![Content::Text {
            text: format!(
                "Tool call validation failed:\n- Parameter '{}' must be a string.",
                selector.parameter
            ),
            annotations: None,
        }],
        structured_content: None,
        is_error: true,
    })
}
