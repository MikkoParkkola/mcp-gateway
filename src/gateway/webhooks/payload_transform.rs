// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Webhook payload transformation.

use super::{TaggedNotification, Value, WebhookHandlerState};

// ============================================================================
// Payload transformation
// ============================================================================

/// Transform webhook payload to MCP notification.
pub(super) fn transform_payload(
    payload: &Value,
    state: &WebhookHandlerState,
) -> Result<TaggedNotification, String> {
    let transform = &state.definition.transform;

    // Extract event type.
    let event_type = if let Some(template) = &transform.event_type {
        extract_template_value(template, payload)?
    } else {
        format!("webhook.{}.{}", state.capability_name, state.webhook_name)
    };

    let transformed_data = project_data(transform, payload);

    // If no transform data specified, use the entire payload.
    let data = if transformed_data.is_empty() {
        payload.clone()
    } else {
        Value::Object(transformed_data)
    };

    Ok(TaggedNotification {
        source: state.capability_name.clone(),
        event_type,
        data,
        event_id: None,
    })
}

/// Each mapped key whose template resolves, as a string. A mapping with no
/// `{...}` is a literal and is taken as written; a template that names a
/// path the payload lacks omits its key. There is no raw-path form.
pub(super) fn project_data(
    transform: &crate::capability::WebhookTransform,
    payload: &Value,
) -> serde_json::Map<String, Value> {
    transform
        .data
        .iter()
        .filter_map(|(key, template)| {
            extract_template_value(template, payload)
                .ok()
                .map(|value| (key.clone(), Value::String(value)))
        })
        .collect()
}

/// Extract value from template (supports `{field.nested}` syntax).
pub(super) fn extract_template_value(template: &str, payload: &Value) -> Result<String, String> {
    let mut result = template.to_string();

    // Find all {field.path} patterns.
    let re = regex::Regex::new(r"\{([^}]+)\}").map_err(|e| format!("Invalid regex: {e}"))?;

    for cap in re.captures_iter(template) {
        let path = &cap[1];
        if let Some(value) = extract_json_path(path, payload) {
            let value_str = match value {
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            result = result.replace(&format!("{{{path}}}"), &value_str);
        } else {
            return Err(format!("Path not found: {path}"));
        }
    }

    Ok(result)
}

/// Extract value from JSON using dot-notation path (e.g., "data.issue.id").
pub(super) fn extract_json_path<'a>(path: &str, payload: &'a Value) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = payload;

    for part in parts {
        current = match current {
            Value::Object(map) => map.get(part)?,
            Value::Array(arr) => {
                let index: usize = part.parse().ok()?;
                arr.get(index)?
            }
            _ => return None,
        };
    }

    Some(current)
}
