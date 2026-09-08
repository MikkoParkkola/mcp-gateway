// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Read-only validation of the finite elicitation request and result shapes.
//!
//! This validates the schema a client is asked to render, never the answer
//! against that schema. No defaults, transformations or reference resolution.

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::meta::ElicitationMode;

/// Validate required request fields without reconstructing the raw params.
pub(crate) fn validate_request(params: Option<&Value>) -> Option<ElicitationMode> {
    let raw_params = params?;
    let mode = ElicitationMode::from_params(Some(raw_params))?;
    let params = raw_params.as_object()?;
    params.get("message")?.as_str()?;
    match mode {
        ElicitationMode::Form => {
            if !valid_form_schema(params.get("requestedSchema")?) {
                return None;
            }
        }
        ElicitationMode::Url => {
            url::Url::parse(params.get("url")?.as_str()?).ok()?;
            // The legacy adapter inserts an absent ID only. A bad present ID
            // must refuse the entire batch before any member is delivered.
            if params
                .get("elicitationId")
                .is_some_and(|id| id.as_str().is_none_or(str::is_empty))
            {
                return None;
            }
        }
    }
    Some(mode)
}

/// The recognized action, independent of the consumer's refusal policy.
pub(crate) enum ElicitAction {
    /// The client accepted; the mode's result fields are valid.
    Accept,
    /// The person declined the request.
    Decline,
    /// The person cancelled the request.
    Cancel,
}

impl ElicitAction {
    /// The protocol spelling, independent of the consumer's error type.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}

/// Structural failure, separate from a recognized personal refusal.
pub(crate) enum ElicitResultError<'a> {
    /// A required action or mode-specific accepted field is unusable.
    Malformed,
    /// A string action outside the protocol's closed set.
    UnknownAction(&'a str),
}

/// Validate an `ElicitResult` while leaving every field in the caller's value.
pub(crate) fn validate_result(
    mode: ElicitationMode,
    result: &Value,
) -> Result<ElicitAction, ElicitResultError<'_>> {
    let action = result
        .get("action")
        .and_then(Value::as_str)
        .ok_or(ElicitResultError::Malformed)?;
    match action {
        "accept" => {
            let valid = match mode {
                ElicitationMode::Form => result.get("content").is_some_and(Value::is_object),
                ElicitationMode::Url => result.get("content").is_none(),
            };
            if valid {
                Ok(ElicitAction::Accept)
            } else {
                Err(ElicitResultError::Malformed)
            }
        }
        "decline" => Ok(ElicitAction::Decline),
        "cancel" => Ok(ElicitAction::Cancel),
        other => Err(ElicitResultError::UnknownAction(other)),
    }
}

fn valid_form_schema(schema: &Value) -> bool {
    let Some(schema) = schema.as_object() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    schema.get("type").and_then(Value::as_str) == Some("object")
        && valid_keywords(schema, &["type", "properties", "required"])
        && optional(schema, "required", |required| {
            required.as_array().is_some_and(|names| {
                let mut seen = HashSet::new();
                names.iter().all(|name| {
                    name.as_str()
                        .is_some_and(|name| properties.contains_key(name) && seen.insert(name))
                })
            })
        })
        && properties.values().all(valid_property)
}

fn valid_property(property: &Value) -> bool {
    let Some(property) = property.as_object() else {
        return false;
    };
    match property.get("type").and_then(Value::as_str) {
        Some("string") => valid_string(property),
        Some("number" | "integer") => {
            valid_keywords(property, &["type", "minimum", "maximum", "default"])
                && ["minimum", "maximum", "default"]
                    .iter()
                    .all(|key| optional(property, key, Value::is_number))
        }
        Some("boolean") => {
            valid_keywords(property, &["type", "default"])
                && optional(property, "default", Value::is_boolean)
        }
        Some("array") => valid_multi_enum(property),
        _ => false,
    }
}

fn valid_string(property: &Map<String, Value>) -> bool {
    valid_keywords(
        property,
        &[
            "type",
            "minLength",
            "maxLength",
            "pattern",
            "format",
            "default",
            "enum",
            "oneOf",
        ],
    ) && ["minLength", "maxLength"]
        .iter()
        .all(|key| optional(property, key, nonnegative_integer))
        && ["pattern", "default"]
            .iter()
            .all(|key| optional(property, key, Value::is_string))
        && optional(property, "format", |format| {
            matches!(
                format.as_str(),
                Some("email" | "uri" | "date" | "date-time")
            )
        })
        && optional(property, "enum", enum_values)
        && optional(property, "oneOf", titled_options)
        && !(property.contains_key("enum") && property.contains_key("oneOf"))
}

fn valid_multi_enum(property: &Map<String, Value>) -> bool {
    let Some(items) = property.get("items").and_then(Value::as_object) else {
        return false;
    };
    let valid_items = if items.contains_key("anyOf") {
        valid_keywords(items, &["anyOf"]) && items.get("anyOf").is_some_and(titled_options)
    } else {
        valid_keywords(items, &["type", "enum"])
            && items.get("type").and_then(Value::as_str) == Some("string")
            && items.get("enum").is_some_and(enum_values)
    };
    valid_items
        && valid_keywords(
            property,
            &["type", "items", "minItems", "maxItems", "default"],
        )
        && ["minItems", "maxItems"]
            .iter()
            .all(|key| optional(property, key, nonnegative_integer))
        && optional(property, "default", string_list)
}

fn titled_options(options: &Value) -> bool {
    options.as_array().is_some_and(|options| {
        !options.is_empty()
            && options.iter().all(|option| {
                option.as_object().is_some_and(|option| {
                    valid_keywords(option, &["const"])
                        && option.get("const").is_some_and(Value::is_string)
                        && option.get("title").is_some_and(Value::is_string)
                })
            })
    })
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

fn enum_values(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string))
}

fn nonnegative_integer(value: &Value) -> bool {
    value.as_f64().is_some_and(|number| {
        number >= 0.0 && number.fract().classify() == std::num::FpCategory::Zero
    })
}

fn optional(object: &Map<String, Value>, key: &str, valid: impl FnOnce(&Value) -> bool) -> bool {
    object.get(key).is_none_or(valid)
}

/// Reject known schema constructs outside the subset at this exact position.
/// Unknown extension keys are annotations to preserve, not schemas to traverse.
fn valid_keywords(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    const VALIDATION: &[&str] = &[
        "type",
        "properties",
        "required",
        "default",
        "enum",
        "const",
        "oneOf",
        "anyOf",
        "allOf",
        "not",
        "if",
        "then",
        "else",
        "items",
        "prefixItems",
        "additionalItems",
        "contains",
        "minContains",
        "maxContains",
        "unevaluatedItems",
        "uniqueItems",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minProperties",
        "maxProperties",
        "patternProperties",
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "dependentSchemas",
        "dependentRequired",
        "dependencies",
        "definitions",
        "$defs",
        "$ref",
        "$dynamicRef",
        "$recursiveRef",
        "$schema",
        "$vocabulary",
    ];
    object
        .keys()
        .all(|key| !VALIDATION.contains(&key.as_str()) || allowed.contains(&key.as_str()))
        && ["title", "description", "$comment"]
            .iter()
            .all(|key| optional(object, key, Value::is_string))
}
