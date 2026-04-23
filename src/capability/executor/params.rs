//! Parameter substitution, response extraction, and cache-key helpers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Response;
use serde_json::Value;

use crate::{Error, Result};

use super::xml::xml_to_json;
use super::{super::RestConfig, CapabilityExecutor};

impl CapabilityExecutor {
    /// Handle an API response.
    ///
    /// Supports JSON (default) and XML response formats.  The format is
    /// determined by the `response_format` field in `RestConfig`, falling
    /// back to auto-detection from the `Content-Type` response header.
    pub(super) async fn handle_response(
        &self,
        response: Response,
        config: &RestConfig,
    ) -> Result<Value> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Protocol(format!(
                "API returned {}: {}",
                status,
                // Truncate error to avoid leaking sensitive data
                error_text.chars().take(500).collect::<String>()
            )));
        }

        let response_format = config.response_format.to_ascii_lowercase();
        if response_format == "binary" {
            let mime_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let bytes = response
                .bytes()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to read binary response: {e}")))?;
            return Ok(serde_json::json!({
                "data": STANDARD.encode(&bytes),
                "mime_type": mime_type,
                "size": bytes.len(),
            }));
        }

        let is_xml = detect_xml_format(response.headers(), &response_format);

        let body: Value = if is_xml {
            let text = response
                .text()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to read XML response: {e}")))?;
            xml_to_json(&text)
                .map_err(|e| Error::Protocol(format!("Failed to parse XML response: {e}")))?
        } else {
            response
                .json()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to parse response: {e}")))?
        };

        if let Some(ref path) = config.response_path {
            self.extract_path(&body, path)
        } else {
            Ok(body)
        }
    }

    /// Extract a value at a dot-separated path from a JSON response.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(super) fn extract_path(&self, value: &Value, path: &str) -> Result<Value> {
        let mut current = value;

        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }

            current = match current {
                Value::Object(map) => map.get(segment).unwrap_or(&Value::Null),
                Value::Array(arr) => {
                    if let Ok(index) = segment.parse::<usize>() {
                        arr.get(index).unwrap_or(&Value::Null)
                    } else {
                        &Value::Null
                    }
                }
                _ => &Value::Null,
            };
        }

        Ok(current.clone())
    }

    /// Substitute `{param}` references in a string template.
    ///
    /// After placeholder substitution, `{keychain.X}` and `{env.VAR}` secrets
    /// are resolved via [`SecretResolver`](crate::secrets::SecretResolver).
    pub(super) fn substitute_string(&self, template: &str, params: &Value) -> Result<String> {
        let mut result = template.to_string();

        if let Value::Object(map) = params {
            for (key, value) in map {
                let placeholder = format!("{{{key}}}");
                if result.contains(&placeholder) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => String::new(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    result = result.replace(&placeholder, &value_str);
                }
            }
        }

        result = self.secret_resolver.resolve(&result)?;
        Ok(result)
    }

    /// Resolve a map of string templates to `(key, value)` query-param pairs.
    ///
    /// Empty, `"null"`, and still-unresolved `{placeholder}` values are
    /// filtered out to avoid sending empty parameters to APIs.
    pub(super) fn substitute_params(
        &self,
        template: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        for (key, value_template) in template {
            let value = self.substitute_string(value_template, params)?;
            // Skip empty values and unresolved {placeholder} templates
            if !value.is_empty() && value != "null" && !value.starts_with('{') {
                result.push((key.clone(), value));
            }
        }

        Ok(result)
    }

    /// Map input parameters to API parameters using `param_map`.
    ///
    /// For example, `param_map: { query: q }` maps the caller's `"query"` key
    /// to the API's `"q"` query parameter.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(super) fn map_params(
        &self,
        param_map: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        if let Value::Object(map) = params {
            for (input_name, api_name) in param_map {
                if let Some(value) = map.get(input_name) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => continue, // Skip null values
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    if !value_str.is_empty() {
                        result.push((api_name.clone(), value_str));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Substitute parameters recursively throughout a JSON value template.
    ///
    /// A pure placeholder string like `"{priority}"` is replaced by the
    /// original typed value (integer, boolean, etc.) rather than its string
    /// representation. Null and unresolved placeholders are dropped from
    /// object fields.
    pub(super) fn substitute_value(&self, template: &Value, params: &Value) -> Result<Value> {
        match template {
            Value::String(s) => self.substitute_string_value(s, params),
            Value::Object(map) => self.substitute_object_value(map, params),
            Value::Array(arr) => {
                let result: Result<Vec<Value>> = arr
                    .iter()
                    .map(|v| self.substitute_value(v, params))
                    .collect();
                Ok(Value::Array(result?))
            }
            _ => Ok(template.clone()),
        }
    }

    /// Build a cache key for a capability + params combination.
    #[allow(clippy::unused_self)]
    pub(super) fn build_cache_key(
        &self,
        capability: &super::super::CapabilityDefinition,
        params: &Value,
    ) -> String {
        let params_hash = {
            use sha2::{Digest, Sha256};
            let json = serde_json::to_string(params).unwrap_or_default();
            let digest = Sha256::digest(json.as_bytes());
            // Use first 16 bytes (128 bits) — sufficient for a cache key.
            hex::encode(&digest[..16])
        };
        format!("{}:{}", capability.name, params_hash)
    }

    // ── Private decomposition helpers ─────────────────────────────────────────

    fn substitute_string_value(&self, s: &str, params: &Value) -> Result<Value> {
        let trimmed = s.trim();
        // Pure placeholder like "{priority}" → preserve original typed value
        if is_pure_placeholder(trimmed) {
            let key = &trimmed[1..trimmed.len() - 1];
            if let Some(value) = params.as_object().and_then(|m| m.get(key)) {
                return Ok(if value.is_null() {
                    Value::Null
                } else {
                    value.clone()
                });
            }
        }

        let substituted = self.substitute_string(s, params)?;
        // Try to re-parse if the result looks like JSON
        if (substituted.starts_with('{') && substituted.ends_with('}'))
            || (substituted.starts_with('[') && substituted.ends_with(']'))
        {
            Ok(serde_json::from_str(&substituted).unwrap_or(Value::String(substituted)))
        } else {
            Ok(Value::String(substituted))
        }
    }

    fn substitute_object_value(
        &self,
        map: &serde_json::Map<String, Value>,
        params: &Value,
    ) -> Result<Value> {
        let mut result = serde_json::Map::new();
        for (k, v) in map {
            let substituted = self.substitute_value(v, params)?;
            // Skip null values and unresolved placeholders
            if substituted.is_null() {
                continue;
            }
            if let Value::String(ref s) = substituted
                && is_unresolved_placeholder(s)
            {
                continue;
            }
            result.insert(k.clone(), substituted);
        }
        Ok(Value::Object(result))
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

/// Returns `true` when `s` is a single `{key}` placeholder (not a secret ref).
fn is_pure_placeholder(s: &str) -> bool {
    s.starts_with('{')
        && s.ends_with('}')
        && !s.contains(' ')
        && s.matches('{').count() == 1
        && !s.starts_with("{env.")
        && !s.starts_with("{keychain.")
}

/// Returns `true` when a substituted string is still an unresolved placeholder.
fn is_unresolved_placeholder(s: &str) -> bool {
    s.starts_with('{') && s.ends_with('}') && !s.contains(' ')
}

/// Determine whether the response should be parsed as XML.
///
/// Priority: explicit `response_format` field > `Content-Type` header.
fn detect_xml_format(headers: &reqwest::header::HeaderMap, response_format: &str) -> bool {
    if response_format.eq_ignore_ascii_case("xml") {
        true
    } else if response_format.is_empty() {
        headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("xml"))
    } else {
        false
    }
}
