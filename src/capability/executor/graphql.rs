//! GraphQL protocol executor
//!
//! Implements [`ProtocolExecutor`] for GraphQL APIs — sends a
//! `{ query, variables }` JSON body as a POST request to the configured
//! endpoint.

use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;

use super::CapabilityExecutor;
use super::rest::{ExecutionContext, ProtocolExecutor};
use crate::capability::definition::ProtocolConfig;
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// GraphQL protocol executor.
///
/// Builds the canonical `{ "query": "...", "variables": {...} }` body from
/// the [`GraphqlConfig`](crate::capability::GraphqlConfig) and caller
/// parameters, POSTs to the endpoint, then extracts the `data` field
/// (or propagates GraphQL-level errors).
pub struct GraphqlExecutor<'a> {
    /// Shared reference to the parent executor (owns the HTTP client,
    /// credential stores, etc.)
    pub(super) executor: &'a CapabilityExecutor,
}

impl GraphqlExecutor<'_> {
    /// Build the JSON body for a GraphQL request.
    ///
    /// # Body structure
    ///
    /// ```json
    /// { "query": "...", "variables": { ... } }
    /// ```
    ///
    /// The `query` comes from:
    /// 1. `params.query` (caller override), or
    /// 2. `config.query` (default from capability definition)
    ///
    /// Variables are merged: `config.variables` as base, then
    /// `params.variables` (or all remaining params) overlaid on top.
    pub(crate) fn build_body(
        config: &crate::capability::GraphqlConfig,
        params: &Value,
    ) -> Result<Value> {
        let params_obj = params.as_object();

        // 1. Resolve query string
        let query = params_obj
            .and_then(|m| m.get("query"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| config.query.clone())
            .ok_or_else(|| {
                Error::Config(
                    "GraphQL query not provided: set 'query' in config or pass as parameter"
                        .to_string(),
                )
            })?;

        // Substitute {param} placeholders in the query template
        let query = if let Some(obj) = params_obj {
            let mut q = query;
            for (key, value) in obj {
                if key == "query" || key == "variables" {
                    continue;
                }
                let placeholder = format!("{{{key}}}");
                if q.contains(&placeholder) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    q = q.replace(&placeholder, &value_str);
                }
            }
            q
        } else {
            query
        };

        // 2. Merge variables: config defaults + caller overrides
        let mut variables = serde_json::Map::new();

        // Base: config.variables
        for (k, v) in &config.variables {
            variables.insert(k.clone(), v.clone());
        }

        // Overlay: caller-supplied variables
        if let Some(caller_vars) = params_obj
            .and_then(|m| m.get("variables"))
            .and_then(Value::as_object)
        {
            for (k, v) in caller_vars {
                variables.insert(k.clone(), v.clone());
            }
        }

        let mut body = serde_json::Map::new();
        body.insert("query".to_string(), Value::String(query));
        if !variables.is_empty() {
            body.insert("variables".to_string(), Value::Object(variables));
        }

        Ok(Value::Object(body))
    }

    /// Parse a GraphQL response, checking for errors.
    ///
    /// A GraphQL response always has the shape:
    /// ```json
    /// { "data": { ... }, "errors": [ ... ] }
    /// ```
    ///
    /// If `errors` is present and non-empty, we return an error containing
    /// the first error message. Otherwise we return `data`.
    fn parse_response(body: Value, response_path: Option<&str>) -> Result<Value> {
        // Check for GraphQL-level errors
        if let Some(errors) = body.get("errors").and_then(Value::as_array)
            && !errors.is_empty()
        {
            let messages: Vec<&str> = errors
                .iter()
                .filter_map(|e| e.get("message").and_then(Value::as_str))
                .collect();
            let combined = if messages.is_empty() {
                serde_json::to_string(errors).unwrap_or_else(|_| "Unknown GraphQL error".into())
            } else {
                messages.join("; ")
            };
            return Err(Error::Protocol(format!("GraphQL error: {combined}")));
        }

        // Extract data (or return full response if no data field)
        let result = body.get("data").cloned().unwrap_or(body);

        // Apply response_path extraction if configured
        if let Some(path) = response_path {
            Ok(extract_path(&result, path))
        } else {
            Ok(result)
        }
    }
}

/// Extract a value at a dot-separated path from a JSON value.
fn extract_path(value: &Value, path: &str) -> Value {
    let mut current = value;

    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }

        // Skip the "data" prefix since we already unwrapped it
        if segment == "data" && std::ptr::eq(current, value) {
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

    current.clone()
}

#[async_trait]
impl ProtocolExecutor for GraphqlExecutor<'_> {
    fn protocol_name(&self) -> &'static str {
        "graphql"
    }

    async fn execute(
        &self,
        config: &ProtocolConfig,
        params: Value,
        ctx: &ExecutionContext<'_>,
    ) -> Result<Value> {
        let graphql_config = config.as_graphql().ok_or_else(|| {
            Error::Config(format!(
                "GraphqlExecutor received non-GraphQL config: {}",
                config.protocol_name()
            ))
        })?;

        if graphql_config.endpoint.is_empty() {
            return Err(Error::Config(
                "GraphQL endpoint URL not configured".to_string(),
            ));
        }
        validate_url_not_ssrf(&graphql_config.endpoint)?;

        // Build the { query, variables } body
        let body = Self::build_body(graphql_config, &params)?;

        // Build headers with secret/env substitution
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value_template) in &graphql_config.headers {
            let value = self.executor.substitute_string(value_template, &params)?;
            if let Ok(header_name) = name.parse::<reqwest::header::HeaderName>()
                && let Ok(header_value) = value.parse::<reqwest::header::HeaderValue>()
            {
                headers.insert(header_name, header_value);
            }
        }

        // Inject auth if configured on the capability
        if ctx.capability.auth.required && ctx.capability.auth.param.is_none() {
            self.executor
                .inject_auth(&mut headers, &ctx.capability.auth)
                .await?;
        }

        // Always set Content-Type for GraphQL
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .expect("static content-type is valid"),
        );

        let timeout = Duration::from_secs(ctx.timeout_secs);
        let response = self
            .executor
            .client
            .post(&graphql_config.endpoint)
            .headers(headers)
            .json(&body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("GraphQL request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Protocol(format!(
                "GraphQL endpoint returned {}: {}",
                status,
                error_text.chars().take(500).collect::<String>()
            )));
        }

        let response_body: Value = response
            .json()
            .await
            .map_err(|e| Error::Protocol(format!("Failed to parse GraphQL response: {e}")))?;

        Self::parse_response(response_body, graphql_config.response_path.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::GraphqlConfig;
    use std::collections::HashMap;

    // ── GraphqlConfig serde round-trip ───────────────────────────────────

    #[test]
    fn graphql_config_round_trips_through_serde_json() {
        let config = GraphqlConfig {
            endpoint: "https://api.github.com/graphql".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert(
                    "Authorization".to_string(),
                    "Bearer {env.GITHUB_TOKEN}".to_string(),
                );
                h
            },
            query: Some("query { viewer { login } }".to_string()),
            variables: {
                let mut v = HashMap::new();
                v.insert("first".to_string(), serde_json::json!(5));
                v
            },
            response_path: Some("data.viewer".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let restored: GraphqlConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.endpoint, "https://api.github.com/graphql");
        assert_eq!(
            restored.headers.get("Authorization").unwrap(),
            "Bearer {env.GITHUB_TOKEN}"
        );
        assert_eq!(
            restored.query.as_deref(),
            Some("query { viewer { login } }")
        );
        assert_eq!(restored.variables.get("first"), Some(&serde_json::json!(5)));
        assert_eq!(restored.response_path.as_deref(), Some("data.viewer"));
    }

    #[test]
    fn graphql_config_round_trips_through_serde_yaml() {
        let config = GraphqlConfig {
            endpoint: "https://api.example.com/graphql".to_string(),
            headers: HashMap::new(),
            query: Some("{ users { id name } }".to_string()),
            variables: HashMap::new(),
            response_path: None,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let restored: GraphqlConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(restored.endpoint, "https://api.example.com/graphql");
        assert_eq!(restored.query.as_deref(), Some("{ users { id name } }"));
    }

    #[test]
    fn graphql_config_defaults_are_sensible() {
        let config: GraphqlConfig = serde_json::from_str("{}").unwrap();
        assert!(config.endpoint.is_empty());
        assert!(config.headers.is_empty());
        assert!(config.query.is_none());
        assert!(config.variables.is_empty());
        assert!(config.response_path.is_none());
    }

    // ── build_body ──────────────────────────────────────────────────────

    #[test]
    fn build_body_uses_config_query_when_no_param_query() {
        let config = GraphqlConfig {
            query: Some("query { viewer { login } }".to_string()),
            ..Default::default()
        };
        let params = serde_json::json!({});

        let body = GraphqlExecutor::build_body(&config, &params).unwrap();
        assert_eq!(body["query"], "query { viewer { login } }");
    }

    #[test]
    fn build_body_caller_query_overrides_config() {
        let config = GraphqlConfig {
            query: Some("query { default }".to_string()),
            ..Default::default()
        };
        let params = serde_json::json!({
            "query": "query { override }"
        });

        let body = GraphqlExecutor::build_body(&config, &params).unwrap();
        assert_eq!(body["query"], "query { override }");
    }

    #[test]
    fn build_body_merges_variables_caller_wins() {
        let config = GraphqlConfig {
            query: Some("query($first: Int) { repos(first: $first) { name } }".to_string()),
            variables: {
                let mut v = HashMap::new();
                v.insert("first".to_string(), serde_json::json!(5));
                v.insert("owner".to_string(), serde_json::json!("default-owner"));
                v
            },
            ..Default::default()
        };
        let params = serde_json::json!({
            "variables": {
                "first": 10,
                "extra": "new"
            }
        });

        let body = GraphqlExecutor::build_body(&config, &params).unwrap();
        assert_eq!(body["variables"]["first"], 10); // caller wins
        assert_eq!(body["variables"]["owner"], "default-owner"); // config preserved
        assert_eq!(body["variables"]["extra"], "new"); // caller addition
    }

    #[test]
    fn build_body_substitutes_placeholders_in_query() {
        let config = GraphqlConfig {
            query: Some("query { user(login: \"{username}\") { name } }".to_string()),
            ..Default::default()
        };
        let params = serde_json::json!({
            "username": "octocat"
        });

        let body = GraphqlExecutor::build_body(&config, &params).unwrap();
        let query = body["query"].as_str().unwrap();
        assert!(
            query.contains("octocat"),
            "placeholder should be substituted"
        );
        assert!(!query.contains("{username}"), "placeholder should be gone");
    }

    #[test]
    fn build_body_omits_variables_when_empty() {
        let config = GraphqlConfig {
            query: Some("{ viewer { login } }".to_string()),
            ..Default::default()
        };
        let params = serde_json::json!({});

        let body = GraphqlExecutor::build_body(&config, &params).unwrap();
        assert!(body.get("variables").is_none());
    }

    #[test]
    fn build_body_no_query_returns_error() {
        let config = GraphqlConfig::default();
        let params = serde_json::json!({});

        let err = GraphqlExecutor::build_body(&config, &params).unwrap_err();
        assert!(err.to_string().contains("query not provided"), "{err}");
    }

    // ── parse_response ──────────────────────────────────────────────────

    #[test]
    fn parse_response_extracts_data() {
        let response = serde_json::json!({
            "data": {
                "viewer": { "login": "octocat" }
            }
        });

        let result = GraphqlExecutor::parse_response(response, None).unwrap();
        assert_eq!(result["viewer"]["login"], "octocat");
    }

    #[test]
    fn parse_response_with_path_extracts_nested() {
        let response = serde_json::json!({
            "data": {
                "viewer": {
                    "login": "octocat",
                    "repositories": { "totalCount": 42 }
                }
            }
        });

        let result =
            GraphqlExecutor::parse_response(response, Some("viewer.repositories")).unwrap();
        assert_eq!(result["totalCount"], 42);
    }

    #[test]
    fn parse_response_graphql_errors_returned_as_error() {
        let response = serde_json::json!({
            "data": null,
            "errors": [
                { "message": "Field 'foo' not found" },
                { "message": "Syntax error" }
            ]
        });

        let err = GraphqlExecutor::parse_response(response, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("GraphQL error"), "{msg}");
        assert!(msg.contains("Field 'foo' not found"), "{msg}");
        assert!(msg.contains("Syntax error"), "{msg}");
    }

    #[test]
    fn parse_response_empty_errors_array_is_success() {
        let response = serde_json::json!({
            "data": { "viewer": { "login": "ok" } },
            "errors": []
        });

        let result = GraphqlExecutor::parse_response(response, None).unwrap();
        assert_eq!(result["viewer"]["login"], "ok");
    }

    #[test]
    fn parse_response_no_data_field_returns_full_body() {
        // Some GraphQL servers return non-standard shapes for introspection
        let response = serde_json::json!({
            "__schema": { "types": [] }
        });

        let result = GraphqlExecutor::parse_response(response.clone(), None).unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn parse_response_data_path_skips_data_prefix() {
        let response = serde_json::json!({
            "data": {
                "viewer": { "login": "test" }
            }
        });

        // Path "data.viewer" should skip the "data" prefix since we already unwrap it
        let result = GraphqlExecutor::parse_response(response, Some("data.viewer")).unwrap();
        assert_eq!(result["login"], "test");
    }
}
