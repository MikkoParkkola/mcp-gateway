//! JSON-RPC 2.0 protocol executor
//!
//! Implements [`ProtocolExecutor`] for JSON-RPC 2.0 services — sends
//! `{ jsonrpc: "2.0", id: <uuid>, method: <name>, params: <merged> }`
//! as a POST request to the configured endpoint.
//!
//! This is also the foundation for Google A2A protocol support, which
//! uses JSON-RPC 2.0 as its transport layer.

use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;

use super::CapabilityExecutor;
use super::rest::{ExecutionContext, ProtocolExecutor};
use crate::capability::definition::ProtocolConfig;
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// JSON-RPC 2.0 protocol executor.
///
/// Builds a spec-compliant JSON-RPC 2.0 request from the
/// [`JsonRpcConfig`](crate::capability::JsonRpcConfig) and caller
/// parameters, POSTs to the endpoint, then extracts the `result` field
/// (or propagates JSON-RPC-level errors).
pub struct JsonRpcExecutor<'a> {
    /// Shared reference to the parent executor (owns the HTTP client,
    /// credential stores, etc.)
    pub(super) executor: &'a CapabilityExecutor,
}

impl JsonRpcExecutor<'_> {
    /// Build a JSON-RPC 2.0 request body.
    ///
    /// # Body structure
    ///
    /// ```json
    /// { "jsonrpc": "2.0", "id": "<uuid>", "method": "...", "params": { ... } }
    /// ```
    ///
    /// Default parameters from `config.default_params` are merged with
    /// caller-supplied parameters (caller wins on key collision).
    pub(crate) fn build_request(
        config: &crate::capability::JsonRpcConfig,
        params: &Value,
    ) -> Result<Value> {
        if config.method.is_empty() {
            return Err(Error::Config(
                "JSON-RPC method name not configured".to_string(),
            ));
        }

        // Merge default_params with caller params (caller wins)
        let merged_params = Self::merge_params(&config.default_params, params);

        let id = uuid::Uuid::new_v4().to_string();

        let mut body = serde_json::Map::new();
        body.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
        body.insert("id".to_string(), Value::String(id));
        body.insert("method".to_string(), Value::String(config.method.clone()));
        body.insert("params".to_string(), merged_params);

        Ok(Value::Object(body))
    }

    /// Merge default parameters with caller-supplied parameters.
    ///
    /// If both are objects, defaults serve as base and caller wins on
    /// key collision. If the caller supplies a non-object (e.g. an array
    /// for positional params per JSON-RPC spec), the caller value is
    /// used as-is and defaults are ignored.
    fn merge_params(defaults: &Value, caller: &Value) -> Value {
        match (defaults, caller) {
            // Both objects: merge with caller winning
            (Value::Object(def), Value::Object(cal)) => {
                let mut merged = def.clone();
                for (k, v) in cal {
                    merged.insert(k.clone(), v.clone());
                }
                Value::Object(merged)
            }
            // Caller has an object, defaults are null/empty
            (Value::Null, _) => caller.clone(),
            // Caller is null/empty, use defaults
            (_, Value::Null) => defaults.clone(),
            (_, Value::Object(cal)) if cal.is_empty() => defaults.clone(),
            // Caller is non-object (e.g. positional array) — use as-is
            (_, _) => caller.clone(),
        }
    }

    /// Parse a JSON-RPC 2.0 response.
    ///
    /// A JSON-RPC 2.0 response has one of two shapes:
    ///
    /// Success: `{ "jsonrpc": "2.0", "id": "...", "result": <value> }`
    /// Error:   `{ "jsonrpc": "2.0", "id": "...", "error": { "code": -32600, "message": "...", "data": ... } }`
    ///
    /// If `error` is present, we return an `Error::Protocol` with the
    /// error code and message. Otherwise we return `result`.
    pub(crate) fn parse_response(body: Value) -> Result<Value> {
        // Check for JSON-RPC error
        if let Some(error) = body.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Unknown JSON-RPC error");
            let data_suffix = error
                .get("data")
                .map(|d| format!(" (data: {d})"))
                .unwrap_or_default();

            return Err(Error::Protocol(format!(
                "JSON-RPC error {code}: {message}{data_suffix}"
            )));
        }

        // Extract result (or return the full body if no result field)
        Ok(body.get("result").cloned().unwrap_or(body))
    }
}

#[async_trait]
impl ProtocolExecutor for JsonRpcExecutor<'_> {
    fn protocol_name(&self) -> &'static str {
        "jsonrpc"
    }

    async fn execute(
        &self,
        config: &ProtocolConfig,
        params: Value,
        ctx: &ExecutionContext<'_>,
    ) -> Result<Value> {
        let jsonrpc_config = config.as_jsonrpc().ok_or_else(|| {
            Error::Config(format!(
                "JsonRpcExecutor received non-JSON-RPC config: {}",
                config.protocol_name()
            ))
        })?;

        if jsonrpc_config.endpoint.is_empty() {
            return Err(Error::Config(
                "JSON-RPC endpoint URL not configured".to_string(),
            ));
        }
        validate_url_not_ssrf(&jsonrpc_config.endpoint)?;

        // Build the JSON-RPC 2.0 request body
        let body = Self::build_request(jsonrpc_config, &params)?;

        // Build headers with secret/env substitution
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value_template) in &jsonrpc_config.headers {
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

        // Always set Content-Type for JSON-RPC
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
            .post(&jsonrpc_config.endpoint)
            .headers(headers)
            .json(&body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("JSON-RPC request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Protocol(format!(
                "JSON-RPC endpoint returned {}: {}",
                status,
                error_text.chars().take(500).collect::<String>()
            )));
        }

        let response_body: Value = response
            .json()
            .await
            .map_err(|e| Error::Protocol(format!("Failed to parse JSON-RPC response: {e}")))?;

        Self::parse_response(response_body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::JsonRpcConfig;
    use std::collections::HashMap;

    // ── JsonRpcConfig serde round-trip ──────────────────────────────────

    #[test]
    fn jsonrpc_config_round_trips_through_serde_json() {
        let config = JsonRpcConfig {
            endpoint: "http://localhost:8545".to_string(),
            method: "eth_blockNumber".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert(
                    "Authorization".to_string(),
                    "Bearer {env.RPC_TOKEN}".to_string(),
                );
                h
            },
            default_params: serde_json::json!({"tag": "latest"}),
        };

        let json = serde_json::to_string(&config).unwrap();
        let restored: JsonRpcConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.endpoint, "http://localhost:8545");
        assert_eq!(restored.method, "eth_blockNumber");
        assert_eq!(
            restored.headers.get("Authorization").unwrap(),
            "Bearer {env.RPC_TOKEN}"
        );
        assert_eq!(restored.default_params["tag"], "latest");
    }

    #[test]
    fn jsonrpc_config_round_trips_through_serde_yaml() {
        let config = JsonRpcConfig {
            endpoint: "http://localhost:8080/rpc".to_string(),
            method: "system.listMethods".to_string(),
            headers: HashMap::new(),
            default_params: serde_json::Value::Null,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let restored: JsonRpcConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(restored.endpoint, "http://localhost:8080/rpc");
        assert_eq!(restored.method, "system.listMethods");
    }

    #[test]
    fn jsonrpc_config_defaults_are_sensible() {
        let config: JsonRpcConfig = serde_json::from_str("{}").unwrap();
        assert!(config.endpoint.is_empty());
        assert!(config.method.is_empty());
        assert!(config.headers.is_empty());
        assert!(config.default_params.is_null());
    }

    // ── build_request ──────────────────────────────────────────────────

    #[test]
    fn build_request_produces_valid_jsonrpc_20() {
        let config = JsonRpcConfig {
            method: "eth_blockNumber".to_string(),
            ..Default::default()
        };
        let params = serde_json::json!({});

        let body = JsonRpcExecutor::build_request(&config, &params).unwrap();

        // Must have jsonrpc: "2.0"
        assert_eq!(body["jsonrpc"], "2.0");
        // Must have a non-empty id
        assert!(!body["id"].as_str().unwrap().is_empty());
        // Must have the method name
        assert_eq!(body["method"], "eth_blockNumber");
        // Must have a params field
        assert!(body.get("params").is_some());
    }

    #[test]
    fn build_request_id_is_valid_uuid() {
        let config = JsonRpcConfig {
            method: "test".to_string(),
            ..Default::default()
        };
        let body = JsonRpcExecutor::build_request(&config, &serde_json::json!({})).unwrap();
        let id = body["id"].as_str().unwrap();
        assert!(
            uuid::Uuid::parse_str(id).is_ok(),
            "id must be a valid UUID: {id}"
        );
    }

    #[test]
    fn build_request_merges_default_params_with_caller() {
        let config = JsonRpcConfig {
            method: "eth_call".to_string(),
            default_params: serde_json::json!({"tag": "latest", "verbose": false}),
            ..Default::default()
        };
        let params = serde_json::json!({"tag": "pending", "extra": 42});

        let body = JsonRpcExecutor::build_request(&config, &params).unwrap();
        let result_params = &body["params"];

        // Caller wins on collision
        assert_eq!(result_params["tag"], "pending");
        // Default preserved
        assert_eq!(result_params["verbose"], false);
        // Caller addition
        assert_eq!(result_params["extra"], 42);
    }

    #[test]
    fn build_request_uses_defaults_when_caller_params_null() {
        let config = JsonRpcConfig {
            method: "test".to_string(),
            default_params: serde_json::json!({"key": "value"}),
            ..Default::default()
        };

        let body = JsonRpcExecutor::build_request(&config, &serde_json::Value::Null).unwrap();
        assert_eq!(body["params"]["key"], "value");
    }

    #[test]
    fn build_request_positional_array_params_override_defaults() {
        // JSON-RPC allows params as a positional array
        let config = JsonRpcConfig {
            method: "test".to_string(),
            default_params: serde_json::json!({"key": "value"}),
            ..Default::default()
        };
        let params = serde_json::json!(["arg1", "arg2"]);

        let body = JsonRpcExecutor::build_request(&config, &params).unwrap();
        let result_params = &body["params"];
        assert!(result_params.is_array());
        assert_eq!(result_params[0], "arg1");
    }

    #[test]
    fn build_request_empty_method_returns_error() {
        let config = JsonRpcConfig::default();
        let err = JsonRpcExecutor::build_request(&config, &serde_json::json!({})).unwrap_err();
        assert!(
            err.to_string().contains("method name not configured"),
            "{err}"
        );
    }

    // ── parse_response ─────────────────────────────────────────────────

    #[test]
    fn parse_response_extracts_result() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"block": 12345}
        });

        let result = JsonRpcExecutor::parse_response(response).unwrap();
        assert_eq!(result["block"], 12345);
    }

    #[test]
    fn parse_response_result_can_be_scalar() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "result": "0x4b7"
        });

        let result = JsonRpcExecutor::parse_response(response).unwrap();
        assert_eq!(result, "0x4b7");
    }

    #[test]
    fn parse_response_error_with_code_and_message() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        });

        let err = JsonRpcExecutor::parse_response(response).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("JSON-RPC error"), "{msg}");
        assert!(msg.contains("-32601"), "{msg}");
        assert!(msg.contains("Method not found"), "{msg}");
    }

    #[test]
    fn parse_response_error_with_data_field() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "error": {
                "code": -32000,
                "message": "Server error",
                "data": "stack trace here"
            }
        });

        let err = JsonRpcExecutor::parse_response(response).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("-32000"), "{msg}");
        assert!(msg.contains("Server error"), "{msg}");
        assert!(msg.contains("stack trace here"), "{msg}");
    }

    #[test]
    fn parse_response_no_result_field_returns_full_body() {
        // Non-standard response without explicit result field
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "custom_field": "value"
        });

        let result = JsonRpcExecutor::parse_response(response.clone()).unwrap();
        assert_eq!(result, response);
    }

    // ── ProtocolConfig integration ─────────────────────────────────────

    #[test]
    fn protocol_config_jsonrpc_protocol_name() {
        let config = ProtocolConfig::Jsonrpc(JsonRpcConfig::default());
        assert_eq!(config.protocol_name(), "jsonrpc");
    }

    #[test]
    fn protocol_config_as_jsonrpc_returns_some_for_jsonrpc_variant() {
        let config = ProtocolConfig::Jsonrpc(JsonRpcConfig {
            endpoint: "http://localhost:8545".to_string(),
            ..Default::default()
        });
        assert!(config.as_jsonrpc().is_some());
        assert!(config.as_rest().is_none());
        assert!(config.as_graphql().is_none());
    }

    #[test]
    fn protocol_config_as_jsonrpc_returns_none_for_rest_variant() {
        let config = ProtocolConfig::Rest(Box::default());
        assert!(config.as_jsonrpc().is_none());
    }

    #[test]
    fn service_jsonrpc_maps_to_protocol_config_jsonrpc() {
        use crate::capability::definition::{ProviderConfig, RestConfig};

        let provider = ProviderConfig {
            service: "jsonrpc".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                endpoint: "http://localhost:8545".to_string(),
                method: "eth_blockNumber".to_string(),
                static_params: {
                    let mut m = HashMap::new();
                    m.insert("tag".to_string(), serde_json::json!("latest"));
                    m
                },
                ..Default::default()
            },
        };

        let proto = provider.protocol_config();
        assert_eq!(proto.protocol_name(), "jsonrpc");
        let jrpc = proto.as_jsonrpc().unwrap();
        assert_eq!(jrpc.endpoint, "http://localhost:8545");
        assert_eq!(jrpc.method, "eth_blockNumber");
        assert_eq!(jrpc.default_params["tag"], "latest");
    }

    #[test]
    fn service_jsonrpc_uses_base_url_plus_path_when_no_endpoint() {
        use crate::capability::definition::{ProviderConfig, RestConfig};

        let provider = ProviderConfig {
            service: "jsonrpc".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                base_url: "http://localhost:8080".to_string(),
                path: "/rpc".to_string(),
                method: "system.listMethods".to_string(),
                ..Default::default()
            },
        };

        let proto = provider.protocol_config();
        let jrpc = proto.as_jsonrpc().unwrap();
        assert_eq!(jrpc.endpoint, "http://localhost:8080/rpc");
        assert_eq!(jrpc.method, "system.listMethods");
    }
}
