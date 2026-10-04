// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Protocol configurations: REST, GraphQL and JSON-RPC.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// REST API configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestConfig {
    /// Base URL for the API
    #[serde(default)]
    pub base_url: String,

    /// Path template (supports {param} substitution).
    ///
    /// When [`Self::path_selector`] is configured, this may repeat the
    /// selector's default path as a compatibility fallback for older gateway
    /// binaries that do not understand `path_selector`.
    #[serde(default)]
    pub path: String,

    /// Select one of several path templates from a caller parameter.
    ///
    /// This is a safe, declarative alternative to executable request-transform
    /// snippets for APIs whose route shape changes with an enum-like input.
    /// The selected template receives the same `{param}` substitution as
    /// [`Self::path`]. When the selector parameter is absent, `default` is
    /// used; unknown values fail closed instead of becoming URL fragments.
    /// `path`, when also present, must exactly match the selected default path
    /// and is retained only as a rolling-upgrade fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_selector: Option<PathSelectorConfig>,

    /// Full endpoint URL (alternative to `base_url` + path)
    /// Takes precedence if set
    #[serde(default)]
    pub endpoint: String,

    /// HTTP method
    #[serde(default = "default_method")]
    pub method: String,

    /// Headers to send (supports {param} and {env.VAR} substitution)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Query parameters (supports substitution)
    #[serde(default)]
    pub params: HashMap<String, String>,

    /// Parameter name mapping (e.g., query -> q for search APIs)
    #[serde(default)]
    pub param_map: HashMap<String, String>,

    /// Static parameters merged into every request.
    ///
    /// These are fixed values baked into the capability definition — they do
    /// not need to be supplied by the caller.  User-provided parameters with
    /// the same key always take precedence, so callers can still override a
    /// static default when needed.
    ///
    /// Static params participate in the same substitution pipeline as
    /// dynamic params: they flow into URL path templates, query strings,
    /// request bodies, and header values exactly like caller-supplied params.
    ///
    /// # Example (YAML)
    ///
    /// ```yaml
    /// config:
    ///   base_url: https://api.open-meteo.com
    ///   path: /v1/forecast
    ///   static_params:
    ///     current: "temperature_2m,precipitation,weather_code"
    ///     timezone: "auto"
    /// ```
    #[serde(default)]
    pub static_params: HashMap<String, serde_json::Value>,

    /// Request body template (for POST/PUT)
    #[serde(default)]
    pub body: Option<serde_json::Value>,

    /// Response transformation (jq-like path)
    #[serde(default)]
    pub response_path: Option<String>,

    /// Expected response format: "json" (default) or "xml".
    ///
    /// When set to "xml", the executor parses the response body as XML and
    /// converts it to a JSON object before applying `response_path`.
    /// When empty or "json", the response is parsed as JSON (the default).
    ///
    /// Auto-detection: if this field is empty the executor also checks the
    /// `Content-Type` response header — if it contains `xml`, the response
    /// is treated as XML automatically.
    #[serde(default)]
    pub response_format: String,

    /// Write a base64 field of the response to the configured downloads
    /// directory instead of returning it (MIK-7782, ATTACH.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_file: Option<crate::capability::executor::SaveFileSpec>,

    /// Override the `Content-Type` header for the request body.
    ///
    /// When empty (the default) POST/PUT/PATCH bodies are sent as
    /// `application/json`.  Set to `"text/plain"` to send a raw string body
    /// (useful for databases like `SurrealDB` whose `/sql` endpoint requires
    /// `text/plain`).  The `body` template value must be a JSON string
    /// (`"SELECT ..."`) — it is serialised without the outer quotes before
    /// sending.
    ///
    /// # Example (YAML)
    ///
    /// ```yaml
    /// config:
    ///   base_url: http://127.0.0.1:8000
    ///   path: /sql
    ///   method: POST
    ///   body_content_type: "text/plain"
    ///   body: "SELECT * FROM bus_msg WHERE topic = '{topic}' LIMIT {max_msg}"
    /// ```
    #[serde(default)]
    pub body_content_type: String,
}

/// Declarative selection of a REST path template from an input parameter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathSelectorConfig {
    /// Input property whose string value selects a path.
    #[serde(default)]
    pub parameter: String,

    /// Selector value to use when the caller omits `parameter`.
    #[serde(default)]
    pub default: String,

    /// Selector value to path-template mapping.
    #[serde(default)]
    pub paths: HashMap<String, String>,
}

impl RestConfig {
    /// Get the effective base URL (from endpoint or `base_url`)
    #[must_use]
    pub fn effective_base_url(&self) -> &str {
        if self.endpoint.is_empty() {
            &self.base_url
        } else {
            // Extract base from endpoint (everything before the path)
            &self.endpoint
        }
    }

    /// Check if this uses endpoint style (full URL with path params)
    #[must_use]
    pub fn uses_endpoint(&self) -> bool {
        !self.endpoint.is_empty()
    }

    /// Merge `static_params` with caller-supplied `params`, returning an
    /// effective parameter object where **caller values take precedence**.
    ///
    /// If `static_params` is empty the original `params` value is returned
    /// unchanged (zero allocation in the common case).
    ///
    /// # Merge semantics
    ///
    /// ```text
    /// effective = static_params ∪ caller_params   (caller wins on collision)
    /// ```
    #[must_use]
    pub fn merge_with_static_params<'a>(
        &'a self,
        caller_params: &'a serde_json::Value,
    ) -> std::borrow::Cow<'a, serde_json::Value> {
        if self.static_params.is_empty() {
            return std::borrow::Cow::Borrowed(caller_params);
        }

        // Start with static params as base, then overlay caller params on top.
        let mut merged = serde_json::Map::with_capacity(
            self.static_params.len() + caller_params.as_object().map_or(0, serde_json::Map::len),
        );

        for (k, v) in &self.static_params {
            merged.insert(k.clone(), v.clone());
        }

        if let Some(caller_obj) = caller_params.as_object() {
            for (k, v) in caller_obj {
                merged.insert(k.clone(), v.clone());
            }
        }

        std::borrow::Cow::Owned(serde_json::Value::Object(merged))
    }
}

fn default_method() -> String {
    "GET".to_string()
}

/// GraphQL API configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphqlConfig {
    /// GraphQL endpoint URL (e.g. `https://api.github.com/graphql`)
    #[serde(default)]
    pub endpoint: String,

    /// HTTP headers to send (supports `{env.VAR}` substitution for auth)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Default query template.
    ///
    /// Supports `{param}` substitution — caller-supplied parameters replace
    /// matching placeholders in the query string before it is sent.
    #[serde(default)]
    pub query: Option<String>,

    /// Default GraphQL variables.
    ///
    /// These are merged with caller-supplied variables (caller wins on key
    /// collision) and sent in the `variables` field of the JSON body.
    #[serde(default)]
    pub variables: HashMap<String, serde_json::Value>,

    /// Response path for extracting a nested field from the GraphQL `data`
    /// response (dot-separated, e.g. `"data.viewer"`).
    #[serde(default)]
    pub response_path: Option<String>,
}

/// JSON-RPC 2.0 API configuration
///
/// Defines how to call a JSON-RPC 2.0 service: the endpoint URL, the
/// method name, optional default parameters, and HTTP headers.
///
/// Note: `GraphqlConfig` uses `#[derive(Default)]` on the struct definition.
///
/// At execution time the executor builds a spec-compliant request:
///
/// ```json
/// { "jsonrpc": "2.0", "id": "<uuid>", "method": "<method>", "params": <merged> }
/// ```
///
/// Default parameters from `default_params` are merged with caller-supplied
/// parameters (caller wins on key collision), mirroring the merge semantics
/// used by `RestConfig::static_params` and `GraphqlConfig::variables`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonRpcConfig {
    /// JSON-RPC endpoint URL (e.g. `http://localhost:8545`)
    #[serde(default)]
    pub endpoint: String,

    /// JSON-RPC method name (e.g. `eth_blockNumber`, `system.listMethods`)
    #[serde(default)]
    pub method: String,

    /// HTTP headers to send (supports `{env.VAR}` substitution for auth)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Default parameters merged with caller-supplied params.
    ///
    /// Caller-supplied keys always win on collision. This is analogous to
    /// `RestConfig::static_params` / `GraphqlConfig::variables`.
    #[serde(default)]
    pub default_params: serde_json::Value,
}

// Note: JsonRpcConfig and GraphqlConfig both use #[derive(Default)]
// on their struct definitions above, so no manual impl is needed.

/// Protocol-specific configuration, derived from `ProviderConfig.service` + `config`.
///
/// This enum is the extension point for future protocol adapters.
///
/// `ProtocolConfig` is NOT deserialized from YAML directly — it is produced
/// by [`ProviderConfig::protocol_config()`] to preserve backward
/// compatibility with existing capability definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolConfig {
    /// REST/HTTP protocol (the original and default).
    ///
    /// Boxed to reduce the size difference between enum variants (clippy
    /// `large_enum_variant`).  `RestConfig` is the largest variant because it
    /// carries many optional fields; boxing keeps the enum itself small.
    Rest(Box<RestConfig>),
    /// GraphQL protocol — sends `{ query, variables }` as a POST.
    Graphql(GraphqlConfig),
    /// JSON-RPC 2.0 protocol — sends `{ jsonrpc, id, method, params }` as a POST.
    Jsonrpc(JsonRpcConfig),
    // Future variants:
    // Grpc(GrpcConfig),
    // Cli(CliConfig),
    // Wasm(WasmConfig),
}

impl ProtocolConfig {
    /// Returns the protocol name for logging and dispatch.
    #[must_use]
    pub fn protocol_name(&self) -> &'static str {
        match self {
            ProtocolConfig::Rest(_) => "rest",
            ProtocolConfig::Graphql(_) => "graphql",
            ProtocolConfig::Jsonrpc(_) => "jsonrpc",
        }
    }

    /// Extract the inner `RestConfig`, if this is a REST protocol.
    #[must_use]
    pub fn as_rest(&self) -> Option<&RestConfig> {
        match self {
            ProtocolConfig::Rest(c) => Some(c.as_ref()),
            _ => None,
        }
    }

    /// Extract the inner `GraphqlConfig`, if this is a GraphQL protocol.
    #[must_use]
    pub fn as_graphql(&self) -> Option<&GraphqlConfig> {
        match self {
            ProtocolConfig::Graphql(c) => Some(c),
            _ => None,
        }
    }

    /// Extract the inner `JsonRpcConfig`, if this is a JSON-RPC protocol.
    #[must_use]
    pub fn as_jsonrpc(&self) -> Option<&JsonRpcConfig> {
        match self {
            ProtocolConfig::Jsonrpc(c) => Some(c),
            _ => None,
        }
    }
}
