//! Capability definition types
//!
//! These types map directly to the YAML capability definition format.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

use crate::transform::TransformConfig;

/// A capability definition describing how to call a REST API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    /// Capability format version
    #[serde(default = "default_version")]
    pub fulcrum: String,

    /// Unique capability name (used as MCP tool name)
    #[serde(default)]
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// Input/output schema
    #[serde(default)]
    pub schema: SchemaDefinition,

    /// Provider configurations
    #[serde(deserialize_with = "deserialize_providers")]
    pub providers: ProvidersConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Caching configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// Metadata for categorization and discovery
    #[serde(default)]
    pub metadata: CapabilityMetadata,

    /// Response transform pipeline configuration (applied by the executor).
    #[serde(default)]
    pub transform: TransformConfig,

    /// Response transform applied by `gateway_invoke` after the backend
    /// returns its result.
    ///
    /// Supports `project`, `rename`, `redact`, and `format` operations.
    /// When empty (the default) the response passes through unchanged.
    ///
    /// # Example (YAML)
    ///
    /// ```yaml
    /// response_transform:
    ///   project: [id, name]
    ///   redact:
    ///     - pattern: '\b\d{4}-\d{4}-\d{4}-\d{4}\b'
    ///       replacement: "[REDACTED]"
    /// ```
    #[serde(default, skip_serializing_if = "TransformConfig::is_empty")]
    pub response_transform: TransformConfig,

    /// Webhook endpoint definitions for inbound events
    #[serde(default)]
    pub webhooks: HashMap<String, WebhookDefinition>,

    /// Optional SHA-256 pin of the capability file contents.
    ///
    /// When present, the loader verifies that the on-disk file still matches
    /// this hash. A mismatch is rejected as a rug-pull and the capability is
    /// NOT loaded. The hash is computed over the file contents with the
    /// `sha256:` line stripped out, so pinning does not depend on the hash
    /// of the hash itself.
    ///
    /// See `crate::capability::hash` for the canonical computation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// FSM workflow states in which this capability is visible.
    ///
    /// When empty (the default) the capability is **always visible** — this
    /// preserves full backward compatibility with existing capability files.
    ///
    /// When non-empty, the capability is only included in `tools/list` when
    /// the session's current FSM state appears in this list.
    ///
    /// # Example (YAML)
    ///
    /// ```yaml
    /// visible_in_states:
    ///   - checkout
    ///   - payment
    /// ```
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_in_states: Vec<String>,
}

/// Provider configurations supporting both named and fallback arrays
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProvidersConfig {
    /// Named providers (primary, secondary, etc.)
    pub named: HashMap<String, ProviderConfig>,
    /// Fallback providers (ordered list)
    pub fallback: Vec<ProviderConfig>,
}

impl ProvidersConfig {
    /// Check if empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.named.is_empty() && self.fallback.is_empty()
    }

    /// Check if contains a key
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.named.contains_key(key)
    }

    /// Get a named provider
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ProviderConfig> {
        self.named.get(key)
    }
}

impl<'de> Deserialize<'de> for ProvidersConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_providers(deserializer)
    }
}

/// Custom deserializer for providers that handles both formats:
/// - Standard: { primary: {...}, secondary: {...} }
/// - With fallback array: { primary: {...}, fallback: [{...}, {...}] }
fn deserialize_providers<'de, D>(deserializer: D) -> Result<ProvidersConfig, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};
    use std::fmt;

    struct ProvidersVisitor;

    impl<'de> Visitor<'de> for ProvidersVisitor {
        type Value = ProvidersConfig;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of provider configurations")
        }

        fn visit_map<M>(self, mut map: M) -> Result<ProvidersConfig, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut named = HashMap::new();
            let mut fallback = Vec::new();

            while let Some(key) = map.next_key::<String>()? {
                if key == "fallback" {
                    // Try to deserialize as array first, then as single provider
                    let value: serde_json::Value = map.next_value()?;
                    if let Some(arr) = value.as_array() {
                        for item in arr {
                            if let Ok(provider) = serde_json::from_value(item.clone()) {
                                fallback.push(provider);
                            }
                        }
                    } else if let Ok(provider) = serde_json::from_value(value) {
                        fallback.push(provider);
                    }
                } else {
                    let provider: ProviderConfig = map.next_value()?;
                    named.insert(key, provider);
                }
            }

            Ok(ProvidersConfig { named, fallback })
        }
    }

    deserializer.deserialize_map(ProvidersVisitor)
}

fn default_version() -> String {
    "1.0".to_string()
}

/// Schema definition for input/output
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Input schema (JSON Schema format)
    #[serde(default)]
    pub input: serde_json::Value,

    /// Output schema (JSON Schema format)
    #[serde(default)]
    pub output: serde_json::Value,
}

/// Provider configuration for REST API calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Service type (rest, graphql, etc.)
    #[serde(default = "default_service")]
    pub service: String,

    /// Cost per call (for routing decisions)
    #[serde(default)]
    pub cost_per_call: f64,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// REST configuration
    #[serde(default)]
    pub config: RestConfig,
}

impl ProviderConfig {
    /// Derive the protocol-specific configuration from the `service` field.
    ///
    /// This is the bridge between the flat YAML structure (which uses a
    /// `service` string + a `config` object) and the typed `ProtocolConfig`
    /// enum used by protocol executors at runtime.
    ///
    /// Unknown or missing service names fall back to `Rest` for backward
    /// compatibility — every existing capability YAML uses `service: rest`
    /// (or omits the field, which defaults to `"rest"`).
    #[must_use]
    pub fn protocol_config(&self) -> ProtocolConfig {
        match self.service.as_str() {
            "rest" | "" => ProtocolConfig::Rest(self.config.clone()),
            "graphql" => {
                // Build GraphqlConfig from the flat RestConfig fields.
                // The YAML `config:` block uses RestConfig for all service
                // types — we map the relevant fields to GraphqlConfig here.
                ProtocolConfig::Graphql(GraphqlConfig {
                    endpoint: if self.config.endpoint.is_empty() {
                        format!("{}{}", self.config.base_url, self.config.path)
                    } else {
                        self.config.endpoint.clone()
                    },
                    headers: self.config.headers.clone(),
                    query: self
                        .config
                        .body
                        .as_ref()
                        .and_then(|b| b.as_str().map(ToString::to_string))
                        .or_else(|| {
                            // Also check for a `query` field in the body object
                            self.config
                                .body
                                .as_ref()
                                .and_then(|b| b.get("query"))
                                .and_then(|q| q.as_str())
                                .map(ToString::to_string)
                        }),
                    variables: self.config.static_params.clone(),
                    response_path: self.config.response_path.clone(),
                })
            }
            "jsonrpc" => {
                // Build JsonRpcConfig from the flat RestConfig fields.
                ProtocolConfig::Jsonrpc(JsonRpcConfig {
                    endpoint: if self.config.endpoint.is_empty() {
                        format!("{}{}", self.config.base_url, self.config.path)
                    } else {
                        self.config.endpoint.clone()
                    },
                    method: self.config.method.clone(),
                    headers: self.config.headers.clone(),
                    default_params: if self.config.static_params.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::Object(
                            self.config
                                .static_params
                                .iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect(),
                        )
                    },
                })
            }
            // Unknown service → fall back to REST with a tracing warning.
            // This preserves backward compat if someone has a typo or
            // uses a service name that isn't implemented yet.
            _other => {
                tracing::warn!(
                    service = %self.service,
                    "Unknown service type, falling back to REST protocol"
                );
                ProtocolConfig::Rest(self.config.clone())
            }
        }
    }
}

fn default_service() -> String {
    "rest".to_string()
}

fn default_timeout() -> u64 {
    30
}

/// REST API configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestConfig {
    /// Base URL for the API
    #[serde(default)]
    pub base_url: String,

    /// Path template (supports {param} substitution)
    #[serde(default)]
    pub path: String,

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
    Rest(RestConfig),
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
            ProtocolConfig::Rest(c) => Some(c),
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

/// Authentication configuration
///
/// # Security Note
///
/// Credentials are NEVER stored directly. All credential references
/// point to secure storage:
///
/// - `keychain:name` - macOS Keychain
/// - `env:VAR_NAME` - Environment variable
/// - `oauth:provider` - OAuth token from vault
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Whether authentication is required
    #[serde(default)]
    pub required: bool,

    /// Authentication type (oauth, `api_key`, basic, bearer, none)
    #[serde(rename = "type", default)]
    pub auth_type: String,

    /// OAuth scopes (for oauth type)
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Credential key reference (e.g., "keychain:gmail-oauth", "`env:API_KEY`")
    /// NEVER contains actual credentials
    #[serde(default)]
    pub key: String,

    /// Human-readable description for obtaining credentials
    #[serde(default)]
    pub description: String,

    /// Header name for API key auth (default: Authorization)
    #[serde(default)]
    pub header: Option<String>,

    /// Prefix for the auth header (e.g., "Bearer", "Token")
    #[serde(default)]
    pub prefix: Option<String>,

    /// Query parameter name for API key auth (e.g., "apiKey", "key").
    /// When set, the credential is injected as a query parameter instead
    /// of an HTTP header.
    #[serde(default)]
    pub param: Option<String>,

    /// OAuth token endpoint URL for the refresh-token grant.
    ///
    /// When `key` is `oauth:<provider>` and the stored token is expired,
    /// the executor will POST `grant_type=refresh_token` here when a
    /// refresh token is available.
    #[serde(default)]
    pub token_endpoint: Option<String>,
}

/// Cache configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Caching strategy (none, exact, fuzzy, semantic)
    #[serde(default)]
    pub strategy: String,

    /// Time-to-live in seconds (0 = no caching)
    #[serde(default)]
    pub ttl: u64,

    /// Cache key template (for custom cache keys)
    #[serde(default)]
    pub key_template: Option<String>,
}

impl CacheConfig {
    /// Get TTL as Duration (None if caching disabled)
    #[must_use]
    pub fn ttl_duration(&self) -> Option<std::time::Duration> {
        if self.ttl > 0 {
            Some(std::time::Duration::from_secs(self.ttl))
        } else {
            None
        }
    }
}

/// Webhook transform configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookTransform {
    /// Template for extracting the event type (e.g., "linear.issue.{action}")
    #[serde(default)]
    pub event_type: Option<String>,
    /// Field mappings: `output_key` -> template or JSON path
    #[serde(default)]
    pub data: HashMap<String, String>,
}

/// Webhook endpoint definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDefinition {
    /// URL path relative to `base_path` (e.g., "/linear/webhook")
    pub path: String,
    /// HTTP method to accept (default: POST)
    #[serde(default = "default_method")]
    pub method: String,
    /// HMAC secret reference (e.g., "`env:LINEAR_WEBHOOK_SECRET`")
    #[serde(default)]
    pub secret: Option<String>,
    /// Header that carries the signature (e.g., "X-Linear-Signature")
    #[serde(default)]
    pub signature_header: Option<String>,
    /// Emit MCP notification when received
    #[serde(default = "default_notify")]
    pub notify: bool,
    /// Payload transform configuration
    #[serde(default)]
    pub transform: WebhookTransform,
}

fn default_notify() -> bool {
    true
}

/// Capability metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    /// Category for grouping
    #[serde(default)]
    pub category: String,

    /// Tags for discovery
    #[serde(default)]
    pub tags: Vec<String>,

    /// Cost category (free, cheap, expensive)
    #[serde(default)]
    pub cost_category: String,

    /// Expected execution time (fast, medium, slow)
    #[serde(default)]
    pub execution_time: String,

    /// Whether the operation is read-only
    #[serde(default)]
    pub read_only: bool,

    /// Data types or entities this tool produces as output.
    ///
    /// Examples: `["teamId", "issueId", "userId"]`
    /// Used by the router to suggest which tools can feed into others.
    #[serde(default)]
    pub produces: Vec<String>,

    /// Data types or entities this tool requires as input.
    ///
    /// Examples: `["teamId", "issueId"]`
    /// Used by the router to surface tools that satisfy this tool's inputs.
    #[serde(default)]
    pub consumes: Vec<String>,

    /// Tool names that are commonly invoked after this one (composition hints).
    ///
    /// Examples: `["linear_create_issue", "linear_update_issue"]`
    /// Surfaced in search results to guide multi-step workflows.
    #[serde(default)]
    pub chains_with: Vec<String>,
}

/// Extract searchable field names and descriptions from a JSON Schema object.
///
/// Walks the `properties` map (one level deep) and collects:
/// - each property name (e.g. `symbol`, `exchange`)
/// - the `description` string of each property, split into words
/// - the top-level schema `description` string, split into words
///
/// Only non-empty, non-duplicate tokens are returned; all tokens are
/// lowercased so callers can do case-insensitive matching cheaply.
///
/// # Example
///
/// ```json
/// {
///   "type": "object",
///   "description": "Stock query parameters",
///   "properties": {
///     "symbol": { "type": "string", "description": "Stock ticker symbol" },
///     "exchange": { "type": "string" }
///   }
/// }
/// ```
///
/// Returns: `["symbol", "exchange", "stock", "ticker", "query", "parameters"]`
#[must_use]
pub fn extract_schema_fields(schema: &serde_json::Value) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut fields = Vec::new();

    // Collect a token, deduplicating across the whole result set.
    let mut push = |token: &str| {
        let token = token.trim().to_lowercase();
        if !token.is_empty() && seen.insert(token.clone()) {
            fields.push(token);
        }
    };

    collect_schema_tokens(schema, &mut push);
    fields
}

/// Recursively collect tokens from a JSON Schema node.
fn collect_schema_tokens(schema: &serde_json::Value, push: &mut impl FnMut(&str)) {
    // Top-level description words
    if let Some(desc) = schema.get("description").and_then(|v| v.as_str()) {
        for word in desc.split_whitespace() {
            let clean = word.trim_matches(|c: char| !c.is_alphanumeric());
            push(clean);
        }
    }

    // Property names and their descriptions
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (name, prop_schema) in props {
            push(name);
            if let Some(desc) = prop_schema.get("description").and_then(|v| v.as_str()) {
                for word in desc.split_whitespace() {
                    let clean = word.trim_matches(|c: char| !c.is_alphanumeric());
                    push(clean);
                }
            }
        }
    }
}

impl CapabilityDefinition {
    /// Build the MCP tool description, appending keyword tags and schema field
    /// names when present.
    ///
    /// The suffixes have the forms:
    /// - `[keywords: tag1, tag2, ...]`
    /// - `[schema: field1, field2, ...]`
    ///
    /// Both are invisible to human readers but searchable by the gateway's
    /// ranking engine and by LLMs reading the description.
    #[must_use]
    fn build_description(&self) -> String {
        let keyword_suffix = if self.metadata.tags.is_empty() {
            String::new()
        } else {
            format!(" [keywords: {}]", self.metadata.tags.join(", "))
        };

        let schema_fields = self.collect_all_schema_fields();
        let schema_suffix = if schema_fields.is_empty() {
            String::new()
        } else {
            format!(" [schema: {}]", schema_fields.join(", "))
        };

        format!("{}{keyword_suffix}{schema_suffix}", self.description)
    }

    /// Collect all schema field tokens from input and output schemas combined,
    /// deduplicating across both.
    fn collect_all_schema_fields(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut fields = Vec::new();

        for token in extract_schema_fields(&self.schema.input)
            .into_iter()
            .chain(extract_schema_fields(&self.schema.output))
        {
            if seen.insert(token.clone()) {
                fields.push(token);
            }
        }

        fields
    }

    /// Convert to MCP tool format
    #[must_use]
    pub fn to_mcp_tool(&self) -> crate::protocol::Tool {
        crate::protocol::Tool {
            name: self.name.clone(),
            title: None,
            description: Some(self.build_description()),
            input_schema: self.schema.input.clone(),
            output_schema: if self.schema.output.is_null() {
                None
            } else {
                Some(self.schema.output.clone())
            },
            annotations: None,
        }
    }

    /// Get the primary provider
    #[must_use]
    pub fn primary_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get("primary")
    }

    /// Get all fallback providers
    #[must_use]
    pub fn fallback_providers(&self) -> &[ProviderConfig] {
        &self.providers.fallback
    }

    /// Check if caching is enabled
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        self.cache.ttl > 0 && !self.cache.strategy.is_empty() && self.cache.strategy != "none"
    }
}

#[cfg(test)]
mod tests;
