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

    /// Response transform pipeline configuration
    #[serde(default)]
    pub transform: TransformConfig,

    /// Webhook endpoint definitions for inbound events
    #[serde(default)]
    pub webhooks: HashMap<String, WebhookDefinition>,
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
            self.static_params.len()
                + caller_params
                    .as_object()
                    .map_or(0, serde_json::Map::len),
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
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let config: AuthConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.required);
        assert!(config.auth_type.is_empty());
    }

    fn make_capability(name: &str, description: &str, tags: Vec<&str>) -> CapabilityDefinition {
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: name.to_string(),
            description: description.to_string(),
            schema: SchemaDefinition::default(),
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata {
                tags: tags.into_iter().map(ToString::to_string).collect(),
                ..CapabilityMetadata::default()
            },
            transform: TransformConfig::default(),
            webhooks: HashMap::new(),
        }
    }

    #[test]
    fn to_mcp_tool_without_tags_uses_plain_description() {
        let cap = make_capability("test_tool", "A test tool", vec![]);
        let tool = cap.to_mcp_tool();
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, Some("A test tool".to_string()));
    }

    #[test]
    fn to_mcp_tool_with_tags_appends_keywords_suffix() {
        let cap = make_capability("search_tool", "Web search", vec!["search", "web", "brave"]);
        let tool = cap.to_mcp_tool();
        let desc = tool.description.unwrap();
        assert!(desc.starts_with("Web search"));
        assert!(desc.contains("[keywords: search, web, brave]"));
    }

    #[test]
    fn to_mcp_tool_single_tag_formats_correctly() {
        let cap = make_capability("weather", "Get weather", vec!["forecast"]);
        let tool = cap.to_mcp_tool();
        assert_eq!(
            tool.description,
            Some("Get weather [keywords: forecast]".to_string())
        );
    }

    #[test]
    fn build_description_with_empty_tags_is_plain() {
        let cap = make_capability("no_tags", "Plain description", vec![]);
        assert_eq!(cap.build_description(), "Plain description");
    }

    #[test]
    fn build_description_with_tags_includes_all_tags() {
        let cap = make_capability("multi", "Desc", vec!["a", "b", "c"]);
        assert_eq!(cap.build_description(), "Desc [keywords: a, b, c]");
    }

    // ── extract_schema_fields ─────────────────────────────────────────────

    #[test]
    fn extract_schema_fields_returns_empty_for_null_schema() {
        // GIVEN: null JSON value (default schema)
        // WHEN: extracting fields
        // THEN: empty vec
        let fields = extract_schema_fields(&serde_json::Value::Null);
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_schema_fields_extracts_property_names() {
        // GIVEN: schema with `symbol` and `exchange` properties
        // WHEN: extracting fields
        // THEN: both property names are present
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string" },
                "exchange": { "type": "string" }
            }
        });
        let fields = extract_schema_fields(&schema);
        assert!(fields.contains(&"symbol".to_string()));
        assert!(fields.contains(&"exchange".to_string()));
    }

    #[test]
    fn extract_schema_fields_includes_property_description_words() {
        // GIVEN: schema where property has a description
        // WHEN: extracting fields
        // THEN: words from property description are included
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string", "description": "Stock ticker symbol" }
            }
        });
        let fields = extract_schema_fields(&schema);
        assert!(fields.contains(&"symbol".to_string()));
        assert!(fields.contains(&"stock".to_string()));
        assert!(fields.contains(&"ticker".to_string()));
    }

    #[test]
    fn extract_schema_fields_includes_top_level_description_words() {
        // GIVEN: schema with a top-level description
        // WHEN: extracting fields
        // THEN: words from the top-level description are included
        let schema = serde_json::json!({
            "type": "object",
            "description": "Market data query",
            "properties": {}
        });
        let fields = extract_schema_fields(&schema);
        assert!(fields.contains(&"market".to_string()));
        assert!(fields.contains(&"data".to_string()));
        assert!(fields.contains(&"query".to_string()));
    }

    #[test]
    fn extract_schema_fields_deduplicates_tokens() {
        // GIVEN: schema where "symbol" appears as property name AND in description
        // WHEN: extracting fields
        // THEN: "symbol" appears only once
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string", "description": "The symbol to look up" }
            }
        });
        let fields = extract_schema_fields(&schema);
        let count = fields.iter().filter(|f| f.as_str() == "symbol").count();
        assert_eq!(count, 1, "symbol should appear exactly once");
    }

    #[test]
    fn extract_schema_fields_lowercases_tokens() {
        // GIVEN: schema with mixed-case property name
        // WHEN: extracting fields
        // THEN: all tokens are lowercase
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "StockSymbol": { "type": "string", "description": "A TICKER value" }
            }
        });
        let fields = extract_schema_fields(&schema);
        assert!(fields.iter().all(|f| f == &f.to_lowercase()));
        assert!(fields.contains(&"stocksymbol".to_string()));
        assert!(fields.contains(&"ticker".to_string()));
        assert!(fields.contains(&"value".to_string()));
    }

    // ── build_description with schema ─────────────────────────────────────

    fn make_capability_with_schema(
        name: &str,
        description: &str,
        tags: Vec<&str>,
        input: serde_json::Value,
    ) -> CapabilityDefinition {
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: name.to_string(),
            description: description.to_string(),
            schema: SchemaDefinition {
                input,
                output: serde_json::Value::Null,
            },
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata {
                tags: tags.into_iter().map(ToString::to_string).collect(),
                ..CapabilityMetadata::default()
            },
            transform: crate::transform::TransformConfig::default(),
            webhooks: HashMap::new(),
        }
    }

    #[test]
    fn build_description_with_schema_appends_schema_suffix() {
        // GIVEN: capability with schema containing symbol and exchange
        // WHEN: building description
        // THEN: [schema: ...] suffix is appended
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string" },
                "exchange": { "type": "string" }
            }
        });
        let cap = make_capability_with_schema("stock_tool", "Get stock data", vec![], schema);
        let desc = cap.build_description();
        assert!(desc.starts_with("Get stock data"));
        assert!(desc.contains("[schema:"));
        assert!(desc.contains("symbol"));
        assert!(desc.contains("exchange"));
    }

    #[test]
    fn build_description_with_tags_and_schema_includes_both_suffixes() {
        // GIVEN: capability with both tags and schema fields
        // WHEN: building description
        // THEN: [keywords: ...] and [schema: ...] both appear
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "symbol": { "type": "string" } }
        });
        let cap = make_capability_with_schema(
            "stock_tool",
            "Get stock data",
            vec!["finance", "market"],
            schema,
        );
        let desc = cap.build_description();
        assert!(desc.contains("[keywords: finance, market]"));
        assert!(desc.contains("[schema:"));
        assert!(desc.contains("symbol"));
    }

    #[test]
    fn build_description_without_schema_omits_schema_suffix() {
        // GIVEN: capability with tags but no schema properties
        // WHEN: building description
        // THEN: no [schema: ...] suffix
        let cap = make_capability("search", "Search tool", vec!["web"]);
        let desc = cap.build_description();
        assert!(!desc.contains("[schema:"));
    }

    #[test]
    fn to_mcp_tool_with_schema_includes_schema_fields_in_description() {
        // GIVEN: capability with a rich input schema
        // WHEN: converting to MCP tool
        // THEN: description contains searchable schema fields
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string", "description": "Stock ticker symbol" },
                "exchange": { "type": "string" },
                "price": { "type": "number" },
                "volume": { "type": "integer" }
            }
        });
        let cap = make_capability_with_schema("market_data", "Fetch market data", vec![], schema);
        let tool = cap.to_mcp_tool();
        let desc = tool.description.unwrap();
        assert!(desc.contains("symbol"), "description must contain 'symbol'");
        assert!(desc.contains("exchange"), "description must contain 'exchange'");
        assert!(desc.contains("price"), "description must contain 'price'");
        assert!(desc.contains("volume"), "description must contain 'volume'");
    }

    #[test]
    fn test_providers_with_fallback_array() {
        let yaml = r"
primary:
  service: openai
  config:
    endpoint: https://api.openai.com/v1/chat
fallback:
  - service: anthropic
    config:
      endpoint: https://api.anthropic.com/v1/messages
  - service: groq
    config:
      endpoint: https://api.groq.com/v1/chat
";
        let providers: ProvidersConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(providers.named.contains_key("primary"));
        assert_eq!(providers.fallback.len(), 2);
        assert_eq!(providers.fallback[0].service, "anthropic");
        assert_eq!(providers.fallback[1].service, "groq");
    }

    #[test]
    fn capability_metadata_produces_consumes_chains_with_default_empty() {
        // GIVEN: no composition fields in JSON
        // WHEN: deserializing CapabilityMetadata
        // THEN: produces, consumes, chains_with all default to empty
        let meta: CapabilityMetadata = serde_json::from_str("{}").unwrap();
        assert!(meta.produces.is_empty());
        assert!(meta.consumes.is_empty());
        assert!(meta.chains_with.is_empty());
    }

    #[test]
    fn capability_metadata_deserializes_all_composition_fields() {
        // GIVEN: JSON with all three composition fields
        // WHEN: deserializing
        // THEN: fields populated correctly
        let json = r#"{
            "produces": ["teamId"],
            "consumes": ["userId"],
            "chains_with": ["linear_create_issue"]
        }"#;
        let meta: CapabilityMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.produces, vec!["teamId"]);
        assert_eq!(meta.consumes, vec!["userId"]);
        assert_eq!(meta.chains_with, vec!["linear_create_issue"]);
    }

    #[test]
    fn capability_metadata_serializes_composition_fields() {
        // GIVEN: CapabilityMetadata with composition data
        // WHEN: serializing to JSON
        // THEN: all fields present
        let meta = CapabilityMetadata {
            produces: vec!["teamId".to_string()],
            consumes: vec!["userId".to_string()],
            chains_with: vec!["next_tool".to_string()],
            ..CapabilityMetadata::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["produces"][0], "teamId");
        assert_eq!(json["consumes"][0], "userId");
        assert_eq!(json["chains_with"][0], "next_tool");
    }
}
