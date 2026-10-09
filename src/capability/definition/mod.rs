// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability definition types
//!
//! These types map directly to the YAML capability definition format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::identity_grants::{CapabilityExposure, GrantSubject};
use crate::protocol::ToolAnnotations;
use crate::transform::TransformConfig;

mod process;
mod protocols;
mod providers;
mod webhook;
pub use process::{
    CliArg, CliConfig, CliOutput, ConditionalArg, DEFAULT_MAX_OUTPUT_BYTES, EachArg, JsonArg,
    MAX_OUTPUT_BYTES_CEILING, McpConfig, McpTransport, PrepareCall, ProcessConfig, RootName,
    ToolCall, ToolSelector, WAIT_INTERVAL_MS, WaitStep, WaitUntil,
};
pub use protocols::{GraphqlConfig, JsonRpcConfig, PathSelectorConfig, ProtocolConfig, RestConfig};
pub use providers::{Integrity, ProvidersConfig};
pub use webhook::WebhookEvent;

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
    #[serde(deserialize_with = "providers::deserialize_providers")]
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

    /// Canonical projection spec (MIK-3534) applied by `gateway_invoke` after
    /// `response_transform` and output-schema validation.
    ///
    /// When set, the dispatched response is mapped onto the canonical schema
    /// ([`crate::projection::schema::ProjectionSpec`]) — `actor` / `subject` /
    /// `env_time` / `url` / `body` buckets — while the untouched (already
    /// redacted/validated) payload is preserved under `_raw`. Projection is a
    /// presentation layer, never redaction: redact via `response_transform`.
    ///
    /// `_full: true` bypasses projection entirely. When the spec resolves no
    /// fields the response passes through unchanged (fail-fast).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<crate::projection::schema::ProjectionSpec>,

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
    #[serde(
        default = "default_timeout",
        deserialize_with = "crate::duration_bound::nonzero_secs"
    )]
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
            "rest" | "" => ProtocolConfig::Rest(Box::new(self.config.clone())),
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
                ProtocolConfig::Rest(Box::new(self.config.clone()))
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

    /// Operator-blessed escape hatch for a gateway-held `oauth:<provider>`
    /// credential that is intentionally shared across every caller (e.g. a
    /// team service account), mirroring `OAuthConfig.shared_account` for MCP
    /// backends (ADR-008 INV-2). Default `false`: on a multi-user gateway, a
    /// capability whose `key` is `oauth:<provider>` is refused unless this is
    /// set, or the capability is `exposure: personal` with a matching caller
    /// identity (MIK-6751).
    #[serde(default)]
    pub shared_account: bool,

    /// Explicit reference to an `accounts.descriptors` MAP KEY — the same
    /// descriptor id an MCP backend's `account` names, and the same logical
    /// `backend_id` of the account key.
    ///
    /// Retained through parse and re-serialization so a capability rewrite
    /// cannot quietly demote a managed capability to a gateway-held token. The
    /// `oauth:<provider>` half of [`Self::key`] must MATCH the referenced
    /// descriptor's `provider`; a capability keyed `oauth:slack` pointing at a
    /// `google` descriptor is a refusal, never a best-effort lookup.
    ///
    /// REST verified-identity propagation is not wired in this increment, so a
    /// recognized reference fails CLOSED at credential resolution
    /// (`executor::credentials`) instead of reaching the shared token storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// Cache configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Caching strategy (none, exact, fuzzy, semantic)
    #[serde(default)]
    pub strategy: String,

    /// Time-to-live in seconds (0 = no caching)
    #[serde(default, deserialize_with = "crate::duration_bound::secs")]
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
    /// Field mappings: `output_key` -> template (`{a.b}` placeholders; text
    /// with none is a literal)
    #[serde(default)]
    pub data: HashMap<String, String>,
}

/// Webhook endpoint definition
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookDefinition {
    /// URL path relative to `base_path` (e.g., "/linear/webhook")
    pub path: String,
    /// HTTP method to accept (default: POST)
    #[serde(default = "webhook::default_method")]
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
    /// Opt-in MCP event for this route (MIK-7630); absent = no event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<WebhookEvent>,
}

fn default_notify() -> bool {
    false
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

    /// Whether this capability registers a caller-chosen destination that a
    /// third party will later deliver to.
    ///
    /// Declared rather than inferred where the shape is not obvious from the
    /// name or the parameters: `gws_gmail_watch` registers a Pub/Sub topic,
    /// which is a delivery destination with neither "webhook" in its name nor a
    /// URL in its schema. `None` falls back to inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers_external_callback: Option<bool>,

    /// Whether the operation may destructively modify user-visible state.
    ///
    /// When omitted, capability tools infer a conservative value from
    /// `read_only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,

    /// Whether repeating the same call has no additional effect.
    ///
    /// When omitted, capability tools infer `true` for read-only operations and
    /// `false` for write operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent: Option<bool>,

    /// Whether the operation interacts with external services or entities.
    ///
    /// API capabilities default to open-world because they call REST services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world: Option<bool>,

    /// Identity exposure for dispatch authorization.
    ///
    /// Defaults to `shared` so existing capability files remain callable until
    /// operators explicitly mark a tool as `personal`.
    #[serde(default, skip_serializing_if = "CapabilityExposure::is_shared")]
    pub exposure: CapabilityExposure,

    /// Owner subject required when `exposure` is `personal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_owner: Option<GrantSubject>,

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
    /// SHA-256 of the whole definition as JSON with every object's keys
    /// sorted, providers with their typed process configs included and the
    /// pin state itself excluded. Numbers keep their exact value (not JCS,
    /// which rounds them through a double and makes 2^53 and 2^53 + 1 equal).
    /// `None` only if the definition cannot be serialized, which never
    /// matches a stored fingerprint (MIK-7814).
    pub(crate) fn fingerprint(&self) -> Option<String> {
        #[cfg(test)]
        FINGERPRINTS.with(|count| count.set(count.get() + 1));
        let value = sorted_keys(serde_json::to_value(self).ok()?);
        Some(crate::hashing::sha256_hex(
            &serde_json::to_vec(&value).ok()?,
        ))
    }

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
            input_schema: crate::capability::schema_validator::advertised_input_schema(
                &self.schema.input,
            ),
            output_schema: crate::capability::advertised_output_schema(&self.schema.output),
            annotations: Some(self.tool_annotations()),
            role: None,
            projection: self.projection.clone(),
        }
    }

    fn tool_annotations(&self) -> ToolAnnotations {
        let read_only = self.metadata.read_only;
        ToolAnnotations {
            title: None,
            read_only_hint: Some(read_only),
            destructive_hint: Some(self.metadata.destructive.unwrap_or(!read_only)),
            idempotent_hint: Some(self.metadata.idempotent.unwrap_or(read_only)),
            open_world_hint: Some(self.metadata.open_world.unwrap_or(true)),
        }
    }

    /// Get the primary provider
    #[must_use]
    pub fn primary_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get("primary")
    }

    /// Check if caching is enabled
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        self.cache.ttl > 0 && !self.cache.strategy.is_empty() && self.cache.strategy != "none"
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "cwe532_debug_redaction_tests.rs"]
mod cwe532_debug_redaction;

/// `true` when this capability hands a caller-chosen destination to a third
/// party that will later call it.
///
/// Such a call creates persistent state outside this gateway, addressed by the
/// caller and authorised by the operator's credential — an out-of-band channel
/// that needs no readable response. `linear_create_webhook` is the shape:
/// a URL parameter, posted to Linear, which then delivers events to it.
///
/// Derived from the definition rather than a hand-kept list, so a capability
/// added later inherits the rule instead of needing to be remembered. The
/// ticket that filed this recorded a hand count of six URL-taking capabilities;
/// the count was wrong, which is the argument for deriving it.
#[must_use]
pub fn creates_caller_addressed_external_state(def: &CapabilityDefinition) -> bool {
    // Not an HTTP method test: a capability backed by a CLI has no method, and
    // `gws_gmail_watch` — which registers a Pub/Sub topic — is exactly that. A
    // read-only capability cannot register anything, so that flag is the
    // transport-independent question, with the method as a fallback where the
    // flag was left at its default.
    // An explicit `read_only: true` settles it. The previous form OR'd the
    // provider method in, so a capability that declared itself read-only but
    // reached its API with POST — which plenty do — was treated as mutating,
    // and an unauthenticated laptop client lost a tool it should have.
    if def.metadata.read_only {
        return false;
    }
    // An explicit declaration wins over EVERY inference below, which is why it
    // is read here rather than further down. Name inference is a fallback, not
    // the contract: `gws_gmail_watch` registers a Pub/Sub topic, whose
    // destination is not a URL and whose name is not "webhook", and inference
    // alone missed it. Read after the inference short-circuits — as it was
    // until MIK-7262 — the declaration lost to the very heuristics it exists to
    // overrule: a GET-reached or `properties`-less definition returned `false`
    // before anyone looked at what its author said.
    // It stays BELOW `read_only` deliberately: that flag is also an author
    // declaration, and the older one. Two explicit declarations in conflict
    // resolve to read-only rather than silently reversing the ruling above.
    if let Some(declared) = def.metadata.registers_external_callback {
        return declared;
    }
    let mutating = def
        .providers
        .named
        .values()
        .chain(def.providers.fallback.iter())
        .any(|p| {
            matches!(
                p.config.method.to_ascii_uppercase().as_str(),
                "POST" | "PUT" | "PATCH"
            )
        })
        // A CLI-backed capability has no HTTP method; not being read-only is
        // what makes it mutating there.
        || def.providers.named.values().any(|p| p.service == "cli");
    if !mutating {
        return false;
    }
    let Some(props) = def
        .schema
        .input
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return false;
    };
    // Narrow deliberately. "Mutating, and takes a URL" is too broad: archiving a
    // page or attaching a link posts a URL as DATA, and blocking those behind
    // admin would take ordinary tools away from the single-user client for no
    // security gain. What matters is REGISTERING an address the third party
    // will later deliver to.
    let name = def.name.to_ascii_lowercase();
    let registers_a_callback = ["webhook", "subscribe", "callback", "watch", "notify"]
        .iter()
        .any(|k| name.contains(k));
    if !registers_a_callback {
        return false;
    }

    props.iter().any(|(name, spec)| {
        let lower = name.to_ascii_lowercase();
        // Not only URLs. A Pub/Sub topic, a queue name or an address is just as
        // much a caller-chosen destination that a third party will deliver to.
        let looks_like_a_destination = lower == "url"
            || lower.ends_with("_url")
            || lower == "callback"
            || lower == "webhook"
            || lower == "endpoint"
            || lower == "address"
            || lower.contains("topic")
            || lower.contains("queue")
            || lower.contains("channel");
        let declared_uri = spec.get("format").and_then(|f| f.as_str()) == Some("uri");
        looks_like_a_destination || declared_uri
    })
}

#[cfg(test)]
mod caller_addressed_state_tests;

/// `value` with every object's keys in sorted order, whatever map type
/// `serde_json` was built with.
fn sorted_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, item)| (key, sorted_keys(item)))
                    .collect(),
            )
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sorted_keys).collect())
        }
        other => other,
    }
}

#[cfg(test)]
thread_local! {
    /// Fingerprints computed on this thread, so a test can show a path
    /// never computes one.
    pub(crate) static FINGERPRINTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
