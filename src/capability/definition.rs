//! Capability definition types
//!
//! These types map directly to the YAML capability definition format.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

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
    pub fn is_empty(&self) -> bool {
        self.named.is_empty() && self.fallback.is_empty()
    }

    /// Check if contains a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.named.contains_key(key)
    }

    /// Get a named provider
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

    /// Request body template (for POST/PUT)
    #[serde(default)]
    pub body: Option<serde_json::Value>,

    /// Response transformation (jq-like path)
    #[serde(default)]
    pub response_path: Option<String>,
}

impl RestConfig {
    /// Get the effective base URL (from endpoint or `base_url`)
    pub fn effective_base_url(&self) -> &str {
        if self.endpoint.is_empty() {
            &self.base_url
        } else {
            // Extract base from endpoint (everything before the path)
            &self.endpoint
        }
    }

    /// Check if this uses endpoint style (full URL with path params)
    pub fn uses_endpoint(&self) -> bool {
        !self.endpoint.is_empty()
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
}

/// Cache configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Caching strategy (none, exact, fuzzy, semantic)
    #[serde(default)]
    pub strategy: String,

    /// Time-to-live in seconds
    #[serde(default)]
    pub ttl: u64,

    /// Cache key template (for custom cache keys)
    #[serde(default)]
    pub key_template: Option<String>,
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
}

impl CapabilityDefinition {
    /// Convert to MCP tool format
    pub fn to_mcp_tool(&self) -> crate::protocol::Tool {
        crate::protocol::Tool {
            name: self.name.clone(),
            title: None,
            description: Some(self.description.clone()),
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
    pub fn primary_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get("primary")
    }

    /// Get all fallback providers
    pub fn fallback_providers(&self) -> &[ProviderConfig] {
        &self.providers.fallback
    }

    /// Check if caching is enabled
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

    #[test]
    fn test_capability_to_mcp_tool() {
        let cap = CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            schema: SchemaDefinition::default(),
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
        };

        let tool = cap.to_mcp_tool();
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, Some("A test tool".to_string()));
    }

    #[test]
    fn test_providers_with_fallback_array() {
        let yaml = r#"
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
"#;
        let providers: ProvidersConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(providers.named.contains_key("primary"));
        assert_eq!(providers.fallback.len(), 2);
        assert_eq!(providers.fallback[0].service, "anthropic");
        assert_eq!(providers.fallback[1].service, "groq");
    }
}
