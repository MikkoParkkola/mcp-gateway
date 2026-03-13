//! Secret injection proxy — credential brokering at the gateway level.
//!
//! Agents call `gateway_execute(tool="weather_forecast", args={...})` and the
//! gateway transparently injects credentials (API keys, OAuth tokens, basic auth)
//! before forwarding to the backend MCP server. Agents never see raw secrets.
//!
//! # Design
//!
//! Each backend can declare zero or more [`CredentialRule`]s. A rule specifies:
//! - Which tools it applies to (glob patterns, or `["*"]` for all)
//! - The credential type (API key, bearer token, basic auth, custom header)
//! - Where the credential value comes from (`{env.VAR}`, `{keychain.SERVICE}`, literal)
//! - Where to inject: into the tool arguments, HTTP headers, or query parameters
//!
//! At dispatch time, [`SecretInjector::inject`] resolves each matching rule and
//! merges the credential into the outbound request. Header overwrites are enforced:
//! injected values always replace agent-supplied values with the same key.
//!
//! # Security properties
//!
//! - Agents never receive raw credential values (injection happens after the agent call)
//! - Domain-scoped: credentials only flow to their intended backend
//! - Header overwrite protection: injected headers overwrite any agent-supplied duplicates
//! - Audit trail: every injection is logged with backend, tool, credential name, and timestamp

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::secrets::SecretResolver;

// ============================================================================
// Configuration types
// ============================================================================

/// A single credential rule for a backend.
///
/// # YAML example
///
/// ```yaml
/// backends:
///   weather_api:
///     http_url: "http://localhost:8080/mcp"
///     secrets:
///       - name: api_key
///         credential_type: api_key
///         value: "{env.WEATHER_API_KEY}"
///         inject_as: argument
///         inject_key: api_key
///         tools: ["*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRule {
    /// Human-readable name for audit logging (e.g., `"openai_api_key"`)
    pub name: String,

    /// Type of credential (informational, used for audit logs)
    #[serde(default = "default_credential_type")]
    pub credential_type: CredentialType,

    /// The credential value — supports `{env.VAR}`, `{keychain.SERVICE}`, or literal.
    ///
    /// Resolved at first use via [`SecretResolver`] and cached for the session.
    pub value: String,

    /// Where to inject the resolved credential
    #[serde(default)]
    pub inject_as: InjectTarget,

    /// The key name for injection:
    /// - For `argument`: the JSON key to set in the tool arguments object
    /// - For `header`: the HTTP header name (e.g., "Authorization")
    /// - For `query`: the query parameter name
    pub inject_key: String,

    /// Tool name patterns this rule applies to. Empty or `["*"]` means all tools.
    /// Supports glob patterns (e.g., `"create_*"`, `"weather_*"`).
    #[serde(default = "default_tools_match")]
    pub tools: Vec<String>,
}

/// Credential type for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// API key (e.g., `X-API-Key: xxx`)
    ApiKey,
    /// Bearer token (e.g., `Authorization: Bearer xxx`)
    Bearer,
    /// Basic auth (e.g., `Authorization: Basic base64(user:pass)`)
    BasicAuth,
    /// Custom header or argument injection
    Custom,
}

/// Where to inject the credential in the outbound request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InjectTarget {
    /// Inject into the tool call arguments JSON object
    #[default]
    Argument,
    /// Inject as an HTTP header on the backend transport
    Header,
    /// Inject as a query parameter (for HTTP backends)
    Query,
}

fn default_credential_type() -> CredentialType {
    CredentialType::ApiKey
}

fn default_tools_match() -> Vec<String> {
    vec!["*".to_string()]
}

// ============================================================================
// Injection result
// ============================================================================

/// The result of secret injection — contains the modified arguments and any
/// additional headers to set on the outbound transport.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// Modified tool arguments with injected credentials
    pub arguments: serde_json::Value,
    /// Additional headers to inject on the outbound HTTP request.
    /// Empty for stdio backends (credentials go into arguments instead).
    pub headers: HashMap<String, String>,
    /// Number of credentials injected (for audit logging)
    pub injected_count: usize,
    /// Names of injected credentials (for audit logging)
    pub injected_names: Vec<String>,
}

// ============================================================================
// SecretInjector
// ============================================================================

/// Resolves and injects credentials into tool calls at dispatch time.
///
/// Holds a [`SecretResolver`] for resolving `{env.VAR}` and `{keychain.SERVICE}`
/// patterns, and the per-backend credential rules from config.
pub struct SecretInjector {
    /// Secret resolver (handles env vars, keychain, caching)
    resolver: Arc<SecretResolver>,
    /// Per-backend credential rules, keyed by backend name
    rules: HashMap<String, Vec<CredentialRule>>,
}

impl SecretInjector {
    /// Create a new secret injector with the given per-backend rules.
    #[must_use]
    pub fn new(rules: HashMap<String, Vec<CredentialRule>>) -> Self {
        Self {
            resolver: Arc::new(SecretResolver::new()),
            rules,
        }
    }

    /// Create an empty injector (no rules configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            resolver: Arc::new(SecretResolver::new()),
            rules: HashMap::new(),
        }
    }

    /// Returns `true` if any backend has credential rules configured.
    #[must_use]
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Returns the number of credential rules for a given backend.
    #[must_use]
    pub fn rule_count(&self, backend: &str) -> usize {
        self.rules.get(backend).map_or(0, Vec::len)
    }

    /// Inject credentials for a tool call on a specific backend.
    ///
    /// Resolves all matching credential rules and returns an [`InjectionResult`]
    /// with the modified arguments and any additional headers.
    ///
    /// # Errors
    ///
    /// Returns an error if a credential value cannot be resolved (e.g., missing
    /// keychain entry or undefined environment variable referenced without default).
    pub fn inject(
        &self,
        backend: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> crate::Result<InjectionResult> {
        let Some(rules) = self.rules.get(backend) else {
            return Ok(InjectionResult {
                arguments,
                headers: HashMap::new(),
                injected_count: 0,
                injected_names: Vec::new(),
            });
        };

        let mut args = arguments;
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut injected_names: Vec<String> = Vec::new();

        for rule in rules {
            if !tool_matches_rule(tool, &rule.tools) {
                continue;
            }

            // Resolve the credential value
            let resolved_value = self.resolver.resolve(&rule.value).map_err(|e| {
                warn!(
                    backend = backend,
                    credential = %rule.name,
                    error = %e,
                    "Failed to resolve credential"
                );
                crate::Error::Config(format!(
                    "Failed to resolve credential '{}' for backend '{}': {e}",
                    rule.name, backend
                ))
            })?;

            // Skip injection if the resolved value is empty (missing env var without default)
            if resolved_value.is_empty() {
                warn!(
                    backend = backend,
                    credential = %rule.name,
                    "Credential resolved to empty value, skipping injection"
                );
                continue;
            }

            match rule.inject_as {
                InjectTarget::Argument => {
                    // Inject into the tool arguments JSON object
                    if let Some(obj) = args.as_object_mut() {
                        // Overwrite protection: always set, never let agent override
                        obj.insert(
                            rule.inject_key.clone(),
                            serde_json::Value::String(resolved_value),
                        );
                    }
                }
                InjectTarget::Header => {
                    // Inject as an HTTP header (overwrite any existing agent-supplied header)
                    headers.insert(rule.inject_key.clone(), resolved_value);
                }
                InjectTarget::Query => {
                    // Query parameters are injected as headers with a special prefix
                    // that the transport layer can recognize and append to the URL.
                    // For now, we inject as a special argument key.
                    if let Some(obj) = args.as_object_mut() {
                        obj.insert(
                            format!("__query_{}", rule.inject_key),
                            serde_json::Value::String(resolved_value),
                        );
                    }
                }
            }

            injected_names.push(rule.name.clone());

            // Audit log: credential injected
            info!(
                backend = backend,
                tool = tool,
                credential = %rule.name,
                credential_type = ?rule.credential_type,
                inject_as = ?rule.inject_as,
                inject_key = %rule.inject_key,
                "Secret injected"
            );
        }

        let injected_count = injected_names.len();
        if injected_count > 0 {
            debug!(
                backend = backend,
                tool = tool,
                count = injected_count,
                credentials = ?injected_names,
                "Secret injection complete"
            );
        }

        Ok(InjectionResult {
            arguments: args,
            headers,
            injected_count,
            injected_names,
        })
    }

    /// Update rules for a backend (for hot-reload support).
    pub fn update_rules(&mut self, backend: &str, rules: Vec<CredentialRule>) {
        if rules.is_empty() {
            self.rules.remove(backend);
        } else {
            self.rules.insert(backend.to_string(), rules);
        }
    }

    /// Clear the secret resolver cache (e.g., after credential rotation).
    pub fn clear_cache(&self) {
        self.resolver.clear_cache();
    }

    /// List configured backend names (for diagnostics).
    #[must_use]
    pub fn configured_backends(&self) -> Vec<&str> {
        self.rules.keys().map(String::as_str).collect()
    }

    /// Return a redacted summary of rules for a backend (safe for logs/diagnostics).
    #[must_use]
    pub fn redacted_rules(&self, backend: &str) -> Vec<RedactedRule> {
        self.rules.get(backend).map_or_else(Vec::new, |rules| {
            rules
                .iter()
                .map(|r| RedactedRule {
                    name: r.name.clone(),
                    credential_type: r.credential_type.clone(),
                    inject_as: r.inject_as.clone(),
                    inject_key: r.inject_key.clone(),
                    tools: r.tools.clone(),
                })
                .collect()
        })
    }
}

/// Redacted credential rule — safe for logging and diagnostics.
/// Does NOT contain the actual credential value.
#[derive(Debug, Clone, Serialize)]
pub struct RedactedRule {
    /// Credential name
    pub name: String,
    /// Credential type
    pub credential_type: CredentialType,
    /// Injection target
    pub inject_as: InjectTarget,
    /// Injection key
    pub inject_key: String,
    /// Tool patterns
    pub tools: Vec<String>,
}

// ============================================================================
// Tool matching
// ============================================================================

/// Check if a tool name matches any of the rule's tool patterns.
pub fn tool_matches_rule(tool: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    for pattern in patterns {
        if pattern == "*" {
            return true;
        }
        if glob_match(pattern, tool) {
            return true;
        }
    }

    false
}

/// Simple glob matching (supports `*` as wildcard).
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Exact match
    if pattern == value {
        return true;
    }

    // Prefix wildcard: `*_suffix` matches `anything_suffix`
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }

    // Suffix wildcard: `prefix_*` matches `prefix_anything`
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    // Contains wildcard: `pre*suf` matches `pre_anything_suf`
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        return value.starts_with(prefix)
            && value.ends_with(suffix)
            && value.len() >= prefix.len() + suffix.len();
    }

    false
}

// ============================================================================
// Builder from config
// ============================================================================

impl SecretInjector {
    /// Build a `SecretInjector` from the parsed gateway config.
    ///
    /// Extracts `secrets` fields from each backend config and aggregates them.
    #[must_use]
    pub fn from_backend_configs(backends: &HashMap<String, crate::config::BackendConfig>) -> Self {
        let mut rules: HashMap<String, Vec<CredentialRule>> = HashMap::new();

        for (name, config) in backends {
            if !config.secrets.is_empty() {
                rules.insert(name.clone(), config.secrets.clone());
                info!(
                    backend = %name,
                    credentials = config.secrets.len(),
                    "Secret injection rules loaded"
                );
            }
        }

        if rules.is_empty() {
            Self::empty()
        } else {
            let total: usize = rules.values().map(Vec::len).sum();
            info!(
                backends = rules.len(),
                total_rules = total,
                "Secret injection proxy initialized"
            );
            Self::new(rules)
        }
    }
}
