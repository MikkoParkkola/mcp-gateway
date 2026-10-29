// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
//! - Where to inject: into the tool arguments or HTTP headers (a query parameter is refused)
//!
//! A backend applies its own rules where its tool call is sent
//! (`Backend::request_attempted`, which every route passes through): each
//! matching rule is resolved by the gateway's shared resolver and merged into
//! the copy of the call that is sent, through `inject_rules`.
//! [`SecretInjector::inject`] applies the same function over a map of rules.
//! Injected values always replace caller-supplied values with the same key. A
//! `query` rule is refused: the gateway sends no secret in a URL.
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

/// Remove the key `rule` owns from the caller's arguments: whatever the caller
/// put there is never forwarded in place of the gateway's credential.
fn drop_caller_value(
    rule: &CredentialRule,
    arguments: &mut serde_json::Map<String, serde_json::Value>,
) {
    match rule.inject_as {
        InjectTarget::Argument => {
            arguments.remove(&rule.inject_key);
        }
        InjectTarget::Query => {
            arguments.remove(&format!("__query_{}", rule.inject_key));
        }
        InjectTarget::Header => {}
    }
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

    /// Resolve `{env.VAR}` credentials against `env` rather than the process
    /// environment, so a value an env file assigns is visible.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.resolver = Arc::new(SecretResolver::new().with_env(env));
        self
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

    /// Drop from `arguments` the keys [`Self::inject`] sets for `backend:tool`
    /// whatever the caller sent, since the value the caller put there never
    /// leaves the gateway. A rule whose credential resolves empty (injection
    /// skips it) or fails keeps the caller's value in view. The send path
    /// reads a backend's own rules ([`strip_overwritten`]); this keyed form
    /// is the flip tests'.
    #[cfg(all(test, feature = "firewall"))]
    pub(crate) fn strip_overwritten(
        &self,
        backend: &str,
        tool: &str,
        arguments: &mut serde_json::Value,
    ) {
        if let Some(rules) = self.rules.get(backend) {
            strip_overwritten(rules, &self.resolver, tool, arguments);
        }
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
        match self.rules.get(backend) {
            Some(rules) => inject_rules(rules, &self.resolver, backend, tool, arguments),
            None => Ok(InjectionResult {
                arguments,
                headers: HashMap::new(),
                injected_count: 0,
                injected_names: Vec::new(),
            }),
        }
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

/// [`SecretInjector::inject`] over one backend's `rules`, resolved by
/// `resolver`: what a backend's own send applies.
///
/// # Errors
///
/// As [`SecretInjector::inject`].
pub(crate) fn inject_rules(
    rules: &[CredentialRule],
    resolver: &SecretResolver,
    backend: &str,
    tool: &str,
    arguments: serde_json::Value,
) -> crate::Result<InjectionResult> {
    let mut args = arguments;
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut injected_names: Vec<String> = Vec::new();

    // Every key a matching rule owns loses the caller's value up front,
    // whatever its credential resolves to now. The firewall check strips
    // the same keys from its own copy on the strength of an earlier
    // resolution; if the credential changed in between and a rule skips,
    // a value the check never saw must not be forwarded (MIK-7888). Doing
    // it before the loop also keeps a skipping rule from deleting what an
    // earlier rule on the same key injected.
    drop_owned(rules, tool, &mut args);

    for rule in rules {
        if !tool_matches_rule(tool, &rule.tools) {
            continue;
        }

        // Resolve the credential value
        let resolved_value = resolver.resolve(&rule.value).map_err(|e| {
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

        // Skip injection if the rule value itself is empty; an unset or empty
        // {env.X} already failed above (C4).
        if resolved_value.is_empty() {
            warn!(
                backend = backend,
                credential = %rule.name,
                "Credential resolved to empty value, skipping injection"
            );
            continue;
        }

        // Each refusal names the backend and the rule, never the value.
        let refusal = |why: &str| {
            crate::Error::Config(format!(
                "backend '{backend}' secret rule '{}' {why}: the rule is not applied",
                rule.name
            ))
        };
        match rule.inject_as {
            InjectTarget::Argument => {
                // Overwrite protection: always set, never let agent override.
                // Arguments that are not an object cannot carry it, and are
                // never sent without it.
                let Some(obj) = args.as_object_mut() else {
                    return Err(refusal(
                        "injects an argument, but the call's arguments are not an object",
                    ));
                };
                obj.insert(
                    rule.inject_key.clone(),
                    serde_json::Value::String(resolved_value),
                );
            }
            InjectTarget::Header => {
                // Checked before the audit line, so a refused call is never
                // recorded as injected.
                if reqwest::header::HeaderValue::from_str(&resolved_value).is_err() {
                    return Err(refusal(
                        "resolved to a value that is not a valid HTTP header value",
                    ));
                }
                // Overwrites any header of the same name the call carries.
                headers.insert(rule.inject_key.clone(), resolved_value);
            }
            // The gateway sends no secret in a URL, and none in the arguments
            // in a URL parameter's place. Config load refuses the rule first.
            InjectTarget::Query => return Err(refusal("injects into a URL query parameter")),
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

/// Drop from `arguments` the keys `rules` set for `tool` whatever the caller
/// sent, for the relay check. A rule whose credential resolves empty
/// (injection skips it) or fails keeps the caller's value in view.
#[cfg(feature = "firewall")]
pub(crate) fn strip_overwritten(
    rules: &[CredentialRule],
    resolver: &SecretResolver,
    tool: &str,
    arguments: &mut serde_json::Value,
) {
    let Some(obj) = arguments.as_object_mut() else {
        return;
    };
    for rule in rules.iter().filter(|r| tool_matches_rule(tool, &r.tools)) {
        if !resolver.resolve(&rule.value).is_ok_and(|v| !v.is_empty()) {
            continue;
        }
        drop_caller_value(rule, obj);
    }
}

/// Drop from `arguments` every key a rule in `rules` owns for `tool`, whatever
/// its credential resolves to: the copy a backend's mirror headers are read
/// from never holds a caller's value for a key the gateway overwrites.
pub(crate) fn drop_owned(rules: &[CredentialRule], tool: &str, arguments: &mut serde_json::Value) {
    if let Some(obj) = arguments.as_object_mut() {
        for rule in rules.iter().filter(|r| tool_matches_rule(tool, &r.tools)) {
            drop_caller_value(rule, obj);
        }
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

#[cfg(test)]
#[path = "secret_injection_flip_tests.rs"]
mod flip_tests;
