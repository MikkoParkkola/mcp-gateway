// SPDX-License-Identifier: MIT

//! `OpenAPI` -> capability conversion engine.
//!
//! Single responsibility: drive spec parsing, SSRF-guarded fetching, and
//! capability generation. Holds the SSRF hardening on `convert_url`.

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::security::ssrf::{PinningResolver, RedirectDecision, SystemResolver, redirect_decision};
use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

use super::auth::ResolvedAuth;
use super::generated::{AuthTemplate, CacheTemplate, GeneratedCapability};
use super::model::{
    OpenApiComponents, OpenApiOperation, OpenApiParameter, OpenApiRequestBody, OpenApiResponse,
    OpenApiSpec,
};
use super::refs::{resolve_parameter, resolve_request_body, resolve_schema_refs};
use super::sanitize::{sanitize_description, yaml_scalar};

/// `OpenAPI` to Capability converter
pub struct OpenApiConverter {
    /// Base name prefix for generated capabilities
    prefix: Option<String>,
    /// Default auth configuration
    default_auth: Option<AuthTemplate>,
    /// Default cache configuration
    default_cache: Option<CacheTemplate>,
    /// Host used when the spec's `servers` block is empty or relative
    /// (e.g. `/api/v3`).  Set automatically by `convert_url` to the host of
    /// the fetched spec.
    host_override: Option<String>,
}

impl OpenApiConverter {
    /// Create a new converter with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: None,
            default_auth: None,
            default_cache: Some(CacheTemplate {
                strategy: "exact".to_string(),
                ttl: 300,
            }),
            host_override: None,
        }
    }

    /// Set the host used to absolute-ify a relative `servers` URL.
    ///
    /// Typical use: when the `OpenAPI` `servers` block contains only a path
    /// (e.g. `/api/v3`, as in the Petstore sample), set this to the host
    /// portion of the fetched spec URL so the generated capabilities have a
    /// valid absolute `base_url`.
    #[must_use]
    pub fn with_host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }

    /// Set a prefix for generated capability names
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    /// Set default auth configuration for all capabilities
    #[must_use]
    pub fn with_default_auth(mut self, auth: AuthTemplate) -> Self {
        self.default_auth = Some(auth);
        self
    }

    /// Set default cache configuration
    #[must_use]
    pub fn with_default_cache(mut self, cache: CacheTemplate) -> Self {
        self.default_cache = Some(cache);
        self
    }

    /// Convert an `OpenAPI` spec file to capabilities
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the spec cannot be parsed.
    pub fn convert_file(&self, path: &str) -> Result<Vec<GeneratedCapability>> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("Failed to read OpenAPI spec: {e}")))?;

        self.convert_string(&content)
    }

    /// Convert an `OpenAPI` spec string to capabilities
    ///
    /// # Errors
    ///
    /// Returns an error if the content cannot be parsed as YAML or JSON.
    pub fn convert_string(&self, content: &str) -> Result<Vec<GeneratedCapability>> {
        // Try JSON first (most specs are served as JSON); fall back to YAML.
        let spec: OpenApiSpec = serde_json::from_str(content)
            .or_else(|_| serde_yaml::from_str(content))
            .map_err(|e| Error::Config(format!("Failed to parse OpenAPI spec: {e}")))?;

        self.convert_spec(&spec)
    }

    /// Fetch an `OpenAPI` spec from `url`, parse it, and convert it to
    /// capabilities.
    ///
    /// The host portion of `url` is automatically set as the converter's
    /// [`with_host_override`] so that relative `servers` entries (such as
    /// Petstore's `/api/v3`) resolve to absolute URLs in the generated
    /// capability YAML.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be fetched, the response is not a
    /// success status, or the spec cannot be parsed.
    pub async fn convert_url(&mut self, url: &str) -> Result<Vec<GeneratedCapability>> {
        info!(url = %url, "Fetching OpenAPI spec");
        let parsed = url::Url::parse(url)
            .map_err(|e| Error::Config(format!("Invalid OpenAPI spec URL '{url}': {e}")))?;

        // SSRF guard: reject private/reserved/loopback targets before any
        // outbound fetch, matching every other capability fetch path
        // (jsonrpc, graphql, executor, discovery, transport). The literal-URL
        // pre-check fails fast on obvious IP targets; the client below then
        // uses PinningResolver (validates every resolved IP, closing the
        // DNS-rebinding window, MIK-4019) and a redirect policy that re-checks
        // each hop, so a public URL cannot redirect into an internal address.
        // Validated unconditionally because convert_url carries no
        // AppState/config — a CLI-supplied spec URL is untrusted input.
        validate_url_not_ssrf(url)?;

        // Capture the host:port so relative `servers` blocks produce a
        // valid absolute base_url in the generated capability YAML.
        if self.host_override.is_none() {
            let scheme = parsed.scheme();
            let host = parsed.host_str().unwrap_or("");
            if !host.is_empty() {
                let port = parsed.port().map_or_else(String::new, |p| format!(":{p}"));
                self.host_override = Some(format!("{scheme}://{host}{port}"));
            }
        }

        let response = reqwest::Client::builder()
            .user_agent(format!("mcp-gateway/{}", env!("CARGO_PKG_VERSION")))
            .dns_resolver(PinningResolver::new(SystemResolver))
            .redirect(reqwest::redirect::Policy::custom(
                |attempt| match redirect_decision(attempt.previous().len(), attempt.url().as_str())
                {
                    RedirectDecision::Stop => attempt.stop(),
                    RedirectDecision::Block(msg) => attempt.error(msg),
                    RedirectDecision::Follow => attempt.follow(),
                },
            ))
            .build()
            .map_err(|e| Error::Config(format!("Failed to build HTTP client: {e}")))?
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Config(format!("Failed to fetch OpenAPI spec: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Config(format!(
                "OpenAPI spec fetch failed: HTTP {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| Error::Config(format!("Failed to read OpenAPI spec body: {e}")))?;

        self.convert_string(&body)
    }

    /// Convert a parsed `OpenAPI` spec to capabilities
    #[allow(clippy::unnecessary_wraps)]
    fn convert_spec(&self, spec: &OpenApiSpec) -> Result<Vec<GeneratedCapability>> {
        let version = spec
            .openapi
            .as_deref()
            .or(spec.swagger.as_deref())
            .unwrap_or("unknown");
        info!(title = %spec.info.title, version = %version, "Converting OpenAPI spec");

        let empty_components = OpenApiComponents::default();
        let components = spec.components.as_ref().unwrap_or(&empty_components);

        // Get base URL. If the servers block is missing or its URL is relative
        // (e.g. "/api/v3"), fall back to the override host supplied on the
        // converter (set automatically when importing from a URL) or a
        // placeholder the operator must edit before deploying.
        let raw_base = spec
            .servers
            .as_ref()
            .and_then(|s| s.first())
            .map(|s| s.url.clone());
        let base_url = Self::resolve_base_url(raw_base.as_deref(), self.host_override.as_deref());

        // Detect the best-match security scheme.
        let auth_scheme = self.pick_security_scheme(components);
        let auth_required = auth_scheme.is_some();

        let mut capabilities = Vec::new();

        for (path, methods) in &spec.paths {
            for (method, operation) in methods {
                if !Self::is_http_method(method) {
                    continue;
                }
                match self.convert_operation(
                    &base_url,
                    path,
                    method,
                    operation,
                    components,
                    auth_scheme.as_ref(),
                ) {
                    Ok(cap) => capabilities.push(cap),
                    Err(e) => {
                        warn!(path = %path, method = %method, error = %e, "Skipping operation");
                    }
                }
            }
        }

        // Stable ordering for deterministic output (tests + diffs).
        capabilities.sort_by(|a, b| a.name.cmp(&b.name));

        info!(
            count = capabilities.len(),
            auth = auth_required,
            "Generated capabilities"
        );
        Ok(capabilities)
    }

    /// True if `method` is one of the standard HTTP operation verbs used by
    /// `OpenAPI`. Any other key under a path (e.g. `parameters`, `summary`,
    /// `servers`) is ignored at conversion time.
    fn is_http_method(method: &str) -> bool {
        matches!(
            method.to_ascii_lowercase().as_str(),
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
        )
    }

    /// Pick a representative security scheme from `components.securitySchemes`.
    ///
    /// Preference order: bearer > `api_key` > oauth2 > basic. The first match
    /// wins; the full mapping is emitted in the generated `auth:` block.
    #[allow(clippy::unused_self)]
    fn pick_security_scheme(&self, components: &OpenApiComponents) -> Option<ResolvedAuth> {
        let schemes = &components.security_schemes;
        if schemes.is_empty() {
            return None;
        }

        // Prefer bearer HTTP auth.
        for (name, scheme) in schemes {
            let t = scheme.scheme_type.to_ascii_lowercase();
            if t == "http" && scheme.scheme.as_deref() == Some("bearer") {
                return Some(ResolvedAuth::bearer(name));
            }
        }
        // Then apiKey (header or query).
        for (name, scheme) in schemes {
            if scheme.scheme_type.eq_ignore_ascii_case("apikey") {
                return Some(ResolvedAuth::api_key(name, scheme));
            }
        }
        // Then oauth2.
        for (name, scheme) in schemes {
            if scheme.scheme_type.eq_ignore_ascii_case("oauth2") {
                return Some(ResolvedAuth::oauth2(name));
            }
        }
        // Finally basic.
        for (name, scheme) in schemes {
            let t = scheme.scheme_type.to_ascii_lowercase();
            if t == "http" && scheme.scheme.as_deref() == Some("basic") {
                return Some(ResolvedAuth::basic(name));
            }
        }
        // Unknown — emit a bearer placeholder so the capability still lists auth.
        schemes.keys().next().map(|n| ResolvedAuth::bearer(n))
    }

    /// Resolve the base URL from the `OpenAPI` `servers` block, combining it
    /// with an optional host override when the spec supplies only a path.
    pub(crate) fn resolve_base_url(raw: Option<&str>, host_override: Option<&str>) -> String {
        let raw = raw.unwrap_or("");
        if raw.is_empty() {
            return host_override
                .unwrap_or("https://api.example.com")
                .to_string();
        }
        // Absolute URL — use as-is.
        if raw.starts_with("http://") || raw.starts_with("https://") {
            return raw.to_string();
        }
        // Relative path (e.g. "/api/v3"). Combine with host override or emit
        // an example placeholder so the operator notices they must edit it.
        if let Some(host) = host_override {
            let host = host.trim_end_matches('/');
            return format!("{host}{raw}");
        }
        format!("https://api.example.com{raw}")
    }

    /// Convert a single operation to a capability
    #[allow(clippy::unnecessary_wraps)]
    fn convert_operation(
        &self,
        base_url: &str,
        path: &str,
        method: &str,
        op: &OpenApiOperation,
        components: &OpenApiComponents,
        auth_scheme: Option<&ResolvedAuth>,
    ) -> Result<GeneratedCapability> {
        // Generate capability name: prefer operationId, otherwise synthesise
        // one from `method_path` (so multiple ops on the same path remain
        // unique).
        let name = if let Some(ref id) = op.operation_id {
            self.format_name(id)
        } else {
            let slug = path.trim_start_matches('/').replace(['/', '{', '}'], "_");
            self.format_name(&format!("{method}_{slug}"))
        };

        debug!(name = %name, path = %path, method = %method, "Converting operation");

        // Build description (summary preferred, falls back to description,
        // then to a synthesized "METHOD /path" string).  Sanitize to strip
        // hidden instructions / control characters / oversized blobs.
        let raw_description = op
            .summary
            .clone()
            .or_else(|| op.description.clone())
            .unwrap_or_else(|| format!("{} {}", method.to_uppercase(), path));
        let description = sanitize_description(&raw_description);

        // Resolve $refs on every parameter before schema generation.
        let resolved_params: Vec<OpenApiParameter> = op
            .parameters
            .iter()
            .filter_map(|p| resolve_parameter(p, components))
            .collect();

        // Resolve $ref on the request body (if any).
        let resolved_body = op
            .request_body
            .as_ref()
            .and_then(|b| resolve_request_body(b, components));

        // Build input schema from resolved parameters and request body.
        let input_schema =
            self.build_input_schema(&resolved_params, resolved_body.as_ref(), components);

        // Build output schema from responses
        let output_schema = self.build_output_schema(&op.responses);

        // Build the YAML
        let yaml = self.build_yaml(
            &name,
            &description,
            base_url,
            path,
            method,
            &resolved_params,
            &input_schema,
            &output_schema,
            auth_scheme,
        );

        Ok(GeneratedCapability { name, yaml })
    }

    /// Format a capability name
    pub(crate) fn format_name(&self, raw: &str) -> String {
        let cleaned = raw
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .to_lowercase();

        // Remove duplicate underscores
        let mut result = String::new();
        let mut prev_underscore = false;
        for c in cleaned.chars() {
            if c == '_' {
                if !prev_underscore {
                    result.push(c);
                }
                prev_underscore = true;
            } else {
                result.push(c);
                prev_underscore = false;
            }
        }

        // Apply prefix
        if let Some(ref prefix) = self.prefix {
            format!("{}_{}", prefix, result.trim_matches('_'))
        } else {
            result.trim_matches('_').to_string()
        }
    }

    /// Build input schema from parameters and request body
    #[allow(clippy::unused_self)]
    fn build_input_schema(
        &self,
        params: &[OpenApiParameter],
        body: Option<&OpenApiRequestBody>,
        components: &OpenApiComponents,
    ) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        // Add parameters
        for param in params {
            if param.name.is_empty() {
                continue;
            }
            let schema = param
                .schema
                .clone()
                .map(|s| resolve_schema_refs(&s, components))
                .unwrap_or(serde_json::json!({"type": "string"}));
            let mut prop = if schema.is_object() {
                schema.as_object().cloned().unwrap_or_default()
            } else {
                serde_json::Map::new()
            };

            if let Some(ref desc) = param.description {
                let sanitized = sanitize_description(desc);
                if !sanitized.is_empty() {
                    prop.insert("description".to_string(), Value::String(sanitized));
                }
            }

            properties.insert(param.name.clone(), Value::Object(prop));

            if param.required {
                required.push(Value::String(param.name.clone()));
            }
        }

        // Add request body properties (simplified — assumes object type).
        // Prefer application/json, then the first entry, then form types.
        if let Some(body) = body {
            let media = body
                .content
                .get("application/json")
                .or_else(|| body.content.get("application/x-www-form-urlencoded"))
                .or_else(|| body.content.values().next());
            if let Some(media) = media
                && let Some(ref raw_schema) = media.schema
            {
                let schema = resolve_schema_refs(raw_schema, components);
                if let Some(body_props) = schema.get("properties").and_then(|p| p.as_object()) {
                    for (k, v) in body_props {
                        properties.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                if let Some(body_required) = schema.get("required").and_then(|r| r.as_array()) {
                    for r in body_required {
                        if !required.contains(r) {
                            required.push(r.clone());
                        }
                    }
                }
            }
        }

        if required.is_empty() {
            serde_json::json!({
                "type": "object",
                "properties": properties
            })
        } else {
            serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": required
            })
        }
    }

    /// Build output schema from responses
    #[allow(clippy::unused_self)]
    fn build_output_schema(&self, responses: &HashMap<String, OpenApiResponse>) -> Value {
        // Look for 200 or 2xx response
        let response = responses
            .get("200")
            .or_else(|| responses.get("201"))
            .or_else(|| responses.get("default"));

        if let Some(resp) = response
            && let Some(ref content) = resp.content
            && let Some(media) = content.get("application/json")
            && let Some(ref schema) = media.schema
        {
            return schema.clone();
        }

        // Default: any object
        serde_json::json!({"type": "object"})
    }

    /// Build the capability YAML
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn build_yaml(
        &self,
        name: &str,
        description: &str,
        base_url: &str,
        path: &str,
        method: &str,
        params: &[OpenApiParameter],
        input_schema: &Value,
        output_schema: &Value,
        auth_scheme: Option<&ResolvedAuth>,
    ) -> String {
        // Build header params — excluded when header is injected by the auth
        // layer (e.g. `Authorization`).
        let header_params: Vec<_> = params
            .iter()
            .filter(|p| p.location.eq_ignore_ascii_case("header"))
            .filter(|p| {
                auth_scheme
                    .and_then(|a| a.header.as_deref())
                    .is_none_or(|h| !h.eq_ignore_ascii_case(&p.name))
            })
            .collect();

        // Build query params — excluded when matching the auth query param.
        let query_params: Vec<_> = params
            .iter()
            .filter(|p| p.location.eq_ignore_ascii_case("query"))
            .filter(|p| {
                auth_scheme
                    .and_then(|a| a.query_param.as_deref())
                    .is_none_or(|q| q != p.name)
            })
            .collect();

        let mut yaml = String::new();

        // Header comment
        let first_line = description
            .lines()
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(name);
        let _ = writeln!(yaml, "# Auto-generated from OpenAPI spec");
        let _ = writeln!(yaml, "# {first_line}");
        yaml.push('\n');

        // Basic info
        yaml.push_str("fulcrum: \"1.0\"\n");
        let _ = writeln!(yaml, "name: {name}");
        let _ = writeln!(yaml, "description: {}", yaml_scalar(description));
        yaml.push('\n');

        // Schema
        yaml.push_str("schema:\n  input:\n");
        for line in serde_yaml::to_string(input_schema)
            .unwrap_or_default()
            .lines()
        {
            let _ = writeln!(yaml, "    {line}");
        }
        yaml.push_str("  output:\n");
        for line in serde_yaml::to_string(output_schema)
            .unwrap_or_default()
            .lines()
        {
            let _ = writeln!(yaml, "    {line}");
        }
        yaml.push('\n');

        // Provider
        yaml.push_str("providers:\n  primary:\n    service: rest\n    cost_per_call: 0\n    timeout: 30\n    config:\n");
        let _ = writeln!(yaml, "      base_url: {}", yaml_scalar(base_url));
        let _ = writeln!(yaml, "      path: {}", yaml_scalar(path));
        let _ = writeln!(yaml, "      method: {}", method.to_uppercase());

        // Headers
        if !header_params.is_empty() {
            yaml.push_str("      headers:\n");
            for param in &header_params {
                let _ = writeln!(yaml, "        {}: \"{{{}}}\"", param.name, param.name);
            }
        }

        // Query params
        if !query_params.is_empty() {
            yaml.push_str("      params:\n");
            for param in &query_params {
                let _ = writeln!(yaml, "        {}: \"{{{}}}\"", param.name, param.name);
            }
        }

        yaml.push('\n');

        // Cache — only emit for safe methods.
        let safe_method = method.eq_ignore_ascii_case("get") || method.eq_ignore_ascii_case("head");
        if safe_method && let Some(ref cache) = self.default_cache {
            yaml.push_str("cache:\n");
            let _ = writeln!(yaml, "  strategy: {}", cache.strategy);
            let _ = writeln!(yaml, "  ttl: {}", cache.ttl);
            yaml.push('\n');
        }

        // Auth
        yaml.push_str("auth:\n");
        if let Some(auth) = auth_scheme {
            yaml.push_str("  required: true\n");
            // CLI `--auth-key` flag wins over the auto-detected key.
            let (auth_type, key, description, header, prefix) =
                if let Some(ref override_tpl) = self.default_auth {
                    (
                        override_tpl.auth_type.clone(),
                        override_tpl.key.clone(),
                        override_tpl.description.clone(),
                        auth.header.clone(),
                        auth.prefix.clone(),
                    )
                } else {
                    (
                        auth.auth_type.clone(),
                        auth.key.clone(),
                        auth.description.clone(),
                        auth.header.clone(),
                        auth.prefix.clone(),
                    )
                };
            let _ = writeln!(yaml, "  type: {auth_type}");
            let _ = writeln!(yaml, "  key: {key}");
            let _ = writeln!(yaml, "  description: {}", yaml_scalar(&description));
            if let Some(h) = header {
                let _ = writeln!(yaml, "  header: {h}");
            }
            if let Some(q) = &auth.query_param {
                let _ = writeln!(yaml, "  param: {q}");
            }
            if let Some(p) = prefix {
                let _ = writeln!(yaml, "  prefix: {p}");
            }
        } else if let Some(ref auth) = self.default_auth {
            // No scheme detected but the operator pinned an auth key on the
            // CLI — emit it so the capability is still usable.
            yaml.push_str("  required: true\n");
            let _ = writeln!(yaml, "  type: {}", auth.auth_type);
            let _ = writeln!(yaml, "  key: {}", auth.key);
            let _ = writeln!(yaml, "  description: {}", yaml_scalar(&auth.description));
        } else {
            yaml.push_str("  required: false\n  type: none\n");
        }
        yaml.push('\n');

        // Metadata
        yaml.push_str("metadata:\n  category: api\n  tags: [openapi, generated]\n  cost_category: unknown\n  execution_time: medium\n");
        let _ = writeln!(yaml, "  read_only: {safe_method}");

        yaml
    }
}

impl Default for OpenApiConverter {
    fn default() -> Self {
        Self::new()
    }
}
