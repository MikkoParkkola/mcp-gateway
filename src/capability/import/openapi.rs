//! OpenAPI → `CapabilityDraft` converter
//!
//! Refactors the existing `OpenApiConverter` to produce `CapabilityDraft`
//! values before YAML generation, preserving existing auth, parameter,
//! request-body, response-schema, examples, and deterministic operation
//! ordering behavior.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, info, warn};

use super::draft::{
    CapabilityDraft, DraftAuth, DraftExample, ImportSourceKind, ReviewState, SafetyClassification,
    TrustCardStub,
};
use crate::{Error, Result};

// ── Re-exported OpenAPI spec structures ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct OpenApiSpec {
    openapi: Option<String>,
    swagger: Option<String>,
    info: OpenApiInfo,
    servers: Option<Vec<OpenApiServer>>,
    paths: HashMap<String, HashMap<String, OpenApiOperation>>,
    components: Option<OpenApiComponents>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiInfo {
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiServer {
    url: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiOperation {
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Vec<OpenApiParameter>,
    #[serde(default)]
    pub request_body: Option<OpenApiRequestBody>,
    #[serde(default)]
    pub responses: HashMap<String, OpenApiResponse>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub security: Option<Vec<HashMap<String, Vec<String>>>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenApiParameter {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "in", default)]
    pub location: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub schema: Option<Value>,
    #[serde(default, rename = "$ref")]
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenApiRequestBody {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub content: HashMap<String, OpenApiMediaType>,
    #[serde(default, rename = "$ref")]
    pub reference: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenApiMediaType {
    #[serde(default)]
    pub schema: Option<Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenApiResponse {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub content: Option<HashMap<String, OpenApiMediaType>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OpenApiComponents {
    #[serde(default)]
    pub schemas: HashMap<String, Value>,
    #[serde(default, rename = "securitySchemes")]
    pub security_schemes: HashMap<String, OpenApiSecurityScheme>,
    #[serde(default)]
    pub parameters: HashMap<String, OpenApiParameter>,
    #[serde(default, rename = "requestBodies")]
    pub request_bodies: HashMap<String, OpenApiRequestBody>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiSecurityScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "in", default)]
    pub location: Option<String>,
}

// ── Resolved auth (same as in openapi.rs) ───────────────────────────────

#[derive(Debug, Clone)]
struct ResolvedAuth {
    auth_type: String,
    key: String,
    description: String,
    header: Option<String>,
    query_param: Option<String>,
    prefix: Option<String>,
}

impl ResolvedAuth {
    fn bearer(scheme_name: &str) -> Self {
        Self {
            auth_type: "bearer".to_string(),
            key: format!("env:{}", env_var_from_scheme(scheme_name)),
            description: format!("Bearer token from OpenAPI security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Bearer".to_string()),
        }
    }

    fn api_key(scheme_name: &str, scheme: &OpenApiSecurityScheme) -> Self {
        let header_name = scheme
            .location
            .as_deref()
            .filter(|l| l.eq_ignore_ascii_case("header"))
            .and(scheme.name.clone());
        let query_name = scheme
            .location
            .as_deref()
            .filter(|l| l.eq_ignore_ascii_case("query"))
            .and(scheme.name.clone());
        Self {
            auth_type: "api_key".to_string(),
            key: format!("env:{}", env_var_from_scheme(scheme_name)),
            description: format!("API key from OpenAPI security scheme '{scheme_name}'"),
            header: header_name,
            query_param: query_name,
            prefix: None,
        }
    }

    fn oauth2(scheme_name: &str) -> Self {
        Self {
            auth_type: "oauth".to_string(),
            key: format!("oauth:{}", slugify_lowercase(scheme_name)),
            description: format!("OAuth2 token for security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Bearer".to_string()),
        }
    }

    fn basic(scheme_name: &str) -> Self {
        Self {
            auth_type: "basic".to_string(),
            key: format!("env:{}", env_var_from_scheme(scheme_name)),
            description: format!("HTTP Basic auth for security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Basic".to_string()),
        }
    }

    fn to_draft_auth(&self) -> DraftAuth {
        DraftAuth {
            auth_type: self.auth_type.clone(),
            key: self.key.clone(),
            description: self.description.clone(),
            header: self.header.clone(),
            query_param: self.query_param.clone(),
            prefix: self.prefix.clone(),
        }
    }
}

fn env_var_from_scheme(scheme_name: &str) -> String {
    let upper: String = scheme_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{}_TOKEN", upper.trim_matches('_'))
}

fn slugify_lowercase(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_description(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut consecutive_newlines = 0;
    for c in raw.chars() {
        if c.is_control() && c != '\n' {
            continue;
        }
        if c == '\n' {
            consecutive_newlines += 1;
            if consecutive_newlines > 2 {
                continue;
            }
        } else {
            consecutive_newlines = 0;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.len() > 2000 {
        format!("{}…", &trimmed[..2000])
    } else {
        trimmed.to_string()
    }
}

// ── $ref resolution ─────────────────────────────────────────────────────

fn resolve_parameter(
    p: &OpenApiParameter,
    components: &OpenApiComponents,
) -> Option<OpenApiParameter> {
    if let Some(ref ref_path) = p.reference {
        let name = ref_path.strip_prefix("#/components/parameters/")?;
        return components.parameters.get(name).cloned().or_else(|| {
            // Try the resolved name as-is
            Some(OpenApiParameter {
                name: name.to_string(),
                location: "query".to_string(),
                required: false,
                description: None,
                schema: None,
                reference: None,
            })
        });
    }
    Some(p.clone())
}

fn resolve_request_body(
    b: &OpenApiRequestBody,
    components: &OpenApiComponents,
) -> Option<OpenApiRequestBody> {
    if let Some(ref ref_path) = b.reference {
        let name = ref_path.strip_prefix("#/components/requestBodies/")?;
        return components.request_bodies.get(name).cloned();
    }
    Some(b.clone())
}

fn resolve_schema_refs(schema: &Value, components: &OpenApiComponents) -> Value {
    if let Some(ref_path) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(name) = ref_path.strip_prefix("#/components/schemas/") {
            if let Some(resolved) = components.schemas.get(name) {
                return resolve_schema_refs(resolved, components);
            }
        }
    }
    if let Some(obj) = schema.as_object() {
        let mut resolved = serde_json::Map::new();
        for (k, v) in obj {
            if k == "$ref" {
                if let Some(ref_path) = v.as_str()
                    && let Some(name) = ref_path.strip_prefix("#/components/schemas/")
                {
                    if let Some(s) = components.schemas.get(name) {
                        let inner = resolve_schema_refs(s, components);
                        if let Some(inner_obj) = inner.as_object() {
                            for (ik, iv) in inner_obj {
                                resolved.insert(ik.clone(), iv.clone());
                            }
                        }
                        continue;
                    }
                }
            }
            resolved.insert(k.clone(), resolve_schema_refs(v, components));
        }
        return Value::Object(resolved);
    }
    if let Some(arr) = schema.as_array() {
        return Value::Array(
            arr.iter()
                .map(|v| resolve_schema_refs(v, components))
                .collect(),
        );
    }
    schema.clone()
}

// ── The converter ───────────────────────────────────────────────────────

/// Converts OpenAPI specifications into `CapabilityDraft` values.
///
/// This is the new import layer replacing direct YAML generation in
/// `OpenApiConverter`. Produces `CapabilityDraft` values that the
/// `ImportGenerator` then materializes as YAML, TrustCards, and risk
/// reports.
pub struct OpenApiDraftConverter {
    /// Base name prefix for generated capabilities.
    prefix: Option<String>,
    /// Default auth configuration (CLI override).
    default_auth: Option<DraftAuth>,
    /// Host override for relative `servers` entries.
    host_override: Option<String>,
    /// Source URL or file path for TrustCard metadata.
    source_id: String,
}

impl OpenApiDraftConverter {
    /// Create a new converter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: None,
            default_auth: None,
            host_override: None,
            source_id: String::new(),
        }
    }

    /// Set the source identity for TrustCard metadata.
    #[must_use]
    pub fn with_source_id(mut self, id: &str) -> Self {
        self.source_id = id.to_string();
        self
    }

    /// Set a prefix for generated capability names.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    /// Set default auth configuration.
    #[must_use]
    pub fn with_default_auth(mut self, auth: DraftAuth) -> Self {
        self.default_auth = Some(auth);
        self
    }

    /// Set the host override.
    #[must_use]
    pub fn with_host_override(mut self, host: &str) -> Self {
        self.host_override = Some(host.to_string());
        self
    }

    /// Convert an OpenAPI spec string to `CapabilityDraft` values.
    ///
    /// # Errors
    ///
    /// Returns an error if the content cannot be parsed.
    pub fn convert_string(&self, content: &str) -> Result<Vec<CapabilityDraft>> {
        let spec: OpenApiSpec = serde_json::from_str(content)
            .or_else(|_| serde_yaml::from_str(content))
            .map_err(|e| Error::Config(format!("Failed to parse OpenAPI spec: {e}")))?;

        self.convert_spec(&spec)
    }

    /// Convert a parsed OpenAPI spec to drafts.
    fn convert_spec(&self, spec: &OpenApiSpec) -> Result<Vec<CapabilityDraft>> {
        let version = spec
            .openapi
            .as_deref()
            .or(spec.swagger.as_deref())
            .unwrap_or("unknown");
        info!(title = %spec.info.title, version = %version, "Converting OpenAPI spec to drafts");

        let empty_components = OpenApiComponents::default();
        let components = spec.components.as_ref().unwrap_or(&empty_components);

        let raw_base = spec
            .servers
            .as_ref()
            .and_then(|s| s.first())
            .map(|s| s.url.clone());
        let base_url = resolve_base_url(raw_base.as_deref(), self.host_override.as_deref());

        let auth_scheme = pick_security_scheme(components);
        let auth_required = auth_scheme.is_some();

        let source_hash = compute_source_hash(spec);

        let mut drafts = Vec::new();

        for (path, methods) in &spec.paths {
            for (method, operation) in methods {
                if !is_http_method(method) {
                    continue;
                }
                match self.convert_operation(
                    &base_url,
                    path,
                    method,
                    operation,
                    components,
                    auth_scheme.as_ref(),
                    auth_required,
                    &source_hash,
                ) {
                    Ok(draft) => drafts.push(draft),
                    Err(e) => {
                        warn!(path = %path, method = %method, error = %e, "Skipping operation");
                    }
                }
            }
        }

        // Deterministic sort by name
        drafts.sort_by(|a, b| a.name.cmp(&b.name));

        info!(count = drafts.len(), "Generated capability drafts");
        Ok(drafts)
    }

    #[allow(clippy::too_many_arguments)]
    fn convert_operation(
        &self,
        base_url: &str,
        path: &str,
        method: &str,
        op: &OpenApiOperation,
        components: &OpenApiComponents,
        auth_scheme: Option<&ResolvedAuth>,
        auth_required: bool,
        source_hash: &str,
    ) -> Result<CapabilityDraft> {
        let name = if let Some(ref id) = op.operation_id {
            format_name_raw(id, self.prefix.as_deref())
        } else {
            let slug = path.trim_start_matches('/').replace(['/', '{', '}'], "_");
            format_name_raw(&format!("{method}_{slug}"), self.prefix.as_deref())
        };

        let raw_description = op
            .summary
            .clone()
            .or_else(|| op.description.clone())
            .unwrap_or_else(|| format!("{} {}", method.to_uppercase(), path));
        let description = sanitize_description(&raw_description);

        let resolved_params: Vec<OpenApiParameter> = op
            .parameters
            .iter()
            .filter_map(|p| resolve_parameter(p, components))
            .collect();

        let resolved_body = op
            .request_body
            .as_ref()
            .and_then(|b| resolve_request_body(b, components));

        let input_schema =
            build_input_schema(&resolved_params, resolved_body.as_ref(), components);
        let output_schema = build_output_schema(&op.responses);

        // Build examples
        let mut examples = Vec::new();
        if let Some(body) = &resolved_body {
            if let Some(media) = body.content.get("application/json")
                && let Some(ref schema) = media.schema
            {
                let resolved = resolve_schema_refs(schema, components);
                examples.push(DraftExample {
                    description: format!("Example request for {name}"),
                    input: resolved,
                    output: output_schema.clone(),
                });
            }
        }
        if examples.is_empty() && !resolved_params.is_empty() {
            let mut example_input = serde_json::Map::new();
            for p in &resolved_params {
                if !p.name.is_empty() {
                    let val = p.schema.as_ref().and_then(example_value_for_schema)
                        .unwrap_or(Value::String("example".to_string()));
                    example_input.insert(p.name.clone(), val);
                }
            }
            examples.push(DraftExample {
                description: format!("Example request for {name}"),
                input: Value::Object(example_input),
                output: output_schema.clone(),
            });
        }

        let safety = SafetyClassification::from_http_method(method);
        let review_state = if safety.requires_review() {
            ReviewState::Pending
        } else {
            ReviewState::Approved
        };
        let enabled = !safety.requires_review();

        // Build auth
        let auth = if let Some(ref override_auth) = self.default_auth {
            (*override_auth).clone()
        } else if let Some(a) = auth_scheme {
            a.to_draft_auth()
        } else {
            DraftAuth::default()
        };

        // Extract headers and query params
        let mut headers = HashMap::new();
        let mut query_params = HashMap::new();
        for p in &resolved_params {
            if p.location.eq_ignore_ascii_case("header") {
                if auth_scheme
                    .and_then(|a| a.header.as_deref())
                    .is_none_or(|h| !h.eq_ignore_ascii_case(&p.name))
                {
                    headers.insert(p.name.clone(), format!("{{{}}}", p.name));
                }
            } else if p.location.eq_ignore_ascii_case("query") {
                if auth_scheme
                    .and_then(|a| a.query_param.as_deref())
                    .is_none_or(|q| q != p.name)
                {
                    query_params.insert(p.name.clone(), format!("{{{}}}", p.name));
                }
            }
        }

        // Request body
        let request_body = resolved_body.as_ref().and_then(|b| {
            b.content
                .get("application/json")
                .and_then(|m| m.schema.clone().map(|s| resolve_schema_refs(&s, components)))
        });

        // TrustCard stub
        let trust_card = Some(TrustCardStub {
            reviewer: None,
            notes: format!("Auto-generated from OpenAPI import of {}", self.source_id),
            generated_at: chrono::Utc::now().to_rfc3339(),
            source_url: self.source_id.clone(),
            source_hash: source_hash.to_string(),
            risk_annotations: if safety.requires_review() {
                vec![format!(
                    "{} operation {} requires review — {}",
                    method.to_uppercase(),
                    name,
                    safety_risk_label(&safety)
                )]
            } else {
                vec!["Read-only operation — low risk".to_string()]
            },
        });

        let tags = op.tags.clone();

        Ok(CapabilityDraft {
            source_kind: ImportSourceKind::OpenApi,
            source_id: self.source_id.clone(),
            protocol: "rest".to_string(),
            name,
            description,
            auth,
            input_schema,
            output_schema,
            examples,
            safety,
            review_state,
            enabled,
            trust_card,
            http_method: method.to_uppercase(),
            base_url: base_url.to_string(),
            path: path.to_string(),
            request_body,
            headers,
            query_params,
            auth_required,
            max_depth: None,
            max_complexity: None,
            oci_package_args: Vec::new(),
            oci_transport: None,
            tags,
        })
    }
}

impl Default for OpenApiDraftConverter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ────────────────────────────────────────────────────

fn is_http_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
}

fn pick_security_scheme(components: &OpenApiComponents) -> Option<ResolvedAuth> {
    let schemes = &components.security_schemes;
    if schemes.is_empty() {
        return None;
    }
    for (name, scheme) in schemes {
        let t = scheme.scheme_type.to_ascii_lowercase();
        if t == "http" && scheme.scheme.as_deref() == Some("bearer") {
            return Some(ResolvedAuth::bearer(name));
        }
    }
    for (name, scheme) in schemes {
        if scheme.scheme_type.eq_ignore_ascii_case("apikey") {
            return Some(ResolvedAuth::api_key(name, scheme));
        }
    }
    for (name, scheme) in schemes {
        if scheme.scheme_type.eq_ignore_ascii_case("oauth2") {
            return Some(ResolvedAuth::oauth2(name));
        }
    }
    for (name, scheme) in schemes {
        let t = scheme.scheme_type.to_ascii_lowercase();
        if t == "http" && scheme.scheme.as_deref() == Some("basic") {
            return Some(ResolvedAuth::basic(name));
        }
    }
    schemes.keys().next().map(|n| ResolvedAuth::bearer(n))
}

fn resolve_base_url(raw: Option<&str>, host_override: Option<&str>) -> String {
    let raw = raw.unwrap_or("");
    if raw.is_empty() {
        return host_override.unwrap_or("https://api.example.com").to_string();
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return raw.to_string();
    }
    if let Some(host) = host_override {
        let host = host.trim_end_matches('/');
        return format!("{host}{raw}");
    }
    format!("https://api.example.com{raw}")
}

fn format_name_raw(raw: &str, prefix: Option<&str>) -> String {
    let cleaned: String = raw
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
    let trimmed = result.trim_matches('_').to_string();
    if let Some(p) = prefix {
        format!("{p}_{trimmed}")
    } else {
        trimmed
    }
}

fn build_input_schema(
    params: &[OpenApiParameter],
    body: Option<&OpenApiRequestBody>,
    components: &OpenApiComponents,
) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

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
        serde_json::json!({"type": "object", "properties": properties})
    } else {
        serde_json::json!({"type": "object", "properties": properties, "required": required})
    }
}

fn build_output_schema(responses: &HashMap<String, OpenApiResponse>) -> Value {
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
    serde_json::json!({"type": "object"})
}

fn example_value_for_schema(schema: &Value) -> Option<Value> {
    if let Some(example) = schema.get("example") {
        return Some(example.clone());
    }
    if let Some(examples) = schema.get("examples").and_then(|v| v.as_array())
        && !examples.is_empty()
    {
        return Some(examples[0].clone());
    }
    match schema.get("type").and_then(|v| v.as_str()) {
        Some("string") => schema
            .get("default")
            .cloned()
            .or(Some(Value::String("example".to_string()))),
        Some("integer") | Some("number") => schema
            .get("default")
            .cloned()
            .or(Some(serde_json::json!(0))),
        Some("boolean") => schema
            .get("default")
            .cloned()
            .or(Some(Value::Bool(false))),
        _ => None,
    }
}

fn compute_source_hash(spec: &OpenApiSpec) -> String {
    use sha2::{Digest, Sha256};
    // Hash a deterministic serialization of key fields
    let mut hasher = Sha256::new();
    hasher.update(spec.info.title.as_bytes());
    hasher.update(spec.info.version.as_bytes());
    // Sort paths for deterministic hashing
    let mut path_keys: Vec<&String> = spec.paths.keys().collect();
    path_keys.sort();
    for pk in path_keys {
        hasher.update(pk.as_bytes());
        if let Some(methods) = spec.paths.get(pk) {
            let mut method_keys: Vec<&String> = methods.keys().collect();
            method_keys.sort();
            for mk in method_keys {
                hasher.update(mk.as_bytes());
            }
        }
    }
    hex::encode(hasher.finalize())
}

fn safety_risk_label(safety: &SafetyClassification) -> &'static str {
    match safety {
        SafetyClassification::ReadOnly => "safe read",
        SafetyClassification::Mutation => "mutates state",
        SafetyClassification::Destructive => "destroys data",
        SafetyClassification::OpenWorld => "broad external access",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETSTORE_JSON: &str = r##"{
      "openapi": "3.0.0",
      "info": { "title": "Petstore", "version": "1.0.0" },
      "servers": [{ "url": "/api/v3" }],
      "paths": {
        "/pet": {
          "post": {
            "operationId": "addPet",
            "summary": "Add a new pet",
            "requestBody": {
              "required": true,
              "content": {
                "application/json": {
                  "schema": { "$ref": "#/components/schemas/Pet" }
                }
              }
            },
            "responses": { "200": { "description": "ok" } }
          }
        },
        "/pet/findByStatus": {
          "get": {
            "operationId": "findPetsByStatus",
            "summary": "Finds Pets by status",
            "parameters": [{
              "name": "status",
              "in": "query",
              "required": false,
              "schema": { "type": "string", "default": "available" }
            }],
            "responses": { "200": { "description": "ok" } }
          }
        },
        "/pet/{petId}": {
          "get": {
            "operationId": "getPetById",
            "summary": "Find pet by ID",
            "parameters": [{
              "name": "petId",
              "in": "path",
              "required": true,
              "schema": { "type": "integer", "format": "int64" }
            }],
            "responses": { "200": { "description": "ok" } }
          },
          "delete": {
            "summary": "Deletes a pet",
            "responses": { "400": { "description": "bad" } }
          }
        }
      },
      "components": {
        "schemas": {
          "Pet": {
            "type": "object",
            "required": ["name"],
            "properties": {
              "id": { "type": "integer" },
              "name": { "type": "string" }
            }
          }
        },
        "securitySchemes": {
          "api_key": { "type": "apiKey", "name": "api_key", "in": "header" }
        }
      }
    }"##;

    #[test]
    fn openapi_drafts_have_auth_and_schemas() {
        let converter = OpenApiDraftConverter::new()
            .with_source_id("petstore.json")
            .with_host_override("https://petstore3.swagger.io");
        let drafts = converter.convert_string(PETSTORE_JSON).unwrap();
        assert!(!drafts.is_empty(), "should produce drafts");

        // Check deterministic ordering
        let names: Vec<&str> = drafts.iter().map(|d| d.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "drafts must be deterministically sorted");

        // addPet is a POST → mutation → review required
        let add_pet = drafts.iter().find(|d| d.name == "addpet").unwrap();
        assert_eq!(add_pet.http_method, "POST");
        assert_eq!(add_pet.safety, SafetyClassification::Mutation);
        assert!(add_pet.review_required());
        assert!(!add_pet.enabled);
        assert!(add_pet.trust_card.is_some());
        assert!(add_pet.auth.auth_type == "api_key");

        // findPetsByStatus is a GET → read-only → approved
        let find = drafts.iter().find(|d| d.name == "findpetsbystatus").unwrap();
        assert_eq!(find.http_method, "GET");
        assert_eq!(find.safety, SafetyClassification::ReadOnly);
        assert!(!find.review_required());
        assert!(find.enabled);
    }

    #[test]
    fn openapi_drafts_produce_deterministic_order() {
        let converter = OpenApiDraftConverter::new()
            .with_source_id("petstore.json")
            .with_host_override("https://petstore3.swagger.io");
        let drafts1 = converter.convert_string(PETSTORE_JSON).unwrap();
        let drafts2 = converter.convert_string(PETSTORE_JSON).unwrap();
        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2, "two generations must produce identical order");
    }

    #[test]
    fn openapi_drafts_preserve_examples() {
        let converter = OpenApiDraftConverter::new()
            .with_source_id("petstore.json")
            .with_host_override("https://petstore3.swagger.io");
        let drafts = converter.convert_string(PETSTORE_JSON).unwrap();
        let find = drafts.iter().find(|d| d.name == "findpetsbystatus").unwrap();
        assert!(
            !find.examples.is_empty(),
            "findPetsByStatus should have examples"
        );
    }

    #[test]
    fn openapi_drafts_trust_card_has_risk_annotations() {
        let converter = OpenApiDraftConverter::new()
            .with_source_id("petstore.json")
            .with_host_override("https://petstore3.swagger.io");
        let drafts = converter.convert_string(PETSTORE_JSON).unwrap();
        let delete = drafts
            .iter()
            .find(|d| d.http_method == "DELETE")
            .unwrap();
        let tc = delete.trust_card.as_ref().unwrap();
        assert!(
            tc.risk_annotations
                .iter()
                .any(|r| r.contains("review")),
            "delete should have risk annotation about review: {:?}",
            tc.risk_annotations
        );
    }
}
