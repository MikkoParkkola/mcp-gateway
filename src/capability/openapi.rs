//! `OpenAPI` to Capability converter
//!
//! Generates capability YAML definitions from `OpenAPI` specifications.
//! Supports `OpenAPI` 3.0 and 3.1.
//!
//! # Usage
//!
//! ```ignore
//! let converter = OpenApiConverter::new();
//! let capabilities = converter.convert_file("api.yaml")?;
//! for cap in capabilities {
//!     cap.write_to_file("capabilities/")?;
//! }
//! ```

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// `OpenAPI` to Capability converter
pub struct OpenApiConverter {
    /// Base name prefix for generated capabilities
    prefix: Option<String>,
    /// Default auth configuration
    default_auth: Option<AuthTemplate>,
    /// Default cache configuration
    default_cache: Option<CacheTemplate>,
}

/// Template for auth configuration
#[derive(Debug, Clone)]
pub struct AuthTemplate {
    /// Auth type (oauth, `api_key`, bearer)
    pub auth_type: String,
    /// Credential key reference
    pub key: String,
    /// Description
    pub description: String,
}

/// Template for cache configuration
#[derive(Debug, Clone)]
pub struct CacheTemplate {
    /// Cache strategy
    pub strategy: String,
    /// TTL in seconds
    pub ttl: u64,
}

/// Generated capability definition (ready to write as YAML)
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedCapability {
    /// Capability name
    pub name: String,
    /// YAML content
    pub yaml: String,
}

impl GeneratedCapability {
    /// Write capability to a file in the specified directory
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the file cannot be written.
    pub fn write_to_file(&self, directory: &str) -> Result<()> {
        let dir = Path::new(directory);
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|e| Error::Config(format!("Failed to create directory: {e}")))?;
        }

        let filename = format!("{}.yaml", self.name);
        let path = dir.join(filename);

        fs::write(&path, &self.yaml)
            .map_err(|e| Error::Config(format!("Failed to write capability file: {e}")))?;

        info!(capability = %self.name, path = %path.display(), "Wrote capability file");
        Ok(())
    }
}

/// Simplified `OpenAPI` spec structure (just what we need)
#[derive(Debug, Deserialize)]
struct OpenApiSpec {
    openapi: Option<String>,
    swagger: Option<String>,
    info: OpenApiInfo,
    servers: Option<Vec<OpenApiServer>>,
    paths: HashMap<String, HashMap<String, OpenApiOperation>>,
    components: Option<OpenApiComponents>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields needed for parsing, may be used in future
struct OpenApiInfo {
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    version: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenApiServer {
    url: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct OpenApiOperation {
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Vec<OpenApiParameter>,
    #[serde(default)]
    request_body: Option<OpenApiRequestBody>,
    #[serde(default)]
    responses: HashMap<String, OpenApiResponse>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    security: Option<Vec<HashMap<String, Vec<String>>>>,
}

#[derive(Debug, Deserialize)]
struct OpenApiParameter {
    name: String,
    #[serde(rename = "in")]
    location: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    description: Option<String>,
    schema: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenApiRequestBody {
    #[serde(default)]
    required: bool,
    content: HashMap<String, OpenApiMediaType>,
}

#[derive(Debug, Deserialize)]
struct OpenApiMediaType {
    schema: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenApiResponse {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    content: Option<HashMap<String, OpenApiMediaType>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenApiComponents {
    #[serde(default)]
    schemas: HashMap<String, Value>,
    #[serde(default, rename = "securitySchemes")]
    security_schemes: HashMap<String, OpenApiSecurityScheme>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenApiSecurityScheme {
    #[serde(rename = "type")]
    scheme_type: String,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "in", default)]
    location: Option<String>,
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
        }
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
        // Try YAML first, then JSON
        let spec: OpenApiSpec = serde_yaml::from_str(content)
            .or_else(|_| serde_json::from_str(content))
            .map_err(|e| Error::Config(format!("Failed to parse OpenAPI spec: {e}")))?;

        self.convert_spec(&spec)
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

        // Get base URL
        let base_url = spec
            .servers
            .as_ref()
            .and_then(|s| s.first())
            .map_or_else(|| "https://api.example.com".to_string(), |s| s.url.clone());

        // Detect auth requirements
        let auth_required = spec
            .components
            .as_ref()
            .is_some_and(|c| !c.security_schemes.is_empty());

        let mut capabilities = Vec::new();

        for (path, methods) in &spec.paths {
            for (method, operation) in methods {
                match self.convert_operation(&base_url, path, method, operation, auth_required) {
                    Ok(cap) => capabilities.push(cap),
                    Err(e) => {
                        warn!(path = %path, method = %method, error = %e, "Skipping operation");
                    }
                }
            }
        }

        info!(count = capabilities.len(), "Generated capabilities");
        Ok(capabilities)
    }

    /// Convert a single operation to a capability
    #[allow(clippy::unnecessary_wraps)]
    fn convert_operation(
        &self,
        base_url: &str,
        path: &str,
        method: &str,
        op: &OpenApiOperation,
        auth_required: bool,
    ) -> Result<GeneratedCapability> {
        // Generate capability name
        let name = if let Some(ref id) = op.operation_id {
            self.format_name(id)
        } else {
            self.format_name(&format!("{}_{}", method, path.replace('/', "_")))
        };

        debug!(name = %name, path = %path, method = %method, "Converting operation");

        // Build description
        let description = op
            .summary
            .clone()
            .or_else(|| op.description.clone())
            .unwrap_or_else(|| format!("{} {}", method.to_uppercase(), path));

        // Build input schema from parameters
        let input_schema = self.build_input_schema(&op.parameters, op.request_body.as_ref());

        // Build output schema from responses
        let output_schema = self.build_output_schema(&op.responses);

        // Build the YAML
        let yaml = self.build_yaml(
            &name,
            &description,
            base_url,
            path,
            method,
            &op.parameters,
            &input_schema,
            &output_schema,
            auth_required,
        );

        Ok(GeneratedCapability { name, yaml })
    }

    /// Format a capability name
    fn format_name(&self, raw: &str) -> String {
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
    ) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        // Add parameters
        for param in params {
            let schema = param
                .schema
                .clone()
                .unwrap_or(serde_json::json!({"type": "string"}));
            let mut prop = if schema.is_object() {
                schema.as_object().cloned().unwrap_or_default()
            } else {
                serde_json::Map::new()
            };

            if let Some(ref desc) = param.description {
                prop.insert("description".to_string(), Value::String(desc.clone()));
            }

            properties.insert(param.name.clone(), Value::Object(prop));

            if param.required {
                required.push(Value::String(param.name.clone()));
            }
        }

        // Add request body properties (simplified - assumes object type)
        if let Some(body) = body {
            if let Some(media) = body.content.get("application/json") {
                if let Some(ref schema) = media.schema {
                    if let Some(body_props) = schema.get("properties").and_then(|p| p.as_object()) {
                        for (k, v) in body_props {
                            properties.insert(k.clone(), v.clone());
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
        }

        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required
        })
    }

    /// Build output schema from responses
    #[allow(clippy::unused_self)]
    fn build_output_schema(&self, responses: &HashMap<String, OpenApiResponse>) -> Value {
        // Look for 200 or 2xx response
        let response = responses
            .get("200")
            .or_else(|| responses.get("201"))
            .or_else(|| responses.get("default"));

        if let Some(resp) = response {
            if let Some(ref content) = resp.content {
                if let Some(media) = content.get("application/json") {
                    if let Some(ref schema) = media.schema {
                        return schema.clone();
                    }
                }
            }
        }

        // Default: any object
        serde_json::json!({"type": "object"})
    }

    /// Build the capability YAML
    #[allow(clippy::too_many_arguments)]
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
        auth_required: bool,
    ) -> String {
        // Build header params
        let header_params: Vec<_> = params.iter().filter(|p| p.location == "header").collect();

        // Build query params
        let query_params: Vec<_> = params.iter().filter(|p| p.location == "query").collect();

        // Check for body
        let has_body = method.eq_ignore_ascii_case("post")
            || method.eq_ignore_ascii_case("put")
            || method.eq_ignore_ascii_case("patch");

        let mut yaml = String::new();

        // Header comment
        let _ = writeln!(
            yaml,
            "# Auto-generated from OpenAPI spec\n# {}\n",
            description.lines().next().unwrap_or(name)
        );

        // Basic info
        yaml.push_str("fulcrum: \"1.0\"\n");
        let _ = writeln!(yaml, "name: {name}");
        let _ = writeln!(
            yaml,
            "description: {}\n",
            serde_yaml::to_string(&description).unwrap_or_else(|_| format!("\"{description}\""))
        );

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
        let _ = writeln!(yaml, "      base_url: {base_url}");
        let _ = writeln!(yaml, "      path: {path}");
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

        // Body placeholder for POST/PUT
        if has_body {
            yaml.push_str("      body:\n        # Add body template with {param} substitutions\n        {}\n");
        }

        yaml.push('\n');

        // Cache
        if let Some(ref cache) = self.default_cache {
            yaml.push_str("cache:\n");
            let _ = writeln!(yaml, "  strategy: {}", cache.strategy);
            let _ = writeln!(yaml, "  ttl: {}\n", cache.ttl);
        }

        // Auth
        yaml.push_str("auth:\n");
        if auth_required {
            yaml.push_str("  required: true\n");
            if let Some(ref auth) = self.default_auth {
                let _ = writeln!(yaml, "  type: {}", auth.auth_type);
                let _ = writeln!(yaml, "  key: {}", auth.key);
                let _ = writeln!(yaml, "  description: \"{}\"", auth.description);
            } else {
                yaml.push_str("  type: bearer\n  key: env:API_TOKEN\n  description: \"Set API_TOKEN environment variable\"\n");
            }
        } else {
            yaml.push_str("  required: false\n");
        }
        yaml.push('\n');

        // Metadata
        yaml.push_str("metadata:\n  category: api\n  tags: [openapi, generated]\n  cost_category: unknown\n  execution_time: medium\n");
        let read_only = method.eq_ignore_ascii_case("get") || method.eq_ignore_ascii_case("head");
        let _ = writeln!(yaml, "  read_only: {read_only}");

        yaml
    }
}

impl Default for OpenApiConverter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OPENAPI: &str = r#"
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.test.com
paths:
  /users/{id}:
    get:
      operationId: getUser
      summary: Get a user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Success
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
"#;

    #[test]
    fn test_convert_openapi() {
        let converter = OpenApiConverter::new();
        let caps = converter.convert_string(SAMPLE_OPENAPI).unwrap();

        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "getuser");
        assert!(caps[0].yaml.contains("base_url: https://api.test.com"));
        assert!(caps[0].yaml.contains("path: /users/{id}"));
        assert!(caps[0].yaml.contains("method: GET"));
    }

    #[test]
    fn test_with_prefix() {
        let converter = OpenApiConverter::new().with_prefix("myapi");
        let caps = converter.convert_string(SAMPLE_OPENAPI).unwrap();

        assert_eq!(caps[0].name, "myapi_getuser");
    }

    #[test]
    fn test_format_name() {
        let converter = OpenApiConverter::new();

        assert_eq!(converter.format_name("GetUser"), "getuser");
        assert_eq!(converter.format_name("get-user-by-id"), "get_user_by_id");
        // Duplicate underscores and trailing are cleaned up
        assert_eq!(converter.format_name("GET /users/{id}"), "get_users_id");
    }
}
