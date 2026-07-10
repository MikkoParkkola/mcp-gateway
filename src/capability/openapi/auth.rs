// SPDX-License-Identifier: MIT

//! Auth-scheme resolution.
//!
//! Single responsibility: turn an `OpenAPI` `securitySchemes` entry into the
//! internal `ResolvedAuth` used while emitting capability YAML.

use super::model::OpenApiSecurityScheme;

/// Auth scheme resolved from an `OpenAPI` `securitySchemes` entry.
///
/// This is the internal representation used while building the capability
/// YAML. It captures the scheme name, mcp-gateway auth type, optional HTTP
/// header, optional query parameter (for `apiKey in: query`), and a
/// human-readable description pointing at the credential env var.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedAuth {
    /// mcp-gateway auth type (`bearer`, `api_key`, `oauth`, `basic`).
    pub(crate) auth_type: String,
    /// Credential reference (e.g. `env:MYAPI_TOKEN`). Overridden by the
    /// `--auth-key` CLI flag via `with_default_auth`.
    pub(crate) key: String,
    /// Human-readable description.
    pub(crate) description: String,
    /// HTTP header name when the scheme places the credential in a header.
    pub(crate) header: Option<String>,
    /// Query parameter name when the scheme places the credential in the
    /// query string (apiKey `in: query`).
    pub(crate) query_param: Option<String>,
    /// Header prefix (e.g. `Bearer`).
    pub(crate) prefix: Option<String>,
}

impl ResolvedAuth {
    pub(crate) fn bearer(scheme_name: &str) -> Self {
        Self {
            auth_type: "bearer".to_string(),
            key: format!("env:{}", env_var_from_scheme(scheme_name)),
            description: format!("Bearer token from OpenAPI security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Bearer".to_string()),
        }
    }

    pub(crate) fn api_key(scheme_name: &str, scheme: &OpenApiSecurityScheme) -> Self {
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

    pub(crate) fn oauth2(scheme_name: &str) -> Self {
        Self {
            auth_type: "oauth".to_string(),
            key: format!("oauth:{}", slugify_lowercase(scheme_name)),
            description: format!("OAuth2 token for security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Bearer".to_string()),
        }
    }

    pub(crate) fn basic(scheme_name: &str) -> Self {
        Self {
            auth_type: "basic".to_string(),
            key: format!("env:{}", env_var_from_scheme(scheme_name)),
            description: format!("HTTP Basic auth for security scheme '{scheme_name}'"),
            header: Some("Authorization".to_string()),
            query_param: None,
            prefix: Some("Basic".to_string()),
        }
    }
}

/// Convert an `OpenAPI` security scheme name into a conventional environment
/// variable name. For example, `petstore_auth` → `PETSTORE_AUTH_TOKEN`.
pub(crate) fn env_var_from_scheme(scheme_name: &str) -> String {
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

/// Lowercase slug form of an `OpenAPI` security scheme name, used as the
/// OAuth provider key (e.g. `oauth:petstore_auth`).
pub(crate) fn slugify_lowercase(s: &str) -> String {
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
