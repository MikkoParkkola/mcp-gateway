// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How [`CapabilityExecutor`] builds a REST request: the URL with its path
//! parameters, the headers with injected credentials, and the static query
//! parameters (moved from `mod.rs`).

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use super::{CapabilityExecutor, RestConfig};
use crate::capability::CapabilityExecutionContext;
use crate::{Error, Result};

impl CapabilityExecutor {
    /// Build URL with path parameter substitution.
    #[allow(clippy::unused_self)]
    pub(super) fn build_url(&self, config: &RestConfig, params: &Value) -> Result<String> {
        let url = if config.uses_endpoint() {
            config.endpoint.clone()
        } else {
            let path = if let Some(selector) = &config.path_selector {
                let selected = match params.get(&selector.parameter) {
                    None | Some(Value::Null) => selector.default.as_str(),
                    Some(Value::String(value)) => value.as_str(),
                    Some(_) => {
                        return Err(Error::Config(format!(
                            "REST path selector parameter '{}' must be a string",
                            selector.parameter
                        )));
                    }
                };

                let path = selector.paths.get(selected).ok_or_else(|| {
                    Error::Config(format!(
                        "No path is configured for REST path selector parameter '{}'",
                        selector.parameter
                    ))
                })?;
                path.replace(&format!("{{{}}}", selector.parameter), selected)
            } else {
                config.path.clone()
            };

            format!("{}{path}", config.base_url)
        };

        // One pass, caller parameters only: a value holding `{other}` is sent
        // as written, and the URL never resolves a secret.
        crate::secrets::fill_placeholders(&url, |key| {
            Ok(params.get(key).map(|value| match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => serde_json::to_string(value).unwrap_or_default(),
            }))
        })
    }

    /// Build headers with credential injection.
    pub(super) async fn build_headers(
        &self,
        config: &RestConfig,
        auth: &crate::capability::AuthConfig,
        params: &Value,
        context: &CapabilityExecutionContext,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();

        for (name, value_template) in &config.headers {
            let value = self.substitute_string(value_template, params)?;

            // Skip an Authorization header whose TEMPLATE names {access_token}
            // with no access_token parameter to fill it; inject_auth handles
            // auth from the credential key. The value is not consulted: a
            // resolved secret may contain that text.
            if name.eq_ignore_ascii_case("authorization")
                && value_template.contains("{access_token}")
                && params.get("access_token").is_none()
            {
                continue;
            }

            if let Ok(header_name) = name.parse::<HeaderName>()
                && let Ok(header_value) = value.parse::<HeaderValue>()
            {
                headers.insert(header_name, header_value);
            }
        }

        // Skip header injection when auth.param is set (credential goes as query param).
        if auth.required && auth.param.is_none() {
            self.inject_auth(&mut headers, auth, context).await?;
        }

        Ok(headers)
    }

    /// Inject authentication into headers.
    ///
    /// # Security
    ///
    /// Credentials are fetched from secure storage and injected at runtime.
    /// They are NEVER logged or stored in memory longer than necessary.
    pub(in crate::capability) async fn inject_auth(
        &self,
        headers: &mut HeaderMap,
        auth: &crate::capability::AuthConfig,
        context: &CapabilityExecutionContext,
    ) -> Result<()> {
        // A recognized `auth.account` is resolved through the SHARED identity
        // resolver — the same strategy instance an MCP backend bound to that
        // descriptor holds — and its headers go on the wire VERBATIM: the
        // provider's own `token_type` is authority this executor must not
        // reformat, and a strategy may mint more than one header. `Ok(None)`
        // means either no account reference or an explicit `shared` descriptor,
        // both of which continue on the existing static path below. Any refusal
        // returns here and never reaches it.
        if let Some(account_headers) = self.resolve_account_headers(auth, context).await? {
            for (name, value) in account_headers {
                let header_name: HeaderName = name.parse().map_err(|_| {
                    Error::Config("Invalid account credential header name".to_string())
                })?;
                let header_value: HeaderValue = value
                    .parse()
                    .map_err(|_| Error::Config("Invalid credential format".to_string()))?;
                headers.insert(header_name, header_value);
            }
            return Ok(());
        }

        let credential = self.fetch_credential(auth, context).await?;

        let header_name: HeaderName = auth
            .header
            .as_deref()
            .unwrap_or("Authorization")
            .parse()
            .map_err(|_| Error::Config("Invalid auth header name".to_string()))?;

        let prefix = auth
            .prefix
            .as_deref()
            .unwrap_or(match auth.auth_type.as_str() {
                "basic" => "Basic",
                "api_key" => "",
                _ => "Bearer",
            });

        let header_value = if prefix.is_empty() {
            credential
        } else {
            format!("{prefix} {credential}")
        };

        let header_val: HeaderValue = header_value
            .parse()
            .map_err(|_| Error::Config("Invalid credential format".to_string()))?;
        headers.insert(header_name, header_val);

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Collect `static_params` that are not already covered by `config.params`
    /// or `config.param_map` templates (GET requests only).
    #[allow(clippy::unused_self)] // method interface kept for future use
    pub(super) fn build_extra_static_params(
        &self,
        config: &RestConfig,
        _params: &Value,
    ) -> Vec<(String, String)> {
        let covered_keys: std::collections::HashSet<&str> = config
            .params
            .keys()
            .chain(config.param_map.keys())
            .map(String::as_str)
            .collect();

        config
            .static_params
            .iter()
            .filter(|(k, _)| !covered_keys.contains(k.as_str()))
            .map(|(k, v)| {
                let v_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => serde_json::to_string(v).unwrap_or_default(),
                };
                (k.clone(), v_str)
            })
            .collect()
    }
}
