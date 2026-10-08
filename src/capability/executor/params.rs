// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Parameter substitution, response extraction, and cache-key helpers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Response;
use serde_json::Value;

use crate::{Error, Result};

use super::xml::xml_to_json;
use super::{super::RestConfig, CapabilityExecutor};

fn graphql_error_message(body: &Value) -> Option<String> {
    let errors = body.get("errors").and_then(Value::as_array)?;
    if errors.is_empty() {
        return None;
    }

    let messages: Vec<&str> = errors
        .iter()
        .filter_map(|error| error.get("message").and_then(Value::as_str))
        .collect();

    if messages.is_empty() {
        Some(serde_json::to_string(errors).unwrap_or_else(|_| "Unknown GraphQL error".to_string()))
    } else {
        Some(messages.join("; "))
    }
}

/// Turn a non-success capability response into the error the caller sees.
///
/// A `429` becomes `Error::Http`, carrying the status as a type instead of as
/// prose a caller would have to parse (GH475.RL.10). Every other status keeps
/// the `Error::Protocol` message it has always had: the gate is `status == 429`
/// alone, not `error_for_status_ref()`'s `Err`, which would type 504 the same
/// way and change how the dispatch classifier reads a timeout.
///
/// A `reqwest::Error` renders its URL, and on this path the URL carries the
/// credential, so the typed error is stripped with `without_url()`. The body
/// does not ride along either, and it is not logged: a backend is free to echo
/// the request that provoked the throttle, credentials included, so the record
/// carries only how much text came back. The status and the endpoint are what
/// an operator acts on; the bytes are what would leak.
pub(super) async fn status_error(response: Response, endpoint: &str) -> Error {
    let status = response.status();
    let typed = response
        .error_for_status_ref()
        .err()
        .map(reqwest::Error::without_url);
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "Unknown error".to_string());
    let body = body.chars().take(500).collect::<String>();

    match typed {
        Some(e) if status == reqwest::StatusCode::TOO_MANY_REQUESTS => {
            tracing::warn!(
                %status,
                %endpoint,
                body_len = body.len(),
                "capability endpoint throttled"
            );
            Error::Http(e)
        }
        // A11-b: a 401 is the one status a managed account can act on, so it is
        // typed by status, never by body text. The REST path does not retry,
        // so 400/403/404 keep today's text.
        Some(e) if status == reqwest::StatusCode::UNAUTHORIZED => Error::Http(e),
        _ => Error::Protocol(format!("{endpoint} returned {status}: {body}")),
    }
}

impl CapabilityExecutor {
    /// Attach the request body for POST/PUT/PATCH methods.
    ///
    /// When `config.body_content_type` is `"text/plain"` and a `body` template
    /// is present the template is substituted and the resulting string is sent
    /// verbatim (no JSON encoding).  This is required for databases such as
    /// `SurrealDB` whose `/sql` endpoint only accepts raw SQL as `text/plain`.
    pub(super) fn attach_request_body(
        &self,
        mut request: reqwest::RequestBuilder,
        config: &RestConfig,
        params: &Value,
        body_nulls: &[String],
    ) -> Result<reqwest::RequestBuilder> {
        let use_plain_text = config.body_content_type.eq_ignore_ascii_case("text/plain");

        if let Some(ref body_template) = config.body {
            if use_plain_text {
                // Substitute into the template and send as a raw string body.
                // The template must be a JSON string value; after substitution
                // we send the string contents (not JSON-encoded).
                let raw = match body_template {
                    Value::String(s) => self.substitute_string(s, params)?,
                    other => self
                        .substitute_value(other, params, KeptNulls::None)?
                        .to_string(),
                };
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "text/plain")
                    .body(raw);
            } else {
                let params = with_nulls(params, body_nulls);
                let kept = KeptNulls::Named(body_nulls);
                let body = self.substitute_value(body_template, &params, kept)?;
                request = request.json(&body);
            }
        } else if !params.is_null() && params.as_object().is_some_and(|o| !o.is_empty()) {
            // No body template — use input params directly as body.
            // Enables LLM APIs where the input IS the request body.
            request = request.json(params);
        }
        Ok(request)
    }

    /// Handle an API response.
    ///
    /// Supports JSON (default) and XML response formats.  The format is
    /// determined by the `response_format` field in `RestConfig`, falling
    /// back to auto-detection from the `Content-Type` response header.
    pub(super) async fn handle_response(
        &self,
        response: Response,
        config: &RestConfig,
    ) -> Result<Value> {
        let status = response.status();

        if !status.is_success() {
            return Err(status_error(response, "API").await);
        }

        let response_format = config.response_format.to_ascii_lowercase();
        if response_format == "text" {
            // Plain-text responses (e.g. Wolfram|Alpha LLM API) aren't JSON.
            // Wrap the raw body so downstream output mapping has a JSON value.
            let text = response
                .text()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to read text response: {e}")))?;
            return Ok(serde_json::json!({ "answer": text, "confidence": "high" }));
        }
        if response_format == "binary" {
            let mime_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let bytes = response
                .bytes()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to read binary response: {e}")))?;
            return Ok(serde_json::json!({
                "data": STANDARD.encode(&bytes),
                "mime_type": mime_type,
                "size": bytes.len(),
            }));
        }

        let is_xml = detect_xml_format(response.headers(), &response_format);

        let body: Value = if is_xml {
            let text = response
                .text()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to read XML response: {e}")))?;
            xml_to_json(&text)
                .map_err(|e| Error::Protocol(format!("Failed to parse XML response: {e}")))?
        } else {
            response
                .json()
                .await
                .map_err(|e| Error::Protocol(format!("Failed to parse response: {e}")))?
        };

        if let Some(ref path) = config.response_path {
            let projected = self.extract_path(&body, path)?;
            if projected.is_null()
                && let Some(message) = graphql_error_message(&body)
            {
                return Err(Error::Protocol(format!("GraphQL error: {message}")));
            }
            Ok(projected)
        } else {
            Ok(body)
        }
    }

    /// Extract a value at a dot-separated path from a JSON response.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(super) fn extract_path(&self, value: &Value, path: &str) -> Result<Value> {
        let mut current = value;

        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }

            current = match current {
                Value::Object(map) => map.get(segment).unwrap_or(&Value::Null),
                Value::Array(arr) => {
                    if let Ok(index) = segment.parse::<usize>() {
                        arr.get(index).unwrap_or(&Value::Null)
                    } else {
                        &Value::Null
                    }
                }
                _ => &Value::Null,
            };
        }

        Ok(current.clone())
    }

    /// Substitute `{param}` references in a string template.
    ///
    /// `{keychain.X}` and `{env.VAR}` secrets are resolved via
    /// [`SecretResolver`](crate::secrets::SecretResolver) in the TEMPLATE,
    /// before any caller value goes in: a caller's argument is data, so a value
    /// such as `{env.NAME}` reaches the provider as that text, never as the
    /// gateway's own secret.
    pub(super) fn substitute_string(&self, template: &str, params: &Value) -> Result<String> {
        self.substitute_string_tracked(template, params)
            .map(|(value, _unfilled)| value)
    }

    /// [`Self::substitute_string`], also saying whether the TEMPLATE named a
    /// `{placeholder}` that no parameter or secret filled. That is known from
    /// the single scan, not guessed from how the result looks. Literal braces
    /// that name no parameter (`{}`, a JSON fragment) are not placeholders.
    fn substitute_string_tracked(&self, template: &str, params: &Value) -> Result<(String, bool)> {
        // One scan of the template resolves secrets and caller parameters
        // together: a substituted value is data and is never scanned again, so
        // a secret holding `{q}` or a caller value holding `{other}` arrives
        // as written (MIK-7888).
        let unfilled = std::cell::Cell::new(false);
        let caller = |key: &str| {
            let found = params
                .as_object()
                .and_then(|map| map.get(key))
                .map(|value| match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => String::new(),
                    _ => serde_json::to_string(value).unwrap_or_default(),
                });
            if found.is_none() && is_parameter_name(key) {
                unfilled.set(true);
            }
            found
        };
        let value = self.secret_resolver.resolve_with(template, &caller)?;
        Ok((value, unfilled.get()))
    }

    /// Resolve a map of string templates to `(key, value)` query-param pairs.
    ///
    /// Empty and `"null"` values are filtered out, and so is a value that
    /// starts with a `{placeholder}` the template named and nothing filled, to
    /// avoid sending empty parameters to APIs. A value is never filtered for
    /// what it looks like: a caller's JSON text or `{env.NAME}`, or a secret
    /// that begins with a brace, is sent as written (MIK-7857).
    pub(super) fn substitute_params(
        &self,
        template: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        for (key, value_template) in template {
            let (value, unfilled) = self.substitute_string_tracked(value_template, params)?;
            if !value.is_empty() && value != "null" && !(unfilled && value.starts_with('{')) {
                result.push((key.clone(), value));
            }
        }

        Ok(result)
    }

    /// Map input parameters to API parameters using `param_map`.
    ///
    /// For example, `param_map: { query: q }` maps the caller's `"query"` key
    /// to the API's `"q"` query parameter.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    pub(super) fn map_params(
        &self,
        param_map: &std::collections::HashMap<String, String>,
        params: &Value,
    ) -> Result<Vec<(String, String)>> {
        let mut result = Vec::new();

        if let Value::Object(map) = params {
            for (input_name, api_name) in param_map {
                if let Some(value) = map.get(input_name) {
                    let value_str = match value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => continue, // Skip null values
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    if !value_str.is_empty() {
                        result.push((api_name.clone(), value_str));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Substitute parameters recursively throughout a JSON value template.
    ///
    /// A pure placeholder string like `"{priority}"` is replaced by the
    /// original typed value (integer, boolean, etc.) rather than its string
    /// representation. Null and unresolved placeholders are dropped from
    /// object fields, except a null `kept` names.
    pub(super) fn substitute_value(
        &self,
        template: &Value,
        params: &Value,
        kept: KeptNulls<'_>,
    ) -> Result<Value> {
        match template {
            Value::String(s) => self.substitute_string_value(s, params),
            Value::Object(map) => self.substitute_object_value(map, params, kept),
            Value::Array(arr) => {
                let result: Result<Vec<Value>> = arr
                    .iter()
                    .map(|v| self.substitute_value(v, params, kept))
                    .collect();
                Ok(Value::Array(result?))
            }
            _ => Ok(template.clone()),
        }
    }

    /// Build a cache key for a capability + params combination.
    ///
    /// `None` means do not cache: personal exposure with no caller identity,
    /// or an attached executor missing a known revision or the invoke snapshot.
    /// Loopback is refused by the caller before this is asked.
    ///
    /// Inner and outer share `{revision, profile, epoch}` plus the already-
    /// resolved outer `cache_binding`. The binding is copied, not re-hashed.
    #[allow(clippy::unused_self)]
    pub(super) fn build_cache_key(
        &self,
        capability: &super::super::CapabilityDefinition,
        params: &Value,
        context: &crate::capability::CapabilityExecutionContext,
    ) -> Option<String> {
        use crate::identity_grants::CapabilityExposure;
        let principal = match (
            capability.metadata.exposure,
            context.caller_identity.as_ref(),
        ) {
            (CapabilityExposure::Personal, None) => return None,
            // An MCP answer came from one caller's child, so it is keyed on
            // that child's name: only that caller reads it back (MIK-7825).
            // Single-user names every unnamed caller one child, as the run does.
            _ if matches!(
                super::process::spawned_process(capability),
                Some(crate::capability::definition::ProcessConfig::Mcp(_))
            ) =>
            {
                format!(
                    "2:{}",
                    super::mcp::principal(capability, context, false).ok()?
                )
            }
            (_, Some(identity)) => {
                format!(
                    "1:{}:{}|{}:{}",
                    identity.authority.len(),
                    identity.authority,
                    identity.subject.len(),
                    identity.subject
                )
            }
            (_, None) => "0:".to_string(),
        };
        let params_hash = {
            use sha2::{Digest, Sha256};
            let json = serde_json::to_string(params).unwrap_or_default();
            let digest = Sha256::digest(json.as_bytes());
            hex::encode(&digest[..16])
        };
        // An attached production executor without a request snapshot must not
        // key under epoch 0 after a reload. Unattached standalone tests have
        // no shared counter and keep `unwrap_or(0)`.
        let attached = self.policy_epoch.is_some();
        let epoch = if attached {
            context.policy_epoch?
        } else {
            context.policy_epoch.unwrap_or(0)
        };
        let revision = known_protocol_revision(context.protocol_revision.as_deref());
        let revision = if attached {
            revision?
        } else {
            revision.unwrap_or("")
        };
        let profile = context
            .routing_profile
            .as_deref()
            .filter(|value| !value.is_empty());
        let profile = if attached {
            profile?
        } else {
            profile.unwrap_or("")
        };
        // Already-resolved outer binding. Empty is the public/anonymous
        // namespace. The resolver digested it; this only length-prefixes.
        let binding = context
            .cache_binding
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("");
        // A process provider keys on its whole definition and pin state, so
        // another definition under the same name never reads its answers,
        // epoch or not. Only where a pin is enforced at run time; other
        // providers keep the epoch key (MIK-7814).
        let definition = match super::process::spawned_process(capability) {
            Some(_) => format!(
                "{}{}",
                match capability.providers.integrity {
                    crate::capability::Integrity::Verified => "p:",
                    crate::capability::Integrity::Unpinned => "u:",
                },
                capability.fingerprint()?
            ),
            None => String::new(),
        };
        Some(format!(
            "v=2|e={epoch}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}",
            revision.len(),
            revision,
            profile.len(),
            profile,
            binding.len(),
            binding,
            capability.name.len(),
            capability.name,
            definition.len(),
            definition,
            principal.len(),
            principal,
            params_hash.len(),
            params_hash
        ))
    }

    // ── Private decomposition helpers ─────────────────────────────────────────

    fn substitute_string_value(&self, s: &str, params: &Value) -> Result<Value> {
        self.substitute_string_value_tracked(s, params)
            .map(|(value, _unfilled)| value)
    }

    /// [`Self::substitute_string_value`], also saying whether the template
    /// named a placeholder nothing filled (see
    /// [`Self::substitute_string_tracked`]).
    fn substitute_string_value_tracked(&self, s: &str, params: &Value) -> Result<(Value, bool)> {
        let trimmed = s.trim();
        // Pure placeholder like "{priority}" → preserve original typed value
        if is_pure_placeholder(trimmed) {
            let key = &trimmed[1..trimmed.len() - 1];
            if let Some(value) = params.as_object().and_then(|m| m.get(key)) {
                let value = if value.is_null() {
                    Value::Null
                } else {
                    value.clone()
                };
                return Ok((value, false));
            }
        }

        let (substituted, unfilled) = self.substitute_string_tracked(s, params)?;
        // Try to re-parse if the result looks like JSON
        let value = if (substituted.starts_with('{') && substituted.ends_with('}'))
            || (substituted.starts_with('[') && substituted.ends_with(']'))
        {
            serde_json::from_str(&substituted).unwrap_or(Value::String(substituted))
        } else {
            Value::String(substituted)
        };
        Ok((value, unfilled))
    }

    fn substitute_object_value(
        &self,
        map: &serde_json::Map<String, Value>,
        params: &Value,
        kept: KeptNulls<'_>,
    ) -> Result<Value> {
        let mut result = serde_json::Map::new();
        for (k, v) in map {
            // Whether a placeholder went unfilled comes from the template
            // scan: a filled value is never dropped for looking like one.
            let (substituted, unfilled) = match v {
                Value::String(s) => self.substitute_string_value_tracked(s, params)?,
                _ => (self.substitute_value(v, params, kept)?, false),
            };
            // Skip null values, except a null `kept` names (MIK-7970), and
            // unresolved placeholders.
            if substituted.is_null() && !v.as_str().is_some_and(|s| kept.keeps(s)) {
                continue;
            }
            if unfilled
                && let Value::String(ref s) = substituted
                && is_unresolved_placeholder(s)
            {
                continue;
            }
            result.insert(k.clone(), substituted);
        }
        Ok(Value::Object(result))
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

/// Classified revision the inner cache may key on: exactly the set the outer
/// classifier can produce, which is `SUPPORTED_VERSIONS` **plus**
/// `MODERN_VERSIONS`. Taking only the first excluded every modern-era caller —
/// `2026-07-28` is deliberately absent from `SUPPORTED_VERSIONS`
/// (`src/protocol/mod.rs`), so an attached executor took the `revision?`
/// bypass on every modern request and the inner cache never stored or served,
/// while the outer cache kept caching under that same revision.
///
/// Unknown, empty and whitespace-padded spellings stay `None`: the outer
/// classifier matches exactly, so a padded value is one no request was served
/// under and must not resolve onto a canonical bucket.
fn known_protocol_revision(revision: Option<&str>) -> Option<&'static str> {
    revision.and_then(crate::protocol::meta::served_revision)
}

/// Returns `true` when `s` is a single `{key}` placeholder (not a secret ref).
fn is_pure_placeholder(s: &str) -> bool {
    s.starts_with('{')
        && s.ends_with('}')
        && !s.contains(' ')
        && s.matches('{').count() == 1
        && !s.starts_with("{env.")
        && !s.starts_with("{keychain.")
}

/// Whether `{name}` names a parameter. Only literal braces are not: `{}` (or
/// blank) and a JSON fragment such as `{"a":1}`, which opens with a quoted
/// key. Any other name (`{first|50}`, `{filter[id]}`, `{a"b}`) is one.
fn is_parameter_name(name: &str) -> bool {
    let name = name.trim_start();
    !name.trim_end().is_empty() && !name.starts_with('"')
}

/// Returns `true` when a substituted string is still an unresolved placeholder.
fn is_unresolved_placeholder(s: &str) -> bool {
    s.starts_with('{') && s.ends_with('}') && !s.contains(' ')
}

/// Determine whether the response should be parsed as XML.
///
/// Priority: explicit `response_format` field > `Content-Type` header.
fn detect_xml_format(headers: &reqwest::header::HeaderMap, response_format: &str) -> bool {
    if response_format.eq_ignore_ascii_case("xml") {
        true
    } else if response_format.is_empty() {
        headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("xml"))
    } else {
        false
    }
}

/// The call's parameters plus the schema `default` of every parameter the REST
/// URL names and the caller left out.
///
/// A `{placeholder}` left in a URL is always wrong, and a parameter that
/// has a default can be left out by design (`ruleset_phase` of a Cloudflare
/// ruleset call). Only URL parameters get this: a default for a query or body
/// field stays the upstream's own to apply.
pub(super) fn with_path_defaults<'a>(
    config: &crate::capability::definition::RestConfig,
    input_schema: &Value,
    params: &'a Value,
) -> std::borrow::Cow<'a, Value> {
    let Some(properties) = input_schema.get("properties").and_then(Value::as_object) else {
        return std::borrow::Cow::Borrowed(params);
    };
    let mut merged: Option<serde_json::Map<String, Value>> = None;
    let templates = url_templates(config, params);
    for (name, property) in properties {
        let Some(default) = property.get("default") else {
            continue;
        };
        let given = params.get(name).is_some_and(|value| !value.is_null());
        let placeholder = format!("{{{name}}}");
        if given || !templates.iter().any(|t| t.contains(&placeholder)) {
            continue;
        }
        merged
            .get_or_insert_with(|| params.as_object().cloned().unwrap_or_default())
            .insert(name.clone(), default.clone());
    }
    merged.map_or(std::borrow::Cow::Borrowed(params), |map| {
        std::borrow::Cow::Owned(Value::Object(map))
    })
}

/// Which nulls filling a pure placeholder an object keeps (MIK-7970).
#[derive(Clone, Copy)]
pub(super) enum KeptNulls<'a> {
    /// None: a plain-text body, where a null is not given.
    None,
    /// A JSON body can carry null: the caller's explicit nulls for these
    /// names, each one its property's schema admits.
    Named(&'a [String]),
}

impl KeptNulls<'_> {
    /// Whether `template` is a pure placeholder for a kept name.
    fn keeps(self, template: &str) -> bool {
        let template = template.trim();
        match self {
            Self::None => false,
            Self::Named(names) => {
                is_pure_placeholder(template)
                    && names.iter().any(|n| *n == template[1..template.len() - 1])
            }
        }
    }
}

/// MIK-7970: the names the caller sent as an explicit null that the
/// property's schema admits. Any other null is not given, as the validator
/// treats it; static params and schema defaults never name a null here.
pub(super) fn admitted_nulls(input_schema: &Value, caller: &Value) -> Vec<String> {
    let properties = input_schema.get("properties");
    caller.as_object().map_or_else(Vec::new, |caller| {
        caller
            .iter()
            .filter(|(name, value)| {
                value.is_null()
                    && super::super::schema_validator::admits_null(
                        properties.and_then(|p| p.get(*name)),
                    )
            })
            .map(|(name, _)| name.clone())
            .collect()
    })
}

/// `params` with each admitted null restored, over a URL default that
/// [`with_path_defaults`] put in its place.
pub(super) fn with_nulls<'a>(params: &'a Value, names: &[String]) -> std::borrow::Cow<'a, Value> {
    if names.is_empty() {
        return std::borrow::Cow::Borrowed(params);
    }
    let mut map = params.as_object().cloned().unwrap_or_default();
    for name in names {
        map.insert(name.clone(), Value::Null);
    }
    std::borrow::Cow::Owned(Value::Object(map))
}

/// Every template `build_url` fills for this call: the endpoint, or the base
/// URL with the path, or with the path the selector picks instead, read as
/// `build_url` reads it (absent or null takes the default). With a selector,
/// `path` is only a compatibility copy of the default route that `build_url`
/// never reads, and an unpicked route names nothing this call sends (MIK-7943).
fn url_templates<'a>(
    config: &'a crate::capability::definition::RestConfig,
    params: &Value,
) -> Vec<&'a str> {
    if config.uses_endpoint() {
        return vec![config.endpoint.as_str()];
    }
    let mut templates = vec![config.base_url.as_str()];
    let Some(selector) = &config.path_selector else {
        templates.push(config.path.as_str());
        return templates;
    };
    let picked = match params.get(&selector.parameter) {
        None | Some(Value::Null) => Some(selector.default.as_str()),
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => None,
    };
    templates.extend(
        picked
            .and_then(|key| selector.paths.get(key))
            .map(String::as_str),
    );
    templates
}

#[cfg(test)]
#[path = "params_secret_tests.rs"]
mod secret_tests;

#[cfg(test)]
#[path = "params_catalogue_tests.rs"]
mod catalogue_tests;
#[cfg(test)]
#[path = "params_cloudflare_tests.rs"]
mod cloudflare_catalogue_tests;
