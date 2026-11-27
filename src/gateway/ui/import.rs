// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `OpenAPI` import API endpoints for the Web UI.
//!
//! Provides two endpoints:
//! - `POST /ui/api/import/openapi/preview` — fetch & parse an `OpenAPI` spec,
//!   return the list of generated tools without writing any files.
//! - `POST /ui/api/import/openapi` — same as preview, plus write selected
//!   tools as YAML capability files and signal a hot-reload.
//!
//! Both endpoints require admin authentication.

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::super::router::AppState;
use super::capabilities::find_capability_file;
use super::errors::{CAPABILITIES_OFF, DIGEST_REQUIRED, DOCUMENT_CHANGED, flat_error};
use super::guard::Guard;
use crate::capability::{GeneratedCapability, OpenApiConverter};
use crate::security::validate_url_not_ssrf;

// ── Request / response types ────────────────────────────────────────

/// Body accepted by both import endpoints.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// URL of the `OpenAPI` spec to fetch. Mutually exclusive with `spec`.
    pub url: Option<String>,
    /// Raw YAML/JSON spec string. Mutually exclusive with `url`.
    pub spec: Option<String>,
    /// Subset of tool names to import. `None` means "import all".
    /// Only used by the write endpoint; ignored by preview.
    pub selected_tools: Option<Vec<String>>,
    /// What the preview answered as `digest`. An import from a `url` must
    /// send it; with an inline `spec` it is checked only if present. The
    /// preview ignores it.
    pub digest: Option<String>,
}

/// Hex-encoded (lowercase) SHA-256 of the text the parser is given. Two
/// equal digests mean the same text, and conversion depends on the text
/// alone, so an import carrying the preview's digest writes what was shown.
fn document_digest(text: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(text.as_bytes()))
}

/// One tool entry returned by the preview endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ToolPreview {
    /// Capability name (e.g. `getuser`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// HTTP method (uppercase, e.g. `GET`).
    pub method: String,
    /// URL path (e.g. `/users/{id}`).
    pub path: String,
    /// Query/path/body parameter names.
    pub parameters: Vec<String>,
    /// `read` for an operation the converter marks `read_only` (GET and
    /// HEAD), else `write`.
    pub class: &'static str,
    /// Always `inferred`: a spec declares no MCP annotations.
    pub class_source: &'static str,
}

/// Response from `POST /ui/api/import/openapi/preview`.
#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    /// The block a server preview carries too.
    pub preview: serde_json::Value,
    /// List of tools that would be generated from the spec.
    pub tools: Vec<ToolPreview>,
    /// The previewed text's digest, for the import to send back.
    pub digest: String,
}

/// Response from `POST /ui/api/import/openapi`.
#[derive(Debug, Serialize)]
pub struct ImportResponse {
    /// Filenames that were written (e.g. `["getuser.yaml"]`).
    pub imported: Vec<String>,
    /// Tool names skipped because they were not in `selected_tools`.
    pub skipped: Vec<String>,
    /// Errors encountered while writing individual files.
    pub errors: Vec<String>,
}

// ── Router ──────────────────────────────────────────────────────────

/// Build the `/ui/api/import/*` sub-router.
pub fn import_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_IMPORT_PREVIEW, post(preview_handler))
        .route(routes::UI_IMPORT, post(import_handler))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `POST /ui/api/import/openapi/preview`
///
/// Fetches the spec (or uses the inline `spec` field), parses it with the
/// existing [`OpenApiConverter`], and returns the list of would-be tools.
/// No files are written.
async fn preview_handler(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    Json(body): Json<ImportRequest>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // After admission, so a caller who may not use the route learns nothing
    // about the setting; before any fetch.
    if state.capability_dirs.is_empty() {
        return flat_error(StatusCode::CONFLICT, CAPABILITIES_OFF.to_string()).into_response();
    }

    let spec_content = match resolve_spec(&generation, &body).await {
        Ok(s) => s,
        Err((status, msg)) => {
            return flat_error(status, msg).into_response();
        }
    };

    let caps = match parse_spec(&spec_content) {
        Ok(c) => c,
        Err(msg) => {
            return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
        }
    };

    let tools: Vec<ToolPreview> = caps.iter().map(tool_preview_from_cap).collect();
    // The same block a server preview carries. The URL is fetched
    // as supplied, but echoed without userinfo, query or fragment, so a
    // query-authenticated spec never returns its key.
    let preview = json!({
        "transport": "openapi",
        "url": body.url.as_deref().map(crate::security::sanitize::redact_url_keep_path),
        "publisher": {"verified": false, "source": null},
        // No server to ask, so nothing reported; the key keeps one shape.
        "package": null,
    });

    let answer = PreviewResponse {
        preview,
        tools,
        digest: document_digest(&spec_content),
    };
    (StatusCode::OK, Json(answer)).into_response()
}

/// `POST /ui/api/import/openapi`
///
/// Fetches and parses the spec, then writes the selected tools as YAML files
/// into the first configured capability directory. A tool whose file name is
/// already taken in any capability directory is refused and its file kept.
/// Returns a summary of what was imported, skipped, and any errors.
async fn import_handler(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
    Json(body): Json<ImportRequest>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    // Everything below runs before anything is written. No capability
    // directory: nothing would load what is written, so nothing is.
    let Some(output_dir) = state.capability_dirs.first().cloned() else {
        return flat_error(StatusCode::CONFLICT, CAPABILITIES_OFF.to_string()).into_response();
    };
    // A blank digest is no digest for an import by address; any digest sent
    // at all, blank included, is compared below.
    let blank = body.digest.as_deref().is_none_or(|d| d.trim().is_empty());
    if body.url.is_some() && blank {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, DIGEST_REQUIRED).into_response();
    }

    let spec_content = match resolve_spec(&generation, &body).await {
        Ok(s) => s,
        Err((status, msg)) => {
            return flat_error(status, msg).into_response();
        }
    };
    // The text fetched now must be the text previewed.
    let sent = body.digest.as_deref();
    if sent.is_some_and(|digest| digest != document_digest(&spec_content)) {
        return flat_error(StatusCode::CONFLICT, DOCUMENT_CHANGED.to_string()).into_response();
    }

    let caps = match parse_spec(&spec_content) {
        Ok(c) => c,
        Err(msg) => {
            return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
        }
    };

    let mut imported = Vec::new();
    let mut skipped = Vec::new();
    let mut errors = Vec::new();
    // How many of `errors` are names already taken, which the operator
    // resolves, rather than writes that failed.
    let mut taken = 0_usize;
    let refusal = |name: &str| format!("{name}: {}", crate::capability::name_taken(name));

    for cap in &caps {
        // Filter by selected_tools when provided.
        if let Some(ref selected) = body.selected_tools
            && !selected.iter().any(|s| s == &cap.name)
        {
            skipped.push(cap.name.clone());
            continue;
        }

        // The gateway loads every directory, so a file of this name in any of
        // them is taken; the writer itself refuses one in `output_dir`.
        if find_capability_file(&state.capability_dirs, &cap.name).is_some() {
            taken += 1;
            errors.push(refusal(&cap.name));
            continue;
        }
        match cap.write_to_file(&output_dir) {
            Ok(()) => imported.push(format!("{}.yaml", cap.name)),
            Err(e) if crate::capability::is_name_taken(&e) => {
                taken += 1;
                errors.push(refusal(&cap.name));
            }
            Err(e) => errors.push(format!("{}: {e}", cap.name)),
        }
    }

    // Anything written, or nothing wrong: 200. Nothing written and every
    // error a taken name: 409, the operator's to resolve. Otherwise a write
    // failed: 500.
    let status = if !imported.is_empty() || errors.is_empty() {
        StatusCode::OK
    } else if taken == errors.len() {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    let response = ImportResponse {
        imported,
        skipped,
        errors,
    };

    (status, Json(json!(response))).into_response()
}

// ── Private helpers ─────────────────────────────────────────────────

/// Resolve the raw spec content from either a URL (fetch) or an inline string.
async fn resolve_spec(
    generation: &crate::config_reload::Generation,
    body: &ImportRequest,
) -> Result<String, (StatusCode, String)> {
    match (&body.url, &body.spec) {
        (Some(url), None) => fetch_spec(url, generation.ssrf_protection()).await,
        (None, Some(spec)) => {
            if spec.trim().is_empty() {
                Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "spec field is empty".to_string(),
                ))
            } else {
                Ok(spec.clone())
            }
        }
        (Some(_), Some(_)) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provide either 'url' or 'spec', not both".to_string(),
        )),
        (None, None) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provide either 'url' or 'spec'".to_string(),
        )),
    }
}

/// Message for a failed spec fetch from `url`. (MIK-8660 seam)
fn fetch_error_message(url: &str, e: &reqwest::Error) -> String {
    crate::security::http_diagnostics::ssrf_refusal(e).map_or_else(
        || format!("Failed to fetch spec from {url}: {e}"),
        |refused| format!("Failed to fetch spec from {url}: {refused}"),
    )
}

/// Fetch an `OpenAPI` spec from a remote URL.
async fn fetch_spec(url: &str, ssrf_protection: bool) -> Result<String, (StatusCode, String)> {
    // Validate URL is well-formed.
    let parsed = url::Url::parse(url).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Invalid URL: {e}"),
        )
    })?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "URL must use http or https scheme".to_string(),
        ));
    }

    // SSRF protection when enabled.
    if ssrf_protection {
        validate_url_not_ssrf(url).map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("SSRF protection blocked URL: {e}"),
            )
        })?;
    }

    // Fetch the spec content. The literal pre-check above fails fast on obvious
    // IP targets, but it is NOT sufficient on its own: a hostname can resolve to
    // a private address (DNS rebinding) or a public URL can 3xx-redirect into an
    // internal one. When SSRF protection is enabled we therefore also pin DNS
    // resolution (PinningResolver validates every resolved IP, closing the
    // rebinding TOCTOU window — MIK-4019) and re-validate every redirect hop,
    // following at most MAX_REDIRECT_HOPS; with protection off the same budget
    // applies without the SSRF check. This mirrors the canonical fetch path in
    // `capability::executor::client::build` and `openapi::convert_url`. The
    // guards stay gated on `ssrf_protection` so an operator may deliberately
    // disable them for trusted internal specs.
    // Never an environment proxy: it would resolve the name instead of the
    // pin below (#1881).
    let policy = if ssrf_protection {
        crate::security::ssrf::ssrf_redirect_policy()
    } else {
        reqwest::redirect::Policy::custom(|attempt| {
            if crate::security::ssrf::hop_budget_spent(attempt.previous().len()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        })
    };
    let base = if ssrf_protection {
        crate::security::ssrf::pinned_client_builder()
    } else {
        reqwest::Client::builder().no_proxy()
    };
    let client = base
        .redirect(policy)
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("mcp-gateway/openapi-importer")
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build HTTP client: {e}"),
            )
        })?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, fetch_error_message(url, &e)))?;

    if !resp.status().is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Remote server returned {} for {}",
                resp.status().as_u16(),
                url
            ),
        ));
    }

    read_spec_body(resp).await
}

/// The most a fetched spec may carry, counted while it is read.
/// Sized for large public API specs, not for MCP listings; an inline `spec`
/// is not counted here.
const SPEC_BUDGET: usize = 32 * 1024 * 1024;

/// `resp`'s body as text, refused with a 502 the moment it passes
/// [`SPEC_BUDGET`], so an over-budget spec is never held whole.
async fn read_spec_body(mut resp: reqwest::Response) -> Result<String, (StatusCode, String)> {
    let unreadable = |e: reqwest::Error| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Failed to read response body: {e}"),
        )
    };
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(unreadable)? {
        if body.len() + chunk.len() > SPEC_BUDGET {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!(
                    "the spec is over its {} MiB budget",
                    SPEC_BUDGET / (1024 * 1024)
                ),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Parse a spec string into generated capabilities.
fn parse_spec(content: &str) -> Result<Vec<GeneratedCapability>, String> {
    let converter = OpenApiConverter::new();
    converter
        .convert_string(content)
        .map_err(|e| format!("Failed to parse OpenAPI spec: {e}"))
}

/// Build a [`ToolPreview`] from a [`GeneratedCapability`].
///
/// Extracts `method` and `path` from the YAML content via simple line scanning
/// so we avoid re-parsing the YAML just for display.
fn tool_preview_from_cap(cap: &GeneratedCapability) -> ToolPreview {
    let mut method = String::new();
    let mut path = String::new();
    let mut parameters: Vec<String> = Vec::new();
    // The converter's own `metadata.read_only` is the YAML's last such line,
    // after every description: a description line that reads the same can
    // only come earlier, so it never sets the class.
    let read_only = cap
        .yaml
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("read_only: "))
        == Some("true");

    for line in cap.yaml.lines() {
        let trimmed = line.trim();
        if method.is_empty()
            && let Some(rest) = trimmed.strip_prefix("method: ")
        {
            method = rest.trim().to_string();
        }
        if path.is_empty()
            && let Some(rest) = trimmed.strip_prefix("path: ")
        {
            path = rest.trim().to_string();
        }
        // Collect param names from inline template refs: `  key: "{param}"`
        if (trimmed.ends_with("}\"") || trimmed.ends_with('}'))
            && let Some(start) = trimmed.find('{')
            && let Some(end) = trimmed.find('}')
            // A line whose first `}` comes before its first `{` is skipped (MIK-8691).
            && start < end
        {
            let param_name = &trimmed[start + 1..end];
            if !param_name.is_empty()
                && param_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !parameters.contains(&param_name.to_string())
            {
                parameters.push(param_name.to_string());
            }
        }
    }

    // Extract description from YAML (first non-comment line starting with "description:")
    let description = cap
        .yaml
        .lines()
        .find(|l| l.trim_start().starts_with("description:"))
        .and_then(|l| l.trim_start().strip_prefix("description:"))
        .map(|d| d.trim().trim_matches('\'').trim_matches('"').to_string())
        .unwrap_or_default();

    ToolPreview {
        name: cap.name.clone(),
        description,
        method,
        path,
        parameters,
        class: if read_only { "read" } else { "write" },
        class_source: "inferred",
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(tp3)]
#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "import_redirect_tests.rs"]
mod redirect_tests;
