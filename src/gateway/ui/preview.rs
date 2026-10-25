// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/previews` (MIK-8838, U6): start a server once to list
//! its tools before it is added, with nothing secret and nothing persisted.
//!
//! A command server runs only inside the ADR-027 sandbox launcher (MIK-8905);
//! until that lands a command preview is refused, so no command ever runs
//! unsandboxed. A URL server is reached under the SSRF guard with no
//! credentials of any kind.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::backend_ops::resolve_backend;
use super::backends::{AddBackendRequest, validate_backend_name};
use super::errors::{admin_auth_required, flat_error};
use super::is_admin;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::protocol::continuation::{ContinuationPurpose, Payload, clock_now};
use crate::security::ssrf::{DestinationPolicy, SSRF_BLOCKED};

use crate::backend::PreviewListing;
use crate::config::{BackendConfig, TransportConfig};

/// What a preview withheld from the resolved backend. Names only, never a
/// value.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct Withheld {
    pub(super) env: Vec<String>,
    pub(super) headers: Vec<String>,
    pub(super) oauth: bool,
    pub(super) secrets: usize,
    pub(super) identity_propagation: bool,
    pub(super) account: bool,
}

/// Strip every credential the resolved backend would carry, and say what was
/// stripped.
///
/// Applied to the *resolved* backend, not the request body: a catalogue entry
/// adds `${NAME}` env references and header templates that expand from the
/// gateway's own environment, and an OAuth stanza that would start a login.
pub(super) fn scrub(backend: &mut BackendConfig) -> Withheld {
    let mut env: Vec<String> = backend.env.drain().map(|(key, _)| key).collect();
    env.sort();
    let mut headers: Vec<String> = backend.headers.drain().map(|(key, _)| key).collect();
    headers.sort();
    let secrets = backend.secrets.len();
    backend.secrets.clear();
    Withheld {
        env,
        headers,
        oauth: backend.oauth.take().is_some(),
        secrets,
        identity_propagation: backend.identity_propagation.take().is_some(),
        account: backend.account.take().is_some(),
    }
}

/// Why a preview is refused before anything starts, with the operator-facing
/// reason. Each one still lets the server be added without a preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// A runtime profile launches differently; a local start would not match.
    Profiled,
    /// A WebSocket or A2A backend; the preview supports command and http(s)
    /// MCP servers.
    Unsupported,
    /// The URL carries userinfo or a query string.
    UrlCredentials,
    /// A command server, while the sandbox launcher is not available.
    NoSandbox,
}

impl Refusal {
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::Profiled => {
                "Preview does not run servers with a runtime profile. You can still add this server."
            }
            Self::Unsupported => {
                "Preview supports command and http(s) MCP servers. You can still add this server."
            }
            Self::UrlCredentials => {
                "Remove the credentials and query from the URL to preview it. You can still add this server."
            }
            Self::NoSandbox => {
                "Command previews run only inside the preview sandbox, which this gateway does not provide yet. You can still add this server."
            }
        }
    }
}

/// The refusal that applies to `backend` before any start, if one does.
pub(super) fn refusal(backend: &BackendConfig) -> Option<Refusal> {
    if backend.runtime_profile.is_some() {
        return Some(Refusal::Profiled);
    }
    match &backend.transport {
        TransportConfig::Stdio { .. } => Some(Refusal::NoSandbox),
        TransportConfig::Http { http_url, .. } => {
            url_carries_credentials(http_url).then_some(Refusal::UrlCredentials)
        }
        TransportConfig::WebSocket { .. } => Some(Refusal::Unsupported),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => Some(Refusal::Unsupported),
    }
}

/// True when `raw` has userinfo or a query string, or does not parse. Such a
/// URL is refused rather than rewritten, so the previewed URL is always the
/// one Save would persist and no credential is ever sent.
fn url_carries_credentials(raw: &str) -> bool {
    url::Url::parse(raw).map_or(true, |url| {
        !url.username().is_empty() || url.password().is_some() || url.query().is_some()
    })
}

// ── The route ────────────────────────────────────────────────────────────────

/// The whole start and listing, then teardown.
const PREVIEW_CAP: Duration = Duration::from_secs(30);

/// Each request's own timeout, past [`PREVIEW_CAP`], so a silent server is
/// always ended by the cap: one answer, 504, never a race with a 502.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

/// The most one response may carry, counted before parsing.
const RESPONSE_BUDGET: usize = 4 * 1024 * 1024;

/// The most a whole preview may read.
const PREVIEW_BUDGET: usize = 8 * 1024 * 1024;

/// The add body, plus the token from the describe step.
#[derive(Debug, Deserialize)]
pub(super) struct PreviewRequest {
    #[serde(flatten)]
    add: AddBackendRequest,
    confirm: Option<String>,
}

/// The gateways (by `AppState` address) with a confirmed preview running: one
/// at a time per gateway. A guard releases its entry when dropped, so every
/// exit frees it, a client that disconnects included.
static BUSY: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());

struct Busy(usize);

impl Busy {
    fn acquire(state: &Arc<AppState>) -> Option<Self> {
        let key = Arc::as_ptr(state).addr();
        // The lock is released before any guard exists: a guard built under
        // it (as `then_some` would, even when the insert fails) is dropped
        // under it too, and its `Drop` takes the same lock and deadlocks.
        let inserted = BUSY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
        inserted.then(|| Self(key))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

fn transport_label(backend: &crate::config::BackendConfig) -> (&'static str, Option<String>) {
    match &backend.transport {
        crate::config::TransportConfig::Http { http_url, .. } => ("http", Some(http_url.clone())),
        crate::config::TransportConfig::Stdio { .. } => ("stdio", None),
        crate::config::TransportConfig::WebSocket { .. } => ("websocket", None),
        #[cfg(feature = "a2a")]
        crate::config::TransportConfig::A2a { .. } => ("a2a", None),
    }
}

/// `POST /ui/api/previews`: describe (no `confirm`) or run (with it).
pub(super) async fn preview_backend(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    Json(request): Json<PreviewRequest>,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    let principal = client.map(|c| c.name).unwrap_or_default();
    let add = request.add;
    if let Err(message) = validate_backend_name(&add.name) {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, message).into_response();
    }
    let resolved = match resolve_backend(
        add.registry.as_deref().unwrap_or(&add.name),
        add.command.as_deref(),
        add.url.as_deref(),
        add.description.as_deref(),
        add.env,
    ) {
        Ok(resolved) => resolved,
        Err(message) => {
            return flat_error(StatusCode::UNPROCESSABLE_ENTITY, message).into_response();
        }
    };
    let mut backend = resolved.backend;
    let withheld = scrub(&mut backend);
    if let Some(refusal) = refusal(&backend) {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, refusal.reason()).into_response();
    }
    let (transport, url) = transport_label(&backend);
    let described = json!({
        "transport": transport,
        "url": url,
        "withheld": withheld,
        "publisher": {"verified": false, "source": null},
    });
    let digest = crate::hashing::sha256_hex(
        &serde_json::to_vec(&json!({"name": add.name, "backend": backend})).unwrap_or_default(),
    );
    let Ok(now) = clock_now() else {
        return flat_error(StatusCode::SERVICE_UNAVAILABLE, "clock unavailable").into_response();
    };

    let Some(token) = request.confirm else {
        let payload = Payload::mint_preview(principal, digest, now);
        return match state.continuation.keyring().mint(&payload) {
            Ok(confirm) => (
                StatusCode::ACCEPTED,
                Json(json!({"confirm": confirm, "preview": described})),
            )
                .into_response(),
            Err(_) => flat_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cannot issue a confirmation now",
            )
            .into_response(),
        };
    };

    // Busy first, then redeem: a busy answer never spends the token.
    let Some(busy) = Busy::acquire(&state) else {
        return flat_error(StatusCode::CONFLICT, "a preview is already running").into_response();
    };
    if !redeem(&state, &token, &principal, &digest, now).await {
        return flat_error(
            StatusCode::CONFLICT,
            "the confirmation is invalid, expired or spent",
        )
        .into_response();
    }
    let response = run_confirmed(&state, &add.name, &backend, described).await;
    drop(busy);
    response
}

/// Open, check and spend a preview confirmation in one step.
async fn redeem(state: &AppState, token: &str, principal: &str, digest: &str, now: u64) -> bool {
    match state.continuation.keyring().open(token, now) {
        Ok(payload)
            if payload
                .require_purpose(ContinuationPurpose::PreviewConfirm)
                .is_ok()
                && payload.redeemable_by(principal, digest).is_ok() =>
        {
            state
                .continuation
                .ledger()
                .consume(&payload.jti, payload.expires_at, now)
                .await
        }
        _ => false,
    }
}

/// Start the scrubbed backend once, list its tools, and close it, all inside
/// [`PREVIEW_CAP`].
async fn run_confirmed(
    state: &AppState,
    name: &str,
    backend: &BackendConfig,
    described: Value,
) -> Response {
    let TransportConfig::Http {
        http_url,
        streamable_http,
        protocol_version,
    } = &backend.transport
    else {
        return flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            Refusal::NoSandbox.reason(),
        )
        .into_response();
    };
    let policy = if state.ssrf_protection {
        DestinationPolicy::Public
    } else {
        DestinationPolicy::Configured
    };
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(PREVIEW_CAP, async {
        let transport = crate::transport::HttpTransport::with_destination(
            http_url,
            std::collections::HashMap::new(),
            REQUEST_TIMEOUT,
            *streamable_http,
            None,
            protocol_version.clone(),
            policy,
        )?;
        transport.set_body_budget(RESPONSE_BUDGET, PREVIEW_BUDGET);
        let listed = async {
            crate::backend::start_detached_http(&transport, name, REQUEST_TIMEOUT).await?;
            crate::backend::list_tools_for_preview(name, transport.as_ref()).await
        }
        .await;
        let _ = crate::transport::Transport::close(transport.as_ref()).await;
        listed
    })
    .await;
    match outcome {
        Err(_) => flat_error(
            StatusCode::GATEWAY_TIMEOUT,
            "the server did not answer within 30 s",
        )
        .into_response(),
        Ok(Err(error)) => {
            let message = error.to_string();
            let status = if message.contains(SSRF_BLOCKED) {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_GATEWAY
            };
            flat_error(status, message).into_response()
        }
        Ok(Ok(listing)) => {
            Json(listed_body(&listing, described, started.elapsed())).into_response()
        }
    }
}

/// The 200 body: each tool with its class and where the class came from.
fn listed_body(listing: &PreviewListing, mut preview: Value, elapsed: Duration) -> Value {
    let tools: Vec<Value> = listing
        .tools
        .iter()
        .map(|tool| {
            let hints = tool.annotations.as_ref();
            let read = hints.and_then(|a| a.read_only_hint) == Some(true);
            json!({
                "name": tool.name,
                "description": tool.description,
                "class": if read { "read" } else { "write" },
                "class_source": if listing.hint_declared.contains(&tool.name) { "declared" } else { "inferred" },
                "destructive": hints.and_then(|a| a.destructive_hint) == Some(true),
            })
        })
        .collect();
    preview["stopped"] = json!(true);
    preview["truncated"] = json!(listing.truncated);
    preview["elapsed_ms"] = json!(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
    json!({
        "preview": preview,
        "tools": tools,
        "withheld_tools": listing.withheld.iter().map(|name| json!({"name": name})).collect::<Vec<_>>(),
    })
}
