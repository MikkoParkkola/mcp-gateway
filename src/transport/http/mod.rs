// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! HTTP/SSE transport implementation
//!
//! Implements proper MCP SSE client protocol:
//! 1. GET /sse endpoint to establish connection and receive session endpoint
//! 2. POST to the session endpoint (/`messages?session_id=XXX`) for requests
//! 3. SSE stream provides server->client notifications (optional)
//!
//! Supports OAuth 2.0 with PKCE for authenticated backends.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use reqwest::{Client, header};
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use url::Url;

use super::sanitize_url_for_diagnostics;
use crate::oauth::OAuthClient;
#[cfg(test)]
use crate::protocol::meta::KEY_PROTOCOL_VERSION;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::http_diagnostics::SESSION_EXPIRED_MARKER;
use crate::security::ssrf::DestinationPolicy;
use crate::{Error, Result};
pub(super) use modern_meta::with_modern_meta as modern_listen_params;
use modern_meta::{finalise_modern_headers, with_modern_meta};
#[cfg(test)]
use redirect_policy::evaluate_redirect;
use redirect_policy::{RedirectDecision, evaluate_redirect_for};

// Names the test modules reach through `use super::*`, which the code split
// into `requests`, `startup` and `transport_impl` no longer needs here.
#[cfg(test)]
use super::{ResendPermission, Transport};
#[cfg(test)]
use crate::protocol::PROTOCOL_VERSION;
#[cfg(test)]
use crate::protocol::era::Era;
#[cfg(test)]
use crate::protocol::meta::MODERN_VERSIONS;
#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use serde_json::Value;

/// The `tracing` target of the events this module raises, its `startup`,
/// `requests` and `transport_impl` children included: code moved into a child
/// module keeps the target a log filter already names.
const HTTP_TARGET: &str = module_path!();

/// Origin equality per WHATWG (scheme + host + effective port). Used to enforce
/// that an SSE-advertised message endpoint is same-origin as the SSE stream
/// before any per-user credential is sent to it (SSRF + credential-exfil guard).
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Refuse to put an OAuth bearer token on the wire in cleartext.
///
/// CWE-319 / `CodeQL` `rust/cleartext-transmission` #90 and #91: the token this
/// transport attaches is a bearer credential, so anyone on the path can replay
/// it. TLS is therefore required — with one exemption, loopback, because a
/// local MCP backend has no certificate and never leaves the machine.
///
/// Loopback is decided by the classifier the Origin gate and the config-load
/// credential guard already use, so the three cannot drift; `host_str` hands it
/// a bare host, brackets and all for an IPv6 literal. IPv4-mapped IPv6
/// (`http://[::ffff:127.0.0.1]`) is therefore *not* loopback —
/// `Ipv6Addr::is_loopback` says so, and the safe answer for an address form no
/// backend uses is to refuse.
///
/// There is deliberately no configuration escape hatch here, and the config
/// layer's `allow_cleartext_credentials` does not reach this guard: that flag
/// lets an operator accept a readable static header, but a flag that re-enables
/// a HIGH finding for OAuth would leave the alert open, and 4.0.0 is the release
/// that may break it.
///
/// The error is `TransportPermanent`, not `Transport`: waiting never makes a
/// cleartext origin secure, and warm-start treats a plain `Transport` error as
/// "not ready yet" and retries it forever at `debug` level, so the operator
/// sees a backend that silently never starts. Permanent gets one `warn!` and
/// stops.
fn require_secure_oauth_target(url: &Url) -> Result<()> {
    if crate::gateway::is_tls_or_loopback(url) {
        return Ok(());
    }
    Err(Error::TransportPermanent(format!(
        "refusing to send an OAuth token in cleartext to {}; use https:// or a loopback host \
         (allow_cleartext_credentials does not cover OAuth)",
        sanitize_url_for_diagnostics(url.as_str())
    )))
}

/// `Session not found`, as the rust-mcp-sdk and the remotes that copied it
/// report an invalidated MCP session. Both carriages key on it.
const SESSION_NOT_FOUND_CODE: i32 = -32015;

/// Detect the session-expiry signature in a transport error (MIK-5982).
///
/// Matches the safe markers emitted at the HTTP boundary:
/// - `session expired`, produced by
///   [`crate::security::http_diagnostics::safe_http_status_error`] after an untrusted
///   body contained JSON-RPC `-32015` or a case-insensitive `session not found`.
///   The classifier reads that marker rather than the body, because the body no
///   longer reaches an error string — it may echo our own credentials back at us.
///   These two functions are a pair: change the marker in one and session recovery
///   silently stops working, which is what the suite caught when this landed
///   half-applied (MIK-7221).
/// - bare `HTTP 404` responses, which the MCP Streamable HTTP spec defines as
///   "session terminated or expired" (callers gate this on having had a session)
///
/// This covers the cases where the backend surfaces the expiry as a transport
/// `Err` (non-2xx HTTP status, or a transport-layer failure). When the backend
/// instead returns HTTP 200 with the expiry encoded as a JSON-RPC `error`
/// member, use [`is_session_expired_response`] (MIK-6040, #247).
fn is_session_expired_error(err: &Error) -> bool {
    match err {
        Error::Transport(msg) => {
            let lower = msg.to_lowercase();
            lower.contains(SESSION_EXPIRED_MARKER) || lower.starts_with("http 404")
        }
        // A non-2xx whose body was the peer's own JSON-RPC error no longer
        // reaches this classifier as a status string: [`peer_refusal`] hands the
        // caller the peer's code instead. Without this arm the parse would have
        // taken session recovery away from every remote that invalidates a
        // session with a JSON body - the marker path above can only see errors
        // that stayed opaque. The membership test is the same one
        // [`is_session_expired_response`] applies to the 200 carriage, minus
        // `-32600`: on this path a malformed-request refusal is what it says it
        // is, and treating it as an expiry would re-initialize and retry every
        // one of them.
        Error::JsonRpc { code, message, .. } | Error::JsonRpcRetryable { code, message, .. } => {
            let lower = message.to_lowercase();
            // The marker set is the Transport arm's, mirrored: a peer that words
            // its expiry as "session expired" reaches one arm or the other
            // depending only on whether its body happened to parse, and the two
            // carriages must not disagree about what the peer said.
            *code == SESSION_NOT_FOUND_CODE
                || lower.contains("session not found")
                || lower.contains(SESSION_EXPIRED_MARKER)
        }
        _ => false,
    }
}

/// Whether a non-2xx status is the peer saying "not now" rather than "not ever".
///
/// A refusal carried as a status is normally terminal: a peer that declines
/// `resources/subscribe` with a 405 declines the retry identically, and
/// [`peer_refusal`] hands the caller that refusal so it stops asking. The
/// transient statuses are the exception — an overloaded peer answering 429 or
/// 503 is asking to be asked again, and it may carry that answer in a
/// JSON-RPC error body like any other. Converting those to `Error::JsonRpc`
/// would make them terminal for every caller on this transport, so they keep
/// the peer's code in [`Error::JsonRpcRetryable`] instead: the probe reads the
/// code, the retry classifiers read the carriage. Flattening them back to a
/// single variant is what this predicate exists to prevent.
fn status_invites_a_retry(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

/// The peer's own JSON-RPC error, if that is what this non-2xx body is.
///
/// The MCP HTTP binding lets a peer refuse with a status rather than a 200, so
/// a body that parses as a JSON-RPC error *answering this request* is an answer
/// and not a fault: retrying it asks a peer that has already replied, and
/// restarting the transport tears down a connection that is working. The
/// `id` test is what keeps that narrow. A proxy's error page, a gateway's own
/// JSON, or an error correlated to some other call are none of them this call's
/// answer, and each stays
/// [`crate::security::http_diagnostics::safe_http_status_error`]'s opaque transport fault.
///
/// The peer's `message` does reach the caller here, which the surrounding
/// status-error path deliberately avoids for untrusted bodies. The exposure is
/// the one the 200 carriage already accepts: a JSON-RPC error member is the
/// peer's own text about its own refusal, and it is surfaced verbatim when the
/// same refusal arrives with a 200.
///
/// The status and the body answer different questions. The body says what the
/// peer replied; the status says whether that reply was final. A transient
/// status keeps both facts in [`Error::JsonRpcRetryable`], because the health
/// probe reads the code and the retry classifiers read the carriage
/// (MIK-7217, OUTBOUND.2).
fn peer_refusal(body: &str, id: &RequestId, status: reqwest::StatusCode) -> Option<Error> {
    let response: JsonRpcResponse = serde_json::from_str(body).ok()?;
    if response.id.as_ref() != Some(id) {
        return None;
    }
    let error = response.error?;
    Some(if status_invites_a_retry(status) {
        Error::JsonRpcRetryable {
            code: error.code,
            message: error.message,
            status: status.as_u16(),
            data: error.data,
        }
    } else {
        Error::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        }
    })
}

/// Detect the session-expiry signature in a *successful-transport* JSON-RPC
/// response whose body carries an `error` member (MIK-6040, #247).
///
/// Some remotes (notably OAuth-protected Streamable HTTP servers that invalidate
/// the MCP session on token refresh) return HTTP 200 with the expiry encoded as
/// a JSON-RPC error rather than a non-2xx status. The transport layer sees this
/// as `Ok(JsonRpcResponse)` with `error: Some(..)`, so the [`is_session_expired_error`]
/// classifier — which only inspects transport `Err` strings — never fires. This
/// sibling classifier inspects the embedded error and matches:
/// - code `-32015` (rust-mcp-sdk "Session not found")
/// - code `-32600` (Invalid Request, observed for session-not-found on some remotes)
/// - any `message` containing "session not found" (case-insensitive)
///
/// Per MCP 2025-11-25 §2.5.4 the recovery is identical to the `Err` path: drop
/// the stale `MCP-Session-Id`, send a fresh `InitializeRequest`, and retry once.
fn is_session_expired_response(resp: &JsonRpcResponse) -> bool {
    resp.error.as_ref().is_some_and(|e| {
        e.code == SESSION_NOT_FOUND_CODE
            || e.code == -32600
            || e.message.to_lowercase().contains("session not found")
    })
}

/// HTTP transport for MCP servers using SSE or Streamable HTTP protocol
pub struct HttpTransport {
    /// HTTP client
    client: Client,
    /// Base URL (SSE endpoint or direct HTTP endpoint)
    base_url: String,
    /// Message endpoint URL (received from SSE handshake, or same as `base_url` for streamable)
    message_url: RwLock<Option<String>>,
    /// Custom headers
    headers: HashMap<String, String>,
    /// The owning `Backend`'s era cache, attached at start (MIK-7214.HEADER.9).
    ///
    /// Shared rather than copied: the verdict is re-probed on the backend when
    /// an ordinary answer contradicts it, and a copy taken at start would keep
    /// shaping requests for a peer that has since been replaced. `OnceLock`
    /// because a transport is rebuilt per start, so the cache it serves never
    /// changes for the life of this object.
    era: std::sync::OnceLock<Arc<crate::protocol::era::EraCache>>,
    /// Per-caller-identity MCP session ids (MIK-6784).
    ///
    /// A single `HttpTransport` is Arc-shared across every gateway user for a given backend, so a
    /// single `Option<String>` session slot (the prior design) let the first caller's
    /// `MCP-Session-Id` be stamped onto every other caller's outbound request — a stateful upstream
    /// could then serve one user's session-bound data to another. Partitioning by the caller's
    /// stable identity binding
    /// ([`crate::identity_propagation::PropagatedCredential::cache_binding`]) closes that hole:
    /// each identity negotiates and reuses its own upstream session. The empty-string key is the
    /// shared default bucket used by the no-identity static path (plain [`Transport::request`]), so
    /// single-tenant behavior is byte-for-byte unchanged.
    sessions: RwLock<HashMap<String, String>>,
    /// Set by [`HttpTransport::mark_single_tenant`] when the owning `Backend`
    /// built this instance for a per-user pool slot (MIK-6735 `PoolKey::PerUser`).
    /// `false` (the default) means this instance may be the backend's shared
    /// slot, Arc-shared across every caller — the exact scenario `sessions`
    /// exists to isolate — so it stays multi-entry and load-bearing there;
    /// only when `true` is it safe to assert the map is single-tenant. See
    /// the `debug_assert!` at the session-write site below for the invariant
    /// this hint unlocks.
    single_tenant_hint: AtomicBool,

    /// Request ID counter
    request_id: AtomicU64,
    /// Ends every listen body task when the transport closes (MIK-7630 I5).
    listen_cancel: tokio_util::sync::CancellationToken,
    /// Redirect hops this client has followed, ever (MIK-7272.SUB.4).
    ///
    /// Incremented by the redirect policy closure on the `Follow` arm, which
    /// reqwest runs before it dials the next hop. The JSON-RPC dispatch site
    /// samples it either side of `send()`: an unchanged count proves the
    /// request never left the origin it was addressed to, which is what makes
    /// a connect failure there provably pre-dispatch. A 307 re-submits the
    /// body, so a connect failure *after* a hop says nothing about whether the
    /// redirecting origin already executed the call.
    ///
    /// Client-global, not per-request: a concurrent peer request's hop inflates
    /// the delta and the sampling request degrades to the coarse
    /// `Error::Transport`, i.e. today's terminal settlement. That is the
    /// fail-safe direction -- the counter can only ever cost a retry, never
    /// license one.
    redirects_followed: Arc<AtomicU64>,
    /// Connected flag
    connected: AtomicBool,
    /// Request timeout (used in client builder)
    #[allow(dead_code)]
    timeout: Duration,
    /// `Some(true)`: Streamable HTTP (direct POST). `Some(false)`: the legacy
    /// SSE handshake. `None`: not yet detected; the first handshake decides
    /// and stores the answer here, so a reconnect does not probe again.
    streamable_http: RwLock<Option<bool>>,
    /// Whether this start already switched transport once (see `handshake`).
    switched: AtomicBool,
    /// OAuth client for authenticated backends (Arc allows background refresh task to share it)
    oauth_client: Option<Arc<TokioMutex<OAuthClient>>>,
    /// Background token-refresh task handle, set during `initialize()`.
    /// Stored in a lock so `initialize(&self)` can assign it after construction.
    refresh_task: RwLock<Option<JoinHandle<()>>>,
    /// Protocol version override (if `None`, uses `PROTOCOL_VERSION` with fallback)
    protocol_version: RwLock<Option<String>>,
}

/// Outgoing header modes for the HTTP transport call-sites.
#[derive(Clone, Copy)]
enum HeaderMode<'a> {
    Sse,
    /// The legacy session GET of the I5 listener: `Sse` plus the shared
    /// bucket's `MCP-Session-Id`, which `Sse` deliberately omits.
    SessionStream,
    Request {
        method: &'a str,
    },
    Notify,
    Close,
}

/// Build the `Authorization: Bearer …` header value for `token`.
///
/// Returns a clean [`Error::OAuth`] instead of panicking when the token carries
/// bytes illegal in an HTTP header value — control characters or bytes outside
/// visible ASCII (MIK-6909). A backend credential is attacker-influenceable in
/// federated/token-exchange deployments, so a malformed token must fail the
/// request as an auth error, never abort the process. The token is never echoed
/// into the error, keeping the credential out of logs (CWE-532).
fn bearer_header_value(token: &str) -> Result<header::HeaderValue> {
    header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| Error::OAuth("OAuth token is not a valid HTTP header value".into()))
}

impl HttpTransport {
    /// Create a new HTTP transport
    ///
    /// If `streamable_http` is true, uses direct POST without SSE handshake.
    /// Otherwise uses SSE protocol (GET for endpoint, POST for messages).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: bool,
    ) -> Result<Arc<Self>> {
        Self::new_with_oauth(url, headers, timeout, streamable_http, None, None)
    }

    /// Create a new HTTP transport with optional OAuth client and protocol version
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new_with_oauth(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: bool,
        oauth_client: Option<OAuthClient>,
        protocol_version: Option<String>,
    ) -> Result<Arc<Self>> {
        let configured = DestinationPolicy::Configured;
        Self::with_destination(
            url,
            headers,
            timeout,
            Some(streamable_http),
            oauth_client,
            protocol_version,
            configured,
        )
    }

    /// [`Self::new_with_oauth`] under a backend destination policy: `Public`
    /// refuses a private literal base before anything connects, and pins names.
    /// A `None` flavour is detected at connect (see `TransportConfig::Http`).
    pub(crate) fn with_destination(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: Option<bool>,
        oauth_client: Option<OAuthClient>,
        protocol_version: Option<String>,
        destination: DestinationPolicy,
    ) -> Result<Arc<Self>> {
        // Parse the base URL once so the redirect policy can enforce
        // same-origin on every hop (credential-exfil guard, see
        // `evaluate_redirect`). An unparseable base cannot function as a
        // transport at all, so failing construction here is correct.
        let base_origin = Url::parse(url)
            .map_err(|e| Error::Transport(format!("Invalid transport base URL: {e}")))?;
        destination.check_literal(&base_origin)?;
        // Refuse at construction, not only at request time: `initialize` runs
        // the full authorization flow and starts a refresh task, so a
        // request-time-only guard would mint a credential it may never send.
        if oauth_client.is_some() {
            require_secure_oauth_target(&base_origin)?;
        }
        let redirects_followed = Arc::new(AtomicU64::new(0));
        let client = client::build(
            base_origin,
            timeout,
            destination,
            Arc::clone(&redirects_followed),
        )?;

        Ok(Arc::new(Self {
            client,
            base_url: url.to_string(),
            message_url: RwLock::new(None),
            headers,
            era: std::sync::OnceLock::new(),
            sessions: RwLock::new(HashMap::new()),
            single_tenant_hint: AtomicBool::new(false),
            request_id: AtomicU64::new(1),
            listen_cancel: tokio_util::sync::CancellationToken::new(),
            redirects_followed,
            connected: AtomicBool::new(false),
            timeout,
            streamable_http: RwLock::new(streamable_http),
            switched: AtomicBool::new(false),
            oauth_client: oauth_client.map(|c| Arc::new(TokioMutex::new(c))),
            refresh_task: RwLock::new(None),
            protocol_version: RwLock::new(protocol_version),
        }))
    }

    /// Store a new OAuth refresh task, aborting any prior one.
    ///
    /// `initialize()` is re-entered on reconnect/session-expiry (see
    /// `request()`), so the refresh-task slot must be idempotent: dropping a
    /// `JoinHandle` does not cancel the spawned task, so a plain overwrite would
    /// orphan the previous refresh loop — keeping the OAuth-client `Arc` alive
    /// and continuing to persist a gateway-held token (F3, MIK-6746).
    fn store_refresh_task(&self, handle: tokio::task::JoinHandle<()>) {
        if let Some(old) = self.refresh_task.write().replace(handle) {
            old.abort();
        }
    }

    /// Mark this instance as built for a per-user pool slot (MIK-6735).
    ///
    /// `Backend::start_entry` calls this immediately after construction, and
    /// only for a `PoolKey::PerUser` slot, whose transport is dedicated to
    /// one caller identity for its whole lifetime — no other identity is ever
    /// routed through it. That is what makes the `sessions` single-tenant
    /// `debug_assert!` provably safe to enable: it must stay OFF (the
    /// default) for a `Shared`-slot instance, which is Arc-shared across
    /// every caller and relies on `sessions` staying multi-entry.
    /// Attach the owning `Backend`'s era cache, so outbound messages can be
    /// shaped for the dialect the peer actually speaks (MIK-7214.HEADER.9).
    ///
    /// A setter rather than a constructor parameter: `new` and `new_with_oauth`
    /// are both public, and widening two published signatures for a value only
    /// the lifecycle can supply would put an argument in front of every
    /// external caller that has nothing to pass for it.
    ///
    /// Idempotent by construction. A second call is the lifecycle attaching a
    /// cache to a transport that already has one, which cannot happen for a
    /// freshly built transport and must not silently swap the cache if it ever
    /// did.
    pub(crate) fn attach_era(&self, era: Arc<crate::protocol::era::EraCache>) {
        let _ = self.era.set(era);
    }

    /// The peer's era, as far as it is known right now.
    ///
    /// Never probes and never blocks on one in flight: an unresolved era reads
    /// `None`, and `None` means legacy. Waiting here would deadlock — the probe
    /// is itself a request through this transport.
    /// Non-blocking on purpose: see `EraCache::cached_now`. This runs on the
    /// path the probe itself takes.
    fn outbound_era(&self) -> Option<crate::protocol::era::Era> {
        self.era.get().and_then(|era| era.cached_now())
    }

    pub(crate) fn mark_single_tenant(&self) {
        self.single_tenant_hint.store(true, Ordering::Relaxed);
    }
}

// ADR-008 / F3 (MIK-6746): RAII backstop — a discarded/partial-init transport
// must not leak a token-refresh loop. `initialize()` stores the refresh
// `JoinHandle` before `establish_sse_connection().await?`; if that `?` fails, or
// the transport is otherwise dropped without an awaited `close()`, the handle is
// dropped, which *detaches* (does not cancel) the tokio task — orphaning a loop
// that keeps refreshing + persisting a gateway-held OAuth token. Aborting on drop
// closes that no-close path. Composes with `close()`: after close the slot is
// `None`, so this abort is a no-op (no double abort).
impl Drop for HttpTransport {
    fn drop(&mut self) {
        if let Some(handle) = self.refresh_task.get_mut().take() {
            handle.abort();
        }
    }
}

mod cancel_guard;
mod client;
/// The guarded client, for the A2A transport (MIK-8063): the same redirect
/// policy and pinned resolution as every HTTP backend.
#[cfg(feature = "a2a")]
pub(crate) use client::build as guarded_client;
mod extra_headers;
#[allow(
    dead_code,
    reason = "MIK-7630 I5: opened by the listener once I4 lands"
)]
mod listen;
mod modern_meta;
mod redirect_policy;
mod requests;
mod sse_decoder;
mod startup;
mod transport_impl;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sse_decoder_tests;

#[cfg(test)]
mod private_redirect_tests;
