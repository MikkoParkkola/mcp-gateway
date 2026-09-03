// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Transport implementations for MCP backends

mod http;
mod stdio;
pub mod websocket;

pub use self::http::HttpTransport;
pub use self::stdio::StdioTransport;
pub use self::websocket::McpFrame;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use tokio::sync::oneshot;

use crate::{Result, protocol::JsonRpcResponse};

/// Transport trait for MCP communication
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a request and wait for response
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;

    /// Send a request with additional per-request outbound headers (e.g. a
    /// propagated end-user identity credential, MIK-6704) plus the caller's
    /// identity key that partitions upstream session state (MIK-6784).
    ///
    /// The headers are passed by value down the call stack — never stashed on
    /// the shared transport — so concurrent requests from different users cannot
    /// cross-contaminate (tenant isolation, IDP.3). `identity_key` is the stable
    /// per-caller binding (see [`crate::identity_propagation::PropagatedCredential`]
    /// `::cache_binding`); an HTTP-header-bearing transport uses it to select and
    /// store an `MCP-Session-Id` bucket unique to that caller, so a stateful
    /// upstream cannot serve one user's session-bound data to another (MIK-6784).
    /// `None` selects the shared default bucket, preserving single-tenant
    /// behavior byte-for-byte. Transports that carry no HTTP headers (stdio,
    /// websocket) ignore both `extra_headers` and `identity_key` and behave
    /// exactly like [`Transport::request`]. Default impl ignores them.
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        self.request(method, params).await
    }

    /// Whether this transport instance actually applies `extra_headers`
    /// passed to [`Transport::request_with_headers`] to the wire (MIK-6710).
    ///
    /// The default `request_with_headers` impl above ignores `extra_headers`
    /// entirely and falls back to [`Transport::request`], so a caller that
    /// resolves a per-user identity-propagation credential (MIK-6704) and
    /// forwards it via `request_with_headers` to a transport that does not
    /// override this method would have that credential silently dropped —
    /// the backend then runs unauthenticated while the caller's audit trail
    /// records a mint, not a refusal. Identity-propagation dispatch gates
    /// (`resolve_caller_credential`, the direct backend route) call this
    /// BEFORE minting or forwarding a credential, and fail closed for a
    /// `required` backend when it returns `false`.
    ///
    /// Defaults to `false` (fail closed): only [`crate::transport::HttpTransport`]
    /// overrides this to `true`. stdio and websocket transports carry no
    /// per-request HTTP header channel and must not claim otherwise.
    fn carries_identity_headers(&self) -> bool {
        false
    }

    /// Send a notification (no response expected)
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;

    /// Send a notification carrying the caller's identity key, so a
    /// header-bearing transport can route it through the same
    /// `MCP-Session-Id` bucket [`Transport::request_with_headers`] used for
    /// that identity (MIK-6735 fix 2). Mirrors the `request`/
    /// `request_with_headers` split above: `_identity_key` is ignored by the
    /// default impl, which falls back to plain [`Transport::notify`] — exactly
    /// right for stdio/websocket transports that carry no per-request HTTP
    /// header channel and have no session bucket to select. `None` preserves
    /// single-tenant behavior byte-for-byte.
    async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _identity_key: Option<&str>,
    ) -> Result<()> {
        self.notify(method, params).await
    }

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Close the transport
    async fn close(&self) -> Result<()>;
}

/// RAII removal of a `pending` entry when its request future is dropped.
///
/// [`Transport::request`] implementations register a response `oneshot` sender
/// in their `pending` map before writing the request, then await the response.
/// The map entry is normally removed by the reader task when it routes the
/// matching response, or by the transport's own request timeout. Neither fires
/// when an OUTER timeout or task abort drops the in-flight request future
/// first — the entry would otherwise leak in `pending` for the life of the
/// transport, and a late response would find no matching sender.
///
/// The entry is meant to live exactly as long as the request does, so the guard
/// removes it on drop. On the success path the reader has already removed the
/// entry, making the removal a harmless no-op.
pub(crate) struct PendingRequestGuard<'a> {
    pending: &'a DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    key: String,
}

impl<'a> PendingRequestGuard<'a> {
    /// Wrap a `pending` map entry so it is removed when the guard drops.
    #[must_use]
    pub(crate) fn new(
        pending: &'a DashMap<String, oneshot::Sender<JsonRpcResponse>>,
        key: &str,
    ) -> Self {
        Self {
            pending,
            key: key.to_string(),
        }
    }
}

impl Drop for PendingRequestGuard<'_> {
    fn drop(&mut self) {
        self.pending.remove(&self.key);
    }
}
