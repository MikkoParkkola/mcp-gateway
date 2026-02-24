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

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::{Client, header};
use serde_json::Value;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};
use url::Url;

use super::Transport;
use crate::oauth::OAuthClient;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, SUPPORTED_VERSIONS, RequestId};
use crate::{Error, Result};

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
    /// Session ID (extracted from `message_url` or headers)
    session_id: RwLock<Option<String>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// Connected flag
    connected: AtomicBool,
    /// Request timeout (used in client builder)
    #[allow(dead_code)]
    timeout: Duration,
    /// Use Streamable HTTP (direct POST, no SSE handshake)
    streamable_http: bool,
    /// OAuth client for authenticated backends (protected by async mutex for token refresh)
    oauth_client: Option<TokioMutex<OAuthClient>>,
    /// Protocol version override (if `None`, uses `PROTOCOL_VERSION` with fallback)
    protocol_version: RwLock<Option<String>>,
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
        let client = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .tcp_nodelay(true)
            .redirect(reqwest::redirect::Policy::limited(5)) // Follow redirects
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(Arc::new(Self {
            client,
            base_url: url.to_string(),
            message_url: RwLock::new(None),
            headers,
            session_id: RwLock::new(None),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            timeout,
            streamable_http,
            oauth_client: oauth_client.map(TokioMutex::new),
            protocol_version: RwLock::new(protocol_version),
        }))
    }

    /// Initialize the connection
    ///
    /// For SSE mode: establishes SSE handshake to get message endpoint
    /// For Streamable HTTP: uses URL directly (trailing slash only for localhost/Starlette)
    /// For OAuth-enabled backends: initializes OAuth client and obtains token first
    ///
    /// # Errors
    ///
    /// Returns an error if OAuth authorization fails, SSE handshake fails,
    /// or protocol version negotiation is unsuccessful.
    pub async fn initialize(&self) -> Result<()> {
        // Initialize OAuth client if configured
        if let Some(ref oauth_mutex) = self.oauth_client {
            let mut oauth = oauth_mutex.lock().await;
            oauth.initialize().await?;

            // If we don't have a valid token, trigger authorization flow
            if !oauth.has_valid_token() {
                info!(url = %self.base_url, "OAuth required - initiating authorization flow");
                oauth.authorize().await?;
            }
        }

        if self.streamable_http {
            // Streamable HTTP: use URL directly
            // Never add trailing slash — Dart/shelf (Pieces) returns 404 for trailing slash.
            // Starlette compatibility was the original reason, but it handles both.
            let url = self.base_url.clone();
            *self.message_url.write() = Some(url.clone());
            info!(url = %url, oauth = self.oauth_client.is_some(), "Streamable HTTP mode - direct POST");
        } else {
            // SSE mode: GET the SSE endpoint to receive the message endpoint
            let message_endpoint = self.establish_sse_connection().await?;
            let full_message_url = self.resolve_message_url(&message_endpoint)?;
            *self.message_url.write() = Some(full_message_url.clone());
            info!(sse_url = %self.base_url, message_url = %full_message_url, oauth = self.oauth_client.is_some(), "SSE handshake complete");
        }

        // Send initialize request via the message endpoint
        // Use configured protocol version if set, otherwise use latest
        let version = self.protocol_version.read().clone().unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(0),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        };

        let response = self.send_request(&request).await?;

        // Check for protocol version mismatch error
        if let Some(ref error) = response.error {
            let error_msg = &error.message;

            // If server rejected our protocol version, try to negotiate
            if error_msg.contains("Unsupported protocol version") || error_msg.contains("protocol version") {
                // Try to extract supported versions from error message
                if let Some(negotiated_version) = self.negotiate_protocol_version(error_msg).await {
                    warn!(
                        url = %self.base_url,
                        rejected_version = %version,
                        negotiated_version = %negotiated_version,
                        "Server rejected protocol version, retrying with negotiated version"
                    );

                    // Update our protocol version
                    *self.protocol_version.write() = Some(negotiated_version.clone());

                    // Retry initialize with new version
                    let retry_request = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        id: RequestId::Number(0),
                        method: "initialize".to_string(),
                        params: Some(serde_json::json!({
                            "protocolVersion": negotiated_version,
                            "capabilities": {},
                            "clientInfo": {
                                "name": "mcp-gateway",
                                "version": env!("CARGO_PKG_VERSION")
                            }
                        })),
                    };

                    let retry_response = self.send_request(&retry_request).await?;

                    if retry_response.error.is_some() {
                        return Err(Error::Protocol(format!(
                            "Initialize failed with negotiated version {}: {:?}",
                            negotiated_version, retry_response.error
                        )));
                    }

                    // Success with negotiated version
                    info!(url = %self.base_url, version = %negotiated_version, "Successfully negotiated protocol version");
                } else {
                    return Err(Error::Protocol(format!("Protocol version negotiation failed: {error_msg}")));
                }
            } else {
                return Err(Error::Protocol(format!("Initialize failed: {error:?}")));
            }
        }

        // Send initialized notification
        self.notify("notifications/initialized", None).await?;

        self.connected.store(true, Ordering::Relaxed);
        debug!(url = %self.base_url, streamable = %self.streamable_http, "HTTP transport initialized");

        Ok(())
    }

    /// Get OAuth access token if OAuth is configured
    async fn get_oauth_token(&self) -> Result<Option<String>> {
        if let Some(ref oauth_mutex) = self.oauth_client {
            let oauth = oauth_mutex.lock().await;
            let token = oauth.get_token().await?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Negotiate protocol version from error message
    /// Parse "supported versions: X, Y, Z" and find best match
    #[allow(clippy::unused_async)] // async for future network-based negotiation
    async fn negotiate_protocol_version(&self, error_msg: &str) -> Option<String> {
        // Try to extract supported versions from error message
        // Example: "Bad Request: Unsupported protocol version (supported versions: 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07)"
        let supported_versions = self.parse_supported_versions(error_msg)?;

        debug!(
            url = %self.base_url,
            server_versions = ?supported_versions,
            client_versions = ?SUPPORTED_VERSIONS,
            "Negotiating protocol version"
        );

        // Find highest version supported by both client and server
        for &client_version in SUPPORTED_VERSIONS {
            if supported_versions.iter().any(|v| v == client_version) {
                return Some(client_version.to_string());
            }
        }

        // No match found
        warn!(
            url = %self.base_url,
            server_versions = ?supported_versions,
            client_versions = ?SUPPORTED_VERSIONS,
            "No compatible protocol version found"
        );
        None
    }

    /// Parse supported versions from error message
    #[allow(clippy::unused_self)] // method on self for logical grouping
    fn parse_supported_versions(&self, error_msg: &str) -> Option<Vec<String>> {
        // Look for pattern: "supported versions: X, Y, Z" or "supported: X, Y, Z"
        let patterns = [
            "supported versions:",
            "supported:",
        ];

        for pattern in &patterns {
            if let Some(versions_start) = error_msg.to_lowercase().find(pattern) {
                let versions_str = &error_msg[versions_start + pattern.len()..];

                // Extract until closing paren or end of string
                let versions_str = if let Some(end) = versions_str.find(')') {
                    &versions_str[..end]
                } else {
                    versions_str
                };

                // Split by comma and trim
                let versions: Vec<String> = versions_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                if !versions.is_empty() {
                    return Some(versions);
                }
            }
        }

        None
    }

    /// Establish SSE connection and get the message endpoint
    async fn establish_sse_connection(&self) -> Result<String> {
        use futures::StreamExt;

        let version = self.protocol_version.read().clone().unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "text/event-stream".parse().unwrap());
        headers.insert("MCP-Protocol-Version", version.parse().unwrap());

        // Add OAuth token if available
        if let Some(token) = self.get_oauth_token().await? {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            debug!(url = %self.base_url, "SSE connection with OAuth token");
        }

        // Add custom headers (for auth, etc.)
        for (key, value) in &self.headers {
            if let (Ok(k), Ok(v)) = (
                key.parse::<reqwest::header::HeaderName>(),
                value.parse::<reqwest::header::HeaderValue>(),
            ) {
                headers.insert(k, v);
            }
        }

        debug!(url = %self.base_url, "Establishing SSE connection");

        let response = self
            .client
            .get(&self.base_url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("SSE connection failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transport(format!("SSE endpoint returned: {status}")));
        }

        // Stream the SSE response to find the endpoint event
        // We only need to read until we get the endpoint event, then stop
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        let mut event_type: Option<String> = None;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| Error::Transport(format!("Failed to read SSE chunk: {e}")))?;

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete lines in the buffer
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim().to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() {
                    event_type = None;
                    continue;
                }

                if let Some(event) = line.strip_prefix("event:") {
                    event_type = Some(event.trim().to_string());
                } else if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();

                    if event_type.as_deref() == Some("endpoint") {
                        debug!(endpoint = %data, "Received message endpoint from SSE");

                        // Extract session_id from the endpoint URL if present
                        if let Ok(url) = Url::parse(data)
                            .or_else(|_| Url::parse(&format!("http://localhost{data}")))
                        {
                            for (key, value) in url.query_pairs() {
                                if key == "session_id" {
                                    *self.session_id.write() = Some(value.to_string());
                                    debug!(session_id = %value, "Extracted session ID");
                                }
                            }
                        }

                        return Ok(data.to_string());
                    }
                }
            }
        }

        Err(Error::Transport(
            "SSE stream ended without endpoint event. Server may not support MCP SSE protocol."
                .to_string(),
        ))
    }

    /// Resolve a potentially relative message URL against the SSE URL
    fn resolve_message_url(&self, endpoint: &str) -> Result<String> {
        // If endpoint is already absolute, use it directly
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            return Ok(endpoint.to_string());
        }

        // Parse the base SSE URL
        let base_url = Url::parse(&self.base_url)
            .map_err(|e| Error::Transport(format!("Invalid SSE URL: {e}")))?;

        // Resolve relative URL
        let resolved = base_url
            .join(endpoint)
            .map_err(|e| Error::Transport(format!("Failed to resolve endpoint URL: {e}")))?;

        Ok(resolved.to_string())
    }

    /// Get the message URL, falling back to SSE URL if not set
    fn get_message_url(&self) -> String {
        self.message_url
            .read()
            .clone()
            .unwrap_or_else(|| self.base_url.clone())
    }

    /// Send a raw request to the message endpoint
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        let message_url = self.get_message_url();
        let version = self.protocol_version.read().clone().unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        // Accept both JSON and SSE - some servers return SSE for POST requests
        headers.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        headers.insert("MCP-Protocol-Version", version.parse().unwrap());

        // Add OAuth token if available (refreshes automatically if expired)
        if let Some(token) = self.get_oauth_token().await? {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
        }

        // Add session ID if available
        if let Some(ref session_id) = *self.session_id.read() {
            debug!(session_id = %session_id, method = %request.method, "Sending request with session ID");
            headers.insert("MCP-Session-Id", session_id.parse().unwrap());
        } else {
            debug!(method = %request.method, "Sending request without session ID");
        }

        // Add custom headers
        for (key, value) in &self.headers {
            if let (Ok(k), Ok(v)) = (
                key.parse::<reqwest::header::HeaderName>(),
                value.parse::<reqwest::header::HeaderValue>(),
            ) {
                headers.insert(k, v);
            }
        }

        let response = self
            .client
            .post(&message_url)
            .headers(headers)
            .json(request)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Request failed: {e}")))?;

        // Extract session ID from response headers if not already set
        if self.session_id.read().is_none() {
            if let Some(session_id) = response.headers().get("mcp-session-id") {
                if let Ok(id) = session_id.to_str() {
                    info!(session_id = %id, url = %message_url, "Stored session ID from response");
                    *self.session_id.write() = Some(id.to_string());
                }
            } else {
                // Debug: log all headers to find session ID
                debug!(url = %message_url, "No session ID in response. Headers: {:?}",
                    response.headers().iter()
                        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
                        .collect::<Vec<_>>()
                );
            }
        } else {
            debug!(session_id = %self.session_id.read().as_ref().unwrap(), "Using existing session ID");
        }

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Transport(format!("HTTP {status}: {body}")));
        }

        // Check Content-Type to determine response format
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("text/event-stream") {
            // Parse SSE response - extract JSON from "data:" line
            let text = response
                .text()
                .await
                .map_err(|e| Error::Transport(format!("Failed to read SSE response: {e}")))?;

            // Find the data line and extract JSON
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let json_str = data.trim();
                    return serde_json::from_str(json_str)
                        .map_err(|e| Error::Transport(format!("Failed to parse SSE data: {e}")));
                }
            }
            Err(Error::Transport("No data in SSE response".to_string()))
        } else {
            // Parse JSON response
            response
                .json()
                .await
                .map_err(|e| Error::Transport(format!("Failed to parse response: {e}")))
        }
    }

    /// Get next request ID
    #[allow(clippy::cast_possible_wrap)] // request IDs won't exceed i64::MAX
    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params,
        };

        self.send_request(&request).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let message_url = self.get_message_url();
        let version = self.protocol_version.read().clone().unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        // Accept both JSON and SSE - some servers (Beeper) require this for all requests
        headers.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        headers.insert("MCP-Protocol-Version", version.parse().unwrap());

        // Add OAuth token if available
        if let Some(token) = self.get_oauth_token().await? {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
        }

        if let Some(ref session_id) = *self.session_id.read() {
            headers.insert("MCP-Session-Id", session_id.parse().unwrap());
        }

        let response = self
            .client
            .post(&message_url)
            .headers(headers)
            .json(&notification)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("Notification failed: {e}")))?;

        if !response.status().is_success() {
            warn!(
                status = %response.status(),
                url = %message_url,
                "Notification failed"
            );
        }

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);

        // Send session termination if we have a session ID
        let session_id = self.session_id.read().clone();
        let message_url = self.get_message_url();

        if let Some(ref id) = session_id {
            let _ = self
                .client
                .delete(&message_url)
                .header("MCP-Session-Id", id)
                .send()
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    /// Helper: create an `HttpTransport` for testing (streamable HTTP mode, no OAuth)
    fn make_transport(url: &str) -> Arc<HttpTransport> {
        HttpTransport::new(url, HashMap::new(), Duration::from_secs(30), true).unwrap()
    }

    fn make_transport_sse(url: &str) -> Arc<HttpTransport> {
        HttpTransport::new(url, HashMap::new(), Duration::from_secs(30), false).unwrap()
    }

    // =========================================================================
    // Construction
    // =========================================================================

    #[test]
    fn new_creates_transport_with_defaults() {
        let t = make_transport("http://localhost:8080/mcp");
        assert_eq!(t.base_url, "http://localhost:8080/mcp");
        assert!(t.streamable_http);
        assert!(!t.is_connected());
        assert!(t.message_url.read().is_none());
        assert!(t.session_id.read().is_none());
        assert!(t.oauth_client.is_none());
    }

    #[test]
    fn new_with_custom_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        let t = HttpTransport::new("http://localhost:8080", headers, Duration::from_secs(5), false).unwrap();
        assert_eq!(t.headers.get("X-Custom").unwrap(), "value");
        assert!(!t.streamable_http);
    }

    #[test]
    fn new_with_oauth_and_protocol_version() {
        let t = HttpTransport::new_with_oauth(
            "http://localhost:8080",
            HashMap::new(),
            Duration::from_secs(30),
            true,
            None,
            Some("2024-11-05".to_string()),
        )
        .unwrap();
        assert_eq!(
            *t.protocol_version.read(),
            Some("2024-11-05".to_string())
        );
    }

    // =========================================================================
    // parse_supported_versions
    // =========================================================================

    #[test]
    fn parse_supported_versions_from_paren_format() {
        let t = make_transport("http://localhost");
        let msg = "Bad Request: Unsupported protocol version (supported versions: 2025-06-18, 2025-03-26, 2024-11-05)";
        let versions = t.parse_supported_versions(msg).unwrap();
        assert_eq!(versions, vec!["2025-06-18", "2025-03-26", "2024-11-05"]);
    }

    #[test]
    fn parse_supported_versions_from_supported_colon() {
        let t = make_transport("http://localhost");
        let msg = "Supported: 2024-11-05, 2024-10-07";
        let versions = t.parse_supported_versions(msg).unwrap();
        assert_eq!(versions, vec!["2024-11-05", "2024-10-07"]);
    }

    #[test]
    fn parse_supported_versions_case_insensitive() {
        let t = make_transport("http://localhost");
        let msg = "SUPPORTED VERSIONS: 2025-03-26";
        let versions = t.parse_supported_versions(msg).unwrap();
        assert_eq!(versions, vec!["2025-03-26"]);
    }

    #[test]
    fn parse_supported_versions_returns_none_for_no_match() {
        let t = make_transport("http://localhost");
        let msg = "Some random error message without versions";
        assert!(t.parse_supported_versions(msg).is_none());
    }

    #[test]
    fn parse_supported_versions_empty_after_colon() {
        let t = make_transport("http://localhost");
        let msg = "supported versions:)";
        // After colon there's ")" which yields an empty string before it
        assert!(t.parse_supported_versions(msg).is_none());
    }

    // =========================================================================
    // resolve_message_url
    // =========================================================================

    #[test]
    fn resolve_message_url_absolute_http() {
        let t = make_transport("http://localhost:8080/sse");
        let result = t.resolve_message_url("http://other:9090/messages").unwrap();
        assert_eq!(result, "http://other:9090/messages");
    }

    #[test]
    fn resolve_message_url_absolute_https() {
        let t = make_transport("https://api.example.com/sse");
        let result = t.resolve_message_url("https://api.example.com/messages?session_id=abc").unwrap();
        assert_eq!(result, "https://api.example.com/messages?session_id=abc");
    }

    #[test]
    fn resolve_message_url_relative_path() {
        let t = make_transport_sse("http://localhost:8080/sse");
        let result = t.resolve_message_url("/messages?session_id=123").unwrap();
        assert_eq!(result, "http://localhost:8080/messages?session_id=123");
    }

    #[test]
    fn resolve_message_url_relative_sibling() {
        let t = make_transport_sse("http://localhost:8080/api/sse");
        let result = t.resolve_message_url("messages").unwrap();
        assert_eq!(result, "http://localhost:8080/api/messages");
    }

    // =========================================================================
    // get_message_url
    // =========================================================================

    #[test]
    fn get_message_url_returns_base_when_not_set() {
        let t = make_transport("http://localhost:8080/mcp");
        assert_eq!(t.get_message_url(), "http://localhost:8080/mcp");
    }

    #[test]
    fn get_message_url_returns_set_url() {
        let t = make_transport("http://localhost:8080/mcp");
        *t.message_url.write() = Some("http://localhost:8080/messages".to_string());
        assert_eq!(t.get_message_url(), "http://localhost:8080/messages");
    }

    // =========================================================================
    // next_id
    // =========================================================================

    #[test]
    fn next_id_increments() {
        let t = make_transport("http://localhost");
        let id1 = t.next_id();
        let id2 = t.next_id();
        let id3 = t.next_id();
        assert_eq!(id1, RequestId::Number(1));
        assert_eq!(id2, RequestId::Number(2));
        assert_eq!(id3, RequestId::Number(3));
    }

    // =========================================================================
    // is_connected / connected state
    // =========================================================================

    #[test]
    fn initially_not_connected() {
        let t = make_transport("http://localhost");
        assert!(!t.is_connected());
    }

    #[test]
    fn connected_state_toggles() {
        let t = make_transport("http://localhost");
        assert!(!t.is_connected());
        t.connected.store(true, Ordering::Relaxed);
        assert!(t.is_connected());
        t.connected.store(false, Ordering::Relaxed);
        assert!(!t.is_connected());
    }
}
