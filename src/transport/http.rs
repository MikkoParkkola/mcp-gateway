//! HTTP/SSE transport implementation
//!
//! Implements proper MCP SSE client protocol:
//! 1. GET /sse endpoint to establish connection and receive session endpoint
//! 2. POST to the session endpoint (/`messages?session_id=XXX`) for requests
//! 3. SSE stream provides server->client notifications (optional)

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::{Client, header};
use serde_json::Value;
use tracing::{debug, info, warn};
use url::Url;

use super::Transport;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId};
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
}

impl HttpTransport {
    /// Create a new HTTP transport
    ///
    /// If `streamable_http` is true, uses direct POST without SSE handshake.
    /// Otherwise uses SSE protocol (GET for endpoint, POST for messages).
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
        streamable_http: bool,
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
        }))
    }

    /// Initialize the connection
    ///
    /// For SSE mode: establishes SSE handshake to get message endpoint
    /// For Streamable HTTP: uses URL directly (with trailing slash if needed)
    pub async fn initialize(&self) -> Result<()> {
        if self.streamable_http {
            // Streamable HTTP: use URL directly (add trailing slash if needed for Starlette)
            let mut url = self.base_url.clone();
            if !url.ends_with('/') {
                url.push('/');
            }
            *self.message_url.write() = Some(url.clone());
            info!(url = %url, "Streamable HTTP mode - direct POST");
        } else {
            // SSE mode: GET the SSE endpoint to receive the message endpoint
            let message_endpoint = self.establish_sse_connection().await?;
            let full_message_url = self.resolve_message_url(&message_endpoint)?;
            *self.message_url.write() = Some(full_message_url.clone());
            info!(sse_url = %self.base_url, message_url = %full_message_url, "SSE handshake complete");
        }

        // Send initialize request via the message endpoint
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(0),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        };

        let response = self.send_request(&request).await?;

        if response.error.is_some() {
            return Err(Error::Protocol("Initialize failed".to_string()));
        }

        // Send initialized notification
        self.notify("notifications/initialized", None).await?;

        self.connected.store(true, Ordering::Relaxed);
        debug!(url = %self.base_url, streamable = %self.streamable_http, "HTTP transport initialized");

        Ok(())
    }

    /// Establish SSE connection and get the message endpoint
    async fn establish_sse_connection(&self) -> Result<String> {
        use futures::StreamExt;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            "text/event-stream".parse().unwrap(),
        );
        headers.insert("MCP-Protocol-Version", PROTOCOL_VERSION.parse().unwrap());

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
                        if let Ok(url) = Url::parse(data).or_else(|_| {
                            Url::parse(&format!("http://localhost{data}"))
                        }) {
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
            "SSE stream ended without endpoint event. Server may not support MCP SSE protocol.".to_string()
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

        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        // Accept both JSON and SSE - some servers return SSE for POST requests
        headers.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        headers.insert("MCP-Protocol-Version", PROTOCOL_VERSION.parse().unwrap());

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
            let text = response.text().await
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

        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert("MCP-Protocol-Version", PROTOCOL_VERSION.parse().unwrap());

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
