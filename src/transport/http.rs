//! HTTP/SSE transport implementation

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::{Client, header};
use serde_json::Value;
use tracing::{debug, warn};

use super::Transport;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId};
use crate::{Error, Result};

/// HTTP transport for MCP servers
pub struct HttpTransport {
    /// HTTP client
    client: Client,
    /// Base URL
    url: String,
    /// Custom headers
    headers: HashMap<String, String>,
    /// Session ID (from server)
    session_id: RwLock<Option<String>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// Connected flag
    connected: AtomicBool,
    /// Request timeout
    timeout: Duration,
}

impl HttpTransport {
    /// Create a new HTTP transport
    pub fn new(
        url: &str,
        headers: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<Arc<Self>> {
        let client = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)  // Keep up to 10 idle connections per host
            .pool_idle_timeout(Duration::from_secs(90))  // Keep connections alive for 90s
            .tcp_keepalive(Duration::from_secs(30))  // TCP keepalive every 30s
            .tcp_nodelay(true)  // Disable Nagle's algorithm for lower latency
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;

        Ok(Arc::new(Self {
            client,
            url: url.to_string(),
            headers,
            session_id: RwLock::new(None),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            timeout,
        }))
    }

    /// Initialize the connection
    pub async fn initialize(&self) -> Result<()> {
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
        debug!(url = %self.url, "HTTP transport initialized");

        Ok(())
    }

    /// Send a raw request
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        headers.insert("MCP-Protocol-Version", PROTOCOL_VERSION.parse().unwrap());

        // Add session ID if available
        if let Some(ref session_id) = *self.session_id.read() {
            headers.insert("MCP-Session-Id", session_id.parse().unwrap());
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
            .post(&self.url)
            .headers(headers)
            .json(request)
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        // Extract session ID from response headers
        if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                *self.session_id.write() = Some(id.to_string());
            }
        }

        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transport(format!("HTTP error: {status}")));
        }

        // Check content type for SSE
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("text/event-stream") {
            // Parse SSE response
            self.parse_sse_response(response).await
        } else {
            // Parse JSON response
            response
                .json()
                .await
                .map_err(|e| Error::Transport(e.to_string()))
        }
    }

    /// Parse SSE response to get JSON-RPC response
    async fn parse_sse_response(&self, response: reqwest::Response) -> Result<JsonRpcResponse> {
        let text = response
            .text()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        // Find the data line
        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                return serde_json::from_str(data).map_err(|e| Error::Transport(e.to_string()));
            }
        }

        Err(Error::Transport("No data in SSE response".to_string()))
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
            .post(&self.url)
            .headers(headers)
            .json(&notification)
            .send()
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        if !response.status().is_success() {
            warn!(
                status = %response.status(),
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
        if let Some(ref id) = session_id {
            let _ = self
                .client
                .delete(&self.url)
                .header("MCP-Session-Id", id)
                .send()
                .await;
        }

        Ok(())
    }
}
