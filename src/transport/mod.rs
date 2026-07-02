//! Transport implementations for MCP backends

mod http;
mod stdio;
pub mod websocket;

pub use self::http::HttpTransport;
pub use self::stdio::StdioTransport;
pub use self::websocket::McpFrame;

use async_trait::async_trait;
use serde_json::Value;

use crate::{Result, protocol::JsonRpcResponse};

/// Transport trait for MCP communication
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a request and wait for response
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;

    /// Send a request with additional per-request outbound headers (e.g. a
    /// propagated end-user identity credential, MIK-6704).
    ///
    /// The headers are passed by value down the call stack — never stashed on
    /// the shared transport — so concurrent requests from different users cannot
    /// cross-contaminate (tenant isolation, IDP.3). Transports that carry no
    /// HTTP headers (stdio, websocket) ignore `extra_headers` and behave exactly
    /// like [`Transport::request`]; only HTTP-header-bearing transports apply
    /// them. Default impl ignores the headers.
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
    ) -> Result<JsonRpcResponse> {
        self.request(method, params).await
    }

    /// Send a notification (no response expected)
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Close the transport
    async fn close(&self) -> Result<()>;
}
