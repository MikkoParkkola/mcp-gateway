//! Transport implementations for MCP backends

mod http;
mod stdio;

pub use self::http::HttpTransport;
pub use self::stdio::StdioTransport;

use async_trait::async_trait;
use serde_json::Value;

use crate::{Result, protocol::JsonRpcResponse};

/// Transport trait for MCP communication
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a request and wait for response
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;

    /// Send a notification (no response expected)
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;

    /// Check if transport is connected
    fn is_connected(&self) -> bool;

    /// Close the transport
    async fn close(&self) -> Result<()>;
}
