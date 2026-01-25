//! Error types for MCP Gateway

use std::io;

use thiserror::Error;

/// Result type alias for MCP Gateway
pub type Result<T> = std::result::Result<T, Error>;

/// MCP Gateway errors
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Backend not found
    #[error("Backend not found: {0}")]
    BackendNotFound(String),

    /// Backend unavailable (circuit open)
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    /// Backend timeout
    #[error("Backend timeout: {0}")]
    BackendTimeout(String),

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// JSON-RPC error
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc {
        /// Error code
        code: i32,
        /// Error message
        message: String,
        /// Optional data
        data: Option<serde_json::Value>,
    },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Server shutdown
    #[error("Server shutdown")]
    Shutdown,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Create a JSON-RPC error
    pub fn json_rpc(code: i32, message: impl Into<String>) -> Self {
        Self::JsonRpc {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Convert to JSON-RPC error code
    #[must_use]
    pub fn to_rpc_code(&self) -> i32 {
        match self {
            Self::JsonRpc { code, .. } => *code,
            Self::Json(_) => -32700,     // Parse error
            Self::Protocol(_) => -32600, // Invalid request
            Self::BackendNotFound(_) => -32001,
            Self::BackendUnavailable(_) => -32000,
            Self::BackendTimeout(_) => -32000,
            Self::Transport(_) => -32000,
            _ => -32603, // Internal error
        }
    }
}

/// Standard JSON-RPC error codes
pub mod rpc_codes {
    /// Parse error - Invalid JSON
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid Request - Not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Server error range start
    pub const SERVER_ERROR_START: i32 = -32000;
    /// Server error range end
    pub const SERVER_ERROR_END: i32 = -32099;
}
