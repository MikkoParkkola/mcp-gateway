//! Stdio transport implementation (subprocess)
//!
//! Spawns an MCP server as a child process and communicates via JSON-RPC over
//! stdin/stdout.  Supports automatic protocol version negotiation: if the
//! server rejects the gateway's preferred version, the transport parses the
//! error for supported versions and retries with the highest mutually
//! supported version.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

use super::Transport;
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId,
    is_version_mismatch_error, negotiate_best_version, parse_supported_versions_from_error,
};
use crate::{Error, Result};

/// Stdio transport for subprocess MCP servers
pub struct StdioTransport {
    /// Child process
    child: Mutex<Option<Child>>,
    /// Pending requests waiting for response
    pending: dashmap::DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// Connected flag
    connected: AtomicBool,
    /// Command to execute
    command: String,
    /// Environment variables
    env: HashMap<String, String>,
    /// Working directory
    cwd: Option<String>,
    /// Request timeout for initialize and JSON-RPC calls
    request_timeout: std::time::Duration,
    /// Writer handle
    writer: Mutex<Option<tokio::process::ChildStdin>>,
    /// Negotiated protocol version (config override or auto-negotiated)
    protocol_version: RwLock<Option<String>>,
}

impl StdioTransport {
    /// Create a new stdio transport
    ///
    /// If `protocol_version` is `Some`, that version is used for the
    /// initialize handshake.  Otherwise the gateway attempts its latest
    /// version and auto-negotiates downward on rejection.
    #[must_use]
    pub fn new(
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        request_timeout: std::time::Duration,
        protocol_version: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            child: Mutex::new(None),
            pending: dashmap::DashMap::new(),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            command: command.to_string(),
            env,
            cwd,
            request_timeout,
            writer: Mutex::new(None),
            protocol_version: RwLock::new(protocol_version),
        })
    }

    /// Start the subprocess
    ///
    /// # Errors
    ///
    /// Returns an error if the command cannot be spawned or MCP initialization fails.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let parts = shlex::split(&self.command).ok_or_else(|| {
            Error::Config(format!("Invalid stdio command quoting: {}", self.command))
        })?;
        if parts.is_empty() {
            return Err(Error::Config("Empty command".to_string()));
        }

        let program = parts[0].as_str();
        let args = &parts[1..];

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Set environment
        for (key, value) in &self.env {
            cmd.env(key, value);
        }

        // Set working directory
        if let Some(ref cwd) = self.cwd {
            cmd.current_dir(cwd);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Transport(format!("Failed to spawn: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stdin".to_string()))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stderr".to_string()))?;

        *self.writer.lock().await = Some(stdin);
        *self.child.lock().await = Some(child);

        // Spawn reader task
        let transport = Arc::clone(self);
        tokio::spawn(async move {
            debug!("Reader task started");
            let mut reader = BufReader::new(stdout).lines();

            loop {
                match reader.next_line().await {
                    Ok(Some(line)) => {
                        debug!(line_len = line.len(), "Received line from stdout");
                        if let Err(e) = transport.handle_response(&line) {
                            error!(error = %e, line = %line, "Failed to handle response");
                        }
                    }
                    Ok(None) => {
                        debug!("Stdout EOF reached - process may have exited");
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Error reading from stdout");
                        break;
                    }
                }
            }

            transport.connected.store(false, Ordering::Relaxed);
            debug!("Stdio reader task ended");
        });

        let command = self.command.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                debug!(command = %command, line_len = line.len(), "Received line from stderr");
            }
        });

        // Initialize with protocol version negotiation. If initialization
        // fails, tear down the spawned process now; otherwise reader tasks keep
        // the transport Arc alive and failed starts leak orphan MCP servers.
        if let Err(error) = self.initialize().await {
            if let Err(close_error) = self.close().await {
                warn!(error = %close_error, "Failed to clean up stdio process after initialization error");
            }
            return Err(error);
        }

        Ok(())
    }

    /// Build the JSON-RPC initialize params for a given protocol version.
    fn build_init_params(version: &str) -> Value {
        serde_json::json!({
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-gateway",
                "version": env!("CARGO_PKG_VERSION")
            }
        })
    }

    /// Initialize the MCP connection with automatic version negotiation.
    ///
    /// 1. Sends `initialize` with the configured or latest protocol version.
    /// 2. On success, checks if the server responded with a different version
    ///    (spec-compliant negotiation) and records it.
    /// 3. On error containing version info, parses supported versions and
    ///    retries with the highest mutually supported version.
    async fn initialize(&self) -> Result<()> {
        let version = self
            .protocol_version
            .read()
            .clone()
            .unwrap_or_else(|| PROTOCOL_VERSION.to_string());

        debug!(
            command = %self.command,
            version = %version,
            "Sending MCP initialize"
        );

        let response = self
            .request("initialize", Some(Self::build_init_params(&version)))
            .await?;

        if let Some(ref error) = response.error {
            let error_msg = &error.message;

            // Protocol version mismatch — attempt negotiation
            if is_version_mismatch_error(error_msg) {
                return self.negotiate_and_retry(&version, error_msg).await;
            }

            return Err(Error::Protocol(format!(
                "Initialize failed for '{}': {error_msg}",
                self.command
            )));
        }

        // Success — check if server negotiated a different version
        if let Some(ref result) = response.result
            && let Some(server_version) = result.get("protocolVersion").and_then(Value::as_str)
        {
            if server_version == version {
                debug!(
                    command = %self.command,
                    version = %server_version,
                    "Protocol version accepted"
                );
            } else {
                info!(
                    command = %self.command,
                    requested = %version,
                    negotiated = %server_version,
                    "Server negotiated different protocol version"
                );
                *self.protocol_version.write() = Some(server_version.to_string());
            }
        }

        self.finish_initialization().await
    }

    /// Parse the error for supported versions, find a match, and retry.
    async fn negotiate_and_retry(&self, rejected_version: &str, error_msg: &str) -> Result<()> {
        let server_versions = parse_supported_versions_from_error(error_msg);

        let negotiated = server_versions
            .as_deref()
            .and_then(|sv| negotiate_best_version(sv));

        let Some(negotiated) = negotiated else {
            return Err(Error::Protocol(format!(
                "Protocol version negotiation failed for '{}': server rejected {rejected_version}, \
                 no compatible version found (server said: {error_msg})",
                self.command
            )));
        };

        warn!(
            command = %self.command,
            rejected = %rejected_version,
            negotiated = %negotiated,
            "Retrying initialize with negotiated protocol version"
        );

        // Retry with negotiated version
        let retry_response = self
            .request("initialize", Some(Self::build_init_params(negotiated)))
            .await?;

        if let Some(ref error) = retry_response.error {
            return Err(Error::Protocol(format!(
                "Initialize failed for '{}' even with negotiated version {negotiated}: {}",
                self.command, error.message
            )));
        }

        *self.protocol_version.write() = Some(negotiated.to_string());

        info!(
            command = %self.command,
            version = %negotiated,
            "Successfully negotiated protocol version"
        );

        self.finish_initialization().await
    }

    /// Complete the initialization handshake (send `initialized` notification).
    async fn finish_initialization(&self) -> Result<()> {
        // Yield to ensure I/O is processed before sending notification
        tokio::task::yield_now().await;

        // Send initialized notification
        self.notify("notifications/initialized", None).await?;

        // Yield again to ensure notification reaches the server
        tokio::task::yield_now().await;

        // Give the server time to fully transition to ready state
        // This is necessary because some MCP servers (like fulcrum) have async
        // initialization that continues after receiving the notification
        debug!("Waiting for server to complete initialization");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        self.connected.store(true, Ordering::Relaxed);

        let negotiated = self.protocol_version.read().clone();
        info!(
            command = %self.command,
            version = negotiated.as_deref().unwrap_or(PROTOCOL_VERSION),
            "Stdio transport initialized"
        );

        Ok(())
    }

    /// Handle a response line from stdout
    fn handle_response(&self, line: &str) -> Result<()> {
        debug!(line = %line, "Parsing response");
        let response: JsonRpcResponse = serde_json::from_str(line)?;

        if let Some(ref id) = response.id {
            let key = id.to_string();
            debug!(id = %key, pending_keys = ?self.pending.iter().map(|r| r.key().clone()).collect::<Vec<_>>(), "Looking for pending request");
            if let Some((_, sender)) = self.pending.remove(&key) {
                debug!(id = %key, "Found pending request, sending response");
                let _ = sender.send(response);
            } else {
                debug!(id = %key, "No pending request found for response");
            }
        } else {
            debug!("Response has no ID (notification?)");
        }

        Ok(())
    }

    /// Write a message to stdin
    async fn write_message(&self, message: &str) -> Result<()> {
        debug!(message_len = message.len(), message = %message, "Writing to stdin");
        let mut writer = self.writer.lock().await;
        if let Some(ref mut stdin) = *writer {
            stdin
                .write_all(message.as_bytes())
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
            stdin
                .flush()
                .await
                .map_err(|e| Error::Transport(e.to_string()))?;
            // Drop the lock before yielding to allow concurrent reads
            drop(writer);
            // Yield to give the runtime a chance to process the I/O
            tokio::task::yield_now().await;
            debug!("Write complete and flushed");
            Ok(())
        } else {
            Err(Error::Transport("Not connected".to_string()))
        }
    }

    /// Get next request ID
    #[allow(clippy::cast_possible_wrap)] // request IDs won't exceed i64::MAX
    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: id.clone(),
            method: method.to_string(),
            params,
        };

        let message = serde_json::to_string(&request)?;
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id.to_string(), tx);

        if let Err(e) = self.write_message(&message).await {
            self.pending.remove(&id.to_string());
            return Err(e);
        }

        // Wait for response with timeout
        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport("Response channel closed".to_string())),
            Err(_) => {
                self.pending.remove(&id.to_string());
                Err(Error::BackendTimeout("Request timed out".to_string()))
            }
        }
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };

        let message = serde_json::to_string(&notification)?;
        self.write_message(&message).await
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);

        // Close stdin
        *self.writer.lock().await = None;

        // Kill child process
        if let Some(ref mut child) = *self.child.lock().await {
            let _ = child.kill().await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_transport(cmd: &str) -> Arc<StdioTransport> {
        StdioTransport::new(
            cmd,
            HashMap::new(),
            None,
            std::time::Duration::from_secs(30),
            None,
        )
    }

    // =========================================================================
    // Construction
    // =========================================================================

    #[test]
    fn new_stores_command_and_defaults() {
        let t = make_transport("node server.js");
        assert_eq!(t.command, "node server.js");
        assert!(!t.is_connected());
        assert!(t.env.is_empty());
        assert!(t.cwd.is_none());
        assert!(t.protocol_version.read().is_none());
    }

    #[test]
    fn new_with_env_and_cwd() {
        let mut env = HashMap::new();
        env.insert("NODE_ENV".to_string(), "test".to_string());
        let t = StdioTransport::new(
            "node index.js",
            env,
            Some("/tmp".to_string()),
            std::time::Duration::from_secs(45),
            None,
        );
        assert_eq!(t.env.get("NODE_ENV").unwrap(), "test");
        assert_eq!(t.cwd.as_deref(), Some("/tmp"));
        assert_eq!(t.request_timeout, std::time::Duration::from_secs(45));
    }

    #[test]
    fn new_with_explicit_protocol_version() {
        let t = StdioTransport::new(
            "echo",
            HashMap::new(),
            None,
            std::time::Duration::from_secs(30),
            Some("2025-06-18".to_string()),
        );
        assert_eq!(*t.protocol_version.read(), Some("2025-06-18".to_string()));
    }

    // =========================================================================
    // next_id
    // =========================================================================

    #[test]
    fn next_id_increments_sequentially() {
        let t = make_transport("echo");
        assert_eq!(t.next_id(), RequestId::Number(1));
        assert_eq!(t.next_id(), RequestId::Number(2));
        assert_eq!(t.next_id(), RequestId::Number(3));
    }

    // =========================================================================
    // handle_response - valid JSON-RPC responses
    // =========================================================================

    #[test]
    fn handle_response_routes_to_pending_request() {
        let t = make_transport("echo");
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        t.pending.insert("1".to_string(), tx);

        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        t.handle_response(json).unwrap();

        let response = rx.try_recv().unwrap();
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn handle_response_string_id() {
        let t = make_transport("echo");
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        t.pending.insert("req-42".to_string(), tx);

        let json = r#"{"jsonrpc":"2.0","id":"req-42","result":{}}"#;
        t.handle_response(json).unwrap();

        let response = rx.try_recv().unwrap();
        assert!(response.result.is_some());
    }

    #[test]
    fn handle_response_no_matching_pending() {
        let t = make_transport("echo");
        // No pending request registered - should not panic
        let json = r#"{"jsonrpc":"2.0","id":99,"result":{}}"#;
        t.handle_response(json).unwrap();
    }

    #[test]
    fn handle_response_no_id_notification() {
        let t = make_transport("echo");
        // Notifications have no id - should be handled gracefully
        let json = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
        t.handle_response(json).unwrap();
    }

    #[test]
    fn handle_response_error_response() {
        let t = make_transport("echo");
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        t.pending.insert("5".to_string(), tx);

        let json =
            r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"Method not found"}}"#;
        t.handle_response(json).unwrap();

        let response = rx.try_recv().unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }

    #[test]
    fn handle_response_invalid_json_returns_error() {
        let t = make_transport("echo");
        let result = t.handle_response("not valid json");
        assert!(result.is_err());
    }

    // =========================================================================
    // build_init_params
    // =========================================================================

    #[test]
    fn build_init_params_contains_version() {
        let params = StdioTransport::build_init_params("2025-06-18");
        assert_eq!(params["protocolVersion"], "2025-06-18");
        assert_eq!(params["clientInfo"]["name"], "mcp-gateway");
    }

    // =========================================================================
    // is_connected
    // =========================================================================

    #[test]
    fn initially_not_connected() {
        let t = make_transport("echo");
        assert!(!t.is_connected());
    }

    #[test]
    fn connected_flag_toggles() {
        let t = make_transport("echo");
        t.connected.store(true, Ordering::Relaxed);
        assert!(t.is_connected());
        t.connected.store(false, Ordering::Relaxed);
        assert!(!t.is_connected());
    }

    #[tokio::test]
    async fn request_cleans_pending_entry_when_write_fails() {
        let t = make_transport("echo");

        let result = t.request("tools/list", None).await;

        assert!(matches!(result, Err(Error::Transport(message)) if message == "Not connected"));
        assert!(t.pending.is_empty());
    }
}
