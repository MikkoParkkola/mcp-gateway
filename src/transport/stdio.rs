//! Stdio transport implementation (subprocess)

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error};

use super::Transport;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId};
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
    /// Writer handle
    writer: Mutex<Option<tokio::process::ChildStdin>>,
}

impl StdioTransport {
    /// Create a new stdio transport
    #[must_use]
    pub fn new(command: &str, env: HashMap<String, String>, cwd: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            child: Mutex::new(None),
            pending: dashmap::DashMap::new(),
            request_id: AtomicU64::new(1),
            connected: AtomicBool::new(false),
            command: command.to_string(),
            env,
            cwd,
            writer: Mutex::new(None),
        })
    }

    /// Start the subprocess
    ///
    /// # Errors
    ///
    /// Returns an error if the command cannot be spawned or MCP initialization fails.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let parts: Vec<&str> = self.command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(Error::Config("Empty command".to_string()));
        }

        let program = parts[0];
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

        // Initialize
        self.initialize().await?;

        Ok(())
    }

    /// Initialize the MCP connection
    async fn initialize(&self) -> Result<()> {
        let response = self
            .request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;

        if response.error.is_some() {
            return Err(Error::Protocol("Initialize failed".to_string()));
        }

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
        debug!(command = %self.command, "Stdio transport initialized");

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

        let (tx, rx) = oneshot::channel();
        self.pending.insert(id.to_string(), tx);

        let message = serde_json::to_string(&request)?;
        self.write_message(&message).await?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Transport("Response channel closed".to_string())),
            Err(_) => {
                self.pending.remove(&id.to_string());
                Err(Error::BackendTimeout("Request timed out".to_string()))
            }
        }
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });

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
