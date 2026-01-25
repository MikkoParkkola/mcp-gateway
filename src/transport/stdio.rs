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
            let mut reader = BufReader::new(stdout).lines();

            while let Ok(Some(line)) = reader.next_line().await {
                if let Err(e) = transport.handle_response(&line) {
                    error!(error = %e, "Failed to handle response");
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

        // Send initialized notification
        self.notify("notifications/initialized", None).await?;

        self.connected.store(true, Ordering::Relaxed);
        debug!(command = %self.command, "Stdio transport initialized");

        Ok(())
    }

    /// Handle a response line from stdout
    fn handle_response(&self, line: &str) -> Result<()> {
        let response: JsonRpcResponse = serde_json::from_str(line)?;

        if let Some(ref id) = response.id {
            let key = id.to_string();
            if let Some((_, sender)) = self.pending.remove(&key) {
                let _ = sender.send(response);
            }
        }

        Ok(())
    }

    /// Write a message to stdin
    async fn write_message(&self, message: &str) -> Result<()> {
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
            Ok(())
        } else {
            Err(Error::Transport("Not connected".to_string()))
        }
    }

    /// Get next request ID
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
