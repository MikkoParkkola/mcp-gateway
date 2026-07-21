// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stdio transport implementation (subprocess)
//!
//! Spawns an MCP server as a child process and communicates via JSON-RPC over
//! stdin/stdout.  Supports automatic protocol version negotiation: if the
//! server rejects the gateway's preferred version, the transport parses the
//! error for supported versions and retries with the highest mutually
//! supported version.

use std::collections::HashMap;
use std::ffi::OsString;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

#[cfg(test)]
use super::StdioRaceTestGate;
use super::{Transport, validate_json_rpc_response};
use crate::protocol::{
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId,
    is_version_mismatch_error, negotiate_best_version, parse_supported_versions_from_error,
};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StdioSessionPhase {
    #[default]
    Idle,
    Starting,
    Connected,
    Closed,
}

#[derive(Default)]
struct StdioSessionState {
    generation: u64,
    phase: StdioSessionPhase,
    initialize_result: Option<Value>,
}

#[derive(Clone, Copy)]
enum WireAccess {
    Starting(u64),
    Connected,
}

#[cfg(unix)]
const FALLBACK_EXEC_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg(windows)]
const FALLBACK_EXEC_PATH: &str = r"C:\Windows\System32;C:\Windows";
#[cfg(not(any(unix, windows)))]
const FALLBACK_EXEC_PATH: &str = "";

fn configure_child_environment(cmd: &mut Command, backend_env: &HashMap<String, String>) {
    cmd.env_clear();

    let path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from(FALLBACK_EXEC_PATH));
    cmd.env("PATH", path);

    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| dirs::home_dir().map(std::path::PathBuf::into_os_string))
    {
        cmd.env("HOME", home);
    }

    let tmpdir =
        std::env::var_os("TMPDIR").unwrap_or_else(|| std::env::temp_dir().into_os_string());
    cmd.env("TMPDIR", tmpdir);

    #[cfg(windows)]
    for key in [
        "USERPROFILE",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }

    // Backend configuration is authoritative and may intentionally override
    // a safe default such as PATH, HOME, or TMPDIR.
    for (key, value) in backend_env {
        cmd.env(key, value);
    }
}

/// Stdio transport for subprocess MCP servers
pub struct StdioTransport {
    /// Child process
    child: Mutex<Option<Child>>,
    /// Pending requests waiting for response
    pending: dashmap::DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// Generation-tagged connection state and cached initialize handshake.
    session: RwLock<StdioSessionState>,
    /// Serializes public writes/replays with generation invalidation and close.
    session_gate: Mutex<()>,
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
    #[cfg(test)]
    initialize_replay_test_gate: RwLock<Option<Arc<StdioRaceTestGate>>>,
    #[cfg(test)]
    initialize_request_entry_test_gate: RwLock<Option<Arc<StdioRaceTestGate>>>,
    #[cfg(test)]
    close_after_invalidation_test_gate: RwLock<Option<Arc<StdioRaceTestGate>>>,
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
            session: RwLock::new(StdioSessionState::default()),
            session_gate: Mutex::new(()),
            command: command.to_string(),
            env,
            cwd,
            request_timeout,
            writer: Mutex::new(None),
            protocol_version: RwLock::new(protocol_version),
            #[cfg(test)]
            initialize_replay_test_gate: RwLock::new(None),
            #[cfg(test)]
            initialize_request_entry_test_gate: RwLock::new(None),
            #[cfg(test)]
            close_after_invalidation_test_gate: RwLock::new(None),
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

        // Backend processes get only the minimal execution environment plus
        // values explicitly assigned to this backend. In particular, secrets
        // loaded into the gateway process must not be inherited implicitly.
        configure_child_environment(&mut cmd, &self.env);

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

        let generation = {
            let _session_guard = self.lock_session_gate().await?;
            self.begin_generation()
        };

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

            let _session_guard = transport.session_gate.lock().await;
            transport.invalidate_generation(generation);
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
        if let Err(error) = self.initialize(generation).await {
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
    async fn initialize(&self, generation: u64) -> Result<()> {
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
            .request_on_wire(
                "initialize",
                Some(Self::build_init_params(&version)),
                WireAccess::Starting(generation),
            )
            .await?;

        if let Some(ref error) = response.error {
            let error_msg = &error.message;

            // Protocol version mismatch — attempt negotiation
            if is_version_mismatch_error(error_msg) {
                return self
                    .negotiate_and_retry(generation, &version, error_msg)
                    .await;
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

        let result = response.result.ok_or_else(|| {
            Error::Protocol(format!(
                "Initialize response from '{}' omitted its result",
                self.command
            ))
        })?;

        self.finish_initialization(generation, result).await
    }

    /// Parse the error for supported versions, find a match, and retry.
    async fn negotiate_and_retry(
        &self,
        generation: u64,
        rejected_version: &str,
        error_msg: &str,
    ) -> Result<()> {
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
            .request_on_wire(
                "initialize",
                Some(Self::build_init_params(negotiated)),
                WireAccess::Starting(generation),
            )
            .await?;

        if let Some(ref error) = retry_response.error {
            return Err(Error::Protocol(format!(
                "Initialize failed for '{}' even with negotiated version {negotiated}: {}",
                self.command, error.message
            )));
        }

        *self.protocol_version.write() = Some(negotiated.to_string());
        let result = retry_response.result.ok_or_else(|| {
            Error::Protocol(format!(
                "Initialize response from '{}' omitted its result",
                self.command
            ))
        })?;

        info!(
            command = %self.command,
            version = %negotiated,
            "Successfully negotiated protocol version"
        );

        self.finish_initialization(generation, result).await
    }

    /// Complete the initialization handshake (send `initialized` notification).
    async fn finish_initialization(&self, generation: u64, initialize_result: Value) -> Result<()> {
        // Yield to ensure I/O is processed before sending notification
        tokio::task::yield_now().await;

        // Send initialized notification
        self.notify_on_wire(
            "notifications/initialized",
            None,
            WireAccess::Starting(generation),
        )
        .await?;

        // Yield again to ensure notification reaches the server
        tokio::task::yield_now().await;

        // Give the server time to fully transition to ready state
        // This is necessary because some MCP servers (like fulcrum) have async
        // initialization that continues after receiving the notification
        debug!("Waiting for server to complete initialization");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let _session_guard = self.lock_session_gate().await?;
        {
            let session = self.session.read();
            if session.generation != generation || session.phase != StdioSessionPhase::Starting {
                return Err(Error::Transport(format!(
                    "Stdio child '{}' was invalidated during initialization",
                    self.command
                )));
            }
        }

        let child_is_alive = {
            let mut child = self.lock_child().await?;
            match child.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(status)) => {
                        debug!(?status, "Stdio child exited during initialization");
                        false
                    }
                    Err(error) => {
                        warn!(%error, "Failed to verify stdio child after initialization");
                        false
                    }
                },
                None => false,
            }
        };
        if !child_is_alive {
            self.invalidate_generation(generation);
            return Err(Error::Transport(format!(
                "Stdio child '{}' exited during initialization",
                self.command
            )));
        }

        {
            let mut session = self.session.write();
            if session.generation != generation || session.phase != StdioSessionPhase::Starting {
                return Err(Error::Transport(format!(
                    "Stdio child '{}' was invalidated during initialization",
                    self.command
                )));
            }
            session.initialize_result = Some(initialize_result);
            session.phase = StdioSessionPhase::Connected;
        }

        let negotiated = self.protocol_version.read().clone();
        info!(
            command = %self.command,
            version = negotiated.as_deref().unwrap_or(PROTOCOL_VERSION),
            "Stdio transport initialized"
        );

        Ok(())
    }

    fn next_generation(generation: u64) -> u64 {
        generation.wrapping_add(1)
    }

    fn begin_generation(&self) -> u64 {
        let mut session = self.session.write();
        session.generation = Self::next_generation(session.generation);
        session.phase = StdioSessionPhase::Starting;
        session.initialize_result = None;
        session.generation
    }

    fn invalidate_generation(&self, generation: u64) {
        let mut session = self.session.write();
        if session.generation == generation {
            session.generation = Self::next_generation(session.generation);
            session.phase = StdioSessionPhase::Closed;
            session.initialize_result = None;
        }
    }

    fn invalidate_current_generation(&self) {
        let mut session = self.session.write();
        session.generation = Self::next_generation(session.generation);
        session.phase = StdioSessionPhase::Closed;
        session.initialize_result = None;
    }

    fn has_cached_initialize(&self) -> bool {
        let session = self.session.read();
        session.phase == StdioSessionPhase::Connected && session.initialize_result.is_some()
    }

    async fn lock_session_gate(&self) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        tokio::time::timeout(self.request_timeout, self.session_gate.lock())
            .await
            .map_err(|_| {
                Error::BackendTimeout("Timed out waiting for stdio session state".to_string())
            })
    }

    async fn lock_child(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Child>>> {
        tokio::time::timeout(self.request_timeout, self.child.lock())
            .await
            .map_err(|_| {
                Error::BackendTimeout("Timed out checking stdio child liveness".to_string())
            })
    }

    fn ensure_wire_access(&self, access: WireAccess) -> Result<()> {
        let session = self.session.read();
        let allowed = match access {
            WireAccess::Starting(generation) => {
                session.generation == generation && session.phase == StdioSessionPhase::Starting
            }
            WireAccess::Connected => session.phase == StdioSessionPhase::Connected,
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::Transport("Not connected".to_string()))
        }
    }

    async fn cached_initialize_if_live(&self) -> Result<Value> {
        let _session_guard = self.lock_session_gate().await?;
        let (candidate_generation, initialize_result) = {
            let session = self.session.read();
            if session.phase != StdioSessionPhase::Connected {
                return Err(Error::Transport(
                    "Stdio session was invalidated before initialize replay".to_string(),
                ));
            }
            let result = session.initialize_result.clone().ok_or_else(|| {
                Error::Protocol("Connected stdio session has no initialize result".to_string())
            })?;
            (session.generation, result)
        };

        let mut child = self.lock_child().await?;
        let Some(child) = child.as_mut() else {
            self.invalidate_generation(candidate_generation);
            return Err(Error::Transport(
                "Stdio initialize cache has no live child process".to_string(),
            ));
        };
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                self.invalidate_generation(candidate_generation);
                return Err(Error::Transport(format!(
                    "Stdio child '{}' exited before initialize replay ({status})",
                    self.command
                )));
            }
            Err(error) => {
                self.invalidate_generation(candidate_generation);
                return Err(Error::Transport(format!(
                    "Failed to verify stdio child '{}' before initialize replay: {error}",
                    self.command
                )));
            }
        }

        let session = self.session.read();
        if session.generation != candidate_generation
            || session.phase != StdioSessionPhase::Connected
        {
            return Err(Error::Transport(
                "Stdio session was invalidated before initialize replay".to_string(),
            ));
        }
        Ok(initialize_result)
    }

    async fn request_on_wire(
        &self,
        method: &str,
        params: Option<Value>,
        access: WireAccess,
    ) -> Result<JsonRpcResponse> {
        let session_guard = self.lock_session_gate().await?;
        self.ensure_wire_access(access)?;

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

        if let Err(error) = self.write_message(&message).await {
            self.pending.remove(&id.to_string());
            return Err(error);
        }
        drop(session_guard);

        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(response)) => validate_json_rpc_response(response, &id),
            Ok(Err(_)) => Err(Error::Transport("Response channel closed".to_string())),
            Err(_) => {
                self.pending.remove(&id.to_string());
                Err(Error::BackendTimeout("Request timed out".to_string()))
            }
        }
    }

    async fn notify_on_wire(
        &self,
        method: &str,
        params: Option<Value>,
        access: WireAccess,
    ) -> Result<()> {
        let _session_guard = self.lock_session_gate().await?;
        self.ensure_wire_access(access)?;
        let notification = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };
        self.write_message(&serde_json::to_string(&notification)?)
            .await
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
        #[cfg(test)]
        if method == "initialize" {
            let entry_gate = self.initialize_request_entry_test_gate.read().clone();
            if let Some(gate) = entry_gate {
                gate.pause().await;
            }
        }

        // One stdio child is one MCP protocol session. `start()` already sent
        // initialize and retained the exact negotiated result, so a logical
        // client handshake on `/mcp/{backend}` must be answered locally rather
        // than forwarding an invalid second initialize to the same child. An
        // initialize from any non-connected phase is always external/stale;
        // only the private startup path may write while `Starting`.
        if method == "initialize" {
            if !self.has_cached_initialize() {
                return Err(Error::Transport("Not connected".to_string()));
            }
            #[cfg(test)]
            let replay_gate = self.initialize_replay_test_gate.read().clone();
            #[cfg(test)]
            if let Some(gate) = replay_gate {
                gate.pause().await;
            }
            let result = self.cached_initialize_if_live().await?;
            debug!("Replaying cached stdio initialize result");
            return Ok(JsonRpcResponse::success(self.next_id(), result));
        }

        self.request_on_wire(method, params, WireAccess::Connected)
            .await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        // The child received this notification during `finish_initialization`.
        // Consume a direct client's matching logical-session notification once
        // the transport is connected instead of delivering it twice.
        if method == "notifications/initialized" {
            if !self.has_cached_initialize() {
                return Err(Error::Transport("Not connected".to_string()));
            }
            self.cached_initialize_if_live().await?;
            debug!("Consuming duplicate stdio initialized notification for live generation");
            return Ok(());
        }

        self.notify_on_wire(method, params, WireAccess::Connected)
            .await
    }

    fn is_connected(&self) -> bool {
        let generation = {
            let session = self.session.read();
            if session.phase != StdioSessionPhase::Connected {
                return false;
            }
            session.generation
        };
        // Defense in depth (Fix C): the reader task closes the session on
        // stdout EOF, but a zombie child or a not-yet-scheduled reader task can
        // leave the cached phase as Connected. A stale Connected phase makes
        // `Backend::ensure_started` a no-op and dispatches requests into a dead
        // pipe — the core reason a tripped breaker never recovered. Confirm real
        // liveness with a non-blocking waitpid. `try_lock` keeps this sync
        // method from blocking; on lock contention we trust the flag.
        if let Ok(mut guard) = self.child.try_lock() {
            let Some(child) = guard.as_mut() else {
                self.invalidate_generation(generation);
                return false;
            };
            if !matches!(child.try_wait(), Ok(None)) {
                self.invalidate_generation(generation);
                return false;
            }
        }
        true
    }

    async fn close(&self) -> Result<()> {
        // The gate is the close/replay/write linearization point. A request
        // already holding it completes its wire write or replay first; after
        // close acquires it, the old generation is invalidated before either
        // writer or child can be observed again.
        let _session_guard = self.session_gate.lock().await;
        self.invalidate_current_generation();
        #[cfg(test)]
        {
            let close_gate = self.close_after_invalidation_test_gate.read().clone();
            if let Some(gate) = close_gate {
                gate.pause().await;
            }
        }

        // Close stdin
        *self.writer.lock().await = None;

        // Kill child process
        if let Some(ref mut child) = *self.child.lock().await {
            let _ = child.kill().await;
        }

        Ok(())
    }

    #[cfg(test)]
    fn set_initialize_replay_test_gate(&self, gate: Option<Arc<StdioRaceTestGate>>) {
        *self.initialize_replay_test_gate.write() = gate;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[cfg(unix)]
    const CHILD_SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_CHILD_ENV_SCENARIO";
    #[cfg(unix)]
    const PARENT_SECRET_ENV: &str = "MCP_GATEWAY_TEST_PARENT_SECRET";
    #[cfg(unix)]
    const EXPLICIT_BACKEND_ENV: &str = "MCP_GATEWAY_TEST_EXPLICIT_BACKEND";
    #[cfg(unix)]
    const DUPLICATE_REJECTING_STDIO_FIXTURE: &str = r#"#!/bin/sh
events=$1
initialized=0
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            if [ "$initialized" -eq 0 ]; then
                initialized=1
                printf '%s\n' initialize >> "$events"
                printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"close-race-fake","version":"1.0"}}}'
            else
                printf '%s\n' duplicate-initialize >> "$events"
                printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"duplicate initialize"}}'
            fi
            ;;
        *'"method":"notifications/initialized"'*)
            printf '%s\n' notifications/initialized >> "$events"
            ;;
    esac
done
"#;

    fn make_transport(cmd: &str) -> Arc<StdioTransport> {
        StdioTransport::new(
            cmd,
            HashMap::new(),
            None,
            std::time::Duration::from_secs(30),
            None,
        )
    }

    #[cfg(unix)]
    async fn attach_live_test_child(transport: &Arc<StdioTransport>) {
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn live test child");
        *transport.child.lock().await = Some(child);
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
    fn connected_phase_without_child_is_not_live() {
        let t = make_transport("echo");
        t.session.write().phase = StdioSessionPhase::Connected;
        assert!(!t.is_connected());
        assert_eq!(t.session.read().phase, StdioSessionPhase::Closed);
    }

    #[tokio::test]
    async fn request_cleans_pending_entry_when_write_fails() {
        let t = make_transport("echo");

        let result = t.request("tools/list", None).await;

        assert!(matches!(result, Err(Error::Transport(message)) if message == "Not connected"));
        assert!(t.pending.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connected_transport_replays_cached_initialize_without_writing() {
        let t = make_transport("echo");
        attach_live_test_child(&t).await;
        let expected = serde_json::json!({
            "protocolVersion": "2025-11-25",
            "serverInfo": { "name": "strict-fake", "version": "1.0" }
        });
        {
            let mut session = t.session.write();
            session.initialize_result = Some(expected.clone());
            session.phase = StdioSessionPhase::Connected;
        }

        let response = t
            .request(
                "initialize",
                Some(serde_json::json!({"protocolVersion": "2025-11-25"})),
            )
            .await
            .expect("cached initialize response");

        assert_eq!(response.id, Some(RequestId::Number(1)));
        assert_eq!(response.result, Some(expected));
        assert!(response.error.is_none());
        assert!(t.pending.is_empty());
        t.close().await.expect("close live test child");
    }

    #[tokio::test]
    async fn cached_initialize_liveness_check_honors_configured_timeout() {
        let configured_timeout = std::time::Duration::from_millis(25);
        let t = StdioTransport::new("echo", HashMap::new(), None, configured_timeout, None);
        {
            let mut session = t.session.write();
            session.initialize_result = Some(serde_json::json!({
                "protocolVersion": "2025-11-25"
            }));
            session.phase = StdioSessionPhase::Connected;
        }
        let _held_child_lock = t.child.lock().await;

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            t.request("initialize", None),
        )
        .await
        .expect("liveness validation must use the configured timeout");

        assert!(matches!(result, Err(Error::BackendTimeout(_))));
    }

    #[tokio::test]
    async fn connected_initialize_cache_without_child_is_rejected() {
        let t = make_transport("echo");
        {
            let mut session = t.session.write();
            session.initialize_result = Some(serde_json::json!({
                "protocolVersion": "2025-11-25"
            }));
            session.phase = StdioSessionPhase::Connected;
        }

        let result = t.request("initialize", None).await;

        assert!(matches!(result, Err(Error::Transport(_))));
        assert!(!t.is_connected());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn close_invalidation_before_initialize_precheck_never_falls_through_to_writer() {
        let workspace = tempfile::tempdir().expect("create close-race workspace");
        let server = workspace.path().join("duplicate-rejecting-mcp.sh");
        let events = workspace.path().join("events.log");
        std::fs::write(&server, DUPLICATE_REJECTING_STDIO_FIXTURE)
            .expect("write duplicate-rejecting fixture");
        let server = server.to_string_lossy();
        let events_arg = events.to_string_lossy();
        assert!(!server.contains('\''));
        assert!(!events_arg.contains('\''));
        let transport = StdioTransport::new(
            &format!("/bin/sh '{server}' '{events_arg}'"),
            HashMap::new(),
            None,
            std::time::Duration::from_secs(1),
            None,
        );
        transport.start().await.expect("start close-race fixture");

        let entry_gate = StdioRaceTestGate::new();
        let close_gate = StdioRaceTestGate::new();
        *transport.initialize_request_entry_test_gate.write() = Some(Arc::clone(&entry_gate));
        *transport.close_after_invalidation_test_gate.write() = Some(Arc::clone(&close_gate));

        let request_transport = Arc::clone(&transport);
        let request =
            tokio::spawn(async move { request_transport.request("initialize", None).await });
        entry_gate.wait_until_entered().await;

        let close_transport = Arc::clone(&transport);
        let close = tokio::spawn(async move { close_transport.close().await });
        close_gate.wait_until_entered().await;

        entry_gate.release();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), request)
            .await
            .expect("invalidated initialize request must finish")
            .expect("initialize task");
        let observed = std::fs::read_to_string(&events).expect("read close-race event log");

        close_gate.release();
        close.await.expect("close task").expect("close transport");

        assert!(matches!(result, Err(Error::Transport(_))), "{result:?}");
        assert_eq!(
            observed.lines().collect::<Vec<_>>(),
            ["initialize", "notifications/initialized"],
            "invalidated request wrote a duplicate initialize"
        );
    }

    #[tokio::test]
    async fn unconnected_transport_never_replays_cached_initialize() {
        let t = make_transport("echo");
        t.session.write().initialize_result = Some(serde_json::json!({
            "protocolVersion": "2025-11-25"
        }));

        let result = t.request("initialize", None).await;

        assert!(matches!(result, Err(Error::Transport(message)) if message == "Not connected"));
        assert!(t.pending.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connected_transport_consumes_duplicate_initialized_without_writing() {
        let t = make_transport("echo");
        attach_live_test_child(&t).await;
        {
            let mut session = t.session.write();
            session.initialize_result = Some(serde_json::json!({
                "protocolVersion": "2025-11-25"
            }));
            session.phase = StdioSessionPhase::Connected;
        }

        t.notify("notifications/initialized", None)
            .await
            .expect("duplicate initialized notification is consumed");
        t.close().await.expect("close live test child");
    }

    #[test]
    #[cfg(unix)]
    fn backend_subprocess_receives_only_safe_and_explicit_environment() {
        let current_test_binary = std::env::current_exe().expect("resolve current test binary");
        let scenario_name = "transport::stdio::tests::stdio_child_environment_isolation_scenario";
        let output = std::process::Command::new(current_test_binary)
            .args(["--exact", scenario_name, "--nocapture"])
            .env(CHILD_SCENARIO_ENV, "1")
            .env(
                PARENT_SECRET_ENV,
                "dummy-parent-secret-must-not-reach-backend",
            )
            .output()
            .expect("run isolated child-environment scenario");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains(scenario_name),
            "nested test filter did not execute the environment scenario; stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            output.status.success(),
            "stdio child environment scenario failed; stdout={stdout:?} stderr={stderr:?}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn stdio_child_environment_isolation_scenario() {
        if std::env::var_os(CHILD_SCENARIO_ENV).is_none() {
            return;
        }
        assert!(
            std::env::var_os(PARENT_SECRET_ENV).is_some(),
            "nested scenario must start with the parent-only sentinel present"
        );

        let workspace = tempfile::tempdir().expect("create stdio child workspace");
        let server = workspace.path().join("server.sh");
        std::fs::write(
            &server,
            r#"while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'
            ;;
        *'"method":"env/check"'*)
            parent_secret_present=false
            explicit_backend_present=false
            path_present=false
            home_present=false
            tmpdir_present=false
            cwd_preserved=false
            [ "${MCP_GATEWAY_TEST_PARENT_SECRET+x}" = x ] && parent_secret_present=true
            [ "${MCP_GATEWAY_TEST_EXPLICIT_BACKEND:-}" = configured-value ] && explicit_backend_present=true
            [ -n "${PATH:-}" ] && path_present=true
            [ -n "${HOME:-}" ] && home_present=true
            [ -n "${TMPDIR:-}" ] && tmpdir_present=true
            [ -f server.sh ] && cwd_preserved=true
            printf '{"jsonrpc":"2.0","id":2,"result":{"parent_secret_present":%s,"explicit_backend_present":%s,"path_present":%s,"home_present":%s,"tmpdir_present":%s,"cwd_preserved":%s}}\n' \
                "$parent_secret_present" "$explicit_backend_present" "$path_present" \
                "$home_present" "$tmpdir_present" "$cwd_preserved"
            ;;
    esac
done
"#,
        )
        .expect("write stdio child server");

        let transport = StdioTransport::new(
            "sh server.sh",
            HashMap::from([(
                EXPLICIT_BACKEND_ENV.to_string(),
                "configured-value".to_string(),
            )]),
            Some(workspace.path().to_string_lossy().into_owned()),
            std::time::Duration::from_secs(5),
            None,
        );

        transport.start().await.expect("start stdio child server");
        let response = transport
            .request("env/check", None)
            .await
            .expect("request child environment report");
        transport.close().await.expect("close stdio child server");

        let report = response.result.expect("environment report result");
        assert_eq!(report["parent_secret_present"], false);
        assert_eq!(report["explicit_backend_present"], true);
        assert_eq!(report["path_present"], true);
        assert_eq!(report["home_present"], true);
        assert_eq!(report["tmpdir_present"], true);
        assert_eq!(report["cwd_preserved"], true);
    }
}
