// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stdio transport implementation (subprocess)
//!
//! Spawns an MCP server as a child process and communicates via JSON-RPC over
//! stdin/stdout.  Supports automatic protocol version negotiation: if the
//! server rejects the gateway's preferred version, the transport parses the
//! error for supported versions and retries with the highest mutually
//! supported version.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
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

use crate::transport::notification_sink::DeliveryHandle;

use super::{PendingRequestGuard, Transport};
use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION,
    RequestId, is_version_mismatch_error, negotiate_best_version,
    parse_supported_versions_from_error,
};
use crate::{Error, Result};

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
        "APPDATA",
        "LOCALAPPDATA",
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

    // Operator-level npm settings that are behaviour rather than credentials,
    // and that apply to every backend rather than to one. An allowlist, not a
    // deny list: npm's credential surface is open-ended — `_password`,
    // `certfile`, `keyfile`, `userconfig`, and registry URLs with embedded
    // userinfo all name secrets — and anything a deny rule misses reaches every
    // backend. A backend that needs a credential names it in its own `env:`.
    // A backend that names one of these settings keeps its own value: see
    // `forwarded_npm_config`.
    for (name, value) in forwarded_npm_config(std::env::vars_os(), backend_env) {
        cmd.env(name, value);
    }

    // Backend configuration is authoritative and may intentionally override
    // a safe default such as PATH, HOME, or TMPDIR.
    for (key, value) in backend_env {
        cmd.env(key, value);
    }
}

const CACHE_ENV: &str = "npm_config_cache";

/// How many stderr lines are kept from a child, for classifying a failure.
const STDERR_TAIL_LINES: usize = 20;

/// How long a failed start waits for the child's stderr to be drained.
const STDERR_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// How long a failed start waits for a child that is still dying.
///
/// Only the exit status is wanted here, and only a child that has already
/// exited has one. A child still alive after this is one the caller was about
/// to be told about anyway, and it is killed on the failure path either way.
const EXIT_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// npm settings forwarded to every backend.
///
/// Matched case-insensitively, because npm reads its environment that way and
/// `NPM_CONFIG_ALLOW_GIT` is the spelling npm's own documentation uses. The
/// operator's spelling is what the child receives.
const FORWARDED_NPM_SETTINGS: [&str; 6] = [
    "npm_config_allow_git",
    "npm_config_cafile",
    "npm_config_prefer_offline",
    "npm_config_offline",
    "npm_config_strict_ssl",
    "npm_config_loglevel",
];

/// The operator's npm settings that this gateway passes on.
///
/// `npm_config_cache` is not among them, and cannot be added by accident: the
/// gateway assigns that per backend, and a shared cache is what tears under
/// concurrent installs.
///
/// A setting `backend_env` already names is skipped, in whatever spelling
/// either side used. Forwarding it as well would leave the child holding the
/// same setting twice, and npm keeps the last value it reads: on Unix the child
/// environment is passed in sorted order, so the operator's lowercase
/// `npm_config_strict_ssl` arrives after a backend's `NPM_CONFIG_STRICT_SSL` and
/// silently overrules the backend's explicit choice.
fn forwarded_npm_config<I>(
    vars: I,
    backend_env: &HashMap<String, String>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)>
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    vars.into_iter()
        .filter(|(key, _)| {
            key.to_str().is_some_and(|name| {
                let name = name.to_ascii_lowercase();
                FORWARDED_NPM_SETTINGS.contains(&name.as_str())
                    && !backend_env
                        .keys()
                        .any(|configured| configured.eq_ignore_ascii_case(name.as_str()))
            })
        })
        .collect()
}

/// A per-backend npm cache, so backends sharing a command cannot tear one tree.
#[must_use]
pub fn isolated_package_manager_env<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    mut backend_env: HashMap<String, String, S>,
) -> HashMap<String, String, S> {
    if let Some(dir) = assigned_package_cache_dir(backend_name, command, &backend_env) {
        backend_env.insert(CACHE_ENV.to_string(), dir.to_string_lossy().into_owned());
    }
    backend_env
}

/// The cache directory the gateway assigns to a backend, or `None` when it
/// assigns none.
///
/// `None` means the value in the child's environment, if there is one, came
/// from the operator: either this backend does not invoke a package manager,
/// or its configuration already names a cache. That distinction is the whole
/// point of returning the path rather than only writing it into the
/// environment — the repair deletes what it is handed, and a directory the
/// gateway did not create is not the gateway's to delete, however much a
/// caller's `npm_config_cache` looks like one [#1759].
#[must_use]
pub fn assigned_package_cache_dir<S: std::hash::BuildHasher>(
    backend_name: &str,
    command: &str,
    backend_env: &HashMap<String, String, S>,
) -> Option<PathBuf> {
    if !invokes_npm(command) || backend_env.contains_key(CACHE_ENV) {
        return None;
    }
    Some(
        crate::config_persistence::gateway_data_dir()
            .join("pkg-cache")
            .join(sanitize_cache_component(backend_name)),
    )
}

fn invokes_npm(command: &str) -> bool {
    command
        .split_whitespace()
        .next()
        .map(|program| program.rsplit('/').next().unwrap_or(program))
        .is_some_and(|program| matches!(program, "npx" | "npm" | "pnpm" | "yarn" | "bunx"))
}

fn sanitize_cache_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
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
    /// Where to deliver a notification for each call that supplied a progress
    /// token.
    ///
    /// Keyed by the token itself, because stdout is one multiplexed stream:
    /// "which stream it arrived on" cannot separate two calls in flight here,
    /// so the token the caller supplied is the whole correlation.
    ///
    /// The map holds the destination, not the payload. Accumulating frames and
    /// flushing them when the call ends is collect-then-emit, which ADR-014 §1
    /// rejects: a progress update that arrives with the result is not progress.
    progress_destinations: dashmap::DashMap<String, DeliveryHandle>,
    /// What a failed start said, kept only long enough to classify it.
    ///
    /// A package manager that cannot use its install tree says so here and
    /// dies before it can answer anything, so this is the only place that
    /// failure is visible: it is what tells a failed install apart from a
    /// backend that is merely dead.
    ///
    /// Child stderr is text from a process the gateway did not write, so it
    /// stays in memory and is read only to pick a needle out of it. The text
    /// itself is never logged and never handed to a caller, and the next start
    /// of this backend drops it. Redaction would have to cover every shape a
    /// credential can take — a bare token, a PEM block, a JSON body holding a
    /// key — and one missed shape is one credential in the log.
    stderr_tail: Arc<std::sync::Mutex<VecDeque<String>>>,
    /// The task draining the child's stderr, so a failure can wait for the
    /// child's last words instead of racing them.
    stderr_reader: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// How the child of the last start exited, once it was seen to.
    exit_status: std::sync::Mutex<Option<std::process::ExitStatus>>,
    /// The cache directory the gateway assigned this backend, or `None`.
    ///
    /// `Some` is the gateway's to clear; `None` says the value that reaches
    /// the child, if any, came from the operator's own configuration.
    assigned_cache: Option<PathBuf>,
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
        Self::new_with_assigned_cache(command, env, cwd, request_timeout, protocol_version, None)
    }

    /// [`StdioTransport::new`], telling the transport which cache this gateway
    /// assigned.
    ///
    /// The caller that built the environment is the only one that knows, and
    /// the repair reads it rather than the environment: a path the operator
    /// configured has the same shape as one the gateway assigned.
    #[must_use]
    pub fn new_with_assigned_cache(
        command: &str,
        env: HashMap<String, String>,
        cwd: Option<String>,
        request_timeout: std::time::Duration,
        protocol_version: Option<String>,
        assigned_cache: Option<PathBuf>,
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
            progress_destinations: dashmap::DashMap::new(),
            stderr_tail: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            stderr_reader: std::sync::Mutex::new(None),
            exit_status: std::sync::Mutex::new(None),
            assigned_cache,
        })
    }

    pub(crate) fn diagnostic_command(&self) -> String {
        crate::security::summarize_stdio_command(&self.command)
    }

    /// Drops what the previous attempt said, so each start is judged on its own.
    fn clear_stderr_tail(&self) {
        if let Ok(mut tail) = self.stderr_tail.lock() {
            tail.clear();
        }
        if let Ok(mut status) = self.exit_status.lock() {
            *status = None;
        }
    }

    /// Waits, briefly, for the stderr reader to finish.
    ///
    /// The reader is its own task, so a child that dies mid-handshake is
    /// visible to the failure path before the last thing it said has been
    /// read. A child that has exited closes the pipe, so this returns as soon
    /// as there is nothing left to read and only ever waits out the grace for
    /// a backend that is still alive.
    async fn settle_stderr_tail(&self) {
        let handle = self
            .stderr_reader
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(handle) = handle {
            let _ = tokio::time::timeout(STDERR_DRAIN_GRACE, handle).await;
        }
    }

    /// The cache directory this gateway assigned, if it assigned one.
    pub(crate) fn assigned_package_cache_dir(&self) -> Option<&Path> {
        self.assigned_cache.as_deref()
    }

    /// The cache directory the child is given, whoever chose it.
    pub(crate) fn package_cache_dir(&self) -> Option<PathBuf> {
        self.env.get(CACHE_ENV).map(PathBuf::from)
    }

    /// How the child exited, if a failed start saw it exit.
    ///
    /// `None` covers both "the child is still running" and "no failed start
    /// has looked yet", which is all a caller can do anything with: the status
    /// is only ever read to classify a failure.
    pub(crate) fn exit_status(&self) -> Option<std::process::ExitStatus> {
        self.exit_status.lock().ok().and_then(|status| *status)
    }

    /// Waits, briefly, for a child that is on its way out, and records how it
    /// went.
    ///
    /// A process that fails at startup writes its reason and exits; the order
    /// those two become visible here is not fixed, and a status read before
    /// the exit is reaped is `None`. This is only called on a failed start, so
    /// the wait can never delay a backend that is working.
    async fn settle_child_exit(&self) {
        let mut guard = self.child.lock().await;
        let Some(child) = guard.as_mut() else {
            return;
        };
        let Ok(Ok(status)) = tokio::time::timeout(EXIT_DRAIN_GRACE, child.wait()).await else {
            return;
        };
        if let Ok(mut slot) = self.exit_status.lock() {
            *slot = Some(status);
        }
    }

    /// The child's last lines on stderr, as one block.
    ///
    /// For classifying a failure, never for a log: see `stderr_tail`.
    pub(crate) fn stderr_tail(&self) -> String {
        self.stderr_tail.lock().map_or_else(
            |_| String::new(),
            |tail| tail.iter().cloned().collect::<Vec<_>>().join("\n"),
        )
    }

    /// Start the subprocess and complete the MCP handshake.
    ///
    /// A failure leaves the child's last stderr lines settled, so whoever
    /// decides what to do about the failure can read what it said.
    ///
    /// # Errors
    ///
    /// Returns an error if the command cannot be spawned or initialization
    /// fails.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.clear_stderr_tail();

        let parts = crate::transport::split_command(&self.command).ok_or_else(|| {
            Error::Config(format!(
                "Invalid stdio command quoting: {}",
                crate::security::summarize_stdio_command(&self.command)
            ))
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

        let mut child = cmd.spawn().map_err(|e| match e.kind() {
            // A command path that does not exist, or a file that is not
            // executable. No amount of waiting fixes either, and warm-start
            // retries transport failures indefinitely -- so before this, a
            // typo in a backend command was respawned once a minute for the
            // life of the process with no indication the config was wrong.
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
                Error::TransportPermanent(format!("Failed to spawn: {e}"))
            }
            _ => Error::Transport(format!("Failed to spawn: {e}")),
        })?;

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

        // Spawn reader task.
        //
        // WEAK on purpose. A strong `Arc` here is an ownership cycle: the task
        // holds the transport, the transport holds the `Child`, the child only
        // dies when it is killed or dropped, the transport only drops when this
        // task ends, and this task only ends at stdout EOF - which needs the
        // child to die. Nothing breaks that loop except an explicit `close()`,
        // so a transport that is merely dropped leaks its MCP server process
        // forever, and `kill_on_drop(true)` above never fires.
        //
        // With a `Weak`, dropping the last real handle drops the transport,
        // which drops the `Child`, which kills the process, which closes stdout,
        // which ends this task. Ownership does the cleanup; nothing has to
        // decide when it is safe.
        let transport = Arc::downgrade(self);
        tokio::spawn(async move {
            debug!("Reader task started");
            let mut reader = BufReader::new(stdout).lines();

            loop {
                match reader.next_line().await {
                    Ok(Some(line)) => {
                        debug!(line_len = line.len(), "Received line from stdout");
                        let Some(transport) = transport.upgrade() else {
                            debug!("Transport dropped while reading; stopping reader task");
                            return;
                        };
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

            if let Some(transport) = transport.upgrade() {
                transport.connected.store(false, Ordering::Relaxed);
            }
            debug!("Stdio reader task ended");
        });

        self.spawn_stderr_reader(stderr);

        // Initialize with protocol version negotiation. If initialization
        // fails, tear down the spawned process now rather than waiting for the
        // caller to drop its handle: `start` is called on an `Arc<Self>` the
        // caller usually keeps, so a failed start would otherwise leave the
        // child running until that handle happens to go away.
        //
        // This used to be load-bearing for a different reason - the reader task
        // held a strong `Arc`, so nothing but an explicit close could ever reap
        // the child. It holds a `Weak` now, so drop alone is sufficient and this
        // is only about being prompt.
        if let Err(error) = self.initialize().await {
            return Err(self.fail_start(error).await);
        }

        Ok(())
    }

    /// Drains the child's stderr into the tail, for as long as it lives.
    ///
    /// Kept out of `start` for length alone; it is the task `start` spawns.
    fn spawn_stderr_reader(&self, stderr: tokio::process::ChildStderr) {
        let command = self.diagnostic_command();
        let stderr_tail = Arc::clone(&self.stderr_tail);
        let reader = tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // The line itself is not logged, at any level: see
                // `stderr_tail`. Its length is all the log gets.
                debug!(command = %command, line_len = line.len(), "Received line from stderr");
                if let Ok(mut tail) = stderr_tail.lock() {
                    if tail.len() == STDERR_TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(line);
                }
            }
        });
        if let Ok(mut slot) = self.stderr_reader.lock() {
            *slot = Some(reader);
        }
    }

    /// Tears down a child whose handshake failed, leaving enough behind to
    /// classify the failure.
    async fn fail_start(&self, error: Error) -> Error {
        // Order matters: the exit status has to be read before `close` kills
        // the child, and the stderr after, because the reader only reaches EOF
        // once the child is gone.
        self.settle_child_exit().await;
        if let Err(close_error) = self.close().await {
            warn!(error = %close_error, "Failed to clean up stdio process after initialization error");
        }
        self.settle_stderr_tail().await;
        error
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
            command = %self.diagnostic_command(),
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
                self.diagnostic_command()
            )));
        }

        // Success — check if server negotiated a different version
        if let Some(ref result) = response.result
            && let Some(server_version) = result.get("protocolVersion").and_then(Value::as_str)
        {
            if server_version == version {
                debug!(
                    command = %self.diagnostic_command(),
                    version = %server_version,
                    "Protocol version accepted"
                );
            } else {
                info!(
                    command = %self.diagnostic_command(),
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
                self.diagnostic_command()
            )));
        };

        warn!(
            command = %self.diagnostic_command(),
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
                self.diagnostic_command(),
                error.message
            )));
        }

        *self.protocol_version.write() = Some(negotiated.to_string());

        info!(
            command = %self.diagnostic_command(),
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
            command = %self.diagnostic_command(),
            version = negotiated.as_deref().unwrap_or(PROTOCOL_VERSION),
            "Stdio transport initialized"
        );

        Ok(())
    }

    /// Register the progress token this transport will route a backend's
    /// notifications by.
    ///
    /// Until a token is registered nothing carrying it is kept: a backend's own
    /// token is passed through only when it matches a registered one.
    ///
    /// The token registered here is the **gateway-minted** `gw-<uuid>`, not the
    /// caller's. Minting happens above every transport, on the shared outbound
    /// funnel (`crate::backend::ops`), so by the time a request reaches this
    /// file the caller's token has already been substituted and recorded.
    /// ADR-014 §2 marks the older rule -- register the caller's own token and
    /// never mint -- superseded, and names the three defects that sink it: a
    /// keyspace that collapses `7` and `"7"`, a bare `insert` that lets one
    /// live call overwrite another's owner, and a reused token outliving its
    /// request.
    // Registered from `Transport::request` below, before the request is
    // written: the reader task can route a notification back before the write
    // returns, and an unregistered token is dropped.
    ///
    /// The handle is snapshotted here rather than at capture time because this
    /// is the one point where the caller's sink and token translation are both
    /// in scope. The reader task has neither.
    /// Returns whether this call took ownership of the token. A refusal is
    /// not a failure the caller must handle, but it does decide who may
    /// deregister: whoever did not insert must not remove.
    #[must_use]
    pub(crate) fn register_progress_token(&self, token: &str) -> bool {
        // Vacant-only. A colliding live key must fail closed: overwriting the
        // incumbent reroutes one call's progress onto another call's channel,
        // which is worse than losing it. The third defect ADR-014 §2 names.
        match self.progress_destinations.entry(token.to_string()) {
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(DeliveryHandle::capture(token));
                true
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                // ci-allow-secret-log: a minted progress token is a correlation id, not a credential
                warn!(
                    token = %token,
                    "progress token is already registered to a live call; refusing to reroute it"
                );
                false
            }
        }
    }

    /// End a token's registration, dropping the sender it held.
    ///
    /// Only the registration's owner may call this. A refused duplicate that
    /// deregistered on its way out would retire the *incumbent's* destination
    /// and silence a call that is still running -- the refusal would cause the
    /// very cross-call damage it exists to prevent.
    ///
    /// A sender outliving its request is a leak with a live channel on the end
    /// of it, so this runs from the guard's `Drop` on every exit path.
    pub(crate) fn deregister_progress_token(&self, token: &str) {
        self.progress_destinations.remove(token);
    }

    /// Deliver a peer notification to the call that supplied its progress token.
    ///
    /// A notification with no token, or one whose token no caller supplied, is
    /// dropped exactly as before — on a multiplexed stdout there is nothing else
    /// to attribute it to, and inventing an owner is the failure this guards.
    // ponytail: token-less methods (`notifications/message`) stay unattributable
    // over stdio; a per-request stream is what would carry them, and stdio has
    // none. Named as a design event in the SUB.2b note rather than papered over.
    fn capture_notification(&self, notification: JsonRpcNotification) {
        // Note the asymmetry with the outgoing side: a request carries the
        // token under `params._meta`, a `notifications/progress` carries it as
        // a direct member of `params`.
        //
        // Progress only. This route carries no level filter -- a progress
        // frame can never meet one -- so admitting any method that happens to
        // carry a token would let a backend stamp `progressToken` onto a
        // `notifications/message` and reach a client that filtered that
        // severity out.
        let token = (notification.method == "notifications/progress")
            .then(|| {
                notification
                    .params
                    .as_ref()
                    .and_then(|p| p.get("progressToken"))
                    .and_then(progress_token_string)
            })
            .flatten();

        match token.and_then(|t| self.progress_destinations.get(&t)) {
            Some(destination) => {
                debug!(method = %notification.method, "Delivering peer notification to its caller");
                // Sent, not queued, and from the reader task: `deliver` uses
                // `try_send`, because a blocking send here would park the only
                // reader of this backend's stdout.
                destination.deliver(notification);
            }
            None => {
                debug!(method = %notification.method, "Ignoring peer notification");
            }
        }
    }

    /// Handle a response line from stdout
    ///
    /// The line is classified before it is routed. A peer notification is kept
    /// for the caller that supplied its progress token and otherwise ignored; a
    /// peer *request* is refused, because routing one to a pending caller would
    /// answer that caller with a frame carrying neither `result` nor `error`.
    fn handle_response(&self, line: &str) -> Result<()> {
        debug!(line = %line, "Parsing response");
        let response = match serde_json::from_str::<JsonRpcMessage>(line)? {
            JsonRpcMessage::Response(response) => response,
            JsonRpcMessage::Notification(notification) => {
                self.capture_notification(notification);
                return Ok(());
            }
            JsonRpcMessage::Request(request) => {
                return Err(Error::Protocol(format!(
                    "Peer sent request '{}' on the response stream",
                    request.method
                )));
            }
        };

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

/// A progress token is a string or a number on the wire; the capture map is
/// keyed by its string form so both spellings of one token agree.
fn progress_token_string(token: &Value) -> Option<String> {
    match token {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The caller's progress token as an outgoing request carries it.
///
/// Note the asymmetry with `capture_notification`: a request carries the token
/// under `params._meta`, while an incoming `notifications/progress` carries it
/// as a direct member of `params`. Reading the wrong shape here leaves the
/// stdio leg dead while the HTTP one still looks green.
fn request_progress_token(params: Option<&Value>) -> Option<String> {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .and_then(progress_token_string)
}

/// Keep a progress-token registration alive exactly as long as its request,
/// and drain it wherever that request ends.
///
/// `register_progress_token` inserts and only a drain removes, so every exit
/// path has to reach one. A drain written as a statement after the await
/// reaches three of them -- success, a write error, the internal timeout --
/// and misses the fourth: an OUTER timeout or a task abort drops the in-flight
/// request future mid-await, the statement never runs, and the entry lives for
/// the transport's lifetime. That is growth rather than misrouting, because
/// `gw-<uuid>` keys never collide and a stranded entry cannot capture another
/// call's notifications, but it is unbounded growth.
///
/// This is `crate::transport::PendingRequestGuard`'s counterpart: same problem,
/// same shape, the other map. Drop publishes what was captured, so all four
/// paths drain through one place. Publishing outside a notification scope is a
/// no-op, which is what a cancelled request wants.
struct ProgressRegistrationGuard<'a> {
    transport: &'a StdioTransport,
    token: String,
    /// Whether this guard's registration is the one in the map.
    ///
    /// `false` when the token was already registered to a live call. The
    /// guard still exists -- construction has no failure mode the request
    /// path can act on -- but it owns nothing and must retire nothing.
    owns_registration: bool,
}

impl<'a> ProgressRegistrationGuard<'a> {
    /// Register `token` on `transport` and hold it for the guard's lifetime.
    #[must_use]
    fn register(transport: &'a StdioTransport, token: &str) -> Self {
        let owns_registration = transport.register_progress_token(token);
        Self {
            transport,
            token: token.to_string(),
            owns_registration,
        }
    }
}

impl Drop for ProgressRegistrationGuard<'_> {
    fn drop(&mut self) {
        if self.owns_registration {
            self.transport.deregister_progress_token(&self.token);
        }
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

        // Register before the write: the reader task can route a notification
        // back before `write_message` returns. The token registered is whatever
        // the params carry on the wire -- for a call the gateway minted for
        // (`src/gateway/meta_mcp/invoke.rs`) that is the minted `gw-<uuid>`,
        // never the caller's own token (MIK-7272.SUB.2b). Draining it is the
        // guard's job on every exit path, cancellation included.
        let _progress_cleanup = request_progress_token(request.params.as_ref())
            .map(|token| ProgressRegistrationGuard::register(self, &token));

        let message = serde_json::to_string(&request)?;
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id.to_string(), tx);
        // Removing the entry is the guard's job on every path: on success the
        // reader task has already routed the response and the removal is a
        // no-op, and on an error, an internal timeout or CANCELLATION (an
        // outer timeout or task abort dropping this future mid-await) the
        // guard's Drop is the only thing that removes it — without it a
        // stranded entry would leak here for the transport's lifetime.
        let _cleanup = PendingRequestGuard::new(&self.pending, &id.to_string());

        // Both guards drop after this value is produced, which is where the
        // pending entry and the progress registration are retired.
        match self.write_message(&message).await {
            Err(e) => Err(e),
            // Wait for response with timeout
            Ok(()) => match tokio::time::timeout(self.request_timeout, rx).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err(Error::Transport("Response channel closed".to_string())),
                Err(_) => Err(Error::BackendTimeout("Request timed out".to_string())),
            },
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
        if !self.connected.load(Ordering::Relaxed) {
            return false;
        }
        // Defense in depth (Fix C): the reader task flips `connected=false` on
        // stdout EOF, but a zombie child or a not-yet-scheduled reader task can
        // leave the cached flag stale-true. A stale-true flag makes
        // `Backend::ensure_started` a no-op and dispatches requests into a dead
        // pipe — the core reason a tripped breaker never recovered. Confirm real
        // liveness with a non-blocking waitpid. `try_lock` keeps this sync
        // method from blocking; on lock contention we trust the flag.
        if let Ok(mut guard) = self.child.try_lock()
            && let Some(child) = guard.as_mut()
            && let Ok(Some(_status)) = child.try_wait()
        {
            // Child has exited; reconcile the cached flag so callers and future
            // checks see the truth.
            self.connected.store(false, Ordering::Relaxed);
            return false;
        }
        true
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
#[path = "stdio_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stdio_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
mod spawn_classification_tests {
    use super::StdioTransport;
    use crate::Error;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn a_missing_command_is_reported_as_permanent() {
        // END TO END, not a synthetic classifier input: this really tries to
        // spawn, so it pins the actual io::ErrorKind the OS returns rather than
        // the one this code assumes it returns.
        let transport = StdioTransport::new(
            "/nonexistent/definitely-not-a-real-binary",
            HashMap::new(),
            None,
            Duration::from_secs(1),
            None,
        );

        let err = transport
            .start()
            .await
            .expect_err("spawning a missing binary must fail");

        assert!(
            matches!(err, Error::TransportPermanent(_)),
            "a missing command must be permanent, got {err:?}"
        );
    }
}
