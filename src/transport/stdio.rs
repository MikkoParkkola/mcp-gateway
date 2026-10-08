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
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use parking_lot::RwLock;
use process_wrap::tokio::ChildWrapper;
use serde_json::Value;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, error, info, warn};

use crate::transport::notification_sink::DeliveryHandle;

use super::{PendingRequestGuard, Transport};
use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION,
    RequestId, Selectable, checked_selection, initialize_params, is_version_mismatch_error,
    negotiate_best_version, parse_supported_versions_from_error,
};
use crate::{Error, Result};

#[path = "stdio_cache.rs"]
mod cache;
pub(crate) use cache::assigned_package_cache_dir;
pub use cache::isolated_package_manager_env;

#[path = "stdio_env.rs"]
mod env;
pub(crate) use env::configure_child_environment;

/// Stdio transport for subprocess MCP servers
pub struct StdioTransport {
    /// Child process
    child: Mutex<Option<Box<dyn ChildWrapper>>>,
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
    /// How the last start ended if the child died before `initialize` (#526).
    start: early_exit::StartState,
    /// Upstream-notification taps of the events listener (MIK-7630 I5).
    pub(crate) taps: super::upstream_tap::Taps,
    /// Longest frame the reader accepts; set before `start`.
    max_frame_bytes: AtomicUsize,
    /// What a failed start said, kept only long enough to classify it (#1759).
    failure: start_failure::FailureRecord,
    /// The cache directory the gateway assigned this backend, or `None`.
    ///
    /// `Some` is the gateway's to clear; `None` says the value that reaches
    /// the child, if any, came from the operator's own configuration.
    assigned_cache: Option<std::path::PathBuf>,
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

    /// Set the longest frame this transport accepts (clamped to the ceiling).
    /// Call before [`start`](Self::start).
    pub fn set_max_frame_bytes(&self, bytes: usize) {
        self.max_frame_bytes
            .store(bytes.clamp(1, CEILING_MAX_FRAME_BYTES), Ordering::Relaxed);
    }

    pub(crate) fn diagnostic_command(&self) -> String {
        crate::security::summarize_stdio_command(&self.command)
    }

    /// The child's command, with piped stdio, environment and working
    /// directory.
    fn spawn_command(&self) -> Result<Command> {
        let parts = crate::transport::split_command(&self.command).ok_or_else(|| {
            Error::Config(format!(
                "Invalid stdio command quoting: {}",
                crate::security::summarize_stdio_command(&self.command)
            ))
        })?;
        let Some((program, args)) = parts.split_first() else {
            return Err(Error::Config("Empty command".to_string()));
        };

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
        // The assigned cache goes in as the path itself, not its string form:
        // a data directory that is not valid UTF-8 would otherwise hand the
        // child a lossy copy, a different directory from the one the repair
        // inspects (MIK-7990).
        if let Some(dir) = self.exact_assigned_cache() {
            cmd.env(cache::CACHE_ENV, dir);
        }

        if let Some(ref cwd) = self.cwd {
            cmd.current_dir(cwd);
        }
        Ok(cmd)
    }

    /// Start the subprocess and complete the MCP handshake.
    ///
    /// A failure leaves the child's last stderr lines settled, so whoever
    /// decides what to do about the failure can read what it said.
    ///
    /// # Errors
    ///
    /// Returns an error if the command cannot be spawned or MCP initialization fails.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.start.forget_shown_stderr();
        self.failure.begin();

        let cmd = self.spawn_command()?;
        let mut child = spawn_in_own_tree(cmd)?;

        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stdin".to_string()))?;

        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stdout".to_string()))?;
        let stderr = child
            .stderr()
            .take()
            .ok_or_else(|| Error::Transport("Failed to get stderr".to_string()))?;

        *self.writer.lock().await = Some(stdin);
        *self.child.lock().await = Some(child);
        let (eof_tx, eof_rx) = tokio::sync::watch::channel(false);
        self.start.begin(eof_rx);

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
        let max_frame = self.max_frame_bytes.load(Ordering::Relaxed);
        let stdout_reader = tokio::spawn(async move {
            debug!("Reader task started");
            let mut reader = BufReader::new(stdout);
            let mut frame = Vec::new();

            loop {
                match read_frame(&mut reader, &mut frame, max_frame).await {
                    Ok(Some(line)) => {
                        let line_len = line.len();
                        debug!(line_len, "Received line from stdout");
                        let Some(transport) = transport.upgrade() else {
                            debug!("Transport dropped while reading; stopping reader task");
                            return;
                        };
                        if let Err(e) = transport.handle_response(&line) {
                            error!(error = %e, line_len, "Failed to handle response");
                        }
                    }
                    Ok(None) => {
                        debug!("Stdout EOF reached - process may have exited");
                        break;
                    }
                    Err(e) => {
                        // Includes a frame over MAX_FRAME_BYTES: the stream
                        // cannot be resynchronised, so it is treated as gone.
                        error!(error = %e, "Error reading from stdout");
                        if let Some(transport) = transport.upgrade()
                            && let Some(child) = transport.child.lock().await.as_mut()
                        {
                            let _ = child.start_kill();
                        }
                        break;
                    }
                }
            }

            let _ = eof_tx.send(true);
            if let Some(transport) = transport.upgrade() {
                transport.connected.store(false, Ordering::Relaxed);
                // The stream is over: wake every waiting call now (its receiver
                // sees a closed channel) instead of at its request timeout.
                transport.pending.clear();
                // The listener's receivers see `Closed` at once.
                transport.taps.clear();
            }
            debug!("Stdio reader task ended");
        });

        let stderr_tail = early_exit::spawn_stderr_tail(stderr, self.diagnostic_command());
        self.failure.track(&stderr_tail.1);

        // Initialize with protocol version negotiation. If initialization
        // fails, tear down the spawned process now rather than waiting for the
        // caller to drop its handle: `start` is called on an `Arc<Self>` the
        // caller usually keeps, so a failed start would otherwise leave the
        // child running until that handle happens to go away.
        // (Promptness only: the reader holds a `Weak`, so a drop would reap it.)
        if let Err(mut error) = self.initialize().await {
            // Order matters on the late path: the exit status has to be read
            // before `close` kills the child, and the stderr after, because the
            // reader only reaches EOF once the child is gone.
            let late_reader = if self.start.exited_early() {
                error = self.early_exit_error(stderr_tail).await;
                None
            } else {
                self.settle_child_exit().await;
                Some(stderr_tail.0)
            };
            if let Err(close_error) = self.close().await {
                warn!(error = %close_error, "Failed to clean up stdio process after initialization error");
            }
            if let Some(reader) = late_reader {
                // The child `close` just killed: record that ending, so the
                // failure is not reported as a child still running.
                self.settle_child_exit().await;
                Self::settle_stderr_tail(reader).await;
            }
            // A retry may start on this same transport. This start's reader
            // must be gone first: at its EOF it clears `pending` and marks the
            // transport disconnected, which would land on the retry instead.
            stdout_reader.abort();
            let _ = stdout_reader.await;
            return Err(error);
        }

        Ok(())
    }

    /// Initialize the MCP connection with automatic version negotiation.
    ///
    /// 1. Sends `initialize` with the configured or latest protocol version.
    /// 2. On an error carrying the backend's supported versions, retries once
    ///    with the highest version both sides speak.
    /// 3. Adopts the version the backend selected on the handshake that
    ///    succeeded, refusing one this gateway does not speak.
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

        let mut response = self.init_request(initialize_params(&version)).await?;
        let mut proposed = version.as_str();

        if let Some(ref error) = response.error {
            // Code only, here and below: the message is the backend's own
            // text and may quote back a credential the gateway passed it.
            if !is_version_mismatch_error(&error.message) {
                return Err(Error::Protocol(format!(
                    "Initialize failed for '{}': backend error code {}",
                    self.diagnostic_command(),
                    error.code
                )));
            }
            let Some(negotiated) = parse_supported_versions_from_error(&error.message)
                .as_deref()
                .and_then(negotiate_best_version)
            else {
                return Err(Error::Protocol(format!(
                    "Protocol version negotiation failed for '{}': server rejected {version}, \
                     no compatible version found (backend error code {})",
                    self.diagnostic_command(),
                    error.code
                )));
            };
            warn!(
                command = %self.diagnostic_command(),
                rejected = %version,
                negotiated = %negotiated,
                "Retrying initialize with negotiated protocol version"
            );
            response = self.init_request(initialize_params(negotiated)).await?;
            if let Some(ref error) = response.error {
                return Err(Error::Protocol(format!(
                    "Initialize failed for '{}' even with negotiated version {negotiated}: \
                     backend error code {}",
                    self.diagnostic_command(),
                    error.code
                )));
            }
            proposed = negotiated;
        }

        // The client proposes and the server selects: what this handshake's
        // answer selected governs the session, or what was proposed when it
        // names nothing. Checked before it is written, so a refusal leaves
        // the stored version as it was.
        let selected = checked_selection(response.result.as_ref(), Selectable::LegacyOrModern)?
            .unwrap_or(proposed);
        info!(
            command = %self.diagnostic_command(),
            requested = %proposed,
            negotiated = %selected,
            "Protocol version agreed"
        );
        *self.protocol_version.write() = Some(selected.to_string());

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
        // The listener's taps first: a frame tagged with a live listen, or
        // one of the three resource/prompt notifications while a legacy tap
        // is open. Never progress, so the route below is unchanged.
        if self
            .taps
            .notification(&notification.method, notification.params.as_ref())
        {
            return;
        }
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
                debug!("Delivering peer notification to its caller");
                // Sent, not queued, and from the reader task: `deliver` uses
                // `try_send`, because a blocking send here would park the only
                // reader of this backend's stdout.
                destination.deliver(notification);
            }
            None => {
                debug!("Ignoring peer notification");
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
        let line_len = line.len();
        debug!(line_len, "Parsing response");
        let response = match serde_json::from_str::<JsonRpcMessage>(line)? {
            JsonRpcMessage::Response(response) => response,
            JsonRpcMessage::Notification(notification) => {
                self.capture_notification(notification);
                return Ok(());
            }
            JsonRpcMessage::Request(_) => {
                // The method is peer text, so it is not repeated: the error
                // reaches the log.
                return Err(Error::Protocol(
                    "Peer sent a request on the response stream".to_string(),
                ));
            }
        };

        if let Some(ref id) = response.id
            && self
                .taps
                .response_to(id, response.result.as_ref(), response.error.as_ref())
        {
            // A listen is never a pending request (design §4).
            return Ok(());
        }
        if let Some(ref id) = response.id {
            let key = id.to_string();
            let pending_count = self.pending.len();
            debug!(pending_count, "Looking for pending request");
            if let Some((_, sender)) = self.pending.remove(&key) {
                debug!("Found pending request, sending response");
                let _ = sender.send(response);
            } else {
                debug!("No pending request found for response");
            }
        } else {
            debug!("Response has no ID (notification?)");
        }

        Ok(())
    }

    /// Write a message to stdin
    async fn write_message(&self, message: &str) -> Result<()> {
        debug!(message_len = message.len(), "Writing to stdin");
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
            Err(Error::TransportConnect("Not connected".to_string()))
        }
    }

    /// Get next request ID
    #[allow(clippy::cast_possible_wrap)] // request IDs won't exceed i64::MAX
    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::Relaxed) as i64)
    }
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
            let _ = Box::into_pin(child.kill()).await;
        }

        Ok(())
    }
}

#[path = "stdio_tree.rs"]
mod tree;
pub use tree::{CEILING_MAX_FRAME_BYTES, DEFAULT_MAX_FRAME_BYTES, MIN_MAX_FRAME_BYTES};
use tree::{read_frame, spawn_in_own_tree};

#[path = "stdio_early_exit.rs"]
mod early_exit;

#[path = "stdio_listen.rs"]
mod listen;
#[path = "stdio_progress.rs"]
mod progress;
#[path = "stdio_start_failure.rs"]
mod start_failure;
use progress::{progress_token_string, request_progress_token};

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stdio_tap_tests.rs"]
mod tap_tests;

#[cfg(test)]
#[path = "stdio_frame_tests.rs"]
mod frame_tests;

// Unix-only: the fake backend is a `sh` script.
#[cfg(all(test, unix))]
#[path = "stdio_negotiation_tests.rs"]
mod negotiation_tests;

#[cfg(test)]
#[path = "stdio_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
#[path = "stdio_start_refusal_tests.rs"]
mod start_refusal_tests;

#[cfg(test)]
#[path = "stdio_spawn_classification_tests.rs"]
mod spawn_classification_tests;
