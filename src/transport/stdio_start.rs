// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting a stdio backend: spawn the child, start its reader, and complete
//! the MCP handshake with protocol version negotiation.

use super::{
    Arc, BufReader, Command, Error, Ordering, PROTOCOL_VERSION, Result, Selectable, Stdio,
    StdioTransport, Transport, checked_selection, configure_child_environment, debug, early_exit,
    error, info, initialize_params, is_version_mismatch_error, negotiate_best_version,
    parse_supported_versions_from_error, read_frame, reaper, spawn_in_own_tree, warn,
};

impl StdioTransport {
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
        // The reaper exists before any child does (design P4).
        reaper::ensure_started()
            .map_err(|error| Error::Transport(format!("stdio reaper unavailable: {error}")))?;
        // Taken before the spawn: from spawn to install there is no await, so a
        // retire lands either before the spawn (the install guard refuses) or
        // after the install (`kill_tree_now` reaches the tree).
        let mut writer = self.writer.lock().await;
        // A start that begins after a retire spawns nothing; one the retire
        // overtakes from here on is refused at install.
        if self.child.lock().retired {
            return Err(Error::BackendNotFound(
                "stdio backend retired before it started".to_string(),
            ));
        }
        let mut child = spawn_in_own_tree(cmd)?;
        #[cfg(all(test, unix))]
        self.after_spawn_for_test();

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

        // Renewed under the stdin lock, so a write never pairs new stdin with
        // the token a previous `close()` cancelled.
        *self.shutdown.lock() = tokio_util::sync::CancellationToken::new();
        if let Err(refused) = self.install_tree(self.new_tree(child)) {
            *writer = None;
            return Err(refused);
        }
        *writer = Some(stdin);
        drop(writer);
        let eof_tx = Arc::new(tokio::sync::watch::channel(false).0);
        self.start.begin(Arc::clone(&eof_tx));

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
            let latch = early_exit::TripOnDrop(eof_tx);
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
                        // The length only: a parse error can quote the line, and
                        // the line can hold an injected secret (MIK-9035).
                        if transport.handle_response(&line).is_err() {
                            error!(line_len, "Failed to handle a line from the backend");
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
                            && let Some(tree) = transport.child.lock().tree.as_mut()
                        {
                            tree.start_kill();
                        }
                        break;
                    }
                }
            }

            // Before the clear: a request that registers after it sees the
            // latch, and one that registered before it is dropped by it.
            drop(latch);
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

        let stderr = early_exit::spawn_stderr_tail(stderr, self.diagnostic_command());
        self.failure.track(&stderr.tail);

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
                error = self.early_exit_error(stderr).await;
                None
            } else {
                self.settle_child_exit().await;
                Some(stderr)
            };
            self.shut().await;
            if let Some(reader) = late_reader {
                // The child `close` just killed: record that ending, so the
                // failure is not reported as a child still running.
                self.settle_child_exit().await;
                self.settle_stderr_tail(reader).await;
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
    pub(super) async fn initialize(&self) -> Result<()> {
        let version = self
            .protocol_version
            .read()
            .clone()
            .unwrap_or_else(|| PROTOCOL_VERSION.to_string());
        // Computed once, outside the log macros, so each macro head carries
        // only plain locals.
        let command = self.diagnostic_command();

        debug!(
            command = %command,
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
                    "Initialize failed for '{command}': backend error code {}",
                    error.code
                )));
            }
            let Some(negotiated) = parse_supported_versions_from_error(&error.message)
                .as_deref()
                .and_then(negotiate_best_version)
            else {
                return Err(Error::Protocol(format!(
                    "Protocol version negotiation failed for '{command}': server rejected {version}, \
                     no compatible version found (backend error code {})",
                    error.code
                )));
            };
            warn!(
                command = %command,
                rejected = %version,
                negotiated = %negotiated,
                "Retrying initialize with negotiated protocol version"
            );
            response = self.init_request(initialize_params(negotiated)).await?;
            if let Some(ref error) = response.error {
                return Err(Error::Protocol(format!(
                    "Initialize failed for '{command}' even with negotiated version {negotiated}: \
                     backend error code {}",
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
            command = %command,
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
}
