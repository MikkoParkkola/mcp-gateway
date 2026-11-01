// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio serve loop: reading requests, spawning dispatches and draining on shutdown (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

use super::BuiltMetaMcp;
use super::Gateway;
use super::persistence;
use super::stdio_refusal::{admit_stdio_request, stdio_busy_batch_response, stdio_busy_response};
use super::warmstart::build_warm_start_list;
use super::warmstart::{WarmStartMode, WarmerGuard};
use super::{
    AbortOnDrop, MAX_CONCURRENT_STDIO_DISPATCHES, MAX_INFLIGHT_STDIO_REQUESTS, STDIO_DRAIN_TIMEOUT,
    STDIO_SESSION_ID, StdioClient, StdioTelemetry, stdio_channel, stdio_shutdown, stdio_tasks,
};
use super::{StdioNonce, identity_grants, spawn_health_loop, spawn_idle_reaper, stdio_dispatches};
use crate::Result;
use crate::error::rpc_codes::PARSE_ERROR;
use crate::gateway::outbound::OutboundFrame;

impl Gateway {
    /// [`Self::run_stdio`] over any pipe pair. Test builds may pass a gate the
    /// `initialize` response waits on before it is queued (MIK-7387.STDIO.2).
    #[allow(clippy::too_many_lines)]
    pub(super) async fn run_stdio_on<R, W>(
        self,
        input: R,
        output: W,
        #[cfg(test)] initialize_gate: Option<Arc<tokio::sync::Semaphore>>,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            "Starting MCP Gateway (stdio mode)"
        );
        // Drawn before the first request, not inside one (MIK-7570.STDIO.1).
        StdioNonce::process();

        // ── Shared MetaMcp initialisation ────────────────────────────────────
        let BuiltMetaMcp {
            meta_mcp,
            tool_policy: _,
            mtls_policy,
            data_dir,
            record_key,
            ..
        } = self.build_meta_mcp().await?;
        // Held for the whole serve: it owns the governance store's lease.
        let (grant_sink, grants_read) = identity_grants::stdio_identity_grants(
            &self.config,
            self.config_path.as_deref(),
            &meta_mcp,
        )
        .await?;
        // Published later, with the stdio session's config.
        grants_read.into_startup(&self.env);
        // MIK-8278: this session announces tool-list changes to an
        // initialize-era client, so it may say so; the feed is installed
        // before warm-start and the capability load, so their nudges count.
        meta_mcp.set_change_feed(crate::gateway::ChangeFeed::StdioLegacy);
        let (nudges, nudge_rx) = tokio::sync::mpsc::unbounded_channel();
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
        )]
        self.backends.set_change_feed(nudges);
        let warmer = WarmerGuard::new(&self.backends, WarmStartMode::Stdio, None);
        let protocol_telemetry_sink = Arc::new(StdioTelemetry::new(
            match crate::protocol_revision_telemetry::DurableTelemetrySink::open(&data_dir) {
                Ok(sink) => Some(sink),
                Err(error) => {
                    warn!(
                        %error,
                        data_dir = %data_dir.display(),
                        "stdio protocol-revision telemetry is not durable; do not start the measurement window"
                    );
                    None
                }
            },
        ));
        // MIK-8364: a request only records its observation in memory; this
        // saver persists the window off the request path, and the bounded
        // save at teardown takes what is left. Dropped before that save, so
        // no tick starts after it.
        #[cfg(test)]
        let telemetry_save_every = self
            .test_seams
            .telemetry_save_every()
            .unwrap_or(persistence::PROTOCOL_TELEMETRY_SAVE_INTERVAL);
        #[cfg(not(test))]
        let telemetry_save_every = persistence::PROTOCOL_TELEMETRY_SAVE_INTERVAL;
        let telemetry_saver = {
            let sink = Arc::clone(&protocol_telemetry_sink);
            AbortOnDrop::new(persistence::spawn_periodic_save(
                "protocol telemetry save",
                telemetry_save_every,
                None,
                move || Self::save_stdio_protocol_telemetry_unless_busy(&sink),
            ))
        };
        // One config for everything stdio judges with and for its reload
        // context, so a stdio reload reaches intake, tasks and policy (ADR-023).
        // Records name its revision with or without a config file; the startup
        // load's raw bytes are taken here and never outlive this function.
        // Its auth is the default one: stdio authenticates by API key nothing,
        // and the gateway's own `auth` is never resolved here, so one that does
        // not resolve cannot turn stdio's tasks off.
        let live_config = Arc::new(
            crate::config_reload::LiveConfig::from_prepared(
                crate::config_reload::Generation::prepare_startup(
                    self.config.clone(),
                    Arc::new(stdio_tasks::default_auth(
                        self.env.startup(),
                        Arc::clone(&record_key),
                    )),
                ),
            )
            .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch))
            .with_startup_revision(meta_mcp.record_key(), self.env.take_startup_inputs()),
        );
        meta_mcp.set_live_config(Arc::clone(&live_config));
        // MIK-7272.OWNER.2: `<tasks.store_dir>/stdio`, or `None` to serve as before.
        let task_store = stdio_tasks::open(&self.config, &meta_mcp, &live_config).await;
        // MIK-7839.CANCEL.3: a session future dropped before EOF never reaches
        // the async teardown; this guard still stops its task workers.
        let _stop_tasks = task_store.as_ref().map(|(tasks, _)| tasks.stop_on_drop());
        // MIK-7217.STDIO.1: read once, as the store is; discover lists 2026-07-28 by it.
        let serving =
            super::stdio_single::ModernServing::from_setting(self.config.server.modern_protocol);

        // MIK-8364 (Option A): Ctrl+C and SIGTERM end stdio the way stdin EOF
        // does: stop reading, drain what was accepted under the same bound,
        // then the final telemetry save. Without this a signal killed stdio
        // outright and the counts since the last save were lost.
        let (signal_tx, _) = tokio::sync::broadcast::channel(1);
        #[cfg(test)]
        let stop_signal = super::test_seams::shutdown_signal_or_trigger(
            signal_tx,
            self.test_seams.take_shutdown_trigger(),
        );
        #[cfg(not(test))]
        let stop_signal = super::support::shutdown_signal(signal_tx);
        tokio::pin!(stop_signal);
        // Polled once here, before the catalogue install and warm start can
        // spawn a backend, so the OS handlers are registered from now on
        // rather than from the read loop's first poll: a signal in between
        // would otherwise take the default action and, since each backend
        // leads its own process group, leave their trees running.
        let signalled_early = futures::FutureExt::now_or_never(stop_signal.as_mut()).is_some();

        // The overrides in effect at start are recorded now; reloads share it.
        let (override_auditor, override_drain) =
            crate::config_reload::override_audit::OverrideAuditor::start(
                meta_mcp.transparency_log().cloned(),
            );
        override_auditor
            .record_at_start(&self.backends, meta_mcp.transparency_log())
            .await?;
        let reporting =
            crate::config_reload::refusals::ReloadReporting::with_override_audit(override_auditor);
        self.install_stdio_startup_catalogue(
            &meta_mcp,
            &live_config,
            grant_sink.as_ref(),
            &warmer,
            reporting,
        )
        .await?;

        // Warm-start backends (same as HTTP mode). Held for the rest of the
        // function: dropping the guard aborts the retry tasks, so cancelling
        // `run_stdio` anywhere cancels them too, not only the EOF path below.
        let _ = warmer.warm(build_warm_start_list(
            &self.backends,
            &self.config.meta_mcp.warm_start,
            false,
        ));

        // Reap what warm-start and lazy starts spawn, and probe backends so a
        // dead one recovers. Both were HTTP-only or EOF-only before: stdio has
        // no broadcast shutdown channel, so these guards own the tasks and abort
        // them on EVERY exit path, not just the one that reaches EOF.
        let idle_reaper = AbortOnDrop::new(spawn_idle_reaper(Arc::clone(&self.backends), None));
        let health_loop = AbortOnDrop::new(spawn_health_loop(
            Arc::clone(&self.backends),
            &self.config.failsafe.health_check,
            None,
        ));
        // As in HTTP mode, so a hard kill loses at most one interval of spend.
        #[cfg(feature = "cost-governance")]
        let cost_saver = meta_mcp.budget_enforcer.as_ref().map(|enforcer| {
            AbortOnDrop::new(persistence::spawn_cost_saver(
                Arc::clone(enforcer),
                data_dir.clone(),
                persistence::COST_SAVE_INTERVAL,
                None,
            ))
        });

        info!("MCP Gateway stdio mode ready — reading JSON-RPC from stdin");

        // ── Read → dispatch → write loop ────────────────────────────────────
        let mut reader = BufReader::new(input).lines();

        // One writer, owning stdout (design §1). Every producer — responses,
        // notifications, outbound bridged requests — queues here and never
        // touches the handle, which is what makes whole-frame writes a
        // property of the code rather than of timing.
        // Bounded: stdout is the only consumer, so a client that stops
        // reading must stall its producers rather than grow this queue. An
        // unbounded queue would turn a stalled reader into operator-process
        // memory growth.
        let (writer, queue) = self.stdout_queue(&meta_mcp);
        let mut writer_task = tokio::spawn(Self::run_stdout_writer(output, queue));

        // MIK-8278: decide this session's tool-list changes and tell its
        // client, and watch the capability catalogue as HTTP does. The
        // watchers stop with the announcer, so they end on every exit path.
        let announcer = super::tools_changed::stdio::StdioAnnouncer::start(
            (Arc::clone(&self.backends), Arc::clone(&meta_mcp)),
            Arc::clone(&live_config),
            nudge_rx,
            writer.clone(),
        );
        let _capability_watcher = meta_mcp.get_capabilities().and_then(|cap_backend| {
            cap_backend.spawn_listing_watch(Arc::clone(&self.backends), announcer.shutdown());
            #[allow(
                clippy::disallowed_methods,
                reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
            )]
            crate::capability::CapabilityWatcher::start(
                cap_backend,
                announcer.shutdown(),
                Some(self.backends.catalogue_hook()),
            )
            .inspect_err(|error| warn!(%error, "stdio: capability hot-reload disabled"))
            .ok()
        });
        #[cfg(test)]
        super::stdio_seams::announcer_started(announcer.drain_alive());
        // Whether this session began with `initialize`: only such a client
        // is told of changes (a modern one was told `listChanged: false`).
        let mut legacy_handshake = false;

        // Use a fixed session ID for stdio sessions (single client, long-lived)
        let session_id = STDIO_SESSION_ID;
        let (reads, bridge_reads) = (Arc::new(meta_mcp.stdio_reads()), meta_mcp.stdio_reads());
        let channel = Arc::new(stdio_channel::StdioClientChannel::new(
            writer.clone(),
            bridge_reads,
        ));
        let mut dispatches = stdio_dispatches::StdioDispatches::default();
        let cancelled = dispatches.cancelled();
        // Admission, not just concurrency: a client that writes faster than the
        // backends answer would otherwise pile one task per line onto the
        // JoinSet. The permit is released when the dispatch task ends.
        let admission = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STDIO_DISPATCHES));
        // The second bound (design §7). `admission` says how much may RUN;
        // this says how much may be accepted and not yet finished. The read
        // loop consults it without ever awaiting, so a client that pipelines
        // past the cap is refused rather than served by a parked reader.
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_STDIO_REQUESTS));
        // What the handshake declared, kept for the session (MRTR.9). A legacy
        // -shaped `tools/call` carries no `_meta`, so without this every later
        // call would reach the bridge declaring nothing and be refused -32021
        // for a capability the client did in fact announce.
        //
        // Plain local, no lock: `initialize` is dispatched inline below while
        // everything else is spawned, so the write happens-before every task
        // that copies it, and `Declared` is `Copy`.
        let mut handshake_capabilities = crate::protocol::meta::Declared::NONE;

        // Why the loop can end before EOF: see `run_stdout_writer`.
        let mut stdout_died = false;

        loop {
            if signalled_early {
                info!("stdio: shutdown signal received during startup; shutting down");
                break;
            }
            // A closed queue means the stdout writer has exited, so every
            // answer from here on would be written nowhere. Executing the
            // request anyway performs its side effect and discards the only
            // record of it, which is strictly worse than refusing to start:
            // stop admitting, and let the drain below finish what was already
            // accepted.
            //
            // Raced against the read rather than checked after it, because a
            // client that stops reading need not also stop being idle: waiting
            // for a line that never comes would leave the gateway and its
            // backend tasks alive with nowhere to answer. `biased` so a dead
            // stdout wins a tie instead of admitting one more request.
            let line = tokio::select! {
                biased;
                () = writer.closed() => {
                    stdout_died = true;
                    break;
                }
                () = &mut stop_signal => {
                    info!("stdio: shutdown signal received; finishing accepted requests");
                    break;
                }
                // Reaped as each ends, so an aborted dispatch is joined at once
                // and a long session does not accumulate task records.
                Some(joined) = dispatches.join_next(), if !dispatches.is_empty() => {
                    if let Err(error) = joined
                        && !error.is_cancelled()
                    {
                        warn!(%error, "stdio: a dispatch task did not finish cleanly");
                    }
                    continue;
                }
                read = reader.next_line() => match read {
                    Ok(Some(line)) => line,
                    _ => break,
                },
            };

            // ADR-023: this line is judged by the generation current as it is
            // read, held for its whole dispatch; taken before parsing, so a
            // reload while the line is parsed cannot reach it.
            let generation = live_config.generation();
            let sanitize =
                super::stdio_single::InputSanitizing::from_setting(generation.sanitize_input());
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            debug!(line_len = line.len(), "stdio: received line");

            let request: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    // `try_send` (MIK-7684): the reader never waits for stdout
                    // room, or a client that stops reading parks it before EOF.
                    // A full queue drops the answer, as for the busy refusal;
                    // it has no id, so the client could not match it anyway.
                    let parse_error = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": PARSE_ERROR, "message": format!("Parse error: {e}")}
                    });
                    if writer
                        .try_send(OutboundFrame::gateway_stdio(parse_error))
                        .is_err()
                    {
                        warn!("stdio: a parse error could not be queued, dropped");
                    }
                    continue;
                }
            };

            // An id and no method is an answer to one of OUR requests, not a
            // request of ours to serve (design §3). Routed, never dispatched;
            // an id nothing waits on is a late answer to a timed-out prompt,
            // which is expected rather than an error.
            if let Some(reply_id) = stdio_channel::StdioClientChannel::reply_id(&request) {
                if !channel.resolve(&reply_id, request) {
                    debug!(id = %reply_id, "stdio: reply matched no outstanding request");
                }
                continue;
            }

            // Routed here, never dispatched (MIK-7272.LIFE.1). No frame answers
            // it; `initialize` runs inline and is never tracked, so it cannot
            // be cancelled.
            if request.get("method").and_then(serde_json::Value::as_str)
                == Some("notifications/cancelled")
            {
                if let Some(id) = request
                    .pointer("/params/requestId")
                    .and_then(|id| serde_json::from_value(id.clone()).ok())
                {
                    dispatches.cancel(&id);
                }
                #[cfg(test)]
                super::stdio_seams::cancel_recorded();
                continue;
            }

            // Marked, then dispatched as before: announcing starts here.
            // Alone or inside a batch: a legacy client may send it either way.
            let is_initialized = |frame: &serde_json::Value| {
                frame.get("method").and_then(serde_json::Value::as_str)
                    == Some("notifications/initialized")
            };
            if legacy_handshake
                && (is_initialized(&request)
                    || request
                        .as_array()
                        .is_some_and(|frames| frames.iter().any(is_initialized)))
            {
                announcer.initialized();
            }

            // A batch is spawned like a single request (MIK-7684): dispatched
            // inline, it parked the reader on a full stdout. Its answer may now
            // follow frames for later lines; singles are already unordered
            // (design §7.4) and every answer carries its ids. It shares the
            // in-flight cap and the running pool with singles, so two batches
            // may run at once.
            if request.is_array() {
                let Some(slot) = admit_stdio_request(&inflight) else {
                    warn!("stdio: refusing a batch, too many requests already in flight");
                    if let Some(refusal) = stdio_busy_batch_response(&request)
                        && writer
                            .try_send(OutboundFrame::gateway_stdio(refusal))
                            .is_err()
                    {
                        warn!(
                            "stdio: the batch refusal itself could not be queued, ids unanswered"
                        );
                    }
                    continue;
                };
                if writer.is_closed() {
                    stdout_died = true;
                    break;
                }
                let meta_mcp = Arc::clone(&meta_mcp);
                let generation = Arc::clone(&generation);
                let mtls_policy = Arc::clone(&mtls_policy);
                let (writer, reads) = (writer.clone(), Arc::clone(&reads));
                let admission = Arc::clone(&admission);
                dispatches.spawn(None, async move {
                    let _running = admission
                        .acquire_owned()
                        .await
                        .expect("the admission semaphore is never closed");
                    if writer.is_closed() {
                        return;
                    }
                    // MIK-8176: the batch's slots are owned here, from
                    // dispatch through the writer queue.
                    Box::pin(crate::gateway::meta_mcp::sealed_hold::scoped(async {
                        // Boxed: the dispatch future is tens of kilobytes.
                        let (responses, _) = Self::dispatch_streaming_notifications(
                            Box::pin(Self::dispatch_batch_read(
                                &meta_mcp,
                                &generation,
                                &mtls_policy,
                                request,
                                (session_id, sanitize, serving),
                                &reads,
                            )),
                            &writer,
                            &reads,
                            Some(meta_mcp.notification_screen("stdio", session_id)),
                        )
                        .await;
                        if !responses.is_empty() {
                            drop(
                                writer
                                    .send(crate::gateway::outbound::StdioReads::batch_of(responses))
                                    .await,
                            );
                        }
                    }))
                    .await;
                    drop(slot);
                });
                continue;
            }

            // `initialize` inline, everything else spawned (design §2). The
            // handshake response is in the writer's FIFO queue before line 2
            // is read, so no frame a later dispatch produces can precede it —
            // the ordering row 323 asserts, for free from the read loop.
            let spawned =
                request.get("method").and_then(serde_json::Value::as_str) != Some("initialize");
            if !spawned {
                legacy_handshake = true;
                handshake_capabilities = crate::protocol::meta::Declared::from_handshake(
                    request.pointer("/params/capabilities"),
                );
            }
            // Before the task is built, because refusing needs the id and the
            // builder moves the request. `initialize` is dispatched inline and
            // takes no slot: nothing is in flight yet when it runs.
            let slot = if spawned {
                let Some(slot) = admit_stdio_request(&inflight) else {
                    warn!("stdio: refusing a request, too many already in flight");
                    if let Some(refusal) = stdio_busy_response(&request) {
                        // `try_send`, not `send`: the refusal exists to avoid
                        // parking the reader, and awaiting a full stdout queue
                        // parks it just the same. A queue with no room is
                        // already telling the client to slow down.
                        if writer
                            .try_send(OutboundFrame::gateway_stdio(refusal))
                            .is_err()
                        {
                            // Dropped, not buffered: any wait here is the
                            // parked reader again. Logged because the client
                            // is then holding an id that will never be
                            // answered, and the drop is the only record of
                            // why.
                            warn!("stdio: the refusal itself could not be queued, id unanswered");
                        }
                    }
                    continue;
                };
                Some(slot)
            } else {
                None
            };
            let request_id: Option<crate::protocol::RequestId> = request
                .get("id")
                .and_then(|id| serde_json::from_value(id.clone()).ok());
            let task = {
                let meta_mcp = Arc::clone(&meta_mcp);
                let generation = Arc::clone(&generation);
                let mtls_policy = Arc::clone(&mtls_policy);
                // Cloned, not borrowed: the caller context holds
                // `&dyn ClientChannel` and a spawned task needs `'static`.
                let channel = Arc::clone(&channel);
                let tasks = task_store.as_ref().map(|(tasks, _)| Arc::clone(tasks));
                let (writer, reads) = (writer.clone(), Arc::clone(&reads));
                let params = reads.judges().then(|| request.get("params").cloned());
                let cancelled = cancelled.clone();
                let answers = request_id.clone();
                #[cfg(test)]
                let gate = initialize_gate.clone().filter(|_| !spawned);
                #[cfg(test)]
                let hold = Arc::clone(&self.test_seams.stdio_dispatch_hold);
                // MIK-8176: this request's slots are owned by its task, from
                // dispatch through the writer queue.
                // One delivery's facts: dispatch, judge and record.
                Box::pin(crate::gateway::delivery_facts::scope(
                    crate::gateway::meta_mcp::sealed_hold::scoped(async move {
                        #[cfg(test)]
                        hold.pause().await;
                        let ((response, staged), hidden) = Self::dispatch_streaming_notifications(
                            Box::pin(Self::dispatch_single_staged(
                                &meta_mcp,
                                &generation,
                                &mtls_policy,
                                request,
                                StdioClient {
                                    session_id,
                                    channel: &*channel,
                                    handshake_capabilities,
                                    tasks: tasks.as_deref(),
                                    serving,
                                    discover: super::stdio_single::DiscoverListing::Configured,
                                    sanitize,
                                },
                            )),
                            &writer,
                            &reads,
                            Some(meta_mcp.notification_screen("stdio", session_id)),
                        )
                        .await;
                        #[cfg(test)]
                        if let Some(gate) = gate {
                            drop(gate.acquire().await);
                        }
                        // Room first, then the cancel check and the enqueue under
                        // one lock: no frame for the id is queued after its cancel
                        // was processed, however long the queue was full.
                        let params = params.flatten();
                        let response = match response {
                            Some(value) => Some(
                                Self::judge_and_commit(
                                    &meta_mcp,
                                    &reads,
                                    session_id,
                                    (value, params.as_ref(), hidden.as_ref()),
                                    staged,
                                )
                                .await,
                            ),
                            None => None,
                        };
                        // MIK-8176 C1-stdio: the settled answer, before the
                        // cancel check and the enqueue.
                        #[cfg(test)]
                        super::stdio_seams::after_commit().await;
                        #[cfg(test)]
                        if response.is_some() && writer.capacity() == 0 {
                            super::stdio_seams::answer_found_queue_full();
                        }
                        if let Some(response) = response
                            && let Ok(permit) = writer.reserve().await
                        {
                            cancelled.send_unless_cancelled(answers.as_ref(), permit, response);
                        }
                    }),
                ))
            };
            if spawned {
                let slot = slot.expect("a spawned request holds the slot it was admitted on");
                // Non-blocking, and kept: the loop head already races
                // `writer.closed()`, but a stdout that died while this line
                // was being parsed must not buy one more dispatch.
                if writer.is_closed() {
                    stdout_died = true;
                    break;
                }
                // Start order among concurrent dispatches is NOT stdin order
                // (design §7.4): each task requests its permit on its own
                // first poll, so the semaphore queue follows the scheduler,
                // not the client. Only the `initialize` response keeps its
                // guaranteed position, and it keeps it by being inline.
                let admission = Arc::clone(&admission);
                let closed_probe = writer.clone();
                dispatches.spawn(request_id, async move {
                    // The wait that used to be here, moved off the reader. It
                    // is unbounded, so stdout can die inside it: admission was
                    // checked against a queue that may no longer exist, and
                    // dispatching now would run the side effect and throw the
                    // answer away. The read loop leaves by its own `closed()`
                    // arm; this task only has to decline to start.
                    let _running = admission
                        .acquire_owned()
                        .await
                        .expect("the admission semaphore is never closed");
                    if closed_probe.is_closed() {
                        return;
                    }
                    task.await;
                    drop(slot);
                });
            } else if tokio::time::timeout(STDIO_DRAIN_TIMEOUT, task)
                .await
                .is_err()
            {
                // `initialize` stays inline for its ordering, but bounded
                // (MIK-7684): an answer that cannot be queued in time means
                // the client stopped reading. Serving on would answer later
                // lines on a session whose handshake was never answered, so
                // the session ends through the bounded shutdown below.
                warn!("stdio: the initialize answer could not be queued in time; shutting down");
                stdout_died = true;
                break;
            }
        }

        // The read loop is over: the session is ending, so nothing more is
        // announced, though accepted requests still drain (MIK-8278).
        announcer.stop();
        // `writer.is_closed()` as well as the flag: stdout can die during the
        // wait for a line that never comes, and the loop then leaves by the EOF
        // arm. Reporting that as an ordinary EOF would hand the operator the
        // one message that hides why the session ended.
        if stdout_died || writer.is_closed() {
            warn!("stdio: stdout is gone, refusing further requests and shutting down");
        } else {
            info!("stdio: EOF reached, shutting down");
        }
        // EOF drains, it does not abort (design §6): every request the loop
        // accepted still gets its response. Outstanding prompts are failed
        // first — their answers can only arrive on the pipe that just closed —
        // and `close` is terminal, so a question raised inside the drain window
        // is refused rather than left waiting out the bridge's own timeout.
        channel.close();
        // One deadline for the drain and the writer join (MIK-7272.LIFE.1):
        // a client that stops reading stdout blocks the writer, and the two
        // together still end within one `STDIO_DRAIN_TIMEOUT`, not two. Every
        // await after them ends by `shutdown_deadline` (MIK-7685).
        let deadline = tokio::time::Instant::now() + STDIO_DRAIN_TIMEOUT;
        let shutdown_deadline = deadline + stdio_shutdown::STDIO_TEARDOWN_TIMEOUT;
        #[cfg(test)]
        self.test_seams.stdio_drain_started.notify_one();
        if tokio::time::timeout_at(deadline, async {
            while let Some(joined) = dispatches.join_next().await {
                if let Err(e) = joined
                    && !e.is_cancelled()
                {
                    warn!("stdio: dispatch task failed during drain: {e}");
                }
            }
        })
        .await
        .is_err()
        {
            warn!(
                timeout = ?STDIO_DRAIN_TIMEOUT,
                "stdio: dispatch drain timed out; aborting what is left"
            );
            let abort = dispatches.shutdown();
            stdio_shutdown::bounded_step(shutdown_deadline, "dispatch abort", abort).await;
        }
        // Abort the saver: no new tick is scheduled after this. `drop` does not
        // await the abort, so a tick already past its interval may still start
        // its thread, and a tick thread may still be writing. Either is safe:
        // every save holds the sink lock, and the final save below waits for
        // it, so no two saves overlap and no delta is counted twice (MIK-8364).
        drop(telemetry_saver);
        Self::persist_stdio_telemetry_bounded(shutdown_deadline, &protocol_telemetry_sink).await;
        #[cfg(feature = "cost-governance")]
        if let Some(enforcer) = &meta_mcp.budget_enforcer {
            let (enforcer, dir) = (Arc::clone(enforcer), data_dir.clone());
            stdio_shutdown::final_cost_save(shutdown_deadline, cost_saver, enforcer, dir).await;
        }
        // Every sender gone, then the writer joined: the task drains its queue
        // and returns, which is what flushes the responses the drain produced.
        // The announcer holds a sender too: stopped when the read loop ended,
        // dropped before the join so the queue can close.
        drop(announcer);
        drop(writer);
        drop(channel);
        match tokio::time::timeout_at(deadline, &mut writer_task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "stdio: the stdout writer did not finish cleanly"),
            Err(_) => {
                writer_task.abort();
                warn!("stdio: stdout is not being read; unwritten frames are dropped");
            }
        }
        // Stop sweeping and probing before tearing the backends down. Both tasks
        // hold an Arc on the registry and have no shutdown channel in this mode,
        // so leaving either running keeps the registry alive after run_stdio
        // returns. Dropping the guards here is explicit; they would also fire on
        // any other exit path, which is the point of them.
        drop(idle_reaper);
        drop(health_loop);
        let left = shutdown_deadline.saturating_duration_since(tokio::time::Instant::now());
        override_drain.drain(&self.backends, left).await;
        self.stdio_teardown(shutdown_deadline, warmer, task_store)
            .await;
        Ok(())
    }
}
