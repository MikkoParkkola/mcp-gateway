// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway server

// Crate-visible on purpose: this is THE install a bound backend gets, and a
// test that drives a real startup must call the same one rather than a copy of
// its policy.
pub(crate) mod account_bindings;
#[cfg(test)]
mod attestation_start_tests;
#[cfg(test)]
mod audit_start_tests;
mod background;
mod build_meta;
mod cleartext;
#[cfg(all(test, feature = "firewall"))]
mod collusion_share_tests;
mod construct;
mod control_plane_store;
#[cfg(all(test, feature = "cost-governance"))]
mod cost_restart_tests;
mod events_wiring;
#[cfg(test)]
mod gh475_budget_decides_tests;
mod identity_grants;
#[cfg(all(test, feature = "firewall"))]
mod keyless_anomaly_tests;
mod listener;
mod persistence;
mod provenance_signer;
#[cfg(test)]
mod remote_provenance_start_tests;
#[cfg(test)]
mod replica_state_tests;
mod run;
mod run_steps;
#[cfg(test)]
#[path = "tests/mod.rs"]
pub(crate) mod signing_allocation_tests;
mod start_checks;
mod stdio_catalogue;
mod stdio_channel;
mod stdio_delivery;
mod stdio_dispatches;
mod stdio_nonce;
mod stdio_notify;
mod stdio_refusal;
use stdio_refusal::{admit_stdio_request, stdio_busy_batch_response, stdio_busy_response};
mod stdio_shutdown;
mod stdio_tasks;
mod stdio_writer;
mod task_runtime;
#[cfg(test)]
mod test_seams;
pub(crate) use stdio_nonce::StdioNonce;
mod support;
mod tools_changed;
// Two questions leave this module, both to `config_reload`, and each is
// exported under the question it answers. A reload asks about the config that
// would be IN FORCE, so it goes through the overlay. A restart-only edit asks
// what the NEXT START does with the file, which is the startup check itself —
// the same function the bind path calls, named here for the caller.
pub(crate) use cleartext::reload_posture_refusal;
pub(crate) use support::start_refusal as next_start_refusal;
mod warmstart;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};

use tracing::{debug, info, warn};

use super::authz::ToolPolicyAuthorizer;
use super::meta_mcp::{InvokeScope, MetaMcp, MetaMcpCallerContext};
use super::oauth::GatewayKeyPair;
use super::router::CallerStanding;

use super::outbound::OutboundFrame;
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::Config;
use crate::config_reload::{LiveConfig, ReloadContext};

use crate::Result;
#[cfg(test)]
use crate::mtls::MtlsPolicy;
#[cfg(test)]
use crate::security::ToolPolicy;
pub(crate) use background::AbortOnDrop;
#[cfg(test)]
use background::poll_export_source;
use background::{spawn_export_task, spawn_health_loop, spawn_idle_reaper};
use build_meta::BuiltMetaMcp;
use control_plane_store::{build_control_plane_store, control_plane_base};
#[cfg(test)]
use identity_grants::load_configured_identity_grants;
#[cfg(test)]
use provenance_signer::{provenance_key, resolve_provenance_signer};
use warmstart::{WarmStartMode, WarmerGuard, build_warm_start_list};

/// State owner for the single client on a long-lived stdio connection.
const STDIO_SESSION_ID: &str = "stdio-session";

/// How long the EOF path waits for the dispatches it already accepted.
///
/// How many frames may wait for stdout before producers stall.
///
/// Deep enough that an ordinary burst of progress notifications never blocks
/// a dispatch, shallow enough that a client which stops reading stalls the
/// gateway instead of growing its memory.
const STDOUT_QUEUE_DEPTH: usize = 1024;

/// How many stdio requests may be in flight at once.
///
/// Concurrency is the point of MIK-7387, but an uncapped spawn turns a client
/// that writes faster than the backends answer into unbounded task and backend
/// load. One client, so the cap is generous rather than tuned.
const MAX_CONCURRENT_STDIO_DISPATCHES: usize = 64;

/// Accepted-but-unfinished stdio requests, which is a different question from
/// how many may run at once (`MAX_CONCURRENT_STDIO_DISPATCHES`). Sized to the
/// stdout queue: work admitted beyond what the writer can still hold has
/// nowhere to put its answer, so the client is told to slow down instead.
const MAX_INFLIGHT_STDIO_REQUESTS: usize = STDOUT_QUEUE_DEPTH;

/// Bounded rather than unbounded: past it the `JoinSet` aborts what is left,
/// which is exactly the pre-concurrency behaviour and no worse (design §6).
const STDIO_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The stdio protocol-revision sink, shared by every spawned dispatch.
///
/// A `std::sync::Mutex` and never a `tokio` one: every writer is synchronous,
/// so the guard is taken and dropped without an await in between. Holding one
/// across an await would make the dispatch future `!Send` and serialise the
/// concurrent bridged calls this whole change exists to allow (design §5).
pub(crate) type StdioTelemetry =
    std::sync::Mutex<Option<crate::protocol_revision_telemetry::DurableTelemetrySink>>;

/// The standing stdio serves its resource and prompt surfaces at: the client
/// spawned this process, so it holds whatever the operator holds.
const STDIO: CallerStanding = CallerStanding::Admin;

fn expand_home_path(path: &str) -> PathBuf {
    if path == "~" {
        return crate::home_dir::home_dir().unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return crate::home_dir::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    PathBuf::from(path)
}

/// MCP Gateway server
pub struct Gateway {
    /// Configuration
    config: Config,
    /// Path to config file on disk (enables hot-reload when `Some`)
    config_path: Option<std::path::PathBuf>,
    /// A config file found by discovery rather than named (#1868): watched and
    /// reloaded, but never used where `config_path` picks a location (the
    /// governance store) or grants a write (admin config edits).
    watched_config: Option<std::path::PathBuf>,
    /// Backend registry
    backends: Arc<BackendRegistry>,
    /// Shutdown flag
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
    /// The environment the config was evaluated against.
    ///
    /// Every lazy reader — capability credentials, the reload transaction, the
    /// file watcher — resolves through this rather than the process
    /// environment, which no env file is written to.
    env: Arc<crate::config::LiveEnv>,
    /// The one cross-tenant read history of this process (MIK-7116.MIN.2):
    /// both firewalls share it, so `/mcp` and `/mcp/{name}` meet in it.
    #[cfg(feature = "firewall")]
    reads: Arc<crate::security::firewall::tenant_reads::ReadHistory>,
    /// Managed personal-account custody, present only when the config carries an
    /// `accounts` block. `None` is the ordinary gateway: no store, no locks.
    ///
    /// Holding the handle rather than the store is deliberate: an explicit
    /// account shutdown releases the store and its two file locks while this
    /// handle stays here to refuse everything that arrives afterwards.
    custody: Option<Arc<crate::personal_accounts::GatewayCustody>>,
    /// In-process test settings: data directory and bound-port channel.
    #[cfg(test)]
    test_seams: test_seams::TestSeams,
}

/// Who the stdio dispatcher is serving: the session's id, the channel that
/// reaches that client, and what its handshake said it can be asked for.
///
/// Passed as one value because the three are only ever read as a set, and
/// because a caller context built from two of them plus a default for the
/// third is precisely the defect this path had twice over — a
/// `NoClientChannel` for a client that could be asked, then
/// `Declared::NONE` for one that had declared on the handshake.
#[derive(Clone, Copy)]
struct StdioClient<'a> {
    session_id: &'a str,
    channel: &'a dyn crate::gateway::input_bridge::ClientChannel,
    handshake_capabilities: crate::protocol::meta::Declared,
    /// The session's task store; `None` serves no `tasks/*` (MIK-7272.OWNER.2).
    tasks: Option<&'a stdio_tasks::StdioTasks>,
    /// `server.modern_protocol` at stdio start: whether `server/discover`
    /// lists 2026-07-28 (MIK-7217.STDIO.1, design D7).
    modern: bool,
}

/// Copy only the fields backend target mapping routes on.
///
/// `gateway_invoke` routes on `server` and `tool`, `gateway_execute` on
/// each `chain` step's `tool` or a single top-level `tool`, and a
/// surfaced tool routes on its own name. Everything else in the tree is
/// the payload, which the mapping copies into a target and the response
/// contract then never reads. A malformed key is left out exactly as
/// the mapping would have ignored it, so the servers and tools derived
/// from this projection are the ones derived from the whole tree.
fn stdio_routing_keys_only(arguments: &serde_json::Value) -> serde_json::Value {
    let mut routing = serde_json::Map::new();
    for key in ["server", "tool"] {
        if let Some(value) = arguments.get(key).filter(|value| value.is_string()) {
            routing.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(chain) = arguments.get("chain").and_then(serde_json::Value::as_array) {
        let steps = chain
            .iter()
            .map(|step| {
                let mut routing = serde_json::Map::new();
                if let Some(tool) = step.get("tool").filter(|tool| tool.is_string()) {
                    routing.insert("tool".to_owned(), tool.clone());
                }
                serde_json::Value::Object(routing)
            })
            .collect();
        routing.insert("chain".to_owned(), serde_json::Value::Array(steps));
    }
    serde_json::Value::Object(routing)
}

/// Move the client's `params._meta` into the call's `arguments`.
///
/// The borrowed merge can only insert into a copy, because it holds a
/// view of someone else's tree. This dispatcher owns the request, so
/// the same insertion is a move: `arguments` and `_meta` are taken out
/// of the request — which nothing reads after the dispatch below — and
/// handed to the merge's own insertion step. Neither subtree is copied,
/// so an unbounded payload and an unbounded `_meta` both cost the same
/// as a small one.
///
/// Called only where `client_meta_insert_required` has just answered
/// yes, so the fallbacks here are the shapes that predicate already
/// excluded; each returns what the merge returns for it. An absent
/// `arguments` becomes the `{}` the borrowed path substitutes, and
/// still receives the metadata.
fn stdio_take_merged_client_meta(request: &mut serde_json::Value) -> serde_json::Value {
    let empty = || serde_json::Value::Object(serde_json::Map::new());
    let Some(params) = request
        .get_mut("params")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return empty();
    };
    let Some(meta) = params.remove("_meta") else {
        return empty();
    };
    let arguments = params
        .get_mut("arguments")
        .map_or_else(empty, serde_json::Value::take);
    super::router::helpers::insert_client_meta(arguments, meta)
}

impl Gateway {
    /// Run the gateway in stdio mode.
    ///
    /// Reads newline-delimited JSON-RPC from stdin and writes responses to stdout.
    /// Reuses the same `MetaMcp` dispatch logic as the HTTP server so all meta-tools
    /// (`gateway_search_tools`, `gateway_invoke`, etc.) work identically.
    ///
    /// # Errors
    ///
    /// Returns an error if backend registration or `MetaMcp` initialisation fails.
    ///
    /// # Panics
    ///
    /// Panics if RSA key pair generation fails on all retry attempts.
    pub async fn run_stdio(self) -> Result<()> {
        let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
        self.run_stdio_on(
            stdin,
            stdout,
            #[cfg(test)]
            None,
        )
        .await
    }

    /// [`Self::run_stdio`] over any pipe pair. Test builds may pass a gate the
    /// `initialize` response waits on before it is queued (MIK-7387.STDIO.2).
    #[allow(clippy::too_many_lines)]
    async fn run_stdio_on<R, W>(
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
            tool_policy,
            mtls_policy,
            data_dir,
            ..
        } = self.build_meta_mcp().await?;
        // Held for the whole serve: it owns the governance store's lease.
        let grant_sink = identity_grants::stdio_identity_grants(
            &self.config,
            self.config_path.as_deref(),
            &meta_mcp,
        )
        .await?;
        // Give stdio the same explicit reload context as HTTP.
        let warmer = WarmerGuard::new(&self.backends, WarmStartMode::Stdio, None);
        if let Some(path) = self.reload_path() {
            let live_config = Arc::new(
                LiveConfig::new(self.config.clone())
                    .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch)),
            );
            let reload_ctx = Arc::new(
                ReloadContext::new(
                    path.clone(),
                    Arc::clone(&live_config),
                    Arc::clone(&self.backends),
                    self.config.failsafe.clone(),
                    self.config.meta_mcp.cache_ttl,
                )?
                .with_env(Arc::clone(&self.env))
                .with_identity_grant_sink_opt(grant_sink.clone())
                .with_on_registered(warmer.hook()),
            );
            meta_mcp.set_reload_context(reload_ctx);
        }
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
        // MIK-7272.OWNER.2: `<tasks.store_dir>/stdio`, or `None` to serve as before.
        let task_store =
            stdio_tasks::open(&self.config, self.env.startup(), &meta_mcp, &tool_policy).await;
        // MIK-7839.CANCEL.3: a session future dropped before EOF never reaches
        // the async teardown; this guard still stops its task workers.
        let _stop_tasks = task_store.as_ref().map(|(tasks, _)| tasks.stop_on_drop());
        // MIK-7217.STDIO.1: read once, as the store is; discover lists 2026-07-28 by it.
        let modern = self.config.server.modern_protocol;

        // Account strategies must exist before stdio can admit a request, just
        // as they do before the HTTP listener starts serving.
        if self.config.accounts.is_some() {
            let gateway_key_pair = Arc::new(GatewayKeyPair::generate().map_err(|error| {
                crate::Error::Config(format!(
                    "stdio account signing key generation failed: {error}"
                ))
            })?);
            let account_custody = self.custody.as_ref().map(|custody| {
                Arc::clone(custody) as Arc<dyn crate::personal_accounts::AccountCustody>
            });
            account_bindings::install_account_strategies(
                &self.config,
                account_custody.as_ref(),
                &gateway_key_pair,
                &meta_mcp,
                account_bindings::ServeMode::Stdio,
            )?;
        }

        if self.config.capabilities.enabled {
            let account_strategies = meta_mcp.account_strategies();
            account_bindings::declare_account_descriptors(&self.config, &account_strategies);
            let executor = Arc::new(
                CapabilityExecutor::for_config(&self.config.capabilities)
                    .with_env(Arc::clone(&self.env))
                    .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch))
                    .with_account_strategies(account_strategies),
            );
            let cap_backend = Arc::new(CapabilityBackend::new(
                &self.config.capabilities.name,
                executor,
            ));
            let mut refused = Vec::new();
            for dir in &self.config.capabilities.directories {
                match cap_backend.load_from_directory_reporting(dir).await {
                    Ok(report) => {
                        debug!(directory = %dir, count = report.admitted, "Loaded capabilities (stdio)");
                        refused.extend(report.rejected);
                    }
                    Err(error) => {
                        debug!(directory = %dir, %error, "Failed to load optional capabilities (stdio)");
                    }
                }
            }
            if !refused.is_empty() {
                return Err(crate::Error::Config(format!(
                    "capabilities rejected by the account admission gate: {}",
                    refused.join("; ")
                )));
            }
            cap_backend.mark_initial_scan_complete();
            meta_mcp.set_capabilities(cap_backend);
        }

        if self.config.playbooks.enabled {
            let mut engine = crate::playbook::PlaybookEngine::new();
            for dir in &self.config.playbooks.directories {
                if let Ok(count) = engine.load_from_directory(dir) {
                    debug!(directory = %dir, count, "Loaded playbooks (stdio)");
                }
            }
            meta_mcp.set_playbook_engine(engine);
        }

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
        let (writer, queue) = tokio::sync::mpsc::channel::<OutboundFrame>(STDOUT_QUEUE_DEPTH);
        let mut writer_task = tokio::spawn(Self::run_stdout_writer(output, queue));

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
                        "error": {"code": -32700, "message": format!("Parse error: {e}")}
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
                continue;
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
                let tool_policy = Arc::clone(&tool_policy);
                let mtls_policy = Arc::clone(&mtls_policy);
                let telemetry = Arc::clone(&protocol_telemetry_sink);
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
                    Box::pin(crate::gateway::meta_mcp::sealed_hold::scoped(
                        crate::gateway::meta_mcp::sealed_hold::HoldPolicy::CountOnly,
                        async {
                            // Boxed: the dispatch future is tens of kilobytes.
                            let (responses, _) = Self::dispatch_streaming_notifications(
                                Box::pin(Self::dispatch_batch_read(
                                    &meta_mcp,
                                    &tool_policy,
                                    &mtls_policy,
                                    request,
                                    session_id,
                                    &telemetry,
                                    &reads,
                                )),
                                &writer,
                                &reads,
                                Some(meta_mcp.notification_screen("stdio", session_id)),
                            )
                            .await;
                            Self::persist_stdio_protocol_telemetry(&telemetry);
                            if !responses.is_empty() {
                                drop(
                                    writer
                                        .send(crate::gateway::outbound::StdioReads::batch_of(
                                            responses,
                                        ))
                                        .await,
                                );
                            }
                        },
                    ))
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
                let tool_policy = Arc::clone(&tool_policy);
                let mtls_policy = Arc::clone(&mtls_policy);
                let telemetry = Arc::clone(&protocol_telemetry_sink);
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
                // MIK-8176: this request's slots are owned by its task, from
                // dispatch through the writer queue.
                Box::pin(crate::gateway::meta_mcp::sealed_hold::scoped(
                    crate::gateway::meta_mcp::sealed_hold::HoldPolicy::CountOnly,
                    async move {
                        let ((response, staged), hidden) = Self::dispatch_streaming_notifications(
                            Box::pin(Self::dispatch_single_staged(
                                &meta_mcp,
                                &tool_policy,
                                &mtls_policy,
                                request,
                                StdioClient {
                                    session_id,
                                    channel: &*channel,
                                    handshake_capabilities,
                                    tasks: tasks.as_deref(),
                                    modern,
                                },
                                &telemetry,
                            )),
                            &writer,
                            &reads,
                            Some(meta_mcp.notification_screen("stdio", session_id)),
                        )
                        .await;
                        Self::persist_stdio_protocol_telemetry(&telemetry);
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
                        if let Some(response) = response
                            && let Ok(permit) = writer.reserve().await
                        {
                            cancelled.send_unless_cancelled(answers.as_ref(), permit, response);
                        }
                    },
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
        Self::persist_stdio_telemetry_bounded(shutdown_deadline, &protocol_telemetry_sink).await;
        #[cfg(feature = "cost-governance")]
        if let Some(enforcer) = &meta_mcp.budget_enforcer {
            let (enforcer, dir) = (Arc::clone(enforcer), data_dir.clone());
            stdio_shutdown::final_cost_save(shutdown_deadline, cost_saver, enforcer, dir).await;
        }
        // Every sender gone, then the writer joined: the task drains its queue
        // and returns, which is what flushes the responses the drain produced.
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
        self.stdio_teardown(shutdown_deadline, warmer, task_store)
            .await;
        Ok(())
    }

    /// Dispatch a single JSON-RPC request through `MetaMcp`.
    ///
    /// Returns `None` for notifications (no response expected per JSON-RPC spec).
    #[cfg(test)]
    async fn dispatch_single(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: &serde_json::Value,
        session_id: &str,
    ) -> Option<serde_json::Value> {
        Self::dispatch_single_with_sink(
            meta_mcp,
            tool_policy,
            mtls_policy,
            request.clone(),
            StdioClient {
                session_id,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: crate::protocol::meta::Declared::NONE,
                tasks: None,
                modern: false,
            },
            &StdioTelemetry::default(),
        )
        .await
    }

    /// Dispatch one stdio request, durably recording its inbound observation
    /// before any handler can await, fail, or terminate the process.
    /// NFR.OBS.1's stdio half: record one inbound observation and flush it.
    ///
    /// Its own function so the dispatcher below reads as dispatch; the two
    /// calls are the same either way.
    fn observe_stdio_inbound(
        request: &serde_json::Value,
        params: Option<&serde_json::Value>,
        method: &str,
        session_id: &str,
        sink: Option<&mut crate::protocol_revision_telemetry::DurableTelemetrySink>,
    ) {
        crate::protocol_revision_telemetry::observe_inbound_request(
            request,
            params,
            method,
            None,
            Some(session_id),
            crate::protocol_revision_telemetry::Transport::Stdio,
        );
        if let Some(sink) = sink
            && let Err(error) = sink.persist_global()
        {
            warn!(
                %error,
                "failed to persist inbound stdio protocol-revision observation; measurement window is incomplete"
            );
        }
    }

    /// [`Self::dispatch_single_staged`] recording the receipts straight away,
    /// for a caller that judges no frame (a test).
    #[cfg(test)]
    async fn dispatch_single_with_sink(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: serde_json::Value,
        client: StdioClient<'_>,
        sink: &StdioTelemetry,
    ) -> Option<serde_json::Value> {
        let session_id = client.session_id;
        let (answer, staged) =
            Self::dispatch_single_staged(meta_mcp, tool_policy, mtls_policy, request, client, sink)
                .await;
        // No frame is judged here: recorded and settled as built, and the
        // receipts follow the frame as `judge_and_commit` has them follow it.
        let Some(answer) = answer else {
            staged.commit(false);
            return None;
        };
        let frame = answer.delivered_unjudged(meta_mcp, session_id).await;
        staged.commit(frame.delivers_result());
        frame.stdio_value().map(std::borrow::Cow::into_owned)
    }

    /// [`Self::dispatch_relay_scoped`] inside one relay-receipt collector,
    /// which spans dispatch and finalize (COLLUDE.1 §13.3), returning what it
    /// staged: the caller records it after the answer's read verdict. With
    /// relay detection off there is nothing to collect, and no box to allocate.
    #[allow(
        clippy::large_futures,
        reason = "the unboxed arm is the dispatch as it ran before the collector"
    )]
    async fn dispatch_single_staged(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        request: serde_json::Value,
        client: StdioClient<'_>,
        sink: &StdioTelemetry,
    ) -> (
        Option<stdio_delivery::StdioAnswer>,
        crate::gateway::meta_mcp::invoke::relay::StagedReceipts,
    ) {
        let dispatch =
            Self::dispatch_relay_scoped(meta_mcp, tool_policy, mtls_policy, request, client, sink);
        if meta_mcp.relay_active() {
            return meta_mcp.collecting_staged(Box::pin(dispatch)).await;
        }
        (
            dispatch.await,
            crate::gateway::meta_mcp::invoke::relay::StagedReceipts::none(),
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one dispatch path; the telemetry-guard scope is part of it"
    )]
    async fn dispatch_relay_scoped(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        _mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        mut request: serde_json::Value,
        client: StdioClient<'_>,
        protocol_telemetry_sink: &StdioTelemetry,
    ) -> Option<stdio_delivery::StdioAnswer> {
        // Borrowed views throughout: a refused request is never copied.
        // Ownership is taken once, after admission, where it executes.
        use super::router::helpers::extract_tools_call_params_ref;
        use crate::protocol::JsonRpcResponse;

        let session_id = client.session_id;
        let prepared = Self::prepare_signing(meta_mcp, &mut request);
        let (mut signing_context, chain_nonce) = match prepared {
            Ok(prepared) => prepared,
            Err(response) => return Some(stdio_delivery::StdioAnswer::Built(response)),
        };

        // Scoped so the guard is gone before the first await below: see
        // [`StdioTelemetry`].
        let parsed = {
            let mut sink = protocol_telemetry_sink
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Self::parse_and_observe(&request, session_id, sink.as_mut())
        };
        let (id, method, params, request_shape) = match parsed {
            Ok(parsed) => parsed,
            Err(early) => return early.map(stdio_delivery::StdioAnswer::Built),
        };

        let (external_tool, response_targets) = {
            // Response targets are derived here, before dispatch, so live backend
            // state cannot move an accepted call's provenance. The mapping is fed
            // the routing keys alone (same servers, tools, sort, dedup and
            // discovery handling), never a copy of the call arguments.
            // Declared out here: the targets borrow it past the branch.
            let routing_keys;
            let (external_tool, backend_targets) = if method == "tools/call" {
                let empty_arguments = serde_json::Value::Object(serde_json::Map::new());
                let (tool, arguments) = extract_tools_call_params_ref(params);
                routing_keys = stdio_routing_keys_only(arguments.unwrap_or(&empty_arguments));
                (
                    tool.to_string(),
                    super::router::backend_tool_targets_for_call(meta_mcp, tool, &routing_keys),
                )
            } else {
                (method.clone(), Vec::new())
            };
            let response_targets = super::meta_mcp::response_security::meta_response_targets(
                &external_tool,
                &backend_targets,
            );
            (external_tool, response_targets)
        };
        let policy = ToolPolicyAuthorizer { tool_policy };
        let scope = InvokeScope::stdio(&policy);
        let (mut response, execution) = if method == "tools/call" {
            // D3-a: one grant-decision slot spans signing, admission and dispatch.
            super::meta_mcp::grant_audit::slot_rpc(
                meta_mcp.transparency_logger.as_ref(),
                id.clone(),
                Box::pin(Self::dispatch_tools_call(
                    meta_mcp,
                    tool_policy,
                    &mut request,
                    id,
                    client,
                    &mut signing_context,
                    &request_shape,
                )),
            )
            .await
        } else {
            (
                match method.as_str() {
                    // 2026-07-28 MUST, answered without a handshake: on stdio it is
                    // also the backward-compatibility probe. It lists 2026-07-28 when
                    // `server.modern_protocol` was on at stdio start (MIK-7217.STDIO.1);
                    // a batch is a legacy shape and always gets the legacy list.
                    "server/discover" => stdio_tasks::advertised(
                        client.tasks,
                        JsonRpcResponse::success_serialized(
                            id,
                            meta_mcp.discover_document(client.modern),
                        ),
                    ),
                    "initialize" => stdio_tasks::advertised(
                        client.tasks,
                        meta_mcp.handle_initialize(
                            id,
                            params,
                            Some(session_id),
                            None,
                            request_shape.era(),
                            scope,
                        ),
                    ),
                    m @ ("tasks/get" | "tasks/update" | "tasks/cancel") => {
                        let retry = crate::protocol::mrtr::RetryFields::from_params(params);
                        let caller = Self::build_stdio_caller_context(
                            true,
                            None,
                            &policy,
                            &retry,
                            &request_shape,
                            client,
                        );
                        let shape = &request_shape;
                        stdio_tasks::serve(client.tasks, m, id, params, shape, &caller, session_id)
                            .await
                    }
                    "tools/list" => {
                        meta_mcp.handle_tools_list_with_params(id, params, Some(session_id), scope)
                    }
                    m if stdio_catalogue::METHODS.contains(&m) => {
                        stdio_catalogue::dispatch(meta_mcp, m, id, params).await
                    }
                    "logging/setLevel" => meta_mcp.handle_logging_set_level(id, params).await,
                    "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
                    other => {
                        debug!(method = %other, "stdio: unknown method");
                        let message = format!("Method not found: {other}");
                        JsonRpcResponse::error(Some(id), -32601, message)
                    }
                },
                None,
            )
        };

        // As `POST /mcp` does: shaped before signing, receipts stamped to match.
        let stamps = if request_shape.era() == crate::protocol::meta::Era::Modern {
            super::router::shape_modern_response(&mut response, &method)
        } else {
            super::meta_mcp::invoke::relay::GatewayStamps::Legacy
        };
        let chain_source = response.chain_source;
        let mut response = meta_mcp.finalize_content(
            response,
            &super::meta_mcp::response_security::ResponseDeliveryContext {
                method: &method,
                targets: &response_targets,
                correlation: super::meta_mcp::response_security::ResponseCorrelation {
                    session_id,
                    caller: "stdio",
                    external_server: "gateway",
                    external_tool: &external_tool,
                    subject: None,
                },
                signing: signing_context.as_ref(),
                chain_source,
                chain_nonce: chain_nonce.as_deref(),
            },
        );
        meta_mcp.release_unsent_hold(&mut response).await; // MIK-8131
        // MIK-7887.RECEIPT.4: the receipt describes the delivered answer, with
        // the stamps its era got; the judge can only replace the answer.
        {
            let shape = super::meta_mcp::invoke::relay::AnswerShape::of(&external_tool);
            meta_mcp.rebuild_receipt_from_final(response.result.as_ref(), stamps, shape);
        }
        // MIK-7920: recorded after the judge, then settled, by the caller
        // (`judge_and_commit`), as `POST /mcp` does.
        Some(stdio_delivery::StdioAnswer::finalized(
            response,
            external_tool,
            execution,
            signing_context,
        ))
    }

    /// Capture the signing envelope and the chain nonce ahead of parsing:
    /// both are taken out before anything else reads the request.
    fn prepare_signing(
        meta_mcp: &Arc<MetaMcp>,
        request: &mut serde_json::Value,
    ) -> std::result::Result<
        (
            Option<super::meta_mcp::signing::SigningInvocationContext>,
            Option<String>,
        ),
        serde_json::Value,
    > {
        // A bad chain nonce keeps the caller's id; a bad envelope has none.
        let raw_id = crate::protocol::mrtr::raw_request_id(request);
        let mut signing_context = meta_mcp.signing_enabled().then(|| {
            super::meta_mcp::signing::SigningInvocationContext::capture_scoped(
                request,
                meta_mcp.signing_scope(),
            )
        });
        let restored = (signing_context.as_mut()).map_or(Ok(()), |c| c.restore(request));
        let id = restored.is_ok().then_some(raw_id).flatten();
        match restored.and(crate::protocol::mrtr::take_chain_nonce(request)) {
            Ok(chain_nonce) => Ok((signing_context, chain_nonce)),
            Err(error) => Err(crate::protocol::JsonRpcResponse::error(
                id,
                error.to_rpc_code(),
                super::meta_mcp::signing::wire_error_message(&error),
            )
            .to_value_lossy()),
        }
    }

    /// Parse, classify and durably observe one inbound stdio request.
    ///
    /// `Err(None)` means no response is due (a notification); `Err(Some(_))`
    /// carries an already-serialized error response.
    fn parse_and_observe<'r>(
        request: &'r serde_json::Value,
        session_id: &str,
        protocol_telemetry_sink: Option<
            &mut crate::protocol_revision_telemetry::DurableTelemetrySink,
        >,
    ) -> std::result::Result<
        (
            crate::protocol::RequestId,
            String,
            Option<&'r serde_json::Value>,
            crate::protocol::meta::RequestShape,
        ),
        Option<serde_json::Value>,
    > {
        use super::router::helpers::parse_request_ref;
        use crate::protocol::JsonRpcResponse;

        let (id, method, params) = match parse_request_ref(request) {
            Ok((id, method, params)) => (id, method.to_string(), params),
            Err(response) => return Err(Some(response.to_value_lossy())),
        };

        // NFR.OBS.1. Recorded here, above every early return below, so a
        // stdio session is observed on the same terms an HTTP one is. Stdio
        // carries no headers, so the transport declares no revision and a
        // modern request can only have sourced its own from `_meta`.
        //
        // The same classification also controls modern explicit-key admission.
        let request_shape = crate::protocol::meta::classify_and_observe(
            &method,
            params,
            None,
            // Stdio carries no header, so the revision this session negotiated
            // at `initialize` is the only thing a later legacy request can be
            // sourced to. `None` until the handshake happens, which is what
            // keeps the pre-handshake record at `absent`/`none`.
            crate::protocol_revision_telemetry::session_negotiated_revision(Some(session_id)),
        );
        Self::observe_stdio_inbound(
            request,
            params,
            &method,
            session_id,
            protocol_telemetry_sink,
        );

        // ADR-014 §4, the stdio half. Stdio classifies the same body HTTP does,
        // so it declares a level the same way and gets the same filter -- one
        // policy, not one per transport. This runs inside the sink installed by
        // `dispatch_streaming_notifications`.
        crate::transport::notification_sink::set_request_log_level(
            request_shape.declared_log_level(),
        );

        // Notifications have no id — send no response
        if method.starts_with("notifications/") {
            debug!(notification = %method, "stdio: notification (no response)");
            return Err(None);
        }

        // Requests must have an id
        let Some(id) = id else {
            let resp = JsonRpcResponse::error(None, -32600, "Missing id");
            return Err(Some(resp.to_value_lossy()));
        };

        Ok((id, method, params, request_shape))
    }

    /// Handle `tools/call`: policy, signing, admission/replay, then dispatch.
    ///
    /// Ownership of `arguments` is taken only past every refusal — signing,
    /// nonce, admission, replay — because only an executing call needs to
    /// own its payload. `params` is re-derived from `request` here (already
    /// validated by the caller) so the immutable borrow it needs can end
    /// before the one branch below that needs `request` mutably.
    /// Build the stdio-path `MetaMcpCallerContext`, split out of
    /// [`Self::dispatch_tools_call`] purely to keep that function under the
    /// line budget — every field and its rationale are unchanged.
    fn build_stdio_caller_context<'a>(
        is_modern: bool,
        protocol_revision: Option<&'a str>,
        stdio_authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
        retry: &'a crate::protocol::mrtr::RetryFields,
        request_shape: &crate::protocol::meta::RequestShape,
        client: StdioClient<'a>,
    ) -> MetaMcpCallerContext<'a> {
        MetaMcpCallerContext {
            // stdio has no task route: the extension's handle is read
            // back over `tasks/get`, which only the HTTP surface serves,
            // so a handle minted here would name work nobody could ask
            // about. Every stdio call stays synchronous.
            task: None,
            execution: None,
            signing: None,
            is_modern,
            protocol_revision,
            credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL),
            authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
            credential_kind: crate::security::audit::CredentialKind::LocalTransport,
            authorizer: stdio_authorizer,
            // Stdio has no network surface: the client SPAWNED
            // this process and holds what the operator holds.
            // Withholding admin would disarm the single-user setup
            // the origin gate protects, and protect nothing.
            //
            // Explicit since the admin gate moved to the
            // dispatcher: it previously lived on the HTTP path
            // alone, so stdio was never checked and the default
            // non-admin context went unnoticed.
            is_admin: true,
            surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
            // MRTR.9 declares capabilities per request, in the same `_meta`
            // this shape was classified from, so a modern call is read there.
            //
            // A legacy or malformed shape carries no `_meta` to read, and on a
            // session transport that does not mean the client declared
            // nothing — it declared once, on the handshake. Falling back to it
            // is what lets a legacy stdio client be asked for the input it
            // announced; the bridge still refuses anything the handshake did
            // not name.
            input_capabilities: if is_modern {
                request_shape.declared_capabilities()
            } else {
                client.handshake_capabilities
            },
            retry,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            verified_identity: None,
            // The one client this process serves, for binding continuations.
            stdio_nonce: Some(StdioNonce::process()),
            caller_key: None,
            // Same `RequestShape` the `initialize` arm advertises against.
            era: request_shape.era(),
            // The serve loop's own channel: a stdio client reads the same
            // pipe an outbound request is written to, so it can be asked.
            // Non-serve-loop callers still pass `NoClientChannel`.
            channel: client.channel,
            // stdio speaks to one process over two pipes and
            // has no elicitation channel: there is no operator
            // this transport can reach, so a destructive call
            // it cannot confirm is refused rather than asked
            // about. Not "found no session" -- no asker can
            // exist here at all.
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        }
    }

    /// Long by construction: the single place a `tools/call` is admitted,
    /// dispatched and accounted for, and splitting it would put the policy
    /// checks and the outcome they gate in different functions.
    #[expect(clippy::too_many_lines, reason = "one admission path, kept whole")]
    async fn dispatch_tools_call(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        request: &mut serde_json::Value,
        id: crate::protocol::RequestId,
        client: StdioClient<'_>,
        signing_context: &mut Option<super::meta_mcp::signing::SigningInvocationContext>,
        request_shape: &crate::protocol::meta::RequestShape,
    ) -> (
        crate::protocol::JsonRpcResponse,
        Option<super::meta_mcp::admission::SyncLease>,
    ) {
        use super::router::helpers::{
            client_meta_insert_required, extract_tools_call_params_ref, merge_client_meta_ref,
        };
        use crate::protocol::JsonRpcResponse;

        let session_id = client.session_id;
        let empty_arguments = serde_json::Value::Object(serde_json::Map::new());
        let mut execution = None;
        let response = 'tool_call: {
            let params = request.get("params");
            let (tool_name, arguments) = extract_tools_call_params_ref(params);
            let is_meta_tool = meta_mcp.exposes_meta_tool(tool_name);
            let tool_name = tool_name.to_string();

            // The tool policy is applied at the dispatch chokepoint via the
            // authorizer below, not here. The inline check this replaces ran
            // for `gateway_invoke` alone, so a stdio playbook or code-mode
            // step reached a backend with no policy check at all.
            let stdio_authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
                tool_policy: tool_policy.as_ref(),
            };

            let retry = crate::protocol::mrtr::RetryFields::from_params(params);
            // Read before the merge below moves `_meta` out of the request.
            let wants_task = params.is_some_and(|params| params.get("task").is_some());
            let is_modern = matches!(
                request_shape,
                crate::protocol::meta::RequestShape::Modern(_)
            );
            if matches!(
                request_shape,
                crate::protocol::meta::RequestShape::Malformed { .. }
            ) {
                break 'tool_call JsonRpcResponse::error(
                    Some(id),
                    -32602,
                    "Malformed protocol metadata",
                );
            }
            // MIK-7272.SUB.4 §P3 (#528): the same -32602 refusal route 1
            // gives at `router/handlers.rs`. An unusable retry field must not
            // run on as an unprotected fresh call: the caller believes it has
            // replay protection it does not have, and for a destructive tool
            // that is the duplicate side effect it asked to be spared.
            if retry.is_malformed() {
                break 'tool_call JsonRpcResponse::error(
                    Some(id),
                    -32602,
                    format!("malformed request fields: {}", retry.malformed.join(", ")),
                );
            }
            // Verified evidence only: stdio echoes no header, so the session's
            // negotiated revision is the whole reading. The body is not
            // consulted — `params.protocolVersion` is not a `tools/call` field.
            let protocol_revision_owned = crate::protocol::meta::cache_protocol_revision(
                request_shape,
                None,
                crate::protocol_revision_telemetry::session_negotiated_revision(Some(session_id)),
            )
            .map(str::to_owned);
            // The canonical merge, still ahead of everything that reads the
            // arguments — signing, policy, nonce, admission — and now below
            // the two things that need the request whole: the retry fields
            // read `params._meta`, which is exactly the subtree the owning
            // branch moves out, and the shape classification already
            // observed it.
            //
            // The borrowed form still answers the four cases where the
            // merge would insert nothing by aliasing the caller's tree.
            // Where it would insert, the copy it makes is the whole payload
            // and the whole metadata, so the dispatcher spends the
            // ownership it already has instead: same insertion, same
            // precedence, moved rather than copied.
            let arguments = if client_meta_insert_required(arguments, params, is_meta_tool) {
                std::borrow::Cow::Owned(stdio_take_merged_client_meta(request))
            } else {
                merge_client_meta_ref(arguments.unwrap_or(&empty_arguments), params, is_meta_tool)
            };
            let mut caller = Self::build_stdio_caller_context(
                is_modern,
                protocol_revision_owned.as_deref(),
                &stdio_authorizer,
                &retry,
                request_shape,
                client,
            );
            if let Some(context) = signing_context.as_mut()
                && let Err(error) = meta_mcp.prepare_signing_for_call(
                    context,
                    &tool_name,
                    arguments.as_ref(),
                    Some(session_id),
                    &caller,
                )
            {
                break 'tool_call JsonRpcResponse::gateway_error(
                    Some(id),
                    error.to_rpc_code(),
                    super::meta_mcp::signing::wire_error_message(&error),
                );
            }
            caller.signing = signing_context.as_ref();
            if wants_task && let Some(tasks) = client.tasks {
                match stdio_tasks::task_intent(
                    tasks,
                    &id,
                    &tool_name,
                    &arguments,
                    &caller,
                    request_shape,
                    session_id,
                ) {
                    Ok(intent) => caller.task = intent,
                    Err(refusal) => break 'tool_call *refusal,
                }
            }
            let admission = meta_mcp.admit_meta_sync(
                super::meta_mcp::AdmissionOwner::local_operator(),
                &caller,
                &tool_name,
                arguments.as_ref(),
                Some(session_id),
                &id,
            );
            execution = match admission {
                Ok(super::meta_mcp::admission::SyncAdmission::Unprotected) => None,
                Ok(super::meta_mcp::admission::SyncAdmission::Owned(lease)) => Some(lease),
                Ok(super::meta_mcp::admission::SyncAdmission::Replay(response, audit)) => {
                    // #2480: a replay is a delivered call, recorded as its first run was.
                    let (args, session) = (arguments.as_ref(), Some(session_id));
                    break 'tool_call meta_mcp
                        .audit_replay(&tool_name, args, session, &caller, response, audit)
                        .await;
                }
                Err(error) => {
                    break 'tool_call JsonRpcResponse::error(
                        Some(id),
                        error.to_rpc_code(),
                        error.to_string(),
                    );
                }
            };
            caller.execution = execution.as_ref();
            // Handed down borrowed (MIK-8014): only a task, which stores
            // the call, copies it.
            Box::pin(meta_mcp.handle_tools_call_ref(
                id,
                &tool_name,
                arguments,
                Some(session_id),
                caller,
            ))
            .await
        };
        (response, execution)
    }

    /// Dispatch a JSON-RPC batch request.
    #[cfg(test)]
    async fn dispatch_batch(
        meta_mcp: &Arc<MetaMcp>,
        tool_policy: &Arc<crate::security::ToolPolicy>,
        mtls_policy: &Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
    ) -> Vec<serde_json::Value> {
        Self::dispatch_batch_with_sink(
            meta_mcp,
            tool_policy,
            mtls_policy,
            batch,
            session_id,
            &StdioTelemetry::default(),
        )
        .await
    }
}

/// Which single minting strategy kind, if any, this config installs
/// process-wide. Returns the minting kind present among backends
/// (`SignedAssertion` or `TokenExchange`), or `None` when only `Passthrough`
/// or no `identity_propagation` is configured.
///
/// This is a strict allow-list of *implemented* minting strategies, not a
/// `!= Passthrough` deny-list. The deny-list form was unsafe: a backend
/// configured for an as-yet-unimplemented minting strategy (`Vault`,
/// MIK-6730) is `!= Passthrough`, so it would silently install some other
/// strategy and let the meta route mint the wrong credential shape for a
/// backend the operator asked to reach via a different trust model, a silent
/// substitution and an INV-4 violation. Allow-listing means each minting
/// strategy installs its own machinery only once it is actually wired here:
/// `SignedAssertion` (MIK-6704) and `TokenExchange` (RFC 8693, MIK-6729) are
/// both wired; `Vault` is not yet and so returns `None`. `Passthrough` mints
/// nothing (ADR-008, GPT review F1/R2-3, MIK-6746).
///
/// `validate_single_minting_strategy_kind` guarantees at most one minting kind
/// across all backends, so returning the first match is unambiguous.
fn configured_minting_strategy_kind(
    config: &crate::config::Config,
) -> Option<crate::identity_propagation::PropagationStrategyKind> {
    use crate::identity_propagation::PropagationStrategyKind as Kind;
    config.backends.values().find_map(|b| {
        b.identity_propagation.as_ref().and_then(|c| {
            matches!(c.strategy, Kind::SignedAssertion | Kind::TokenExchange).then_some(c.strategy)
        })
    })
}

/// Whether startup should install a minting strategy at all. True iff at least
/// one backend opts into an implemented minting strategy (`SignedAssertion` or
/// `TokenExchange`); see [`configured_minting_strategy_kind`] for the full
/// allow-list rationale and the `Passthrough`-only "install nothing" contract.
///
/// Test-only: production keys off [`configured_minting_strategy_kind`] directly
/// so it can pick the concrete strategy. This stays as a readable predicate for
/// the install-decision tests.
#[cfg(test)]
fn config_installs_minting_strategy(config: &crate::config::Config) -> bool {
    configured_minting_strategy_kind(config).is_some()
}

/// Backends whose gateway-held OAuth token is not blessed for shared use
/// (`oauth.enabled && !oauth.shared_account`) — the set the GW.3 startup
/// warning names (MIK-6784).
///
/// Returns empty unless `auth.single_user` is asserted: the warning only
/// matters when that single switch is the sole thing suppressing the per-user
/// OAuth isolation guard. Under `single_user = true`, any such backend leaks
/// its token — and its upstream MCP session — across users the moment a second
/// identity reaches the gateway.
fn leaky_single_user_backends(config: &Config) -> Vec<&str> {
    if !config.auth.single_user {
        return Vec::new();
    }
    config
        .backends
        .iter()
        .filter(|(_, b)| {
            b.oauth
                .as_ref()
                .is_some_and(|o| o.enabled && !o.shared_account)
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The admission ledger namespaces a client-chosen idempotency key under a
/// principal. Stdio has no OIDC identity and no credential to derive one from,
/// so without a value here every modern mutating call is refused `-32003` and
/// the transport can carry no keyed write at all. A constant is sufficient
/// rather than a stopgap: a stdio process serves exactly the one client that
/// spawned it, and each process owns a separate in-memory
/// `ExecutionAdmission` (`src/idempotency/admission.rs`), so no second caller
/// and no second process can share the namespace this names. This is not an
/// authorization decision — reaching the gateway over stdio already grants
/// full tool access. If the ledger ever gains shared storage, revisit it.
pub(crate) const STDIO_CREDENTIAL_PRINCIPAL: &str = "stdio";

/// A test fixture approximating the caller context a stdio `tools/call`
/// runs under -- why stdio is admin, why it has no channel and no asker --
/// in one named place instead of forty lines per test.
///
/// NOT the production path. `dispatch_tools_call` builds its own context
/// inline (`mod.rs:2762`) and carries the negotiated `protocol_revision`,
/// which this fixture hardcodes to `None`. An earlier doc comment here
/// claimed the helper had been extracted from `dispatch_single_with_sink`;
/// it never was, and no production arm calls it. Assert production stdio
/// behaviour against the dispatcher, not against this.
#[cfg(test)]
fn stdio_caller_context<'a>(
    authorizer: &'a crate::gateway::authz::ToolPolicyAuthorizer<'a>,
    era: crate::protocol::meta::Era,
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        // stdio has no task route: the extension's handle is read back over
        // `tasks/get`, which only the HTTP surface serves.
        task: None,
        execution: None,
        signing: None,
        is_modern: era == crate::protocol::meta::Era::Modern,
        protocol_revision: None,
        credential_principal: Some(STDIO_CREDENTIAL_PRINCIPAL),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::LocalTransport,
        authorizer,
        // Stdio has no port and no network surface: the
        // client SPAWNED this process, so it already holds
        // whatever the operator holds — it could edit the
        // config file just as easily. Withholding admin
        // here would take the management tools away from
        // exactly the single-user setup the origin gate
        // exists to protect, and protect nothing.
        //
        // Explicit since the admin gate moved to the
        // dispatcher: it previously lived on the HTTP path
        // alone, so stdio was never checked and the default
        // non-admin context went unnoticed.
        is_admin: true,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        // stdio carries no per-request capability
        // declaration to read, and absent means absent.
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        // Same `shape` the `initialize` arm advertises
        // against, two arms up.
        era,
        // No `ProxyManager` in this scope -- it is HTTP-only
        // -- so there is no session to put a request on.
        channel: &crate::gateway::input_bridge::NoClientChannel,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        verified_identity: None,
        stdio_nonce: Some(StdioNonce::process()),
        caller_key: None,
        // stdio speaks to one process over two pipes and has no elicitation channel:
        // there is no operator this transport can reach, so a destructive call it
        // cannot confirm is refused rather than asked about. Not "found no session"
        // -- no asker can exist here at all.
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

#[cfg(test)]
mod gateway_bootstrap_tests;

#[cfg(test)]
mod stdio_forward_path_tests;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use serde_json::json;

    use super::{
        Gateway, load_configured_identity_grants, provenance_key, resolve_provenance_signer,
    };
    use crate::{
        backend::BackendRegistry,
        config::{
            BackendConfig, Config, ContextIntegrityPresetConfig, IdentityGrantsConfig,
            TransportConfig,
        },
        gateway::meta_mcp::MetaMcp,
        identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile},
        mtls::{MtlsConfig, MtlsPolicy},
        protocol::{JsonRpcResponse, RequestId},
        security::ToolPolicy,
    };

    mod order2_fsm;

    fn test_meta_mcp() -> Arc<MetaMcp> {
        Arc::new(MetaMcp::new(Arc::new(BackendRegistry::new())))
    }

    fn test_tool_policy() -> Arc<ToolPolicy> {
        Arc::new(ToolPolicy::default())
    }

    fn test_mtls_policy() -> Arc<MtlsPolicy> {
        Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()))
    }

    mod boot;
    mod build_meta_wiring;
    mod startup_strategy;
    mod stdio_dispatch;

    // ── MIK-7212 OBS.1: the observation record on the stdio path ───────────
    //
    // Both record sites live in the HTTP handler (`router/handlers.rs:716` for
    // the revision, `:990` for the tools/list surface). `dispatch_single` is
    // what the stdio read loop calls and it passes neither, so a stdio session
    // is observed by nothing. This module pins that gap as a failing assertion
    // rather than describing it in prose: a criterion nobody can run is a
    // criterion nobody checks.
    //
    // RED ON ARRIVAL, deliberately. The repair is to emit the record from a
    // place both dispatchers reach; adding the emit is not this change's job.
    /// The saturation gate the stdio read loop consults (design §7).
    mod stdio_admission;

    mod stdio_observation;
}
