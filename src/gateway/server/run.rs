// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `Gateway::run`, the HTTP serve mode (moved from `server/mod.rs`, MIK-8144).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use super::Gateway;
use super::control_plane_store::{build_control_plane_store, control_plane_base};
use super::support::log_startup_banner;
#[cfg(test)]
use super::test_seams;
use super::warmstart::{WarmStartMode, WarmerGuard, build_warm_start_list};
use super::{
    BuiltMetaMcp, account_bindings, cleartext, configured_minting_strategy_kind, events_wiring,
    expand_home_path, identity_grants, leaky_single_user_backends, listener, persistence,
    spawn_export_task, spawn_health_loop, spawn_idle_reaper, start_checks, support, task_runtime,
    tools_changed,
};
use crate::capability::CapabilityWatcher;
use crate::config_reload::{ConfigWatcher, LiveConfig, ReloadContext};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::oauth::{AgentAuthState, AgentDefinition, AgentRegistry};
use crate::gateway::proxy::ProxyManager;
use crate::gateway::router::{AppState, account_handles_of, create_router_with_accounts};
use crate::gateway::streaming::NotificationMultiplexer;
use crate::gateway::webhooks::WebhookRegistry;
use crate::playbook::PlaybookEngine;
#[cfg(feature = "firewall")]
use crate::security::firewall::Firewall;
use crate::{Error, Result};

impl Gateway {
    /// Run the gateway.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot bind to the configured address
    /// or if an unrecoverable runtime error occurs.
    ///
    /// # Panics
    ///
    /// Panics if RSA key pair generation fails on all retry attempts.
    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        start_checks::http(&self.config)?;
        let addr = SocketAddr::new(
            self.config
                .server
                .host
                .parse()
                .map_err(|e| Error::Config(format!("Invalid host: {e}")))?,
            self.config.server.port,
        );

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());
        let warmer = WarmerGuard::new(&self.backends, WarmStartMode::Http, Some(&shutdown_tx));

        // Install Prometheus metrics recorder (no-op when feature is disabled).
        #[cfg(feature = "metrics")]
        {
            crate::metrics::install();
            crate::protocol_revision_telemetry::register_metrics();
        }

        // ── Shared MetaMcp initialisation ────────────────────────────────────
        // `data_dir` is read only by the cost-governance persistence tasks.
        #[cfg_attr(not(feature = "cost-governance"), allow(unused_variables))]
        let BuiltMetaMcp {
            meta_mcp,
            tool_policy,
            mtls_policy,
            ranker,
            ranker_path,
            transition_tracker,
            transition_path,
            data_dir,
            transparency_log,
        } = self.build_meta_mcp().await?;
        // F24: this mode delivers tools/list_changed, so it may advertise it.
        meta_mcp.set_change_feed(crate::gateway::ChangeFeed::Http);
        let (tools_changed_tx, tools_changed_rx) = tokio::sync::mpsc::unbounded_channel();
        self.backends.set_change_feed(tools_changed_tx);

        // Log policy and feature states now that the shared builder has run.
        if self.config.security.tool_policy.enabled {
            info!("Tool security policy enabled");
        }
        if self.config.mtls.enabled {
            info!(
                policies = self.config.mtls.policies.len(),
                require_client_cert = self.config.mtls.require_client_cert,
                "mTLS enabled"
            );
        }
        info!("Usage statistics tracking enabled");
        if self.config.cache.enabled {
            info!(
                enabled = true,
                default_ttl = ?self.config.cache.default_ttl,
                max_entries = self.config.cache.max_entries,
                "Response cache initialized"
            );
        }
        if !self.config.routing_profiles.is_empty() {
            info!(
                profiles = ?self.config.routing_profiles.keys().collect::<Vec<_>>(),
                default = %self.config.default_routing_profile,
                "Routing profiles loaded"
            );
        }

        let ranker_for_shutdown = Arc::clone(&ranker);
        let tracker_for_shutdown = Arc::clone(&transition_tracker);

        // T2.6: warn when a surfaced tool's backend is not in warm_start.
        for surfaced in &self.config.meta_mcp.surfaced_tools {
            if !self.config.meta_mcp.warm_start.contains(&surfaced.server) {
                warn!(
                    tool = %surfaced.tool,
                    server = %surfaced.server,
                    "Surfaced tool's backend is not in meta_mcp.warm_start — \
                     schema may be absent until the backend is first used"
                );
            }
        }

        let webhook_registry = WebhookRegistry::new(self.config.webhooks.clone())
            .with_env(Arc::clone(&self.env))
            .with_backend(&self.config.capabilities.name);
        let webhook_registry = Arc::new(parking_lot::RwLock::new(webhook_registry));

        // Load capabilities if enabled. Capability directories can be large;
        // when webhook route construction does not depend on them, populate the
        // backend in the background so health/MCP endpoints bind promptly.
        let _capability_watcher: Option<CapabilityWatcher> = self
            .start_capability_watcher(&meta_mcp, &webhook_registry, &shutdown_tx)
            .await?;

        // Load playbooks if enabled
        if self.config.playbooks.enabled {
            let mut engine = PlaybookEngine::new();
            let mut total_playbooks = 0;
            for dir in &self.config.playbooks.directories {
                match engine.load_from_directory(dir) {
                    Ok(count) => {
                        total_playbooks += count;
                        debug!(directory = %dir, count, "Loaded playbooks");
                    }
                    Err(e) => {
                        debug!(directory = %dir, error = %e, "Failed to load playbooks");
                    }
                }
            }
            if total_playbooks > 0 {
                info!(playbooks = total_playbooks, "Playbook engine ready");
            }
            meta_mcp.set_playbook_engine(engine);
        }

        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&self.backends),
            self.config.streaming.clone(),
        ));
        // One lifecycle registry, swept by the same tick that reaps stream
        // sessions. Constructed here so the reaper has an owner; the write
        // side that populates it is wired separately.
        let session_lifecycle =
            Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
        multiplexer.spawn_reaper_on(Arc::clone(&session_lifecycle));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        let auth_config = Arc::new(ResolvedAuthConfig::try_from_config(
            &self.config.auth,
            self.env.startup(),
        )?);

        // Live config handle: shared by the hot-reload watcher (which swaps it
        // on every applied reload) and AppState (which reads control-plane role
        // mapping through it, so a reload takes effect without restart —
        // MIK-6702). Created unconditionally; without a config path it simply
        // never changes.
        let live_config = Arc::new(
            LiveConfig::new(self.config.clone())
                .with_policy_epoch(Arc::clone(&meta_mcp.policy_epoch)),
        );

        // SIEM evidence-export background task (MIK-6703). None when disabled.
        // The control-plane base, resolved once: the export task, the store
        // and the admin API all name this directory.
        let control_plane_base = control_plane_base(&self.config, self.config_path.as_deref());
        let export_status =
            spawn_export_task(&self.config, &control_plane_base, shutdown_tx.subscribe());

        // Reload context into meta_mcp before AppState; the watcher starts after
        // `create_router`, so the bind-origin snapshot sees the bound config
        // (MIK-6750 r4). ONE grant sink for meta-tool and watcher (its mutex
        // serializes grant reloads), built after the store it records into.
        let control_plane_store = build_control_plane_store(&self.config, &control_plane_base)?;
        let identity_grant_sink = identity_grants::start_identity_grant_audit(
            &self.config,
            &meta_mcp,
            control_plane_store.as_ref(),
            &control_plane_base.path,
        )
        .await?;
        if let Some(path) = self.reload_path() {
            // Ends this context's reload waits on shutdown (#1808): axum's
            // graceful shutdown waits for every handler, and an admin or
            // meta-tool reload waiting on a stalled NFS or FUSE read would
            // otherwise never return. Subscribed before the task is spawned,
            // so a signal sent in between is not missed.
            let reload_stop = tokio_util::sync::CancellationToken::new();
            let mut shutdown_rx = shutdown_tx.subscribe();
            tokio::spawn({
                let reload_stop = reload_stop.clone();
                async move {
                    // A closed channel means the gateway is ending too.
                    drop(shutdown_rx.recv().await);
                    reload_stop.cancel();
                }
            });
            let reload_ctx = Arc::new(
                ReloadContext::new(
                    path.clone(),
                    Arc::clone(&live_config),
                    Arc::clone(&self.backends),
                    self.config.failsafe.clone(),
                    self.config.meta_mcp.cache_ttl,
                )?
                .with_env(Arc::clone(&self.env))
                .with_identity_grant_sink_opt(identity_grant_sink.clone())
                .with_stop(reload_stop)
                .with_capabilities(meta_mcp.get_capabilities())
                .with_on_registered(warmer.hook()),
            );
            meta_mcp.set_reload_context(Arc::clone(&reload_ctx));
        }

        // In-flight request tracker: large initial permits, drain waits for
        // all permits to be returned (i.e., all in-flight requests complete).
        let inflight = Arc::new(tokio::sync::Semaphore::new(10_000));
        #[cfg(test)]
        self.test_seams.report_inflight(&inflight);

        // Create key server if enabled
        let key_server = self.start_key_server(&shutdown_tx)?;

        // Build agent registry from config.
        let agent_registry = Arc::new(AgentRegistry::new());
        for def in &self.config.agent_auth.agents {
            let secret = def.resolved_hs256_secret(self.env.startup())?;
            agent_registry.register(AgentDefinition {
                client_id: def.client_id.clone(),
                name: def.name.clone(),
                hs256_secret: secret,
                rs256_public_key: def.rs256_public_key.clone(),
                scopes: def.scopes.clone(),
                issuer: def.issuer.clone(),
                audience: def.audience.clone(),
            });
        }
        let agent_auth =
            AgentAuthState::new(self.config.agent_auth.enabled, Arc::clone(&agent_registry));
        if self.config.agent_auth.enabled {
            info!(
                agents = agent_registry.len(),
                "Agent auth (issue #80) enabled"
            );
        }

        // Generate gateway RSA key pair for JWKS endpoint.
        let gateway_key_pair = Arc::new(Self::generate_gateway_key_pair());

        // Wire end-user identity propagation (MIK-6704 / ADR-007, MIK-6729):
        // when a backend opts into a *minting* strategy, give MetaMcp the single
        // process-wide strategy that matches the configured kind. Config
        // validation (`validate_single_minting_strategy_kind`) already guarantees
        // at most one minting kind across all backends, and one strategy instance
        // serves every backend of that kind. Each backend's per-request details
        // (audience, token-exchange endpoint/scope) arrive via the
        // `BackendDescriptor` at `propagate()` time, not from this instance.
        //
        // Passthrough (ADR-008 rung 2, MIK-6746) mints NOTHING: the caller attaches its own backend
        // credential and the direct route forwards it verbatim. So a Passthrough-only deployment
        // must NOT install a minting strategy. Doing so would let the meta route
        // (`gateway_invoke`), whose resolver keys off the globally-installed strategy rather than
        // the per-backend `strategy` enum, mint a credential for a Passthrough backend and violate
        // INV-4 (GPT review F1). With the strategy unset the meta route fails closed (required) or
        // falls back to static creds (optional) instead of minting. Mixed deployments (>=1 minting
        // backend plus >=1 passthrough backend) still install the strategy for the minting backend;
        // honoring passthrough on the meta route for that residual case needs the per-backend
        // strategy check in the (currently locked) resolver, tracked on MIK-6746. Interim contract:
        // passthrough is direct-route-only.
        match configured_minting_strategy_kind(&self.config) {
            Some(crate::identity_propagation::PropagationStrategyKind::SignedAssertion) => {
                use crate::identity_propagation::SignedAssertionStrategy;
                // 5-minute assertion lifetime (bounded further by the clamp).
                let strategy = Arc::new(SignedAssertionStrategy::new(
                    Arc::clone(&gateway_key_pair),
                    300,
                ));
                meta_mcp.set_identity_propagation(strategy);
                info!("End-user identity propagation enabled (signed-assertion strategy)");
            }
            Some(crate::identity_propagation::PropagationStrategyKind::TokenExchange) => {
                use crate::identity_propagation::TokenExchangeStrategy;
                // 5-minute subject-token lifetime; the exchanged downstream token
                // lives for whatever TTL the endpoint returns (or a safe default).
                let strategy = Arc::new(TokenExchangeStrategy::new(
                    Arc::clone(&gateway_key_pair),
                    300,
                ));
                meta_mcp.set_identity_propagation(strategy);
                info!("End-user identity propagation enabled (RFC 8693 token-exchange strategy)");
            }
            // Passthrough / Vault / no identity_propagation: install nothing.
            _ => {}
        }

        // Per-backend strategies for `accounts.descriptors` bindings, installed
        // BEFORE serving. This is where a managed account's vault custody and
        // an external descriptor's minting strategy coexist: each is bound to
        // its own backend, and the resolver prefers the per-backend entry over
        // the single process-wide one above. A managed binding with no custody
        // refuses here rather than dispatching as though it were shared.
        let account_custody = self.custody.as_ref().map(|custody| {
            Arc::clone(custody) as Arc<dyn crate::personal_accounts::AccountCustody>
        });
        account_bindings::install_account_strategies(
            &self.config,
            account_custody.as_ref(),
            &gateway_key_pair,
            &meta_mcp,
            account_bindings::ServeMode::Http,
        )?;

        // ADR-008 INV-2 (MIK-6752): declare multi-user status so dispatch can
        // fail closed on gateway-held OAuth tokens that are not per-user
        // isolated. Detection is fail-closed — any enabled auth is treated as
        // multi-user (a single shared API key or bearer can be handed to a whole
        // team; count alone cannot prove otherwise) unless the operator sets
        // `auth.single_user = true`. More than one credential or any OIDC issuer is
        // a hard multi-user signal. See `AuthConfig::implies_multi_user`.
        let multi_user = self
            .config
            .auth
            .implies_multi_user(!self.config.key_server.oidc.is_empty());
        meta_mcp.set_multi_user(multi_user);
        if multi_user {
            info!(
                "Multi-user gateway detected — per-user OAuth isolation guard active (ADR-008 INV-2)"
            );
        }

        // MIK-6784 (GW.3): warn when the operator has asserted `single_user =
        // true` (the sole switch that can suppress the per-user isolation guard)
        // while a backend still relies on a gateway-held OAuth token that is NOT
        // blessed for shared use (`oauth.enabled && !shared_account`). In that
        // configuration the single-user assertion is the ONLY thing preventing
        // one user's token — and its upstream MCP session — from being served to
        // another; if the gateway is ever reached by more than one identity the
        // isolation the guard would have provided is silently gone. We warn
        // rather than refuse because a genuinely single-user deployment is valid.
        // Only while the assertion actually holds the guard off (#2241).
        if self.config.auth.single_user && !multi_user {
            let leaky_backends = leaky_single_user_backends(&self.config);
            if !leaky_backends.is_empty() {
                warn!(
                    backends = ?leaky_backends,
                    "auth.single_user=true suppresses the per-user OAuth isolation guard, but \
                     these backends hold a non-shared gateway OAuth token. If more than one user \
                     reaches this gateway their tokens and upstream MCP sessions will be shared \
                     (MIK-6784). Fix: remove single_user, set oauth.shared_account=true only \
                     for genuinely shared service accounts, or enable per-user identity \
                     propagation."
                );
            }
        }

        // The transition tracker is only used when anomaly_detection=true; pass
        // a fresh tracker so the firewall has its own dedicated state.
        #[cfg(feature = "firewall")]
        let firewall_arc: Option<Arc<Firewall>> = {
            let fw = self.response_firewall(&meta_mcp);
            Some(fw)
        };

        // The write side of the registry: without this the reaper sweeps an
        // empty map forever, which is silent and looks exactly like working.
        #[cfg(feature = "firewall")]
        if let Some(ref firewall) = firewall_arc {
            crate::gateway::session_lifecycle::wire_session_lifecycle(&session_lifecycle, firewall);
        }

        // The per-session stores `meta_mcp` owns are reclaimed the same way.
        crate::gateway::session_lifecycle::wire_meta_session_cleanup(&session_lifecycle, &meta_mcp);

        // Keep a clone of meta_mcp for post-shutdown operations (periodic
        // persistence and graceful shutdown cost saves use this handle).
        // Only the cost-governance shutdown tasks consume this clone.
        #[cfg_attr(not(feature = "cost-governance"), allow(unused_variables))]
        let meta_mcp_for_shutdown = Arc::clone(&meta_mcp);

        // The durable task runtime, opened before any listener exists.
        //
        // Fail-closed, with no volatile fallback. Two things are at stake and
        // both survive a restart: a `tools/call` answered with a handle has
        // promised a record that a later `tasks/get` can read, and `open_runtime`
        // imports the store's committed ownership bindings into admission. A
        // store that will not open is therefore also a store whose owners are
        // unknown — serving past that point would answer a returning caller's
        // own task as absent, which is the one answer the ownership rule uses
        // for a task that is not theirs.
        //
        // Built here rather than inside the `AppState` literal because the
        // subscription registry is shared with the executor's publication seam:
        // two registries would leave a task's notifications going to a listener
        // set no client is on.
        self.config.tasks.validate()?;
        let task_store_dir = expand_home_path(&self.config.tasks.store_dir);
        // The registry re-validates every listener against the same credential
        // stores the request middleware reads, so the two cannot disagree.
        let dashboard_bootstrap = Arc::new(crate::gateway::auth::DashboardBootstrap::new());
        // Webhook registry into MetaMcp (gateway_webhook_status), and events,
        // which re-check credentials against the same authorities as requests.
        let (bearer_principal, bearer_sha256) =
            crate::events::LiveCredentials::static_bearer(auth_config.bearer_token.as_deref());
        let credentials = crate::events::LiveCredentials {
            key_server: key_server.clone(),
            bearer_principal,
            bearer_sha256,
            dashboard: Some(Arc::clone(&dashboard_bootstrap)),
        };
        events_wiring::install(
            &self.config,
            &meta_mcp,
            &webhook_registry,
            &live_config,
            credentials,
        )?;
        let subscriptions = Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(
                crate::gateway::subscription_registry::DEFAULT_MAX_LISTENERS,
                crate::gateway::auth::AuthState {
                    auth_config: Arc::clone(&auth_config),
                    key_server: key_server.clone(),
                    dashboard_bootstrap: Arc::clone(&dashboard_bootstrap),
                    // Only the session cookie reads this; re-validation sets none.
                    tls_enabled: false,
                    live_config: Arc::clone(&live_config),
                    agent_auth: agent_auth.clone(),
                },
            ),
        );
        // The runtime shares meta-MCP's admission authority rather than opening
        // one of its own: a task and a later synchronous call carrying the same
        // owner and idempotency key have to meet at ONE admission index, or the
        // backend runs twice for what the caller sent once.
        //
        // The adapters that are BOTH named in `tasks.recovery_adapters` and
        // still configured backends. Computed here because this is the one
        // place that can see both lists before `AppState` exists; it is the
        // weakest evaluable test on purpose, since deferring a row is not a
        // trust claim and issues no upstream call. Empty means the recovery
        // below is byte-identical to the no-adapter behaviour.
        let managed_adapters: Vec<String> = self.managed_recovery_adapters();
        let (task_service, task_executor) = task_runtime::open(
            &self.config,
            &task_store_dir,
            Arc::clone(&subscriptions),
            &meta_mcp,
            &managed_adapters,
        )
        .await
        .map_err(|error| {
            // A held lease is most often a stdio gateway on the same
            // directory (MIK-7272.OWNER.2, design D6 rev 5 item 7).
            Error::Config(format!(
                "task store at '{}' could not be opened: {error} (a task record refused \
                 here is named in the task store warning above; if the store is held by \
                 another gateway process, possibly a stdio gateway using \
                 '<store_dir>/stdio', give each gateway its own tasks.store_dir)",
                task_store_dir.display()
            ))
        })?;
        let skipped = task_service.skipped_records();
        info!(
            path = %task_store_dir.display(),
            max_workers = self.config.tasks.max_workers,
            skipped_kept_key = skipped.reserved,
            skipped_sealed = skipped.sealed,
            "Durable task store opened"
        );
        // The trusted upstream adapter, installed after the store recovered and
        // before the socket serves. It needs the started backend registry, which
        // is why it cannot be a constructor argument to `open`. With no
        // configured names it is not installed at all and every upstream path
        // stays unreachable.
        if !managed_adapters.is_empty() {
            let installed = task_executor.install_recovery(Arc::new(
                crate::gateway::meta_mcp::upstream::NativeUpstreamTasks::new(
                    Arc::clone(&self.backends),
                    &managed_adapters,
                ),
            ));
            info!(
                adapters = ?managed_adapters,
                installed,
                "Upstream task recovery adapter configured"
            );
        }
        // The periodic expiry owner, started only now: the recovery inside
        // `open_runtime_with_admission` has succeeded, so the sweep can never see
        // a row a restart had not yet settled. The guard is held for the server's
        // lifetime and joined below, before the store closes — dropping it on an
        // early return signals the loop to stop without cutting a deletion that
        // is already in flight.
        let expiry_sweep: crate::gateway::task_service::execution::ExpirySweep =
            match task_executor.start_expiry(self.config.tasks.expiry_interval) {
                Ok(sweep) => sweep,
                Err(error) => {
                    let _ = task_service.shutdown().await;
                    return Err(Error::Config(format!(
                        "task expiry sweep at {:?} could not be started: {error}",
                        self.config.tasks.expiry_interval
                    )));
                }
            };
        info!(
            interval = ?self.config.tasks.expiry_interval,
            "Durable task expiry sweep started"
        );
        // Cloned before the state takes them: shutdown drains the SAME executor
        // that served the traffic, not a second one built to stand in for it.
        let task_service_for_shutdown = Arc::clone(&task_service);
        let task_executor_for_shutdown = Arc::clone(&task_executor);

        // The config watcher, started below, announces listing changes as
        // the explicit reload does; `meta_mcp` moves into the state here.
        let capabilities_for_watcher = meta_mcp.get_capabilities();
        let state = Arc::new(AppState {
            session_lifecycle: Some(Arc::clone(&session_lifecycle)),
            // Shared, not minted: the invoke path mints continuations against
            // `meta_mcp`'s keyring, so a second one here would be a keyring
            // that opens nothing this gateway ever sealed.
            continuation: meta_mcp.continuation(),
            env: Some(Arc::clone(&self.env)),
            backends: Arc::clone(&self.backends),
            meta_mcp,
            meta_mcp_enabled: self.config.meta_mcp.enabled,
            multiplexer: Arc::clone(&multiplexer),
            proxy_manager,
            streaming_config: self.config.streaming.clone(),
            auth_config,
            key_server,
            tool_policy,
            mtls_policy,
            sanitize_input: self.config.security.sanitize_input,
            ssrf_protection: self.config.security.ssrf_protection,
            trust_configured_backends: self.config.security.trust_configured_backends,
            inflight: Arc::clone(&inflight),
            agent_auth,
            gateway_key_pair,
            capability_dirs: if self.config.capabilities.enabled {
                self.config.capabilities.directories.clone()
            } else {
                Vec::new()
            },
            config_path: self.config_path.clone(),
            #[cfg(feature = "firewall")]
            firewall: firewall_arc,
            agent_identity_config: self.config.security.agent_identity.clone(),
            control_plane_store,
            control_plane_base: Some(control_plane_base),
            tasks: task_service,
            task_executor,
            subscriptions,
            live_config: Arc::clone(&live_config),
            export_status,
            transparency_log,
            dashboard_bootstrap,
        });

        // REST capability watch polls through the router's controls, so it
        // joins the running events hub once the router state exists.
        if self.config.events.sources.rest_watch
            && let Some(hub) = state.meta_mcp.events()
        {
            hub.install_watch_source(Arc::new(crate::gateway::router::GatewayWatchHost::new(
                &state,
            )));
        }

        // Webhook routes are built BEFORE the router and handed to it, so the
        // origin gate covers them. Merging them onto the finished router would
        // put them outside the layer that refuses cross-site requests.
        let webhook_routes = self.webhook_routes(&webhook_registry, &multiplexer);

        tools_changed::spawn_drain(
            Arc::clone(&state),
            tools_changed_rx,
            shutdown_tx.subscribe(),
        );

        // Captured before the router takes ownership: the startup banner prints
        // the dashboard link and runs after the bind.
        let dashboard_bootstrap = Arc::clone(&state.dashboard_bootstrap);

        let accounts = account_handles_of(self.custody.as_ref());
        let app = create_router_with_accounts(state, webhook_routes, accounts);

        // Refuse BEFORE opening ANY listener, so a configuration that must not
        // serve never opens a port at all. Only this path reaches it; stdio mode
        // has no listener and is untouched.
        //
        // Ahead of the WebSocket spawn as well as the HTTP bind. It used to sit
        // between them, which spawned a listener on the same host for a config
        // the next line refused — a port opened by a start that then failed,
        // contradicting the guarantee this comment makes.
        if let Some(reason) = support::start_refusal(&self.config) {
            error!("{reason}");
            return Err(Error::Config(reason));
        }

        // Warned on EVERY start while the escape hatch is set, and not only when
        // authentication is off. The narrower condition missed the shape the
        // hatch is most often reached from: authentication enabled with `/mcp`
        // public, which is exactly the exposure it is suppressing. An operator
        // reading their logs then saw no sign that the control was disarmed.
        if self.config.server.allow_unauthenticated_network_bind {
            warn!(
                host = %self.config.server.host,
                "server.allow_unauthenticated_network_bind is set: this gateway serves \
                 callers on the network that it has not authenticated. Authentication \
                 is expected to terminate in front of it."
            );
        }
        if let Some(warning) = cleartext::cleartext_http_warning(&self.config) {
            warn!("{warning}");
        }

        // Bound ONCE, here, and handed to whichever path serves it.
        //
        // Two failure modes meet at this line and both have been live. Binding
        // here AND inside `serve_tls` made every mTLS gateway die on "address
        // already in use". Binding only inside the serving branch fixed that
        // and introduced the opposite fault: the startup banner said Listening
        // and the warm-start ran before anything discovered the port was taken.
        //
        // One bind, before the banner, shared by both paths, has neither.
        let listener = TcpListener::bind(addr).await?;
        // A minted dashboard link names the bound port, not a configured 0.
        if let Ok(bound) = listener.local_addr() {
            dashboard_bootstrap.set_bound_port(bound.port());
        }
        #[cfg(test)]
        self.test_seams.report_bound_port(&listener);

        log_startup_banner(
            &self.config,
            &self.backends,
            Some(dashboard_bootstrap.as_ref()),
        );

        // Warm-start backends: connect + prefetch tools into cache. If the
        // warm_start list is empty, warm ALL backends (makes list/search fast).
        // After the bind, so a refused or failed start contacts no backend.
        let _ = warmer.warm(build_warm_start_list(
            &self.backends,
            &self.config.meta_mcp.warm_start,
            true,
        ));

        // After boot warm-start is scheduled, so no reload precedes it
        // (`MIK-8054`). Start the config file watcher now that the router has snapshotted its
        // startup bind-origin from `live_config` (still equal to the config the
        // listener binds). Held for the server's lifetime so hot-reload stays
        // active. MIK-6750 r4: starting it earlier would let a startup-time
        // reload move `live_config` before the snapshot, surfacing a
        // never-bound host/port in the advertised resource.
        let _config_watcher: Option<ConfigWatcher> = self.start_config_watcher(
            &live_config,
            identity_grant_sink,
            capabilities_for_watcher,
            &shutdown_tx,
            &warmer,
        );

        // Start health check task. Shared with `run_stdio` for the same reason
        // the idle reaper is: a setting that works in one serve mode and
        // silently does nothing in the other is a defect wearing a feature's
        // clothes.
        spawn_health_loop(
            Arc::clone(&self.backends),
            &self.config.failsafe.health_check,
            Some(shutdown_tx.subscribe()),
        );

        // Idle reaper. Shared with `run_stdio`: a setting that works in one serve
        // mode and silently does nothing in the other is the same class of defect
        // this feature exists to correct.
        spawn_idle_reaper(Arc::clone(&self.backends), Some(shutdown_tx.subscribe()));

        // Ends on the shutdown broadcast; awaited before the shutdown save.
        #[cfg(feature = "cost-governance")]
        let cost_saver = meta_mcp_for_shutdown
            .budget_enforcer
            .as_ref()
            .map(|enforcer| {
                persistence::spawn_cost_saver(
                    Arc::clone(enforcer),
                    data_dir.clone(),
                    persistence::COST_SAVE_INTERVAL,
                    Some(shutdown_tx.subscribe()),
                )
            });

        // Plain HTTP or mTLS: one path, one shutdown bound (#2147).
        // A test may start the same shutdown without a signal (MIK-8156).
        #[cfg(test)]
        let shutdown = test_seams::shutdown_signal_or_trigger(
            shutdown_tx,
            self.test_seams.take_shutdown_trigger(),
        );
        #[cfg(not(test))]
        let shutdown = support::shutdown_signal(shutdown_tx);
        let std_listener = listener.into_std()?;
        listener::serve(app, std_listener, addr, &self.config, shutdown).await?;

        // Saved under one deadline, off the runtime's threads (MIK-8157).
        #[cfg(feature = "cost-governance")]
        let cost = meta_mcp_for_shutdown
            .budget_enforcer
            .clone()
            .map(|enforcer| (enforcer, data_dir.clone()));
        // It ends on the shutdown broadcast; a write in flight finishes or
        // is abandoned on its own thread.
        #[cfg(feature = "cost-governance")]
        drop(cost_saver);
        #[cfg(not(feature = "cost-governance"))]
        let cost = None;
        let (ranker, tracker) = (ranker_for_shutdown, tracker_for_shutdown);
        let paths = (ranker_path.clone(), transition_path.clone());
        persistence::save_state_on_shutdown(ranker, paths.0, tracker, paths.1, cost).await;

        // Graceful drain: wait for in-flight requests to complete.
        // The semaphore has 10,000 permits; each in-flight request holds one.
        // We try to acquire all 10,000 (meaning all requests finished) with a timeout.
        let drain_timeout = self.config.server.shutdown_timeout;
        info!(timeout = ?drain_timeout, "Draining in-flight requests...");

        let drain_result = tokio::time::timeout(drain_timeout, inflight.acquire_many(10_000)).await;

        match drain_result {
            Ok(Ok(_permits)) => {
                info!("All in-flight requests completed");
            }
            Ok(Err(_)) => {
                warn!("Inflight semaphore closed unexpectedly during drain");
            }
            Err(_) => {
                let available = inflight.available_permits();
                let remaining = 10_000_usize.saturating_sub(available);
                warn!(
                    remaining_requests = remaining,
                    "Drain timeout reached, proceeding with shutdown"
                );
            }
        }

        // Workers drain, and a drain that runs out cancels the rest; then the
        // expiry sweep is joined while the store is still open, and the store
        // closes (`task_runtime::shutdown` documents the order).
        task_runtime::shutdown(
            expiry_sweep,
            &task_executor_for_shutdown,
            &task_service_for_shutdown,
            task_runtime::ShutdownBudget::within(drain_timeout, drain_timeout),
        )
        .await;

        // Release the custody store before the backends go: the drain above is
        // what guarantees no in-flight request is still holding a credential.
        // Not covered by gateway_bootstrap_tests — no test drives `run`.
        if let Err(e) = self.shutdown_account_custody().await {
            warn!(error = %e, "Personal account custody shutdown failed");
        }

        // Stop all backends, after their warmers can no longer start one.
        info!("Shutting down backends...");
        warmer.cancel().await;
        self.backends.stop_all().await;

        Ok(())
    }
}
