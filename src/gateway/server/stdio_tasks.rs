// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio local operator's durable task store (MIK-7272.OWNER.2, design D6
//! rev 5 items 5–7, the sub4 stdio owner design).
//!
//! Stdio opens `<tasks.store_dir>/stdio`, its own directory beside HTTP's, so
//! the two never contend for one lease by default. When that store cannot be
//! opened, stdio serves exactly as before: no `tasks/*`, task-augmented calls
//! answered synchronously, and no Tasks in its handshake or discover answer.

use crate::error::rpc_codes::{INVALID_PARAMS, METHOD_NOT_FOUND};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tracing::{info, warn};

use crate::config::Config;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::task_service::execution::ExpirySweep;
use crate::gateway::task_service::host::StdioTaskHost;
use crate::gateway::task_service::{TaskExecutor, TaskService};
use crate::protocol::tasks::TaskOptions;

/// The directory stdio's store lives in: `tasks.store_dir` resolved as HTTP
/// resolves it, then `stdio` (D6 rev 5 item 7).
pub(super) fn store_dir(config: &Config) -> PathBuf {
    super::expand_home_path(&config.tasks.store_dir).join("stdio")
}

/// An open stdio task runtime. Shared by every dispatch of the session.
pub(super) struct StdioTasks {
    pub(super) service: Arc<TaskService>,
    pub(super) executor: Arc<TaskExecutor>,
    pub(super) host: Arc<StdioTaskHost>,
    pub(super) options: TaskOptions,
}

impl StdioTasks {
    /// A guard the session frame holds for as long as it serves
    /// (MIK-7839.CANCEL.3). The async teardown never runs for a session
    /// future an embedder drops before EOF; this guard's `Drop` is what still
    /// stops the task workers there. On a normal return it repeats what the
    /// teardown already did.
    pub(super) fn stop_on_drop(&self) -> TasksDropGuard {
        TasksDropGuard::new(&self.executor, &self.service)
    }
}

/// See [`StdioTasks::stop_on_drop`]. Unbound, it would seal the session at once.
#[must_use = "the guard stops the task workers when dropped; bind it for the whole session"]
pub(super) struct TasksDropGuard {
    executor: Arc<TaskExecutor>,
    service: Arc<TaskService>,
}

impl TasksDropGuard {
    pub(super) fn new(executor: &Arc<TaskExecutor>, service: &Arc<TaskService>) -> Self {
        Self {
            executor: Arc::clone(executor),
            service: Arc::clone(service),
        }
    }
}

impl Drop for TasksDropGuard {
    /// Synchronous, and needs no driven runtime: seal the executor, so every
    /// worker ends at its next poll and none starts, then admit no further
    /// store mutation. A write already admitted finishes; nothing waits on it
    /// here, so a stalled disk cannot hold the drop.
    fn drop(&mut self) {
        self.executor.seal();
        self.service.stop_serving();
    }
}

/// Open stdio's store, or `None` when it cannot be opened (logged with the
/// path and the cause). The expiry sweep is returned separately: it is joined
/// at EOF, before the store closes.
pub(super) async fn open(
    config: &Config,
    meta_mcp: &Arc<MetaMcp>,
    live_config: &Arc<crate::config_reload::LiveConfig>,
) -> Option<(Arc<StdioTasks>, ExpirySweep)> {
    let dir = store_dir(config);
    let subscriptions = subscriptions(live_config);
    // No upstream adapter on stdio: every interrupted row it holds is settled
    // on open, and none is kept for an upstream read (D6 rev 5 item 4).
    let opened = super::task_runtime::open(config, &dir, subscriptions, meta_mcp, &[]).await;
    let (service, executor) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            degraded(&dir, &error.to_string());
            return None;
        }
    };
    let expiry = match executor.start_expiry(config.tasks.expiry_interval) {
        Ok(expiry) => expiry,
        Err(error) => {
            let _ = service.shutdown().await;
            degraded(&dir, &error.to_string());
            return None;
        }
    };
    info!(path = %dir.display(), "stdio: durable task store opened");
    let tasks = StdioTasks {
        service,
        executor,
        host: Arc::new(StdioTaskHost {
            meta_mcp: Arc::clone(meta_mcp),
            nonce: super::StdioNonce::process(),
            live_config: Arc::clone(live_config),
        }),
        options: TaskOptions {
            ttl_ms: (config.tasks.default_ttl_ms > 0).then_some(config.tasks.default_ttl_ms),
            poll_interval_ms: (config.tasks.poll_interval_ms > 0)
                .then_some(config.tasks.poll_interval_ms),
        },
    };
    Some((Arc::new(tasks), expiry))
}

/// The executor publishes task notifications to a registry. Stdio has no
/// listener route, so nothing subscribes: the registry admits none, and its
/// authorizer judges with `live_config`'s generations, whose auth is
/// [`default_auth`]: no secret to resolve. The gateway's own auth
/// configuration is never read here, so one that does not resolve cannot turn
/// stdio's tasks off (MIK-7638). Publishing never consults the authorizer;
/// only a delivery would.
fn subscriptions(
    live_config: &Arc<crate::config_reload::LiveConfig>,
) -> Arc<crate::gateway::subscription_registry::SubscriptionRegistry> {
    use crate::gateway::auth::{AuthState, DashboardBootstrap};
    Arc::new(
        crate::gateway::subscription_registry::SubscriptionRegistry::new(
            0,
            AuthState {
                key_server: None,
                dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
                tls_enabled: false,
                // The session's own config, so a reload reaches what this
                // registry re-validates listeners with (ADR-023).
                live_config: Arc::clone(live_config),
                // stdio has no agent middleware: nothing presents an agent token.
                agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
            },
        ),
    )
}

/// stdio's auth: the default configuration, which holds no secret to
/// resolve, under the process's record key. Its generations judge every
/// stdio listener; the gateway's own `auth` is never resolved here.
pub(super) fn default_auth(
    overlay: &crate::config::EnvOverlay,
    record_key: Arc<crate::gateway::record_principal::RecordPrincipalKey>,
) -> crate::gateway::auth::ResolvedAuthConfig {
    // invariant: the default auth config names no secret reference to resolve.
    crate::gateway::auth::ResolvedAuthConfig::try_from_config_keyed(
        &crate::config::AuthConfig::default(),
        overlay,
        record_key,
    )
    .expect("the default auth configuration holds no secret to resolve")
}

fn degraded(dir: &Path, cause: &str) {
    warn!(
        path = %dir.display(),
        cause,
        "stdio: task store unavailable; serving without tasks, and Tasks is not advertised"
    );
}

/// HTTP's own task shutdown, through the shared helper: join the expiry
/// sweep, drain the executor, close the store and release its lease.
pub(super) async fn shutdown(
    tasks: &StdioTasks,
    expiry: ExpirySweep,
    budget: super::task_runtime::ShutdownBudget,
) {
    super::task_runtime::shutdown(expiry, &tasks.executor, &tasks.service, budget).await;
}

/// Remove the Tasks extension from an `initialize` or `server/discover`
/// answer, for a session that serves no `tasks/*`.
pub(super) fn strip_tasks_extension(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove(crate::protocol::extensions::Extension::Tasks.id());
            map.values_mut().for_each(strip_tasks_extension);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_tasks_extension),
        _ => {}
    }
}

/// HTTP's refusal for a request that reaches the Tasks extension without
/// declaring it on that request (`router/handlers.rs`), with the same code,
/// text and data, so the two transports answer alike.
pub(super) fn undeclared(
    id: crate::protocol::RequestId,
    method: &str,
    shape: &crate::protocol::meta::RequestShape,
) -> Option<crate::protocol::JsonRpcResponse> {
    use crate::protocol::extensions::Extension;
    if shape.declared_extensions().contains(Extension::Tasks) {
        return None;
    }
    let tasks = Extension::Tasks.id();
    Some(crate::protocol::JsonRpcResponse::error_with_data(
        Some(id),
        crate::protocol::era::MISSING_REQUIRED_CLIENT_CAPABILITY,
        format!("'{method}' requires the '{tasks}' extension to be declared"),
        serde_json::json!({ "requiredCapabilities": { "extensions": { tasks: {} } } }),
    ))
}

/// What one stdio `tools/call` asks of the task surface.
pub(super) struct IntentRequest<'a> {
    pub(super) id: crate::protocol::RequestId,
    pub(super) tool_name: &'a str,
    pub(super) arguments: &'a Value,
    pub(super) is_modern: bool,
    pub(super) retry: &'a crate::protocol::mrtr::RetryFields,
    pub(super) input_capabilities: crate::protocol::meta::Declared,
    pub(super) session_id: &'a str,
    pub(super) protocol_revision: Option<&'a str>,
    /// What this caller may invoke (MIK-8340).
    pub(super) scope: crate::gateway::meta_mcp::InvokeScope<'a>,
}

impl StdioTasks {
    /// The task intent for a call carrying a `task` member: HTTP's rules
    /// (`task_intent_for_call`) without HTTP's auth gate, owned by the local
    /// operator (D6 rev 5 item 5). `Ok(None)` is the ordinary synchronous path.
    pub(super) fn intent(
        &self,
        req: &IntentRequest<'_>,
    ) -> Result<
        Option<crate::gateway::task_service::TaskIntent>,
        Box<crate::protocol::JsonRpcResponse>,
    > {
        if !req.is_modern
            || req.retry.request_state.is_some()
            || req.retry.input_responses.is_some()
            || !crate::gateway::task_route::is_task_dispatchable(
                &self.host.meta_mcp,
                req.tool_name,
                (req.scope, Some(req.session_id)),
            )
        {
            return Ok(None);
        }
        let Some(key) = req.retry.idempotency_key.as_deref() else {
            return Err(Box::new(crate::protocol::JsonRpcResponse::error(
                Some(req.id.clone()),
                INVALID_PARAMS,
                "task creation requires an idempotency key",
            )));
        };
        let owner = crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL;
        Ok(Some(crate::gateway::task_service::TaskIntent {
            executor: Arc::clone(&self.executor),
            owned: self.owned(
                req.input_capabilities,
                req.session_id,
                req.protocol_revision,
                req.retry.attestation.clone(),
            ),
            request: crate::gateway::meta_mcp::task_admission_request(
                owner.to_owned(),
                key.to_owned(),
                req.tool_name,
                req.arguments,
            ),
            options: self.options,
        }))
    }

    /// The worker's caller for a stdio task: the stdio session's own context,
    /// hosted by this store so the transport mark survives the rebuild.
    fn owned(
        &self,
        input_capabilities: crate::protocol::meta::Declared,
        session_id: &str,
        protocol_revision: Option<&str>,
        attestation: Option<String>,
    ) -> crate::gateway::task_service::OwnedCallerContext {
        crate::gateway::task_service::OwnedCallerContext::new(
            crate::gateway::task_service::host::TaskHost::Stdio(Arc::downgrade(&self.host)),
            crate::gateway::router::OwnedRouterAuthorizer::capture(None, None, None),
            None,
            None,
            None,
            None,
            None,
            super::STDIO_CREDENTIAL_PRINCIPAL.to_owned(),
            crate::gateway::record_principal::InternalPrincipal::new(
                super::STDIO_CREDENTIAL_PRINCIPAL.to_owned(),
            )
            .record_form(self.host.meta_mcp.record_key()),
            crate::gateway::meta_mcp::Authentication::Authenticated,
            crate::security::audit::CredentialKind::LocalTransport,
            // As every stdio call: the client spawned this process.
            true,
            input_capabilities,
            Some(session_id.to_owned()),
            protocol_revision.map(str::to_owned),
            attestation,
        )
    }

    /// `tasks/get`, `tasks/update` and `tasks/cancel` for the local operator.
    /// The delivery check runs under the stdio authorizer; no upstream read
    /// exists on stdio (D6 rev 5 item 4).
    pub(super) async fn dispatch(
        &self,
        method: &str,
        id: crate::protocol::RequestId,
        params: Option<&Value>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: &str,
    ) -> crate::protocol::JsonRpcResponse {
        use crate::gateway::task_route::{TaskOwnerText, TaskRoute};
        let owner = TaskOwnerText::LocalOperator;
        let route = TaskRoute {
            service: &self.service,
            executor: &self.executor,
            owner: &owner,
        };
        match method {
            // Boxed, as the `tools/call` dispatch is: only a `tasks/get`
            // request pays for this arm's future state (MIK-8392).
            "tasks/get" => {
                // A task read serves a stored answer: not this request's.
                crate::gateway::delivery_facts::unvouched();
                Box::pin(self.dispatch_get(id, params, caller, session_id)).await
            }
            "tasks/update" => {
                // THIS update request's caller resumes the round; a resumed
                // result is never response-cached, so no revision is carried.
                let attestation = caller.retry.attestation.clone();
                route
                    .update(id, params, |_| {
                        self.owned(caller.input_capabilities, session_id, None, attestation)
                    })
                    .await
            }
            "tasks/cancel" => route.cancel(id, params).await,
            // Fail closed: a method this body does not name is never handled
            // as one of the three it does.
            other => crate::protocol::JsonRpcResponse::error(
                Some(id),
                METHOD_NOT_FOUND,
                format!("Method not found: {other}"),
            ),
        }
    }

    /// `tasks/get` for the local operator. Its own future, boxed at the call
    /// site, so the shared [`Self::dispatch`] state stays small; the
    /// visibility memo still covers both the pre-pass and the delivery check.
    async fn dispatch_get(
        &self,
        id: crate::protocol::RequestId,
        params: Option<&Value>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: &str,
    ) -> crate::protocol::JsonRpcResponse {
        use crate::gateway::task_route::{TaskOwnerText, TaskRoute};
        let owner = TaskOwnerText::LocalOperator;
        let route = TaskRoute {
            service: &self.service,
            executor: &self.executor,
            owner: &owner,
        };
        crate::gateway::meta_mcp::visible::memo::with_visibility_memo(async {
            // MIK-8392: fill the account outcomes of the named task's
            // recorded targets before the delivery check reads them. Runs
            // under the request's live policy caller, so a cold claim
            // already refused is skipped before it resolves (F4).
            if let (Some(owner_text), Some(task_id)) = (
                owner.text(),
                crate::gateway::task_route::task_id_param(params),
            ) && let Ok(stored) = self.service.get(owner_text, task_id)
            {
                self.host
                    .meta_mcp
                    .prepare_stored_read(&stored, caller.scope(), Some(session_id))
                    .await;
            }
            route
                .get(
                    id.clone(),
                    params,
                    |_| std::future::ready(()),
                    |current| {
                        self.host
                            .meta_mcp
                            .refuse_stored_delivery(
                                &id,
                                current,
                                crate::gateway::meta_mcp::upstream::recovery_attestation(params),
                                Some(session_id),
                                caller,
                            )
                            .map(crate::gateway::meta_mcp::StoredAnswer::deliver)
                    },
                    |current, frame| {
                        self.host.meta_mcp.scan_task_read(
                            current,
                            caller.authorizer.generation(),
                            frame,
                        );
                    },
                )
                .await
        })
        .await
    }
}

/// The answer to `initialize` or `server/discover`, without Tasks when this
/// session serves no `tasks/*` (D6 rev 5 item 6): the advertisement matches the
/// surface in both outcomes.
pub(super) fn advertised(
    tasks: Option<&StdioTasks>,
    mut response: crate::protocol::JsonRpcResponse,
) -> crate::protocol::JsonRpcResponse {
    if tasks.is_none()
        && let Some(result) = response.result.as_mut()
    {
        strip_tasks_extension(result);
    }
    response
}

/// A `tasks/*` method on stdio, refused as HTTP refuses it when the request is
/// not modern or does not declare the extension.
pub(super) async fn serve(
    tasks: Option<&StdioTasks>,
    method: &str,
    id: crate::protocol::RequestId,
    params: Option<&Value>,
    shape: &crate::protocol::meta::RequestShape,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    session_id: &str,
) -> crate::protocol::JsonRpcResponse {
    let Some(tasks) = tasks else {
        return crate::protocol::JsonRpcResponse::error(
            Some(id),
            METHOD_NOT_FOUND,
            format!("Method not found: {method}"),
        );
    };
    if !matches!(shape, crate::protocol::meta::RequestShape::Modern(_)) {
        return crate::protocol::JsonRpcResponse::error(
            Some(id),
            METHOD_NOT_FOUND,
            format!("method '{method}' requires MCP 2026-07-28"),
        );
    }
    if let Some(refusal) = undeclared(id.clone(), method, shape) {
        return refusal;
    }
    tasks.dispatch(method, id, params, caller, session_id).await
}

/// The intent for a stdio `tools/call` carrying a `task` member, or HTTP's
/// refusal for a request that did not declare the extension.
pub(super) fn task_intent(
    tasks: &StdioTasks,
    id: &crate::protocol::RequestId,
    tool_name: &str,
    arguments: &Value,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    shape: &crate::protocol::meta::RequestShape,
    session_id: &str,
) -> Result<Option<crate::gateway::task_service::TaskIntent>, Box<crate::protocol::JsonRpcResponse>>
{
    // A legacy shape cannot declare an extension, and a legacy `task` member
    // was always answered synchronously on stdio: it stays so, unrefused.
    if !caller.is_modern {
        return Ok(None);
    }
    if let Some(refusal) = undeclared(id.clone(), "tools/call", shape) {
        return Err(Box::new(refusal));
    }
    tasks.intent(&IntentRequest {
        id: id.clone(),
        tool_name,
        arguments,
        is_modern: caller.is_modern,
        retry: caller.retry,
        input_capabilities: caller.input_capabilities,
        session_id,
        protocol_revision: caller.protocol_revision,
        scope: caller.scope(),
    })
}
