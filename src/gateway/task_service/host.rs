// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who a durable task runs for: the HTTP router's state, or the stdio
//! gateway's (MIK-7272.OWNER.2, design D6 rev 5 items 1–2,
//! the sub4 stdio owner design).
//!
//! The worker needs only the `MetaMcp` and an authorizer. Each transport keeps
//! its own: HTTP's `RouterAuthorizer`, and stdio's `ToolPolicyAuthorizer`, so
//! no HTTP rule (mTLS, agent auth, the `Http` audit label) reaches a stdio task.

use std::sync::{Arc, Weak};

use crate::gateway::StdioNonce;
use crate::gateway::auth::QuotaPrincipal;
use crate::gateway::authz::{
    Decision, ToolAuthorizer, ToolPolicyAuthorizer, ToolTarget, Transport,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visible::memo::Judged;
use crate::gateway::router::{AppState, OwnedRouterAuthorizer, RouterAuthorizer};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::ToolPolicy;

/// What a stdio gateway lends its tasks. `run_stdio_on` holds the only strong
/// reference, so a worker that outlives the session fails its upgrade and
/// settles before dispatch, as an HTTP worker does after shutdown.
pub(crate) struct StdioTaskHost {
    pub(crate) meta_mcp: Arc<MetaMcp>,
    pub(crate) tool_policy: Arc<ToolPolicy>,
    /// The transport mark. Only `gateway::server` can mint one, so only a
    /// stdio-built host carries it.
    pub(crate) nonce: &'static StdioNonce,
    /// The config stdio serves and reloads, shared with its reload context: a
    /// dispatch or resume takes the generation current when it runs.
    pub(crate) live_config: Arc<crate::config_reload::LiveConfig>,
}

pub(crate) enum TaskHost {
    Http(Weak<AppState>),
    Stdio(Weak<StdioTaskHost>),
}

impl TaskHost {
    pub(crate) fn upgrade(&self) -> Option<LiveHost> {
        match self {
            Self::Http(state) => state.upgrade().map(LiveHost::Http),
            Self::Stdio(host) => host.upgrade().map(LiveHost::Stdio),
        }
    }
}

/// A host for the length of one dispatch.
pub(crate) enum LiveHost {
    Http(Arc<AppState>),
    Stdio(Arc<StdioTaskHost>),
}

impl LiveHost {
    /// The generation current now. Queued work is judged by the one current
    /// when it dispatches or resumes, not the one it was admitted under
    /// (ADR-023); take it once per step.
    pub(crate) fn generation(&self) -> Arc<crate::config_reload::Generation> {
        match self {
            Self::Http(state) => state.live_config.generation(),
            Self::Stdio(host) => host.live_config.generation(),
        }
    }

    /// Run `run` as the caller `authorizer` captured, so a lookup it makes
    /// misses a backend hidden from that caller (`meta_mcp::hiding`), judged
    /// live. A stdio host carries no certificate or agent token: nothing is
    /// hidden there.
    pub(crate) async fn as_caller<F: Future>(
        &self,
        owned: &super::execution::OwnedCallerContext,
        run: F,
    ) -> F::Output {
        match self {
            Self::Http(state) => {
                let caller = crate::gateway::router::caller_hiding::RouterHiding::caller(
                    Arc::clone(state),
                    owned.authorizer().clone(),
                    owned.session_id().map(str::to_owned),
                );
                crate::gateway::meta_mcp::hiding::with_caller(caller, run).await
            }
            Self::Stdio(_) => run.await,
        }
    }

    pub(crate) fn meta_mcp(&self) -> &Arc<MetaMcp> {
        match self {
            Self::Http(state) => &state.meta_mcp,
            Self::Stdio(host) => &host.meta_mcp,
        }
    }

    /// Re-admit a resumed task's stored call (MIK-8154 B): a resume is an
    /// admission point, so it gets intake's rule against the current config.
    /// The exemption is judged again on the caller's view; still exempt, the
    /// call is sent as stored under the instances judged now; otherwise its
    /// arguments are sanitized first (a NUL refuses the resume). Returns the
    /// arguments to send and the judgement to send them under. `generation`
    /// is the one this resume step took, the same one its authorizer judges
    /// by, so one step never mixes two (ADR-023).
    pub(crate) async fn readmit(
        &self,
        call: &super::execution::TaskCall,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        (session_id, generation): (Option<&str>, &crate::config_reload::Generation),
    ) -> Result<(serde_json::Value, Judged), Box<JsonRpcResponse>> {
        if !generation.sanitize_input() {
            return Ok((call.arguments.clone(), Judged::default()));
        }
        let request = serde_json::json!({"jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": call.tool, "arguments": call.arguments}});
        // A refusal here is the gateway's, raised into the worker's dispatch
        // cell so the settlement ties it to the task (no-op outside a cell).
        let refused = |e: crate::Error| {
            let e = crate::gateway::delivery_facts::refused(e);
            Box::new(JsonRpcResponse::error(
                Some(RequestId::Number(0)),
                e.to_rpc_code(),
                e.to_string(),
            ))
        };
        // Intake's full rule, in intake's order (MIK-8378): the keys the
        // gateway reads are validated whenever sanitizing is on, an exempt
        // call included, so a dirty one stored by a process with sanitizing
        // off is refused here, never stripped or sent as stored. The
        // exemption below spares only the values.
        let route = crate::security::sanitize::ProtocolRoute::Meta;
        crate::security::sanitize::validate_protocol_fields(&request, &[], route)
            .map_err(refused)?;
        let view =
            crate::gateway::meta_mcp::visible::TargetView::Caller(caller.scope(), session_id);
        // A memo for the judgement alone: the round's dispatch judges live.
        crate::gateway::meta_mcp::visible::memo::with_visibility_memo(async move {
            if crate::gateway::router::sanitize_exempt(self.meta_mcp(), &request, view) {
                return Ok((
                    call.arguments.clone(),
                    crate::gateway::meta_mcp::visible::memo::judged(),
                ));
            }
            // In place, then the arguments taken out, not copied (MIK-8499).
            let mut request = request;
            crate::security::sanitize::sanitize_request_in_place(&mut request, route)
                .map_err(refused)?;
            let arguments = request
                .pointer_mut("/params/arguments")
                .map_or(serde_json::Value::Null, serde_json::Value::take);
            // What `sanitize_exempt` recorded while judging, as the exempt
            // branch returns: a playbook's digest is recorded whether or not
            // the call is exempt, and the run compares against it.
            Ok((arguments, crate::gateway::meta_mcp::visible::memo::judged()))
        })
        .await
    }

    /// The mark a rebuilt context carries: `Some` only for a stdio host.
    pub(crate) fn stdio_nonce(&self) -> Option<&'static StdioNonce> {
        match self {
            Self::Http(_) => None,
            Self::Stdio(host) => Some(host.nonce),
        }
    }

    /// The transport's own authorizer. `router` is the creating request's
    /// captured HTTP identity, which a stdio host ignores.
    pub(crate) fn authorizer<'a>(
        &'a self,
        router: &'a OwnedRouterAuthorizer,
        generation: &'a crate::config_reload::Generation,
    ) -> HostAuthorizer<'a> {
        match self {
            Self::Http(state) => HostAuthorizer::Http(router.borrow(state, generation)),
            Self::Stdio(host) => HostAuthorizer::Stdio(ToolPolicyAuthorizer {
                tool_policy: &host.tool_policy,
            }),
        }
    }
}

pub(crate) enum HostAuthorizer<'a> {
    Http(RouterAuthorizer<'a>),
    Stdio(ToolPolicyAuthorizer<'a>),
}

impl ToolAuthorizer for HostAuthorizer<'_> {
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        match self {
            Self::Http(inner) => inner.decide(target),
            Self::Stdio(inner) => inner.decide(target),
        }
    }

    fn admits_backend(&self, server: &str) -> bool {
        match self {
            Self::Http(inner) => inner.admits_backend(server),
            Self::Stdio(inner) => inner.admits_backend(server),
        }
    }

    fn transport(&self) -> Transport {
        match self {
            Self::Http(inner) => inner.transport(),
            Self::Stdio(inner) => inner.transport(),
        }
    }

    fn caller_name(&self) -> Option<&str> {
        match self {
            Self::Http(inner) => inner.caller_name(),
            Self::Stdio(inner) => inner.caller_name(),
        }
    }

    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        match self {
            Self::Http(inner) => inner.quota_principal(),
            Self::Stdio(inner) => inner.quota_principal(),
        }
    }
    fn backend_grant(&self) -> crate::gateway::authz::BackendGrant<'_> {
        match self {
            Self::Http(inner) => inner.backend_grant(),
            Self::Stdio(inner) => inner.backend_grant(),
        }
    }
}
