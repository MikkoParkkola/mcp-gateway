// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who a durable task runs for: the HTTP router's state, or the stdio
//! gateway's (MIK-7272.OWNER.2, design D6 rev 5 items 1–2,
//! `docs/design/2026-09-30-sub4-stdio-owner.md`).
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
use crate::gateway::meta_mcp::visible::Judged;
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
    /// `security.sanitize_input` at stdio start: a resume re-admits under it.
    pub(crate) sanitize: crate::security::sanitize::InputSanitizing,
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
    /// arguments to send and the judgement to send them under.
    pub(crate) async fn readmit(
        &self,
        call: &super::execution::TaskCall,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) -> Result<(serde_json::Value, Judged), Box<JsonRpcResponse>> {
        let sanitize = match self {
            Self::Http(state) => state.sanitize_input,
            Self::Stdio(host) => host.sanitize == crate::security::sanitize::InputSanitizing::On,
        };
        if !sanitize {
            return Ok((call.arguments.clone(), Judged::default()));
        }
        let request = serde_json::json!({"jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": call.tool, "arguments": call.arguments}});
        let view =
            crate::gateway::meta_mcp::visible::TargetView::Caller(caller.scope(), session_id);
        // A memo for the judgement alone: the round's dispatch judges live.
        crate::gateway::meta_mcp::visible::with_visibility_memo(async {
            if crate::gateway::router::sanitize_exempt(self.meta_mcp(), &request, view) {
                return Ok((
                    call.arguments.clone(),
                    crate::gateway::meta_mcp::visible::judged(),
                ));
            }
            crate::security::sanitize::sanitize_request(&request)
                .map(|clean| (clean["params"]["arguments"].clone(), Judged::default()))
                .map_err(|e| {
                    Box::new(JsonRpcResponse::error(
                        Some(RequestId::Number(0)),
                        -32600,
                        e.to_string(),
                    ))
                })
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
    ) -> HostAuthorizer<'a> {
        match self {
            Self::Http(state) => HostAuthorizer::Http(router.borrow(state)),
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
}
