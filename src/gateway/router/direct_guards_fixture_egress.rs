// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix's hooks into the shared fixture (design
//! `2026-10-08-one-egress-scan.md`): a planted transport in place of the
//! scripted backend, a Warn rule, an audit log, an inspection-only gateway,
//! and the backend-error answers the error-scan rows use (MIK-8139).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde_json::{Value, json};

#[cfg(feature = "firewall")]
use super::{AUDIT_LOG, FIREWALL_RULE, META_FIREWALL};
use super::{Answer, CountingBackend, TRANSPORT};
#[cfg(feature = "firewall")]
use super::{Fx, fixture_inner};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// [`super::fixture_firewalled_with`] with `transport` answering for both backends
/// in place of the scripted one (the egress matrix's planted backend).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_on(
    transport: Arc<dyn Transport>,
    rule: Option<crate::security::firewall::FirewallAction>,
) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    FIREWALL_RULE.with(|r| r.set(rule));
    let fx = fixture_inner(Answer::Ok, true, |meta| meta).await;
    FIREWALL_RULE.with(|r| r.set(None));
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// [`fixture_firewalled_on`] with both firewalls writing their verdicts to
/// the audit log at `audit`.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_audited_on(
    transport: Arc<dyn Transport>,
    audit: std::path::PathBuf,
) -> Fx {
    AUDIT_LOG.with(|a| *a.borrow_mut() = Some(audit));
    let fx = fixture_firewalled_on(transport, None).await;
    AUDIT_LOG.with(|a| *a.borrow_mut() = None);
    fx
}

/// `transport` behind no firewall, with response inspection in action mode:
/// only the content inspection can withhold what it answers.
// Its only consumer is the egress matrix, which is `firewall`-gated.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_inspecting_on(transport: Arc<dyn Transport>) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = fixture_inner(Answer::Ok, false, |mut meta| {
        meta.enable_response_inspection_action_mode();
        meta
    })
    .await;
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// The firewall the last firewalled fixture on this thread gave its Meta-MCP
/// (the router holds its own, on `state.firewall`).
#[cfg(feature = "firewall")]
pub(crate) fn meta_firewall() -> Option<Arc<crate::security::firewall::Firewall>> {
    META_FIREWALL.with(|f| f.borrow().clone())
}

/// The MIK-8139 error answers: a backend error carrying `text`, answered or
/// as a failed dispatch.
pub(super) fn error_answer(answer: Answer, id: RequestId) -> crate::Result<JsonRpcResponse> {
    match answer {
        Answer::RpcErrorText(text) => Ok(JsonRpcResponse::error(Some(id), -32001, text)),
        Answer::RpcErrorData(text) => Ok(JsonRpcResponse::error_with_data(
            Some(id),
            -32001,
            "backend says no",
            json!({"detail": text}),
        )),
        Answer::FailedWith(text) => Err(crate::Error::json_rpc(-32001, text)),
        Answer::ForgedAccount(text) => Err(crate::Error::JsonRpc {
            code: -32603,
            message: text.to_owned(),
            data: Some(json!({
                "schema_version": "accounts.v1",
                "account_id": "acct-1",
                "error": {"code": "reconnect_required"},
            })),
        }),
        _ => unreachable!("not an error answer"),
    }
}

/// The transport both fixture backends answer with: a planted one when a
/// cell set it, the scripted one otherwise.
pub(super) fn backend_transport(
    (calls, seen): (&Arc<AtomicUsize>, &Arc<std::sync::Mutex<Vec<Value>>>),
    answer: Answer,
) -> Arc<dyn Transport> {
    TRANSPORT.with(|t| t.borrow().clone()).unwrap_or_else(|| {
        Arc::new(CountingBackend {
            calls: Arc::clone(calls),
            seen: Arc::clone(seen),
            answer,
            kept: Arc::default(),
        })
    })
}
