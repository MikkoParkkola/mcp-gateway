// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix's hooks into the shared fixture (design
//! `2026-10-08-one-egress-scan.md`): a planted transport in place of the
//! scripted counting transport, a Warn rule, an audit log, an
//! inspection-only gateway, and the backend-error answers (MIK-8139).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::answers::{call_answer, listing, question, recording_answer};
#[cfg(feature = "firewall")]
use super::{AUDIT_LOG, FIREWALL_RULE, META_FIREWALL};
use super::{Answer, TRANSPORT};
#[cfg(feature = "firewall")]
use super::{Fx, fixture_inner};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

#[cfg(feature = "firewall")]
thread_local! {
    static FIREWALL_RULE_KEYS: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// The rule for each backend tool, scoped to the cell's API keys.
/// `send_message` is the A2A backend's one tool.
#[cfg(feature = "firewall")]
pub(super) fn firewall_rules(
    action: crate::security::firewall::FirewallAction,
) -> Vec<crate::security::firewall::FirewallRule> {
    ["read", "send_message"]
        .map(|tool| crate::security::firewall::FirewallRule {
            tool_match: tool.to_string(),
            action,
            reason: None,
            scan: Vec::new(),
            servers: None,
            keys: FIREWALL_RULE_KEYS.with(|k| k.borrow().clone()),
            except: None,
        })
        .to_vec()
}

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

/// [`super::fixture_firewalled_with`] whose `read` rule applies only to the
/// API keys named in `keys`, by their configured names.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_keyed(
    action: crate::security::firewall::FirewallAction,
    keys: &[&str],
) -> Fx {
    let named = keys.iter().map(|k| (*k).to_owned()).collect();
    FIREWALL_RULE.with(|r| r.set(Some(action)));
    FIREWALL_RULE_KEYS.with(|k| *k.borrow_mut() = Some(named));
    let fx = fixture_inner(Answer::Ok, true, |meta| meta).await;
    FIREWALL_RULE.with(|r| r.set(None));
    FIREWALL_RULE_KEYS.with(|k| *k.borrow_mut() = None);
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

/// [`fixture_audited_on`] with the replaced `MetaMcp` armed by `build` (the
/// MIK-8340 withheld/absent twins: surfacing and caller vary, nothing else).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_audited_built_on(
    transport: Arc<dyn Transport>,
    audit: std::path::PathBuf,
    build: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    AUDIT_LOG.with(|a| *a.borrow_mut() = Some(audit));
    let fx = fixture_inner(Answer::Ok, true, build).await;
    AUDIT_LOG.with(|a| *a.borrow_mut() = None);
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// [`super::fixture_hardened_signed_built`] with `transport` answering for both
/// backends (the MIK-8340 twin's signed variant).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_hardened_signed_built_on(
    transport: Arc<dyn Transport>,
    require_nonce: bool,
    build: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = super::fixture_hardened_signed_built(Answer::Ok, require_nonce, build).await;
    TRANSPORT.with(|t| *t.borrow_mut() = None);
    fx
}

/// `transport` behind no firewall, with response inspection in its default
/// observe mode: findings are written onto the answer, nothing is withheld.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_observing_on(transport: Arc<dyn Transport>) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = fixture_inner(Answer::Ok, false, |meta| meta).await;
    TRANSPORT.with(|t| *t.borrow_mut() = None);
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

/// `transport` behind no firewall, with response inspection turned off
/// (`enabled: false`): nothing screens what it answers.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_inspection_off_on(transport: Arc<dyn Transport>) -> Fx {
    TRANSPORT.with(|t| *t.borrow_mut() = Some(transport));
    let fx = fixture_inner(Answer::Ok, false, |mut meta| {
        meta.disable_response_inspection();
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

/// One `Transport` shared by `alpha` and `alpha-pt`, scripted with `Answer`
/// and counting every `tools/call`. `tools/list` names the one tool the rows
/// call, `read`, so the direct route's listing check (F13) admits it; a
/// listing never counts as a call.
pub(super) struct CountingBackend {
    pub(super) calls: Arc<AtomicUsize>,
    /// The params of every `tools/call`, in order (MIK-8078).
    pub(super) seen: Arc<std::sync::Mutex<Vec<Value>>>,
    pub(super) answer: Answer,
    /// What `Answer::AskThenStore` keeps between calls.
    pub(super) kept: Arc<std::sync::Mutex<String>>,
}

#[async_trait::async_trait]
impl Transport for CountingBackend {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                id,
                listing(self.answer, params.as_ref()),
            ));
        }
        self.seen
            .lock()
            .unwrap()
            .push(params.clone().unwrap_or(Value::Null));
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(body) = recording_answer(self.answer, n, params.as_ref(), &self.kept) {
            return Ok(JsonRpcResponse::success(id, body));
        }
        if let Answer::StateOnlyRounds(at, text) = self.answer {
            let round = |text: &str| {
                json!({"resultType": "input_required", "requestState": format!("state-{n}"),
                       "content": [{"type": "text", "text": text}]})
            };
            return Ok(JsonRpcResponse::success(
                id,
                match n.cmp(&at) {
                    std::cmp::Ordering::Less => round("nothing to see"),
                    std::cmp::Ordering::Equal => round(text),
                    std::cmp::Ordering::Greater => {
                        json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
                    }
                },
            ));
        }
        if matches!(
            self.answer,
            Answer::AskOnce
                | Answer::AskNoState
                | Answer::AskMalformed
                | Answer::AskBig
                | Answer::AskWith(_)
                | Answer::AskBadMeta
                | Answer::AskAndError
                | Answer::AskSecond
                | Answer::AskEdited(_)
                | Answer::AskAlways
        ) {
            let asks_now = if matches!(self.answer, Answer::AskAlways) {
                params
                    .as_ref()
                    .and_then(|p| p.get("requestState"))
                    .is_none()
            } else {
                n == usize::from(matches!(self.answer, Answer::AskSecond))
            };
            return Ok(if asks_now {
                let mut asked = JsonRpcResponse::success(id, question(self.answer));
                if matches!(self.answer, Answer::AskAndError) {
                    asked.error = Some(crate::protocol::JsonRpcError {
                        code: -32000,
                        message: "backend failed".to_string(),
                        data: None,
                    });
                }
                asked
            } else {
                JsonRpcResponse::success(
                    id,
                    json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                )
            });
        }
        call_answer(self.answer, id)
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
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

/// [`super::fixture_hardened_signed`] with the production firewall too
/// (MIK-8351: a signed direct retry the chokepoint refuses).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_hardened_signed_firewalled(answer: Answer) -> Fx {
    super::HARDENED.with(|h| h.set(true));
    let fx = fixture_inner(answer, true, |meta| super::signing(meta, true)).await;
    super::HARDENED.with(|h| h.set(false));
    fx
}
