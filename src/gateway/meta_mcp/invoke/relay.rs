// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection (COLLUDE.1, OWASP ASI10) on the meta route, design
//! `2026-09-28-asi10-verbatim-relay.md` §13.3: the egress check on what a
//! backend receives, and the per-call receipts committed at delivery.

use std::cell::RefCell;

use serde_json::Value;

use super::OutboundRetry;
use crate::gateway::meta_mcp::prompt_cache::build_outbound_meta;
use crate::gateway::meta_mcp::{LOCAL_OPERATOR_PRINCIPAL, MetaMcp, MetaMcpCallerContext};

/// Who a relay is keyed on: a caller's key, or the unkeyed fallback bucket.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RelayKey<'a> {
    key: &'a str,
    keyed: bool,
}

impl MetaMcpCallerContext<'_> {
    /// The relay principal: the HTTP caller key (inherited by playbooks,
    /// chains and HTTP tasks), else the stdio operator, one principal that no
    /// caller key can spell, else the unkeyed `session_id` bucket.
    pub(crate) fn relay_caller<'s>(&'s self, session_id: Option<&'s str>) -> RelayKey<'s> {
        if let Some(key) = self.caller_key.filter(|key| !key.is_empty()) {
            return RelayKey { key, keyed: true };
        }
        if self.stdio_nonce.is_some() {
            let key = LOCAL_OPERATOR_PRINCIPAL;
            return RelayKey { key, keyed: true };
        }
        let key = session_id.unwrap_or("meta:unkeyed");
        RelayKey { key, keyed: false }
    }
}

/// The `tools/call` params a backend receives: `name`, `arguments`, the
/// propagable `_meta`, and a retry's `requestState`/`inputResponses`. The one
/// builder for dispatch and for the relay check, so the two cannot drift.
pub(super) fn outbound_params(
    tool: &str,
    arguments: Value,
    inbound_meta: Option<&Value>,
    prompt_cache_key: Option<&str>,
    retry: &OutboundRetry,
) -> Value {
    let mut params = serde_json::json!({ "name": tool, "arguments": arguments });
    if let Some(meta) = build_outbound_meta(inbound_meta, prompt_cache_key)
        && let Value::Object(map) = &mut params
    {
        map.insert("_meta".to_string(), meta);
    }
    retry.apply(&mut params);
    params
}

/// What one egress is checked on, besides its target.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(super) struct Egress<'a> {
    pub(super) arguments: &'a Value,
    pub(super) inbound_meta: Option<&'a Value>,
    pub(super) prompt_cache_key: Option<&'a str>,
    pub(super) retry: &'a OutboundRetry,
}

impl MetaMcp {
    /// The relay check on `server:tool`'s egress, before secret injection.
    /// A capability gets `arguments` only: nothing else is forwarded to it.
    /// `Some` is the `-32002` refusal to answer with.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn relay_refusal(
        &self,
        who: RelayKey<'_>,
        audit: (&str, &str),
        (server, tool): (&str, &str),
        egress: &Egress<'_>,
    ) -> Option<crate::Error> {
        #[cfg(feature = "firewall")]
        {
            use crate::security::firewall::{FirewallAction, RelayCaller};
            let fw = self.firewall.as_ref()?;
            let capability = self
                .get_capabilities()
                .is_some_and(|cap| server == cap.name);
            let params = if capability {
                egress.arguments.clone()
            } else {
                let arguments = egress.arguments.clone();
                let (meta, key) = (egress.inbound_meta, egress.prompt_cache_key);
                outbound_params(tool, arguments, meta, key, egress.retry)
            };
            let caller = RelayCaller::new(who.key, who.keyed);
            let verdict = fw.check_relay(caller, server, tool, &params, audit);
            if verdict.action == FirewallAction::Warn {
                tracing::warn!(server, tool, "Firewall: relay observed");
            }
            if verdict.allowed {
                return None;
            }
            let desc = verdict
                .findings
                .first()
                .map_or("", |f| f.description.as_str());
            Some(crate::Error::Forbidden {
                code: -32002,
                status: 403,
                message: format!("Relay detection blocked: {desc}"),
            })
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (who, audit, server, tool, egress);
            None
        }
    }
}

impl MetaMcp {
    /// Site 1 (§13.3): refuse a relaying call before it is marked dispatched,
    /// releasing its idempotency reservation, since nothing ran.
    pub(super) fn refuse_relay(
        &self,
        caller: &MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        target: (&str, &str),
        egress: &Egress<'_>,
        reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    ) -> crate::Result<()> {
        let audit = (
            session_id.unwrap_or_default(),
            caller.api_key_name.unwrap_or("anonymous"),
        );
        let who = caller.relay_caller(session_id);
        let Some(refused) = self.relay_refusal(who, audit, target, egress) else {
            return Ok(());
        };
        if let Some(reservation) = reservation {
            reservation.release();
        }
        Err(refused)
    }

    /// The caller's channel, recording every bridged prompt it carries.
    pub(super) fn recording_channel<'a>(
        &'a self,
        caller: &'a MetaMcpCallerContext<'_>,
        session_id: Option<&'a str>,
        target: (&'a str, &'a str),
        trace_id: &'a str,
    ) -> RecordingChannel<'a> {
        RecordingChannel {
            inner: caller.channel,
            meta: self,
            who: caller.relay_caller(session_id),
            target,
            api_key_name: caller.api_key_name,
            trace_id,
        }
    }
}

impl super::BridgeDispatcher<'_> {
    /// Site 2 (§13.3): a bridged round carrying a relay is refused before
    /// it is armed. The refusal waits in `relay_refused`, which the call site
    /// reads before any other arm; the bridge sees `NotAdmitted`.
    pub(super) fn refuse_relaying_round(
        &self,
        retry: &OutboundRetry,
    ) -> Result<(), crate::gateway::input_bridge::BridgeError> {
        let egress = Egress {
            arguments: self.arguments,
            inbound_meta: self.inbound_meta,
            prompt_cache_key: self.prompt_cache_key,
            retry,
        };
        let audit = (
            self.session_id.unwrap_or_default(),
            self.api_key_name.unwrap_or("anonymous"),
        );
        let target = (self.server, self.tool);
        let Some(refused) = self.meta.relay_refusal(self.relay, audit, target, &egress) else {
            return Ok(());
        };
        let message = refused.to_string();
        *self.relay_refused.lock() = Some(refused);
        Err(crate::gateway::input_bridge::BridgeError::NotAdmitted { message })
    }
}

/// One result staged for recording, committed only once it is delivered.
struct Receipt {
    key: String,
    keyed: bool,
    server: String,
    tool: String,
    value: Value,
}

tokio::task_local! {
    /// The receipts of the delivery this task owns (§13.3 "Recording").
    static RELAY_RECEIPTS: RefCell<Vec<Receipt>>;
}

/// Run `delivery` with a receipt collector: the HTTP and stdio dispatches
/// (finalize included) and a task's execution. Dropping the scope discards
/// what was staged; only [`MetaMcp::commit_relay_receipts`] records.
pub(crate) async fn collecting<F: std::future::Future>(delivery: F) -> F::Output {
    RELAY_RECEIPTS
        .scope(RefCell::new(Vec::new()), delivery)
        .await
}

impl MetaMcp {
    /// Stage `value`, the result `server:tool` answered `who` with, as gated.
    /// A no-op outside a collector or with relay detection off.
    // ponytail: the value is held whole until commit; stage the capped text
    // instead if large results show up in memory profiles.
    pub(super) fn stage_relay_receipt(
        &self,
        who: RelayKey<'_>,
        (server, tool): (&str, &str),
        value: &Value,
    ) {
        if !self.relay_on() {
            return;
        }
        let _ = RELAY_RECEIPTS.try_with(|receipts| {
            receipts.borrow_mut().push(Receipt {
                key: who.key.to_owned(),
                keyed: who.keyed,
                server: server.to_owned(),
                tool: tool.to_owned(),
                value: value.clone(),
            });
        });
    }

    /// Record every staged receipt, when `response` is a delivered result
    /// rather than an error or a delivery refusal.
    pub(crate) fn commit_relay_receipts(&self, response: &crate::protocol::JsonRpcResponse) {
        let receipts = RELAY_RECEIPTS
            .try_with(|receipts| std::mem::take(&mut *receipts.borrow_mut()))
            .unwrap_or_default();
        if response.error.is_some() || response.delivery_refusal {
            return;
        }
        for receipt in receipts {
            let who = RelayKey {
                key: &receipt.key,
                keyed: receipt.keyed,
            };
            self.record_relay_delivery(who, (&receipt.server, &receipt.tool), &receipt.value);
        }
    }

    /// A copy of `result` to compare after a final check, when receipts are
    /// pending; see [`discard_if_changed`].
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    pub(crate) fn relay_snapshot(&self, result: &Value) -> Option<Value> {
        let pending = RELAY_RECEIPTS
            .try_with(|receipts| !receipts.borrow().is_empty())
            .unwrap_or(false);
        (pending && self.relay_on()).then(|| result.clone())
    }

    /// Record `value` as delivered to `who` from `server:tool`, now.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn record_relay_delivery(
        &self,
        who: RelayKey<'_>,
        (server, tool): (&str, &str),
        value: &Value,
    ) {
        #[cfg(feature = "firewall")]
        if let Some(fw) = self.firewall.as_ref() {
            let caller = crate::security::firewall::RelayCaller::new(who.key, who.keyed);
            fw.record_delivery(caller, server, tool, value);
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (who, server, tool, value);
    }

    /// Whether this gateway records relay receipts at all.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    fn relay_on(&self) -> bool {
        #[cfg(feature = "firewall")]
        {
            self.firewall
                .as_ref()
                .is_some_and(|fw| fw.relay_detection_on())
        }
        #[cfg(not(feature = "firewall"))]
        {
            false
        }
    }
}

/// A final check that changed the delivered result (a redaction) leaves the
/// staged receipts describing text the caller never got: drop them all.
#[cfg_attr(not(feature = "firewall"), allow(dead_code))]
pub(crate) fn discard_if_changed(snapshot: Option<Value>, result: &Value) {
    if snapshot.is_some_and(|before| before != *result) {
        let _ = RELAY_RECEIPTS.try_with(|receipts| receipts.borrow_mut().clear());
    }
}

/// A bridged prompt is content delivered to the caller (§13.3): recorded
/// when it is handed to the client, before the reply is awaited, classified
/// on a copy as a tool result is.
pub(super) struct RecordingChannel<'a> {
    pub(super) inner: &'a dyn crate::gateway::input_bridge::ClientChannel,
    pub(super) meta: &'a MetaMcp,
    pub(super) who: RelayKey<'a>,
    pub(super) target: (&'a str, &'a str),
    pub(super) api_key_name: Option<&'a str>,
    pub(super) trace_id: &'a str,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for RecordingChannel<'_> {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        if let Some(prompt) = params.as_ref().filter(|_| self.meta.relay_on()) {
            let (server, tool) = self.target;
            let (classified, _) = self.meta.apply_context_integrity(
                server,
                tool,
                self.api_key_name,
                self.trace_id,
                prompt.clone(),
            );
            self.meta
                .record_relay_delivery(self.who, self.target, &classified);
        }
        self.inner
            .send_request(session_id, id, method, params)
            .await
    }
}

#[cfg(all(test, feature = "firewall"))]
#[path = "relay_tests.rs"]
mod tests;
