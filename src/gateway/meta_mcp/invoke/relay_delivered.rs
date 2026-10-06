// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.3/.4: a relay receipt commits where delivery is confirmed
//! and describes the answer as it was finally delivered.

use serde_json::Value;

use super::RELAY_RECEIPTS;
use super::{MetaMcp, RelayKey};

impl MetaMcp {
    /// The relay receipt of `value` as delivered to `who` from `server:tool`,
    /// owned so the channel can commit it once delivery is confirmed.
    /// `None` with relay detection off.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn delivery_commit(
        &self,
        who: RelayKey<'_>,
        (server, tool): (&str, &str),
        value: &Value,
    ) -> Option<crate::gateway::input_bridge::DeliveryCommit> {
        #[cfg(feature = "firewall")]
        {
            let fw = std::sync::Arc::clone(self.firewall.as_ref()?);
            let digest = fw.delivery_digest(server, tool, value)?;
            let (key, keyed) = (who.key.to_owned(), who.keyed);
            let (server, tool) = (server.to_owned(), tool.to_owned());
            Some(crate::gateway::input_bridge::DeliveryCommit::new(
                move || {
                    let caller = crate::security::firewall::RelayCaller::new(&key, keyed);
                    fw.record_digest(caller, &server, &tool, &digest);
                },
            ))
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (who, server, tool, value);
            None
        }
    }

    /// A final check may have changed the delivered result (a redaction):
    /// the staged receipts then describe text the caller never got.
    ///
    /// One staged receipt (a single-target call) is rebuilt from what is
    /// delivered, so the text the caller still got keeps its receipt and the
    /// removed text stops being tracked. A plan's step receipts are kept for
    /// [`MetaMcp::rebuild_receipt_from_final`], which keeps each to the text
    /// the final answer still delivers; until then they never commit. Several
    /// receipts of no plan cannot be told apart and are dropped.
    ///
    /// `shape` is how the caller delivered the answer: only a `gateway_invoke`
    /// wrapper is read decoded. A surfaced tool's text is read as delivered,
    /// even when it happens to look like the wrapper (MIK-7906).
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, clippy::needless_pass_by_value)
    )]
    pub(crate) fn restage_if_changed(
        &self,
        snapshot: Option<Value>,
        result: Option<&Value>,
        shape: AnswerShape,
    ) {
        if !snapshot.is_some_and(|before| Some(&before) != result) {
            return;
        }
        let _ = RELAY_RECEIPTS.try_with(|receipts| {
            let mut receipts = receipts.borrow_mut();
            let mut staged = std::mem::take(&mut *receipts);
            // A plan's step receipts wait for the final answer, which keeps
            // each to the text it still delivers (MIK-7887.RECEIPT.2).
            if staged.iter().any(|r| r.in_plan) {
                staged.retain(|r| r.in_plan);
                for r in &mut staged {
                    r.pending_retain = true;
                }
                *receipts = staged;
                return;
            }
            #[cfg(feature = "firewall")]
            if let ([one], Some(delivered), Some(fw)) = (staged.as_slice(), result, &self.firewall)
                && let Some(digest) = fw.delivery_digest(
                    &one.server,
                    &one.tool,
                    &match shape {
                        AnswerShape::InvokeWrapped => {
                            super::super::audit::delivered_value(delivered)
                        }
                        AnswerShape::Literal => std::borrow::Cow::Borrowed(delivered),
                    },
                )
            {
                // A redaction can drop the classification marker with the
                // text; what the call was judged sensitive for stays so.
                let digest = digest.keeping_sensitivity_of(&one.digest);
                receipts.push(super::Receipt {
                    key: one.key.clone(),
                    keyed: one.keyed,
                    server: one.server.clone(),
                    tool: one.tool.clone(),
                    digest,
                    in_plan: false,
                    pending_retain: false,
                });
            }
            #[cfg(not(feature = "firewall"))]
            drop((staged, shape));
        });
    }

    /// MIK-7887.RECEIPT.4: rebuild a single staged receipt from `result` as it
    /// is finally delivered, after every late rewrite (the scope clamp, the
    /// chain, the modern `serverInfo` stamp, a redaction), so the receipt holds
    /// the backend text the caller got and nothing else. Members the gateway
    /// itself wrote on this route are not backend text and are left out.
    ///
    /// A plan's answer is not any one step's text: each step receipt is kept
    /// to what the answer still delivers, never rebuilt from it, so text the
    /// engine wrote is attributed to no backend (MIK-7887.RECEIPT.2).
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, clippy::needless_pass_by_value)
    )]
    pub(crate) fn rebuild_receipt_from_final(
        &self,
        result: Option<&Value>,
        stamps: GatewayStamps,
        shape: AnswerShape,
    ) {
        #[cfg(feature = "firewall")]
        {
            let (Some(result), Some(fw)) = (result, self.firewall.as_deref()) else {
                return;
            };
            if !self.relay_active() {
                return;
            }
            let _ = RELAY_RECEIPTS.try_with(|receipts| {
                let mut receipts = receipts.borrow_mut();
                let copy = receipt_copy(result, stamps, shape);
                if receipts.iter().any(|r| r.in_plan) {
                    keep_plan_receipts(fw, &mut receipts, &plan_answer(copy));
                    return;
                }
                let [one] = receipts.as_mut_slice() else {
                    return;
                };
                if let Some(digest) = fw.delivery_digest(&one.server, &one.tool, &copy) {
                    one.digest = digest.keeping_sensitivity_of(&one.digest);
                }
            });
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (result, stamps, shape);
    }
}

/// A plan's answer as delivered: the steps' JSON a `wrap_tool_success`
/// envelope carries in its one text block, read decoded whether or not it is
/// the exact pretty print; anything else as it stands.
#[cfg(feature = "firewall")]
fn plan_answer(copy: Value) -> Value {
    let decoded = match copy
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([block]) => block
            .get("text")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .filter(|v| v.is_object() || v.is_array()),
        _ => None,
    };
    decoded.unwrap_or(copy)
}

/// Keep each plan step receipt to what `answer` delivers; drop them all when
/// the answer is over the bound they are kept against.
#[cfg(feature = "firewall")]
fn keep_plan_receipts(
    fw: &crate::security::firewall::Firewall,
    receipts: &mut Vec<super::Receipt>,
    answer: &Value,
) {
    let Some(delivered) = fw.delivered_for_plan(answer) else {
        receipts.retain(|r| !r.in_plan);
        return;
    };
    for r in receipts.iter_mut().filter(|r| r.in_plan) {
        let digest = std::mem::take(&mut r.digest);
        r.digest = fw.retain_delivered(digest, &delivered);
        r.pending_retain = false;
    }
}

/// Which members of a delivered result the gateway wrote on its route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayStamps {
    /// A modern answer: the gateway stamps `_meta` `serverInfo` over the
    /// backend's.
    Modern,
    /// A legacy answer: a backend `serverInfo` reaches the caller as sent.
    Legacy,
}

/// How a delivered answer carries its tool's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerShape {
    /// A `gateway_invoke` answer: the gateway wraps the value as JSON text.
    InvokeWrapped,
    /// A surfaced tool's answer: its blocks are read as the caller sees them.
    Literal,
}

impl AnswerShape {
    /// The shape the gateway gives an answer to `external_tool`: only a
    /// `gateway_invoke` answer is wrapped.
    #[must_use]
    pub(crate) fn of(external_tool: &str) -> Self {
        if external_tool == "gateway_invoke" {
            Self::InvokeWrapped
        } else {
            Self::Literal
        }
    }
}

/// The backend text of a finally delivered `result`: the gateway's chain
/// removed, every scope clamped as the wire clamps it (top level and a task
/// envelope's retained result), a modern answer's `serverInfo` stamp removed,
/// and a `gateway_invoke` wrapper read decoded.
#[cfg(feature = "firewall")]
fn receipt_copy(result: &Value, stamps: GatewayStamps, shape: AnswerShape) -> Value {
    let mut copy = result.clone();
    crate::security::signature_chain::strip_chain(&mut copy);
    // Clamped as the wire clamps it, so a backend's text in a scope, top
    // level or in a task envelope's retained result, is never digested.
    crate::protocol::cacheable::clamp_delivered_scope(&mut copy);
    if stamps == GatewayStamps::Modern
        && let Some(meta) = copy.get_mut("_meta").and_then(Value::as_object_mut)
    {
        meta.remove(crate::protocol::meta::KEY_SERVER_INFO);
    }
    // An interim answer (`inputRequests`, `requestState`) is a promoted
    // native result, not a wrapper: its members are delivered as they stand.
    let interim = copy.get("inputRequests").is_some() || copy.get("requestState").is_some();
    match shape {
        AnswerShape::InvokeWrapped if !interim => {
            super::super::audit::delivered_value(&copy).into_owned()
        }
        AnswerShape::InvokeWrapped | AnswerShape::Literal => copy,
    }
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocol::meta::KEY_SERVER_INFO;

    /// A delivered answer with a `serverInfo` in its `_meta`.
    fn answered() -> Value {
        json!({"content": [], "_meta": {KEY_SERVER_INFO: {"name": "named"}, "keep": 1}})
    }

    /// MIK-7887.RECEIPT.4: a modern answer's `serverInfo` is the gateway's
    /// stamp and leaves the receipt copy; the rest of `_meta` stays.
    #[test]
    fn a_modern_copy_drops_the_server_info_stamp() {
        let copy = receipt_copy(&answered(), GatewayStamps::Modern, AnswerShape::Literal);
        assert!(copy["_meta"].get(KEY_SERVER_INFO).is_none(), "{copy}");
        assert_eq!(copy["_meta"]["keep"], 1, "{copy}");
    }

    /// MIK-7887.RECEIPT.4: a legacy answer's `serverInfo` is the backend's,
    /// delivered as sent, so it stays in the receipt copy.
    #[test]
    fn a_legacy_copy_keeps_the_backends_server_info() {
        let copy = receipt_copy(&answered(), GatewayStamps::Legacy, AnswerShape::Literal);
        assert_eq!(copy["_meta"][KEY_SERVER_INFO]["name"], "named", "{copy}");
    }
}
