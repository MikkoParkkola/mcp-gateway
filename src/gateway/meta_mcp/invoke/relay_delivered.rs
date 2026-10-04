// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.3/.4: a relay receipt commits where delivery is confirmed
//! and describes the answer as it was finally delivered.

use serde_json::Value;

#[cfg(feature = "firewall")]
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

    /// MIK-7887.RECEIPT.4: rebuild a single staged receipt from `result` as it
    /// is finally delivered, after every late rewrite (the scope clamp, the
    /// chain, the modern `serverInfo` stamp, a redaction), so the receipt holds
    /// the backend text the caller got and nothing else. Members the gateway
    /// itself wrote on this route are not backend text and are left out. A
    /// plan's receipts cannot be told apart in one answer and are kept as
    /// staged.
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
                let [one] = receipts.as_mut_slice() else {
                    return;
                };
                let copy = receipt_copy(result, stamps, shape);
                if let Some(digest) = fw.delivery_digest(&one.server, &one.tool, &copy) {
                    one.digest = digest.keeping_sensitivity_of(&one.digest);
                }
            });
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (result, stamps, shape);
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
