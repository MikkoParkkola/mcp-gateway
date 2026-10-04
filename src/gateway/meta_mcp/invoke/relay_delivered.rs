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

/// The backend text of a finally delivered `result`: the gateway's own
/// members removed (its chain, the scope verdict it clamps, and on a modern
/// answer its `serverInfo`), and a `gateway_invoke` wrapper read decoded.
#[cfg(feature = "firewall")]
fn receipt_copy(result: &Value, stamps: GatewayStamps, shape: AnswerShape) -> Value {
    let mut copy = result.clone();
    crate::security::signature_chain::strip_chain(&mut copy);
    if let Some(members) = copy.as_object_mut() {
        members.remove("cacheScope");
        if stamps == GatewayStamps::Modern
            && let Some(meta) = members.get_mut("_meta").and_then(Value::as_object_mut)
        {
            meta.remove(crate::protocol::meta::KEY_SERVER_INFO);
        }
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
