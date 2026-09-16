//! MRTR.11a/.11b — deciding how a meta-tool result reaches the client.
//!
//! The synchronous request thread wraps every meta-tool result:
//! `wrap_tool_success` (`meta_mcp_helpers.rs:748`) pretty-prints the whole
//! value into `content[0].text` and states `is_error: false`. For a completed
//! call that is correct. For an interim round it is the defect the dispatch
//! path already documents on its sibling entry point — `resultType:
//! "input_required"` inside a JSON string is not a claim any classifier can
//! read, so a question is committed as an answer. The task worker escaped via
//! `ResultShape::Native`; this thread never got the same escape.
//!
//! Promotion cannot key on `resultType` alone. That string is backend-authored,
//! so discriminating on it lets an untrusted backend turn any result into a
//! client-facing question loop carrying prompts it wrote (.11b, rated HIGH by
//! the second design seat). The claim is therefore routed through the
//! validator, and a claim that fails validation is answered as an upstream
//! fault rather than quietly wrapped — wrapping it would relabel a backend
//! fault as a successful call.
//!
//! The decision is a pure function so it is testable without standing up a
//! `MetaMcp` server; nothing in the tree exercises `dispatch_below_gate`
//! directly, and the rows below are what pin the arms its `ResultShape::Wrapped`
//! branch now takes. The same reason makes it reusable: the chain-interim
//! seam relays `inputRequests` with no capability gate
//! (`chain_interim.rs:101`), and that gate is one of the arms below.

use crate::protocol::meta::Declared;
use crate::protocol::mrtr::InputRequired;
use serde_json::Value;

/// How a meta-tool result should be presented to the caller.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Promotion {
    /// Deliver the result at the top level, unwrapped, so `resultType`,
    /// `inputRequests` and `requestState` stay where a protocol client and the
    /// firewall's `PreserveInputRequired` policy both look for them.
    Native,
    /// An ordinary completed result: wrap it as today. This arm must stay
    /// reachable for every pre-2026 backend, which sends no `resultType` at all.
    Wrap,
    /// The backend claimed a round it cannot have. Answered as a fault against
    /// the backend, never as a completed call.
    UpstreamFault(String),
}

/// Decide the presentation for one meta-tool result.
///
/// Order is load-bearing. The completed case is settled first so a legacy
/// answer can never reach the interim arms; the validator runs before the
/// capability gate so a malformed claim is named as malformed rather than as
/// an undeclared request it never well-formedly made.
pub(crate) fn promote_interim(result: &Value, declared: Declared) -> Promotion {
    // Not a claim at all. `claims_input_required` rather than `from_result`
    // here: `from_result`'s `None` folds "completed" together with "asked
    // badly", and those two take opposite arms.
    if !InputRequired::claims_input_required(result) {
        return Promotion::Wrap;
    }

    // Claimed, but not into a shape the gateway can carry: a malformed
    // `inputRequests`, or a round with neither a question nor a state. Both
    // are backend faults. Wrapping either would present a failed question as a
    // successful answer, which is the .11b regression in its quietest form.
    let Some(interim) = InputRequired::from_result(result) else {
        return Promotion::UpstreamFault(
            "Backend claimed resultType 'input_required' with no usable \
             inputRequests or requestState"
                .to_string(),
        );
    };

    // The per-entry MUST-NOT. Checked per request, not per result: a client
    // that declared elicitation and not sampling may legitimately be sent the
    // one and not the other.
    if let Some(undeclared) = interim.undeclared(declared) {
        let key = undeclared.key;
        let method = undeclared.method;
        return Promotion::UpstreamFault(format!(
            "Backend asked for '{method}' in request '{key}', which this client did not declare"
        ));
    }

    Promotion::Native
}
