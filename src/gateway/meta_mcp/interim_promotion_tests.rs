//! MRTR.11a/.11b — the presentation decision, pinned row by row.
//!
//! Each row names the single check that decides it. The seam is
//! `#[cfg(test)]` and unwired; wiring it into `dispatch_below_gate`'s
//! `ResultShape::Wrapped` arm (`mod.rs:2157`) is the declared follow-up and is
//! deliberately out of scope here.

use super::interim_promotion::{Promotion, promote_interim};
use crate::protocol::meta::Declared;
use serde_json::{Value, json};

/// A client that declared elicitation in its handshake and nothing else.
fn declared_elicitation() -> Declared {
    Declared::from_handshake(Some(&json!({"elicitation": {}})))
}

/// The shape a well-formed backend question takes.
fn elicitation_round() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {
            "q1": {"method": "elicitation/create", "params": {"message": "which account?"}}
        },
        "requestState": "opaque-backend-state"
    })
}

// ---------------------------------------------------------------------------
// The completed arm. It must stay reachable, and it must not consult anything.
// ---------------------------------------------------------------------------

/// Row 1. A pre-2026 backend sends no `resultType` at all. Wrapping is correct
/// for it and always was; promotion must not disturb the legacy path.
#[test]
fn a_legacy_result_with_no_result_type_wraps() {
    let result = json!({"content": "ordinary answer"});
    assert_eq!(promote_interim(&result, Declared::NONE), Promotion::Wrap);
}

/// Row 2. A modern backend that finished says so. `complete` is not the
/// interim discriminator and must not be read as one.
#[test]
fn a_completed_modern_result_wraps() {
    let result = json!({"resultType": "complete", "content": "done"});
    assert_eq!(promote_interim(&result, Declared::NONE), Promotion::Wrap);
}

/// Row 3. The completed arm is settled before capabilities are read, so a
/// client that declared nothing still gets its ordinary answers. A decision
/// that consulted `declared` first would refuse completed results to legacy
/// clients — the regression that would make this change unshippable.
#[test]
fn a_completed_result_wraps_whatever_the_client_declared() {
    let result = json!({"content": "ordinary answer"});
    assert_eq!(promote_interim(&result, Declared::NONE), Promotion::Wrap);
    assert_eq!(
        promote_interim(&result, declared_elicitation()),
        Promotion::Wrap
    );
}

// ---------------------------------------------------------------------------
// The promoted arm.
// ---------------------------------------------------------------------------

/// Row 4. The whole point of .11a: a validated question reaches the client at
/// the top level instead of pretty-printed into `content[0].text`, where
/// neither a protocol client nor the firewall's `PreserveInputRequired` policy
/// can see `requestState`.
#[test]
fn a_validated_declared_round_is_promoted() {
    assert_eq!(
        promote_interim(&elicitation_round(), declared_elicitation()),
        Promotion::Native
    );
}

/// Row 5. A state-only round carries no question, so there is nothing to gate:
/// the backend wants another turn without asking the user anything. It passes
/// with a client that declared nothing, which is what proves the capability
/// gate is per-entry and not a blanket verdict on the result.
#[test]
fn a_state_only_round_is_promoted_even_with_no_declaration() {
    let result = json!({"resultType": "input_required", "requestState": "opaque-backend-state"});
    assert_eq!(promote_interim(&result, Declared::NONE), Promotion::Native);
}

// ---------------------------------------------------------------------------
// The fault arm — .11b. Every row here is a result that CLAIMED a round.
// ---------------------------------------------------------------------------

/// Row 6. The security row. `resultType` is backend-authored, so a bare claim
/// with nothing behind it is the cheapest lever an untrusted backend has. It
/// must not promote, and it must not quietly wrap either: wrapping relabels a
/// backend fault as a successful call.
#[test]
fn a_bare_result_type_claim_is_an_upstream_fault() {
    let result = json!({"resultType": "input_required"});
    assert!(matches!(
        promote_interim(&result, declared_elicitation()),
        Promotion::UpstreamFault(_)
    ));
}

/// Row 7. Malformed presence is a different fault from absence and must not
/// collapse into "asked nothing": `"inputRequests": "surprise"` read as an
/// empty map would relay a state-carrying exchange with no request ever
/// passing the capability gate.
#[test]
fn a_malformed_input_requests_is_an_upstream_fault() {
    let result = json!({
        "resultType": "input_required",
        "inputRequests": "surprise",
        "requestState": "opaque-backend-state"
    });
    assert!(matches!(
        promote_interim(&result, declared_elicitation()),
        Promotion::UpstreamFault(_)
    ));
}

/// Row 8. The MUST-NOT. A client that declared nothing cannot be asked to
/// elicit, and the refusal names which request was refused rather than only
/// that one was.
#[test]
fn an_undeclared_request_is_an_upstream_fault_naming_it() {
    let Promotion::UpstreamFault(message) = promote_interim(&elicitation_round(), Declared::NONE)
    else {
        panic!("an undeclared elicitation must not be promoted");
    };
    assert!(message.contains("q1"), "names the request: {message}");
    assert!(
        message.contains("elicitation/create"),
        "names the method: {message}"
    );
}

/// Row 9. Per-entry, not per-result. This client declared elicitation and not
/// sampling; the sampling entry alone must fail the whole promotion, because a
/// partially-relayed round would ask for a permission never given.
#[test]
fn one_undeclared_entry_among_declared_ones_fails_the_round() {
    let result = json!({
        "resultType": "input_required",
        "inputRequests": {
            "ok": {"method": "elicitation/create", "params": {"message": "fine"}},
            "bad": {"method": "sampling/createMessage", "params": {}}
        },
        "requestState": "opaque-backend-state"
    });
    assert!(matches!(
        promote_interim(&result, declared_elicitation()),
        Promotion::UpstreamFault(_)
    ));
}

/// Row 10. A request carrying no method cannot have been declared — the
/// declaration vocabulary is the gateway's own set, so an unclassifiable
/// question asks for a permission the client was never given the chance to
/// withhold.
#[test]
fn a_request_with_no_method_is_an_upstream_fault() {
    let result = json!({
        "resultType": "input_required",
        "inputRequests": {"q1": {"params": {"message": "no method"}}},
        "requestState": "opaque-backend-state"
    });
    assert!(matches!(
        promote_interim(&result, declared_elicitation()),
        Promotion::UpstreamFault(_)
    ));
}
