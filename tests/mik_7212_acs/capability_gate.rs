// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::meta::{Declared, classify_request};
use mcp_gateway::protocol::mrtr::{InputRequired, Refusal};
use serde_json::{Value, json};

fn interim(requests: &serde_json::Value) -> InputRequired {
    InputRequired::from_result(&json!({
        "resultType": "input_required",
        "inputRequests": requests,
        "requestState": "backend-opaque"
    }))
    .expect("a well-formed interim result")
}

fn declared(names: &[&str]) -> Declared {
    let capabilities: serde_json::Map<String, Value> = names
        .iter()
        .map(|name| ((*name).to_string(), json!({})))
        .collect();
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": capabilities
        }
    });
    classify_request(Some(&params), Some("2026-07-28")).declared_capabilities()
}

#[test]
fn ac_mrtr_9_a_declared_type_is_relayed() {
    // GIVEN a client that declared `elicitation`
    // WHEN the backend asks for an elicitation
    let interim = interim(&json!({
        "confirm": { "method": "elicitation/create", "params": {} }
    }));
    // THEN nothing is refused: the gate must not block the exchange it
    // exists to make safe.
    assert!(
        interim.undeclared(declared(&["elicitation"])).is_none(),
        "a declared capability must be relayable"
    );
}

#[test]
fn ac_mrtr_9_an_undeclared_type_is_refused() {
    // GIVEN a client that declared `elicitation` and nothing else
    // WHEN the backend asks for sampling
    let interim = interim(&json!({
        "draft": { "method": "sampling/createMessage", "params": {} }
    }));
    let refused = interim
        .undeclared(declared(&["elicitation"]))
        .expect("sampling was never declared");
    // THEN the refusal names the capability the client would have had to
    // declare, so the client can act on it rather than guess.
    assert_eq!(refused.reason, Refusal::Capability("sampling"));
    assert_eq!(refused.key, "draft");
}

#[test]
fn ac_mrtr_9_each_entry_is_judged_on_its_own_capability() {
    // GIVEN one result carrying both a declared and an undeclared type
    let interim = interim(&json!({
        "confirm": { "method": "elicitation/create", "params": {} },
        "draft": { "method": "sampling/createMessage", "params": {} }
    }));
    // THEN the undeclared entry is found whichever position it holds — a
    // check that stopped at the first entry would pass this result.
    let refused = interim
        .undeclared(declared(&["elicitation"]))
        .expect("the sampling entry must still be caught");
    assert_eq!(refused.key, "draft");
    assert_eq!(refused.reason, Refusal::Capability("sampling"));
}

#[test]
fn ac_mrtr_9_an_unrecognised_type_is_refused_and_names_no_capability() {
    // A method outside the revision's vocabulary cannot have been declared:
    // the declaration is a list of capability names, and this has none.
    let interim = interim(&json!({
        "odd": { "method": "vendor/askSomething", "params": {} }
    }));
    let refused = interim
        .undeclared(declared(&["elicitation", "sampling", "roots"]))
        .expect("an unclassifiable request must not be relayed");
    assert_eq!(refused.method, "vendor/askSomething");
    assert_eq!(
        refused.reason,
        Refusal::UnrecognisedMethod,
        "no capability may be named, or the client is told to declare one that does not exist"
    );
}

#[test]
fn ac_mrtr_9_an_entry_carrying_no_method_is_refused() {
    // Fail closed. Skipping an entry the gate cannot read would relay it.
    let interim = interim(&json!({ "nameless": { "params": {} } }));
    assert!(
        interim
            .undeclared(declared(&["elicitation", "sampling", "roots"]))
            .is_some(),
        "an entry with no method must be refused, not skipped"
    );
}

#[test]
fn ac_mrtr_9_a_client_that_declared_nothing_is_asked_nothing() {
    let interim = interim(&json!({
        "confirm": { "method": "elicitation/create", "params": {} }
    }));
    assert!(
        interim.undeclared(Declared::NONE).is_some(),
        "an empty declaration permits no question at all"
    );
}
