// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::meta::{Declared, ElicitationMode, classify_request};
use mcp_gateway::protocol::mrtr::InputRequired;
use serde_json::{Value, json};

/// What the client declared, read the way production reads it.
fn form_only_client() -> Declared {
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": { "form": {} }
            }
        }
    });
    let shape = classify_request(Some(&params), Some("2026-07-28"));
    let declared = shape.declared_capabilities();
    assert!(
        declared.has("elicitation"),
        "the fixture must reach the gate as a client that DID declare elicitation, \
         or the refusal below would be MRTR.9's and prove nothing about modes"
    );
    assert!(
        declared.has_elicitation_mode(ElicitationMode::Form)
            && !declared.has_elicitation_mode(ElicitationMode::Url),
        "the fixture must declare form and only form, or the url refusal below is vacuous"
    );
    declared
}

fn interim(requests: &Value) -> InputRequired {
    InputRequired::from_result(&json!({
        "resultType": "input_required",
        "inputRequests": requests,
        "requestState": "backend-opaque"
    }))
    .expect("a well-formed interim result")
}

#[test]
fn ac_mrtr_9a_a_url_mode_request_to_a_form_only_client_is_refused() {
    // GIVEN a client that declared elicitation in form mode only
    let declared = form_only_client();
    // WHEN the backend asks it to navigate to a URL — a mode it did not declare
    let interim = interim(&json!({
        "api_key": {
            "method": "elicitation/create",
            "params": {
                "mode": "url",
                "url": "https://backend.invalid/ui/set_api_key",
                "message": "Please provide your API key to continue."
            }
        }
    }));
    // THEN the gateway must refuse rather than relay it.
    assert!(
        interim.undeclared(declared).is_some(),
        "a url-mode elicitation must be refused to a client that declared form mode only; \
         a gate reading the capability name alone cannot see the mode substructure and \
         relays this request"
    );
}

#[test]
fn ac_mrtr_9a_a_form_mode_request_to_a_form_only_client_is_relayed() {
    // The control. Without it, refusing every elicitation satisfies the case
    // above — and that is a gate no client could ever use.
    let declared = form_only_client();
    let interim = interim(&json!({
        "seat": {
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": "Window or aisle?"
            }
        }
    }));
    assert!(
        interim.undeclared(declared).is_none(),
        "a form-mode elicitation is exactly what this client declared, and must be relayed"
    );
}
