// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7212.MRTR.9a, case 2: the ordering case for the elicitation-mode gate.
//!
//! Moved out of `tests/mik_7212_acs.rs` unchanged, to keep that file under its
//! file-size baseline. The coverage matrix it complements stays there
//! (`mod elicitation_mode_matrix`).

// ===========================================================================
// MIK-7212.MRTR.9a — case 2: every entry is judged, not just one
//
// The matrix cannot see this: all 28 of its cells carry a single request, so an
// implementation that checks only the first entry, or only the last, passes
// every one of them. A forbidden entry in the MIDDLE fails both at once, which
// is why one case covers what a first-and-last pair would.
//
// Keys are named so that alphabetical order — which is the order the entries
// are stored in — puts the forbidden one between the two allowed ones.
// ===========================================================================

mod elicitation_mode_ordering {
    use mcp_gateway::protocol::meta::{Declared, classify_request};
    use mcp_gateway::protocol::mrtr::InputRequired;
    use serde_json::json;

    fn form_only() -> Declared {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "form": {} } }
            }
        });
        classify_request(Some(&params), Some("2026-07-28")).declared_capabilities()
    }

    #[test]
    fn ac_mrtr_9a_a_forbidden_request_between_two_allowed_ones_is_found_and_named() {
        let interim = InputRequired::from_result(&json!({
            "resultType": "input_required",
            "inputRequests": {
                "a_seat": { "method": "elicitation/create", "params": { "mode": "form", "message": "Window or aisle?" } },
                "b_api_key": { "method": "elicitation/create", "params": { "mode": "url", "url": "https://backend.invalid/ui" } },
                "c_meal": { "method": "elicitation/create", "params": { "message": "Any allergies?" } }
            },
            "requestState": "backend-opaque"
        }))
        .expect("a well-formed interim result");

        let refused = interim
            .undeclared(form_only())
            .expect("the url-mode entry must be refused even though it is neither first nor last");
        assert_eq!(
            refused.key, "b_api_key",
            "the refusal must name WHICH entry it refused; naming any other key means the gate \
             stopped at an entry it should have relayed"
        );
    }
}
