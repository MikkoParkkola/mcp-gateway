// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-6704 — identity under MCP 2026-07-28.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 7".
//!
//! Negative-first, deliberately. The revision carries caller *context* on every
//! request, and the tempting mistake is to read that as caller *identity*. The
//! specification says clients **SHOULD identify themselves** — identification,
//! not authentication. Any caller can write any name there.
//!
//! So the first thing these tests establish is what `clientInfo` may **not**
//! do, and only then what it is for.

use mcp_gateway::protocol::meta::{RequestShape, classify_request};
use serde_json::json;

fn request_claiming_to_be(name: &str) -> serde_json::Value {
    json!({
        "name": "gateway_kill_server",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": name, "version": "1.0.0" }
        }
    })
}

#[test]
fn ac_ident_1_client_info_is_carried_but_is_not_an_identity() {
    // It parses. It is available. It is a string the caller chose.
    let RequestShape::Modern(fields) =
        classify_request(Some(&request_claiming_to_be("admin")), None)
    else {
        panic!("a request carrying the protocol fields is modern");
    };
    assert_eq!(fields.client_info_name.as_deref(), Some("admin"));

    // And the type offers no way to turn it into an authorization decision:
    // there is no `is_admin`, no `principal`, no `grants` derived from it. The
    // absence is the control. A field that cannot reach an authorization
    // decision cannot be mistaken for one under deadline.
}

#[test]
fn ac_ident_1_two_callers_claiming_the_same_name_are_not_the_same_caller() {
    // The impersonation, made concrete. If `clientInfo` fed identity, these two
    // requests would be indistinguishable — and one of them is whoever asked
    // second.
    let first = classify_request(Some(&request_claiming_to_be("trusted-ops-tool")), None);
    let second = classify_request(Some(&request_claiming_to_be("trusted-ops-tool")), None);

    let (RequestShape::Modern(a), RequestShape::Modern(b)) = (first, second) else {
        panic!("both are modern requests");
    };
    assert_eq!(a.client_info_name, b.client_info_name);
    // Identical context, and nothing in it decides anything. Authorization is
    // settled by the credential the transport authenticated, which neither of
    // these requests carries at all.
}

#[test]
fn ac_ident_2_capabilities_govern_what_a_client_can_receive_not_what_it_can_reach() {
    // A client declaring `sampling` is saying it can *handle* a sampling
    // request. It is not saying it may *invoke* anything, and a server that
    // widened access on a self-declared capability would let any caller widen
    // its own.
    let params = json!({
        "name": "anything",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "sampling": {}, "elicitation": {}, "roots": {}
            }
        }
    });
    let RequestShape::Modern(fields) = classify_request(Some(&params), None) else {
        panic!("modern request");
    };

    assert!(fields.declares_capability("sampling"));
    assert!(
        !fields.declares_capability("admin"),
        "a capability the client did not declare is not declared, whatever else it sent"
    );
}

#[test]
fn ac_ident_2_an_empty_capability_object_declares_it() {
    // `{"sampling": {}}` is how the specification writes a declared capability
    // with no options. Reading an empty object as "absent" would refuse a
    // conforming client.
    let params = json!({
        "name": "t",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": { "sampling": {} }
        }
    });
    let RequestShape::Modern(fields) = classify_request(Some(&params), None) else {
        panic!("modern request");
    };
    assert!(fields.declares_capability("sampling"));
}

#[test]
fn ac_ident_2_a_null_capability_is_not_a_declaration() {
    // `null` is the shape a client sends when it means "not this one". Treating
    // it as present would have the server rely on something the client said it
    // does not have — the exact thing the revision forbids.
    let params = json!({
        "name": "t",
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": { "sampling": null }
        }
    });
    let RequestShape::Modern(fields) = classify_request(Some(&params), None) else {
        panic!("modern request");
    };
    assert!(!fields.declares_capability("sampling"));
}

// ===========================================================================
// MIK-6704.IDENT.1 — the authoritative form of the rule.
//
// The rows above show `clientInfo` is carried and that nothing in its type
// turns it into a decision. This one shows the stronger thing: no code reads it
// at all outside the parser that produces it.
//
// An absence is the right proof here — a positive test would have to enumerate
// every authorization path and would miss the one added next week — and it is a
// terrible thing to leave as an assumption. So it is pinned. The day something
// reads this field, this test says so and names what to check.
// ===========================================================================

#[test]
fn ac_ident_1_no_code_outside_the_parser_reads_the_self_asserted_name() {
    use std::path::Path;

    fn scan(dir: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir)
            .expect("source tree readable")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // The parser owns the field; everywhere else is the finding.
                if path.ends_with("protocol/meta.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for (n, line) in text.lines().enumerate() {
                    if line.contains("client_info_name") {
                        hits.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
    }

    let mut hits = Vec::new();
    scan(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut hits,
    );

    assert!(
        hits.is_empty(),
        "the client's self-asserted name is now read at {hits:?}. It is \
         identification, not authentication — any caller writes any value there. \
         If this is a log or a display, say so at the site and narrow this test. \
         If it reaches an authorization decision, that is the impersonation \
         MIK-7250 was filed for, arriving by a different door."
    );
}

// ===========================================================================
// MIK-6704.IDENT.5 — where an identity cannot be established for a backend
// that requires one, the gateway refuses rather than falling back to a shared
// credential.
//
// Already built, and this pins it. The fallback is the confused deputy: the
// gateway holds a credential with more reach than the caller, and using it on
// the caller's behalf lends that reach to whoever asked.
// ===========================================================================

mod propagation {
    use mcp_gateway::identity_propagation::PropagationError;

    #[test]
    fn ac_ident_5_a_refusal_is_a_refusal_and_not_a_downgrade() {
        // The error type has no "use the shared credential" variant, and that
        // is the control. A downgrade cannot be expressed, so it cannot be
        // reached by an implementer under deadline.
        let refusal = PropagationError::Refuse("no per-user credential".to_string());
        assert!(
            refusal.to_string().contains("fail-closed"),
            "the refusal says what it is, so an operator reading a log knows the \
             call did not quietly proceed: {refusal}"
        );
    }

    #[test]
    fn ac_ident_5_a_failed_audit_write_is_also_fatal() {
        // A minted credential whose audit record was not durably written is a
        // credential nobody can account for afterwards. Treating that as a
        // warning would leave the audit trail claiming less than happened.
        let audit = PropagationError::AuditFailed("transparency log unavailable".to_string());
        assert!(audit.to_string().contains("fail-closed"));
    }
}
