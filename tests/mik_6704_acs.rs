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

    const LABEL_ONLY_MARKER: &str = "MIK-6704: label only";

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
                let lines: Vec<&str> = text.lines().collect();
                for (n, line) in lines.iter().enumerate() {
                    if !line.contains("client_info_name") {
                        continue;
                    }
                    // A read declared at the site as a label is allowed; the
                    // marker is what makes the use reviewable. An undeclared
                    // read is the finding, wherever it lives.
                    let declared = lines[n.saturating_sub(3)..=n]
                        .iter()
                        .any(|l| l.contains(LABEL_ONLY_MARKER));
                    if !declared {
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
         If this is a log or a display, mark the site `MIK-6704: label only`. \
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

// ===========================================================================
// MIK-6704.IDENT.1a — authorization derives from the authenticated credential.
//
// Its rows read `AuthenticatedClient.principal`, which is crate-private since
// MIK-8697, so they live in src/gateway/auth/tests/principal_ident_tests.rs.
// ===========================================================================

// ===========================================================================
// MIK-6704.IDENT.1a — and every construction site, not only the ones tested.
//
// The rows in src/gateway/auth/tests/principal_ident_tests.rs prove the
// property at the two arms reachable from a test binary. Two more arms — the temporary token and the delegated OIDC bearer —
// live behind `KeyServer`, whose token store is private and whose bearer path
// needs a signed assertion from a real issuer; neither is constructible here.
// They are covered by this guard instead, and so is the arm added next week.
//
// Two sites are deliberately not credential-digests, and the reason is
// recorded rather than the site quietly skipped:
//
//   * `dashboard_client` carries a compile-time constant. A dashboard session
//     cookie is an opaque handle checked against this process's own store, not
//     a credential to digest, and one process has exactly one such identity —
//     it cannot collide with an operator-chosen name because it is not in that
//     namespace.
//   * the delegated OIDC arm digests its own `name`, which looks like the
//     defect and is not: that name is the issuer and subject of a *verified*
//     assertion, not operator-chosen text. `oidc_client_identity_key` is what
//     makes it collision-safe, and `key_server::tests::
//     oidc_client_identity_key_uses_issuer_and_subject_not_email` pins it.
//
// An empty principal is allowed anywhere: it is the form that says no
// credential was presented, and the row above pins what must accompany it.
// ===========================================================================

#[test]
fn ac_ident_1a_every_identity_derives_its_principal_from_a_credential() {
    use std::path::Path;

    const MARKER: &str = "MIK-6704.IDENT.1a:";
    // The dashboard session handle, reasoned about in the block above.
    const DECLARED_CONSTANTS: &[&str] = ["dashboard-session"].as_slice();

    fn scan(dir: &Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir)
            .expect("source tree readable")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, hits);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") || path.ends_with("tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                // The literal, not the type's own definition, its impl, or a
                // function whose return type it merely is: `-> AuthenticatedClient {`
                // opens a body, not an identity. Only the return signature is
                // discounted, so a constructor sharing that line still counts.
                let constructors = line.replace("-> AuthenticatedClient {", "");
                if !constructors.contains("AuthenticatedClient {")
                    || line.contains("struct AuthenticatedClient")
                    || line.contains("impl AuthenticatedClient")
                {
                    continue;
                }
                // The field is near the top of every literal in this repo; a
                // literal that hides it further down reads as unclassified,
                // which is the finding either way.
                let end = (n + 20).min(lines.len());
                let Some((f, field)) = lines[n..end]
                    .iter()
                    .enumerate()
                    // The field itself, not a qualified sibling such as
                    // `quota_principal:`, which would otherwise be found first.
                    .find(|(_, l)| l.trim_start().starts_with("principal:"))
                else {
                    hits.push(format!("{}:{} (no principal field)", path.display(), n + 1));
                    continue;
                };
                let at = n + f;
                let declared = lines[at.saturating_sub(3)..=at]
                    .iter()
                    .any(|l| l.contains(MARKER));
                let derived = field.contains("principal_of(")
                    || field.contains("String::new()")
                    || DECLARED_CONSTANTS.iter().any(|c| field.contains(c));
                if !derived && !declared {
                    hits.push(format!("{}:{} {}", path.display(), at + 1, field.trim()));
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
        "an identity is built whose principal is not derived from the \
         credential that was validated: {hits:?}. `name` will not do — it is \
         operator-chosen, two entries may share one, and authorization keyed \
         on it lets either attach to the other's session. Derive it with \
         `principal_of` over the secret, leave it empty for an identity that \
         presented none, or declare the site `{MARKER} <why>` so the exception \
         is reviewable."
    );
}
