// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MIK-7512 falsifiers, in their own file.
//!
//! Split from the module's unit tests because the combined file crossed the
//! 800-line ceiling, and a new offender cannot be baselined away. The seam
//! is the one that was already there: these five were integration tests
//! until the resolution path went crate-private, and they carry their own
//! red-before-green provenance, which the rows beside them do not.

use axum::http::HeaderMap;

use super::tests::{cfg, header, proven, to_base64url};
use super::*;

// ── MIK-7512 falsifiers, moved in-crate ───────────────────────────────────
//
// These five were integration tests while the resolution path was public.
// Making it crate-private closed the extractor route a review found — an
// external caller could mint a `ProvenPrincipal` by passing any string as
// `verified_jwt_subject` — and the falsifiers moved with the API they test.
//
// Their provenance is the reason the file kept them rather than folding them
// into the rows above. Demonstrated RED before any implementation existed, at
// `cfea18b8`, each for its stated reason:
//
// * `f4a_declared_label_must_not_satisfy_known_agents` — the allowlist
//   compared the conflated id and never read the source
// * `f4b_declared_label_must_not_satisfy_require_id` — a label satisfied
//   `require_id`
// * `f3_unsigned_bearer_must_not_be_proven` — an `alg: none` token resolved
//   to an identity
//
// Both controls were green throughout, which is what makes those three reds
// evidence rather than an artifact of refusing everything.

// ── F4 — funded change 3 ──────────────────────────────────────────────────────
//
// "known_agents APPLIES TO PROVEN IDENTITIES ONLY. A declared-only label can
//  never satisfy it, and never satisfies require_id."

/// F4(a). A caller-supplied `X-Agent-ID` naming an allowlisted agent, with no
/// mTLS and no verified JWT, must be REFUSED: the allowlist is not satisfiable
/// by self-declaration.
///
/// RED at `cfea18b8`: `validate_agent_identity` compares the conflated
/// `identity.id` against `known_agents` (`agent_identity.rs:161`) without ever
/// reading `identity.source`, so the header value satisfies the allowlist.
#[test]
fn f4a_declared_label_must_not_satisfy_known_agents() {
    // GIVEN: an allowlist naming `agent-allowed`, and a caller that merely says so
    let config = cfg(true, false, &["agent-allowed"]);
    let headers = header("x-agent-id", "agent-allowed");

    // WHEN: the identity is extracted and validated, as both routes do
    let identity = extract_agent_identity(&headers, None, None, None);
    let verdict = validate_agent_identity(&identity, &config);

    // THEN: refused, and the message names the proven-principal policy rather
    // than only saying "forbidden" — an unrelated 403 must not mask a missing guard
    let reason = verdict.expect_err(
        "a declared-only label satisfied known_agents: the allowlist is an \
         unauthenticated string match",
    );
    assert!(
        reason.contains("proven"),
        "refusal must name the proven-principal policy, got: {reason}"
    );
}

/// F4(b). `require_id = true` with only a declared label must be REFUSED: a
/// label is not an identity.
///
/// RED at `cfea18b8`: the `let`-`else` at `agent_identity.rs:150` sees `Some`
/// and falls through to the allowlist check, which is skipped when the list is
/// empty, so the request is accepted.
#[test]
fn f4b_declared_label_must_not_satisfy_require_id() {
    // GIVEN: require_id on, no allowlist, and a caller that only declares a label
    let config = cfg(true, true, &[]);
    let headers = header("x-agent-id", "some-agent");

    // WHEN: extract then validate
    let identity = extract_agent_identity(&headers, None, None, None);
    let verdict = validate_agent_identity(&identity, &config);

    // THEN: refused — require_id demands proof, not a tag
    verdict.expect_err(
        "a declared-only label satisfied require_id: an unproven tag was accepted \
         as an identity",
    );
}

/// F4 control. An ANONYMOUS caller against a non-empty `known_agents` with
/// `require_id = false` is accepted today and must stay accepted.
///
/// This is the row that deliberately does NOT flip (`agent_identity.rs:158`
/// returns before the allowlist at `:161`). Without it, an implementation may
/// tighten the anonymous case as a side effect and break deployments that never
/// had that control and were never promised it. It is also what stops F4(a) and
/// F4(b) passing for an implementation that simply refuses everything.
#[test]
fn f4_control_anonymous_caller_is_still_accepted() {
    // GIVEN: a non-empty allowlist, require_id off, and a caller presenting nothing
    let config = cfg(true, false, &["agent-allowed"]);
    let headers = HeaderMap::new();

    // WHEN: extract then validate
    let identity = extract_agent_identity(&headers, None, None, None);
    assert_eq!(
        identity,
        AgentIdentity::default(),
        "a caller presenting nothing must resolve to no proof and no label"
    );
    let verdict = validate_agent_identity(&identity, &config);

    // THEN: accepted, unchanged
    verdict.expect(
        "an anonymous caller was refused: a non-empty known_agents has never \
         refused an unidentified caller and must not start",
    );
}

// ── F3 — funded change 2's middle rung ────────────────────────────────────────
//
// "mTLS > verified JWT claim > declared label". A base64 decode of a JWT
// payload without signature verification is not proof of anything.

/// F3. An unsigned three-segment bearer string carrying `agent_id`, with
/// `alg: none`, must NOT yield a proven identity and must not satisfy
/// `known_agents`.
///
/// RED at `cfea18b8`: `extract_jwt_agent_id` (`agent_identity.rs:187-196`)
/// splits on `.`, base64-decodes segment 1 and reads `agent_id` with no
/// signature check and no call into `validate_agent_token`, so an arbitrary
/// minted string is accepted.
///
/// This row is the one most likely to be dropped once the unsigned decode is
/// deleted, on the grounds that it became redundant. It did not: it pins that
/// the deletion happened.
#[test]
fn f3_unsigned_bearer_must_not_be_proven() {
    // GIVEN: an allowlist, and a token nobody signed that claims to be on it
    let config = cfg(true, false, &["svc-a"]);
    let payload = to_base64url(br#"{"agent_id":"svc-a","sub":"whoever"}"#);
    let token = format!("eyJhbGciOiJub25lIn0.{payload}.not-a-signature");
    // The ONLY way a caller can present a token to this path. There is no
    // longer a bearer parameter to pass one through, which is itself the point:
    // the unsigned decode was deleted, not hardened.
    let headers = header("authorization", &format!("Bearer {token}"));

    // WHEN: extract then validate, exactly as the dispatch routes do.
    // No cert and no verified `sub`: this caller proved nothing.
    let identity = extract_agent_identity(&headers, None, None, None);
    let verdict = validate_agent_identity(&identity, &config);

    // THEN: the unsigned claim is not a proven identity, so it cannot satisfy
    // the allowlist. Either it never becomes an identity at all, or it is
    // refused — both are correct; being ACCEPTED is the defect.
    assert!(
        identity.proven.is_none(),
        "an unsigned, unverified token produced a PROVEN principal: the payload \
         was read without checking the signature"
    );
    verdict.expect(
        "a caller that proved nothing was refused: with require_id off and the \
         token proving nothing, there is no identity to refuse and no control engaged",
    );
}

/// F3 control. Extraction must still ignore a token that carries no `agent_id`
/// at all, rather than inventing one — green today and must stay green.
///
/// Without a control on this side, F3 is satisfied by an implementation that
/// refuses every bearer token, which would be a different bug.
#[test]
fn f3_control_extraction_ignores_a_token_without_the_claim() {
    // GIVEN: a token with no agent_id claim
    let payload = to_base64url(br#"{"sub":"user","iat":1234567890}"#);
    let token = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
    let headers = header("authorization", &format!("Bearer {token}"));

    // WHEN: extract
    let identity = extract_agent_identity(&headers, None, None, None);

    // THEN: nothing is invented, on either side of the split
    assert_eq!(
        identity,
        AgentIdentity::default(),
        "an identity was synthesised from a bearer token the gateway never verified"
    );
}

/// The HIGH from the second focused review: the migration hatch locked out
/// callers who HAD proven themselves.
///
/// `AgentSourceKey::Declared` matches no `ProofSource`, so a caller presenting
/// both proof and a matching declared label failed the pair check and never
/// reached the declared-entry match — which lived only in the no-proof path.
/// The result was perverse in exactly the window the hatch exists to smooth:
/// **presenting stronger proof reduced your access relative to presenting
/// none.**
#[test]
fn the_hatch_does_not_lock_out_a_caller_who_also_proved_itself() {
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![KnownAgent {
        source: AgentSourceKey::Declared,
        id: "legacy-agent".to_string(),
    }];

    // A caller that proves nothing and declares the listed label is admitted.
    let unproven = extract_agent_identity(&header("x-agent-id", "legacy-agent"), None, None, None);
    validate_agent_identity(&unproven, &config).expect("the unproven caller was refused");

    // The SAME caller, now also presenting proof, must not be worse off.
    let mut proven_too = proven("svc-a", ProofSource::VerifiedJwtSubject);
    proven_too.declared = Some(DeclaredLabel {
        id: "legacy-agent".to_string(),
        source: DeclaredSource::Header,
    });
    validate_agent_identity(&proven_too, &config).expect(
        "a caller that proved itself was refused where the same caller presenting NO proof \
         was admitted: proving more must never grant less",
    );
}

/// The control for the row above, so the fall-through cannot become a blanket
/// accept: with the hatch on, a proven principal outside the allowlist and
/// carrying a label that is ALSO not listed is still refused.
#[test]
fn the_hatch_fall_through_still_requires_a_listed_label() {
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![KnownAgent {
        source: AgentSourceKey::Declared,
        id: "legacy-agent".to_string(),
    }];

    let mut identity = proven("svc-a", ProofSource::VerifiedJwtSubject);
    identity.declared = Some(DeclaredLabel {
        id: "not-listed".to_string(),
        source: DeclaredSource::Header,
    });
    validate_agent_identity(&identity, &config)
        .expect_err("the hatch fall-through admitted an unlisted label");
}

/// The LOW-but-concrete from the same review: a caller-controlled label was
/// interpolated raw into refusal strings, which reach the operator log and the
/// identity audit record. A crafted `X-Agent-ID` carrying a newline could
/// forge a log line INSIDE the audit trail — falsifying the very record this
/// criterion exists to make trustworthy, which is worse than leaking a label.
#[test]
fn a_crafted_label_cannot_forge_a_line_in_the_audit_trail() {
    let config = cfg(true, true, &[]);
    // NOT via `X-Agent-ID`: axum refuses a header value carrying a raw
    // newline, so that vector does not exist. The query parameter does, and
    // it is the worse one to spot, because `percent_decode` turns `%0A` into
    // a real newline AFTER the transport has done its validation.
    let identity = extract_agent_identity(
        &HeaderMap::new(),
        Some("agent_id=evil%0Aagent_proven=admin%20agent_proof=mtls"),
        None,
        None,
    );
    assert!(
        identity.declared_id().is_some_and(|d| d.contains('\n')),
        "the fixture must actually deliver a newline, or the assertion below is vacuous"
    );

    let reason = validate_agent_identity(&identity, &config)
        .expect_err("a declared-only label satisfied require_id");

    assert!(
        !reason.contains('\n'),
        "the refusal carried a raw newline, so a caller can inject a line into \
         the audit trail: {reason:?}"
    );
    assert!(
        reason.contains("\\n"),
        "the newline should be rendered as an escape, not dropped — an operator \
         must still see what was sent: {reason:?}"
    );
}
