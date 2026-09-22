// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7512 / `MIK-6746.IDENTITY.1` — falsifiers for provable agent identity.
//!
//! Design: `docs/internal/design/2026-09-21-provable-agent-identity.md` plus the
//! 2026-09-22 revision. Every test below names the **funded change** it derives
//! from before its inputs, so a reviewer can check the assertion against the
//! specification and not only against the code.
//!
//! These are the **baseline-compatible** rows: their assertions are expressible
//! against today's types, so their red is interpretable — it says the current
//! code does the wrong thing, not merely that a field is missing. The rows that
//! need the split type (F1, F2's refusal half, F6, F7) arrive with it; they are
//! listed in the design and are NOT stubbed here, because a test that cannot
//! fail for the right reason is not evidence.
//!
//! RED AT `cfea18b8` — expected failures before implementation:
//!
//! * `f4a_declared_label_must_not_satisfy_known_agents`
//! * `f4b_declared_label_must_not_satisfy_require_id`
//! * `f3_unsigned_bearer_must_not_be_proven`
//!
//! Green at `cfea18b8` and must stay green (controls):
//!
//! * `f4_control_anonymous_caller_is_still_accepted`
//! * `f3_control_extraction_ignores_a_token_without_the_claim`

use mcp_gateway::security::{
    AgentIdentity, AgentIdentityConfig, AgentSourceKey, KnownAgent, extract_agent_identity,
    validate_agent_identity,
};

use axum::http::HeaderMap;

/// An `Authorization: Bearer <token>` header and nothing else.
fn bearer_header(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {token}").parse().expect("header value"),
    );
    headers
}

/// `X-Agent-ID: <value>` and nothing else.
fn declared_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", value.parse().expect("header value"));
    headers
}

/// Config with the feature on, an allowlist, and `require_id` off.
fn allowlist_only(agents: &[&str]) -> AgentIdentityConfig {
    AgentIdentityConfig {
        enabled: true,
        require_id: false,
        known_agents: agents
            .iter()
            .map(|a| KnownAgent {
                source: AgentSourceKey::Jwt,
                id: (*a).to_string(),
            })
            .collect(),
        ..AgentIdentityConfig::default()
    }
}

/// Base64url without padding, as a JWT payload segment is encoded.
fn to_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..take {
            let shift = 18 - 6 * i;
            out.push(char::from(ALPHABET[((n >> shift) & 0x3F) as usize]));
        }
    }
    out
}

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
    let config = allowlist_only(&["agent-allowed"]);
    let headers = declared_header("agent-allowed");

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
    let config = AgentIdentityConfig {
        enabled: true,
        require_id: true,
        known_agents: Vec::new(),
        ..AgentIdentityConfig::default()
    };
    let headers = declared_header("some-agent");

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
    let config = allowlist_only(&["agent-allowed"]);
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
    let config = allowlist_only(&["svc-a"]);
    let payload = to_base64url(br#"{"agent_id":"svc-a","sub":"whoever"}"#);
    let token = format!("eyJhbGciOiJub25lIn0.{payload}.not-a-signature");
    // The ONLY way a caller can present a token to this path. There is no
    // longer a bearer parameter to pass one through, which is itself the point:
    // the unsigned decode was deleted, not hardened.
    let headers = bearer_header(&token);

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
    let headers = bearer_header(&token);

    // WHEN: extract
    let identity = extract_agent_identity(&headers, None, None, None);

    // THEN: nothing is invented, on either side of the split
    assert_eq!(
        identity,
        AgentIdentity::default(),
        "an identity was synthesised from a bearer token the gateway never verified"
    );
}
