// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `security::agent_identity`, in their own file so the module
//! stays under the 800-line ceiling. Included via `#[path]`, the same
//! idiom `identity_propagation::caller_proof` uses.

use axum::http::HeaderMap;

use super::*;

pub(super) fn cfg(enabled: bool, require_id: bool, known: &[&str]) -> AgentIdentityConfig {
    AgentIdentityConfig {
        enabled,
        require_id,
        known_agents: known
            .iter()
            .map(|a| KnownAgent {
                source: AgentSourceKey::Jwt,
                id: (*a).to_string(),
            })
            .collect(),
        ..AgentIdentityConfig::default()
    }
}

pub(super) fn header(name: &str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
        value.parse().expect("header value"),
    );
    headers
}

fn cert(san: &[&str], cn: Option<&str>) -> crate::mtls::identity::CertIdentity {
    crate::mtls::identity::CertIdentity {
        common_name: cn.map(String::from),
        san_uris: san.iter().map(|s| (*s).to_string()).collect(),
        // Deliberately set: the selection rule must never reach it.
        display_name: "cosmetic-display-name".to_string(),
        ..Default::default()
    }
}

pub(super) fn proven(id: &str, proof: ProofSource) -> AgentIdentity {
    AgentIdentity {
        proven: Some(ProvenPrincipal::for_test(id, proof)),
        ..AgentIdentity::default()
    }
}

// ── Extraction: the declared label ────────────────────────────────────────

/// Anchor: funded change 1. A header value is a DECLARED label, never a
/// principal.
#[test]
fn header_yields_a_declared_label_and_no_proof() {
    let identity = extract_agent_identity(&header("x-agent-id", "agent-abc-123"), None, None, None);
    assert_eq!(identity.declared_id(), Some("agent-abc-123"));
    assert_eq!(
        identity.declared.as_ref().map(|d| d.source),
        Some(DeclaredSource::Header)
    );
    assert!(
        identity.proven.is_none(),
        "a header must never produce a proven principal"
    );
}

/// Anchor: funded change 1. `Default` is the no-knowledge state.
#[test]
fn nothing_presented_yields_the_default() {
    let identity = extract_agent_identity(&HeaderMap::new(), None, None, None);
    assert_eq!(identity, AgentIdentity::default());
}

/// Anchor: funded change 1.
#[test]
fn query_param_yields_a_declared_label() {
    let identity = extract_agent_identity(
        &HeaderMap::new(),
        Some("agent_id=agent-q1&other=v"),
        None,
        None,
    );
    assert_eq!(identity.declared_id(), Some("agent-q1"));
    assert_eq!(
        identity.declared.as_ref().map(|d| d.source),
        Some(DeclaredSource::QueryParam)
    );
}

/// Ported unchanged: header over query is still the right order *within*
/// the declared label, which is now the only place that comparison lives.
#[test]
fn header_takes_precedence_over_query_within_the_declared_label() {
    let identity = extract_agent_identity(
        &header("x-agent-id", "from-header"),
        Some("agent_id=from-query"),
        None,
        None,
    );
    assert_eq!(identity.declared_id(), Some("from-header"));
}

/// Ported: whitespace is absence.
#[test]
fn whitespace_only_header_is_absent() {
    let identity = extract_agent_identity(&header("x-agent-id", "   "), None, None, None);
    assert!(identity.declared.is_none());
}

// ── Extraction: the proven rungs ──────────────────────────────────────────

/// **INVERTED, NOT PORTED.** The original
/// `extract_from_jwt_claim` built a token with `alg: none` and asserted it
/// resolved to an identity. It encoded the vulnerability as expected
/// behaviour, so a port that kept it green would keep the bug.
///
/// Anchor: funded change 2. There is no unsigned rung. The signature is the
/// only thing that could make a token's claim proof, and this code no
/// longer has a parameter through which a raw token can arrive.
#[test]
fn an_unsigned_bearer_token_proves_nothing() {
    let payload = to_base64url(br#"{"agent_id":"agent-jwt-1","sub":"test"}"#);
    let token = format!("eyJhbGciOiJub25lIn0.{payload}.signature");
    let identity = extract_agent_identity(
        &header("authorization", &format!("Bearer {token}")),
        None,
        None,
        None,
    );
    assert_eq!(
        identity,
        AgentIdentity::default(),
        "an unverified token payload produced an identity"
    );
}

/// Anchor: funded change 2's middle rung. A `sub` the middleware verified
/// IS a proven principal.
#[test]
fn a_verified_subject_is_a_proven_principal() {
    let identity = extract_agent_identity(&HeaderMap::new(), None, None, Some("svc-a"));
    assert_eq!(identity.proven_id(), Some("svc-a"));
    assert_eq!(
        identity.proven.as_ref().map(ProvenPrincipal::proof),
        Some(ProofSource::VerifiedJwtSubject)
    );
}

/// Anchor: the selection rule. First SAN URI wins.
#[test]
fn mtls_selects_the_first_san_uri() {
    let c = cert(&["spiffe://cluster/ns/agents/sa/runner"], Some("runner"));
    let identity = extract_agent_identity(&HeaderMap::new(), None, Some(&c), None);
    assert_eq!(
        identity.proven_id(),
        Some("spiffe://cluster/ns/agents/sa/runner")
    );
    assert_eq!(
        identity.proven.as_ref().map(ProvenPrincipal::proof),
        Some(ProofSource::MutualTls)
    );
}

/// Anchor: the selection rule. CN is the fallback, not the first choice.
#[test]
fn mtls_falls_back_to_the_common_name() {
    let identity = extract_agent_identity(
        &HeaderMap::new(),
        None,
        Some(&cert(&[], Some("runner"))),
        None,
    );
    assert_eq!(identity.proven_id(), Some("runner"));
}

/// Anchor: the selection rule's total form, and T32's falsifier. An
/// unnameable certificate is NOT an identity, and `display_name` must not
/// be reachable — routing a cosmetic audit string here would make it an
/// allowlist key.
#[test]
fn an_unnameable_certificate_is_not_a_principal() {
    let identity = extract_agent_identity(&HeaderMap::new(), None, Some(&cert(&[], None)), None);
    assert!(
        identity.proven.is_none(),
        "a certificate with no SAN URI and no CN produced a principal, which \
         means the display_name fallback is reachable"
    );
}

/// Anchor: funded change 2, rows 7-8. mTLS outranks a verified JWT, and the
/// JWT is kept as secondary proof rather than discarded — without that
/// field the promise to audit it is unimplementable.
#[test]
fn mtls_outranks_a_verified_jwt_and_the_jwt_is_kept() {
    let c = cert(&["spiffe://cluster/a"], None);
    let identity = extract_agent_identity(&HeaderMap::new(), None, Some(&c), Some("svc-b"));
    assert_eq!(identity.proven_id(), Some("spiffe://cluster/a"));
    assert_eq!(
        identity.secondary_proof.as_ref().map(ProvenPrincipal::id),
        Some("svc-b")
    );
    assert_eq!(
        identity
            .secondary_proof
            .as_ref()
            .map(ProvenPrincipal::proof),
        Some(ProofSource::VerifiedJwtSubject)
    );
}

/// Anchor: the structural guard. Ranking is a comparison on the type, so
/// `MutualTls` must sort above `VerifiedJwtSubject` — if a later edit
/// reorders the variants, this fails rather than silently inverting
/// precedence, which is exactly how the original defect was written.
#[test]
fn proof_source_ordering_is_the_ranking() {
    assert!(ProofSource::MutualTls > ProofSource::VerifiedJwtSubject);
}

// ── Validation: no proof ──────────────────────────────────────────────────

/// Ported: the feature flag still exempts request-time enforcement.
#[test]
fn validate_passes_when_feature_disabled() {
    let identity = extract_agent_identity(&header("x-agent-id", "anything"), None, None, None);
    assert!(validate_agent_identity(&identity, &cfg(false, true, &["other"])).is_ok());
}

/// Ported: the row that deliberately does NOT flip. A non-empty
/// `known_agents` has never refused an unidentified caller.
#[test]
fn anonymous_is_accepted_even_with_a_non_empty_allowlist() {
    let identity = AgentIdentity::default();
    assert!(validate_agent_identity(&identity, &cfg(true, false, &["agent-allowed"])).is_ok());
}

/// Ported: nothing presented at all, `require_id` on.
#[test]
fn require_id_refuses_a_caller_that_proved_nothing() {
    let identity = AgentIdentity::default();
    validate_agent_identity(&identity, &cfg(true, true, &[]))
        .expect_err("require_id accepted nothing");
}

/// **INVERTED, NOT PORTED.** The original
/// `validate_empty_known_agents_skips_allowlist_check` built a
/// header-sourced identity with `require_id: true` and asserted it PASSED,
/// on the stated grounds that an empty allowlist applies no filter. That is
/// not why it passed: it passed because a declared label satisfied
/// `require_id`, which is the vulnerability. The name described a different
/// mechanism from the one under test, so the row could not fail for its
/// stated reason.
///
/// Anchor: funded change 3. A label is not an identity.
#[test]
fn an_empty_allowlist_does_not_let_a_label_satisfy_require_id() {
    let identity = extract_agent_identity(&header("x-agent-id", "any-agent"), None, None, None);
    let reason = validate_agent_identity(&identity, &cfg(true, true, &[]))
        .expect_err("a declared label satisfied require_id under an empty allowlist");
    assert!(
        reason.contains("any-agent"),
        "refusal must name the label: {reason}"
    );
}

/// **INVERTED, NOT PORTED.** The original
/// `validate_known_agents_allowlist_passes_for_listed_agent` built
/// `AgentIdentity { id: "agent-allowed", source: IdentitySource::Header }`
/// and asserted the allowlist ACCEPTED it. Its name claims it tests that a
/// listed agent passes; what it actually pinned is that a self-declared
/// header value satisfies the allowlist — the defect this criterion exists
/// to remove.
///
/// Anchor: funded change 3. An allowlist satisfied by self-declaration is
/// not a control.
#[test]
fn a_declared_label_never_satisfies_the_allowlist() {
    let identity = extract_agent_identity(&header("x-agent-id", "agent-allowed"), None, None, None);
    let reason = validate_agent_identity(&identity, &cfg(true, false, &["agent-allowed"]))
        .expect_err("a declared label satisfied known_agents");
    assert!(
        reason.contains("proven"),
        "refusal must name the proven-principal policy: {reason}"
    );
}

// ── Validation: proven principals ─────────────────────────────────────────

/// RE-ANCHORED. The original refusal row used a header-sourced identity, so
/// it passed for a reason its name did not give. Re-pointed at a PROVEN
/// principal, it now tests what it claims: the allowlist filters proof.
#[test]
fn a_proven_principal_outside_the_allowlist_is_refused() {
    let identity = proven("rogue-agent", ProofSource::VerifiedJwtSubject);
    let reason = validate_agent_identity(&identity, &cfg(true, true, &["agent-allowed"]))
        .expect_err("an unlisted proven principal was accepted");
    assert!(reason.contains("rogue-agent"), "{reason}");
}

/// The admitted case, without which the row above passes for an
/// implementation that refuses everyone.
#[test]
fn a_proven_principal_on_the_allowlist_is_accepted() {
    let identity = proven("agent-allowed", ProofSource::VerifiedJwtSubject);
    assert!(validate_agent_identity(&identity, &cfg(true, true, &["agent-allowed"])).is_ok());
}

// ── Validation: contradiction ─────────────────────────────────────────────

fn with_label(mut identity: AgentIdentity, label: &str) -> AgentIdentity {
    identity.declared = Some(DeclaredLabel {
        id: label.to_string(),
        source: DeclaredSource::Header,
    });
    identity
}

/// Anchor: DECISION 7.1 arm 1, ahead of membership. A principal declaring
/// its own name declares the one label that cannot be a lie.
#[test]
fn a_principal_may_always_declare_its_own_name() {
    let identity = with_label(proven("svc-a", ProofSource::VerifiedJwtSubject), "svc-a");
    let mut config = cfg(true, true, &[]);
    config.principal_labels = vec![PrincipalLabels {
        source: ProofSource::VerifiedJwtSubject,
        id: "svc-a".to_string(),
        labels: vec!["billing".to_string()],
    }];
    assert_eq!(
        validate_agent_identity(&identity, &config).expect("own name refused"),
        IdentityAudit::Clean,
        "exact match must run ahead of mapping membership"
    );
}

/// Anchor: funded change 2. A JWT principal declaring a label outside its
/// mapped set is a contradiction.
#[test]
fn a_mapped_principal_may_not_exceed_its_label_set() {
    let identity = with_label(
        proven("svc-a", ProofSource::VerifiedJwtSubject),
        "invoicing",
    );
    let mut config = cfg(true, true, &[]);
    config.principal_labels = vec![PrincipalLabels {
        source: ProofSource::VerifiedJwtSubject,
        id: "svc-a".to_string(),
        labels: vec!["billing".to_string()],
    }];
    let reason = validate_agent_identity(&identity, &config).expect_err("contradiction accepted");
    assert!(
        reason.contains("invoicing") && reason.contains("svc-a"),
        "{reason}"
    );
}

/// Anchor: RULING 3's default. No entry means the principal may declare
/// only its own name; a differing label is never read as "incomparable".
#[test]
fn an_unmapped_jwt_principal_refuses_a_differing_label() {
    let identity = with_label(
        proven("svc-c", ProofSource::VerifiedJwtSubject),
        "something-else",
    );
    validate_agent_identity(&identity, &cfg(true, true, &[]))
        .expect_err("a missing mapping was read as permission");
}

/// The control for the row above: the same unmapped principal, declaring
/// nothing, is accepted. Without it an unconditional backstop would refuse
/// every authenticated request in a deployment that owes no mapping.
#[test]
fn an_unmapped_principal_declaring_nothing_is_accepted() {
    let identity = proven("svc-c", ProofSource::VerifiedJwtSubject);
    assert!(validate_agent_identity(&identity, &cfg(true, true, &[])).is_ok());
}

/// Anchor: RULING 2. The mTLS label namespace is incomparable, so a
/// mismatch is a detection signal rather than a refusal — and it must
/// actually be signalled, or the ruling's audit promise is empty.
#[test]
fn an_mtls_mismatch_is_audited_not_refused() {
    let mut config = cfg(true, true, &[]);
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    let identity = with_label(
        proven(
            "spiffe://cluster/ns/agents/sa/runner",
            ProofSource::MutualTls,
        ),
        "runner",
    );
    assert_eq!(
        validate_agent_identity(&identity, &config).expect("a waived mTLS mismatch was refused"),
        IdentityAudit::DeclaredLabelMismatch,
        "the mismatch was accepted but not signalled"
    );
}

/// The CRITICAL from the focused review on #681: the allowlist was keyed on
/// the identifier string alone, so an mTLS subject and a JWT `sub` that
/// stringify the same were one entry. Both namespaces are live in a single
/// deployment — a verified JWT rides behind an mTLS certificate — so whichever
/// is easier to obtain inherited the other's access.
///
/// Same shape as the STORE.1 defect: two namespaces compared as if they were
/// one.
#[test]
fn an_allowlist_entry_does_not_cross_proof_namespaces() {
    // GIVEN: the allowlist admits the mTLS subject `runner`
    let mut config = cfg(true, true, &[]);
    config.known_agents = vec![KnownAgent {
        source: AgentSourceKey::Mtls,
        id: "runner".to_string(),
    }];

    // WHEN: a caller proves a JWT `sub` that stringifies identically
    let jwt = proven("runner", ProofSource::VerifiedJwtSubject);

    // THEN: refused. String equality across two namespaces is a coincidence,
    // never an identity.
    validate_agent_identity(&jwt, &config)
        .expect_err("a jwt `sub` inherited an mtls subject's allowlist membership");

    // CONTROL: the principal the entry actually names is still admitted, so
    // this row cannot pass for an implementation that refuses everyone.
    let mtls = proven("runner", ProofSource::MutualTls);
    validate_agent_identity(&mtls, &config).expect("the named mTLS subject was refused");
}

/// The MEDIUM from the same review: the mTLS arm short-circuited ahead of the
/// operator mapping, so a per-principal entry for a certificate subject was
/// unreachable in every configuration. The criterion says a contradicting
/// label "is refused rather than silently applied"; for mTLS callers it never
/// was.
#[test]
fn a_named_mtls_subject_refuses_a_contradicting_label() {
    let mut config = cfg(true, true, &[]);
    config.principal_labels = vec![PrincipalLabels {
        source: ProofSource::MutualTls,
        id: "spiffe://cluster/ns/agents/sa/runner".to_string(),
        labels: vec!["runner".to_string()],
    }];
    let identity = with_label(
        proven(
            "spiffe://cluster/ns/agents/sa/runner",
            ProofSource::MutualTls,
        ),
        "billing",
    );

    validate_agent_identity(&identity, &config)
        .expect_err("a mapped mTLS subject accepted a label outside its set");
}

/// The escape hatch the outage argument needs, now gated on the waiver the
/// design always specified.
///
/// RENAMED from `..._keeps_the_incomparable_default`. That name asserted the
/// widened behaviour as the guarantee: acceptance was never a default in any
/// authority above the code. The ruling says a contradicting label "is a
/// REFUSAL, not a silent override"; the design narrowed that to accepted
/// **under a namespace waiver**; the implementation dropped the condition.
/// Each step small, the composition inverting the ruling.
///
/// Without this row the refusal above would be indistinguishable from making
/// every mTLS mismatch a refusal, which is the outage the waiver exists to
/// prevent — so the escape is pinned, and pinned as an opt-in.
#[test]
fn a_waived_namespace_accepts_and_audits_a_mismatch() {
    let mut config = cfg(true, true, &[]);
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    let identity = with_label(
        proven(
            "spiffe://cluster/ns/agents/sa/runner",
            ProofSource::MutualTls,
        ),
        "runner",
    );

    assert_eq!(
        validate_agent_identity(&identity, &config).expect("an unnamed mTLS subject was refused"),
        IdentityAudit::DeclaredLabelMismatch,
        "the mismatch was accepted but not signalled"
    );
}

/// A `principal_labels` entry naming one namespace must not widen the other,
/// for the same reason the allowlist is keyed by a pair.
#[test]
fn a_label_mapping_does_not_cross_proof_namespaces() {
    let mut config = cfg(true, true, &[]);
    config.principal_labels = vec![PrincipalLabels {
        source: ProofSource::VerifiedJwtSubject,
        id: "runner".to_string(),
        labels: vec!["billing".to_string()],
    }];

    // An mTLS subject of the same name is NOT governed by the jwt entry, so it
    // falls through to the incomparable default rather than borrowing the
    // mapping's permission.
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    let identity = with_label(proven("runner", ProofSource::MutualTls), "billing");
    assert_eq!(
        validate_agent_identity(&identity, &config).expect("refused"),
        IdentityAudit::DeclaredLabelMismatch,
        "an mTLS subject was governed by a jwt-keyed mapping"
    );
}

// ── Validation: the migration hatch ───────────────────────────────────────

/// Anchor: the operator ruling's migration clause.
#[test]
fn the_hatch_restores_declared_only_matching() {
    let identity = extract_agent_identity(&header("x-agent-id", "agent-allowed"), None, None, None);
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![KnownAgent {
        source: AgentSourceKey::Declared,
        id: "agent-allowed".to_string(),
    }];
    assert!(validate_agent_identity(&identity, &config).is_ok());
}

/// The other half of the hatch, and the half that makes the row above worth
/// having: turning the flag on adds a `declared` source, it does NOT re-point
/// proven-principal entries at self-declaration.
///
/// Without this, the row above stays green while the escalation it exists to
/// pin is wide open — an operator who set `{source = "jwt", id = "svc-a"}`
/// and then enabled the hatch would find a bare header satisfying it.
#[test]
fn the_hatch_does_not_re_point_a_proven_entry_at_self_declaration() {
    let identity = extract_agent_identity(&header("x-agent-id", "svc-a"), None, None, None);
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![KnownAgent {
        source: AgentSourceKey::Jwt,
        id: "svc-a".to_string(),
    }];
    validate_agent_identity(&identity, &config)
        .expect_err("a declared label matched a jwt-keyed allowlist entry under the hatch");
}

/// Anchor: the hatch restores exactly one behaviour and NOT
/// header-over-proof. With it on, a contradiction is still a refusal.
#[test]
fn the_hatch_does_not_restore_header_over_proof() {
    let identity = with_label(proven("svc-a", ProofSource::VerifiedJwtSubject), "svc-b");
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    validate_agent_identity(&identity, &config)
        .expect_err("the hatch let a header contradict a proven principal");
}

// ── Helpers ───────────────────────────────────────────────────────────────

#[test]
fn percent_decode_handles_encoded_chars() {
    assert_eq!(percent_decode("a%20b"), "a b");
    assert_eq!(percent_decode("plain"), "plain");
}

pub(super) fn to_base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize]));
        }
    }
    out
}

/// The LOW from the final review: the hatch arm sat ahead of the exact-match
/// arm, so a caller declaring **its own true identity** — with that name also
/// listed as a `declared` entry — was recorded as `DeclaredLabelMismatch`.
///
/// A false positive in the exact record funded change 4 requires. A mismatch
/// signal that fires on non-mismatches degrades the thing the clause exists to
/// produce, and this row fails if the arms are ever reordered back.
#[test]
fn a_principal_declaring_its_own_name_is_never_audited_as_a_mismatch() {
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![
        KnownAgent {
            source: AgentSourceKey::Jwt,
            id: "svc-a".to_string(),
        },
        // The caller's own name ALSO listed as a declared entry — the
        // combination that made the hatch arm fire on a truthful label.
        KnownAgent {
            source: AgentSourceKey::Declared,
            id: "svc-a".to_string(),
        },
    ];

    let mut identity = proven("svc-a", ProofSource::VerifiedJwtSubject);
    identity.declared = Some(DeclaredLabel {
        id: "svc-a".to_string(),
        source: DeclaredSource::Header,
    });

    assert_eq!(
        validate_agent_identity(&identity, &config).expect("a truthful label was refused"),
        IdentityAudit::Clean,
        "a principal declaring its own name was audited as a mismatch: the label \
         that cannot be a lie was recorded as one"
    );
}

/// The control: with the arms in this order the hatch arm must still fire for
/// a label that genuinely differs. Without this, the reorder above would be
/// indistinguishable from deleting the hatch arm.
#[test]
fn the_hatch_arm_still_audits_a_genuinely_different_label() {
    let mut config = cfg(true, true, &[]);
    config.allow_unverified_agent_identity = true;
    config.known_agents = vec![
        KnownAgent {
            source: AgentSourceKey::Jwt,
            id: "svc-a".to_string(),
        },
        KnownAgent {
            source: AgentSourceKey::Declared,
            id: "legacy-name".to_string(),
        },
    ];

    let mut identity = proven("svc-a", ProofSource::VerifiedJwtSubject);
    identity.declared = Some(DeclaredLabel {
        id: "legacy-name".to_string(),
        source: DeclaredSource::Header,
    });

    assert_eq!(
        validate_agent_identity(&identity, &config).expect("the operator-listed label was refused"),
        IdentityAudit::DeclaredLabelMismatch,
        "a genuinely different label stopped being audited as a mismatch"
    );
}

/// The restored default, and the row the grade turns on.
///
/// The ruling is unqualified: *"A declared label CONTRADICTING a proven one is
/// a REFUSAL, not a silent override."* With no waiver, an unmapped mTLS
/// principal presenting a differing label is refused — the same as an unmapped
/// JWT principal. Acceptance is an operator's opt-in, never the shipped
/// behaviour.
///
/// This row is red against the implementation that merged as `fdc3f1c0`,
/// which accepted unconditionally on proof source.
#[test]
fn an_unwaived_mtls_mismatch_is_refused_by_default() {
    // No `incomparable_proof_sources`: the operator has claimed nothing.
    let config = cfg(true, true, &[]);
    let identity = with_label(
        proven(
            "spiffe://cluster/ns/agents/sa/runner",
            ProofSource::MutualTls,
        ),
        "runner",
    );

    validate_agent_identity(&identity, &config).expect_err(
        "an unwaived mTLS mismatch was accepted: the ruling says a contradicting \
         label is a refusal, not a silent override, and acceptance without an \
         operator waiver is that silent override",
    );
}

/// A waiver is per-source: waiving one namespace must not waive the other.
///
/// Without this, `incomparable_proof_sources` could be implemented as a single
/// boolean and pass every other row — which would let an operator waiving mTLS
/// silently stop refusing JWT contradictions, the comparable case the ruling
/// most clearly covers.
#[test]
fn waiving_one_namespace_does_not_waive_the_other() {
    let mut config = cfg(true, true, &[]);
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];

    let jwt = with_label(proven("svc-a", ProofSource::VerifiedJwtSubject), "svc-b");
    validate_agent_identity(&jwt, &config)
        .expect_err("waiving the mTLS namespace also waived the JWT namespace");
}

/// A named principal is still governed by its mapping even under a waiver.
///
/// The waiver says the *namespace* is incomparable, which is a claim about
/// identifiers the operator cannot compare. It is not a claim about the
/// subject they just wrote down: an explicit `principal_labels` row is a
/// comparison the operator has made, so arm 2 still decides it. Without this
/// row, a waiver would silently disable every mTLS mapping.
#[test]
fn a_waiver_does_not_disable_an_explicit_mapping() {
    let mut config = cfg(true, true, &[]);
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    config.principal_labels = vec![PrincipalLabels {
        source: ProofSource::MutualTls,
        id: "spiffe://cluster/ns/agents/sa/runner".to_string(),
        labels: vec!["runner".to_string()],
    }];
    let identity = with_label(
        proven(
            "spiffe://cluster/ns/agents/sa/runner",
            ProofSource::MutualTls,
        ),
        "billing",
    );

    validate_agent_identity(&identity, &config)
        .expect_err("a namespace waiver overrode an explicit per-principal mapping");
}
