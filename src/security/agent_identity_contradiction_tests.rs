// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security::agent_identity` validation when a proven principal and its
//! declared label disagree: what is refused, what is only audited, and how
//! proof namespaces stay apart (moved from `agent_identity_tests.rs`).

use super::*;

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
    // falls through to the WAIVED arm rather than borrowing the mapping's
    // permission — which is why this fixture has to declare the waiver on the
    // next line. Acceptance is never a default: with the waiver omitted this
    // caller is refused, which is what `an_unwaived_mtls_mismatch_is_refused_
    // by_default` pins.
    config.incomparable_proof_sources = vec![ProofSource::MutualTls];
    let identity = with_label(proven("runner", ProofSource::MutualTls), "billing");
    assert_eq!(
        validate_agent_identity(&identity, &config).expect("refused"),
        IdentityAudit::DeclaredLabelMismatch,
        "an mTLS subject was governed by a jwt-keyed mapping"
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
