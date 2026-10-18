// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Validating a resolved agent identity against the config: proof outranks
//! assertion, and a contradicting declared label is refused.

use super::{
    AgentIdentity, AgentIdentityConfig, AgentSourceKey, DeclaredLabel, IdentityAudit, KnownAgent,
    ProvenPrincipal,
};

/// Validate a resolved identity against the config.
///
/// Authorization reads [`AgentIdentity::proven`] only. A declared label can
/// never satisfy `require_id` or `known_agents` — unless
/// `allow_unverified_agent_identity` is set, which restores the legacy
/// behaviour and nothing else.
///
/// # Errors
///
/// Returns the refusal reason, which always names the policy that refused so an
/// unrelated 403 cannot be mistaken for this guard.
pub(crate) fn validate_agent_identity(
    identity: &AgentIdentity,
    config: &AgentIdentityConfig,
) -> Result<IdentityAudit, String> {
    if !config.enabled {
        return Ok(IdentityAudit::Clean);
    }

    let Some(proven) = identity.proven.as_ref() else {
        return validate_without_proof(identity, config);
    };

    // The allowlist is a PROVEN-PRINCIPAL allowlist, keyed by the PAIR.
    //
    // Two conflations, not one. The declared label is not consulted, so
    // self-declared membership is unrepresentable — and the proof source is
    // part of the key, so one proven namespace cannot inherit another's
    // membership by stringifying the same. An mTLS CN of `runner` and a JWT
    // `sub` of `runner` are two principals, and both namespaces are live in a
    // single deployment.
    if !config.known_agents.is_empty() && !admits_proven(&config.known_agents, proven) {
        // The hatch fall-through, and it exists because the alternative is
        // perverse. `AgentSourceKey::Declared` matches no `ProofSource`, so
        // without this a caller presenting BOTH proof and a matching declared
        // label fails the pair check and never reaches the declared-entry
        // match — which lives only in the no-proof path. During the very
        // migration the hatch exists to smooth, presenting STRONGER proof
        // would reduce your access relative to presenting none.
        let hatch_admits = config.allow_unverified_agent_identity
            && identity
                .declared
                .as_ref()
                .is_some_and(|declared| admits_declared(&config.known_agents, &declared.id));
        if !hatch_admits {
            return Err(format!(
                "Agent {} (proven via {}) is not in the known_agents allowlist, which admits \
                 proven principals only and matches on the (source, id) pair",
                quoted(proven.id()),
                proven.proof()
            ));
        }
    }

    check_declared_label(proven, identity.declared.as_ref(), config)
}

/// Does the allowlist name this proven principal, by the `(source, id)` pair?
///
/// One predicate, used by every allowlist that keys on a proven principal, so
/// the two cannot drift apart: a fix applied to one and not the other is a
/// finding class this codebase has already produced more than once.
fn admits_proven(entries: &[KnownAgent], proven: &ProvenPrincipal) -> bool {
    entries
        .iter()
        .any(|entry| entry.source.matches(proven.proof()) && entry.id == proven.id())
}

/// Does the allowlist name this caller-supplied label as a `declared` entry?
///
/// Reachable only under `allow_unverified_agent_identity`. A declared label
/// never matches an `mtls` or `jwt` row even with the hatch on, so turning the
/// flag on does not re-point proven-principal entries at self-declaration.
fn admits_declared(entries: &[KnownAgent], label: &str) -> bool {
    entries
        .iter()
        .any(|entry| entry.source == AgentSourceKey::Declared && entry.id == label)
}

/// The no-proof rows. A label is not an identity.
fn validate_without_proof(
    identity: &AgentIdentity,
    config: &AgentIdentityConfig,
) -> Result<IdentityAudit, String> {
    let Some(declared) = identity.declared.as_ref() else {
        // Nothing at all. `require_id` refuses; a non-empty `known_agents`
        // deliberately does NOT — it has never refused an unidentified caller
        // and this change does not start.
        if config.require_id {
            return Err(
                "Request rejected: agent_identity.require_id is true but the request proved no \
                 agent identity. Present a client certificate or a validated agent token; the \
                 X-Agent-ID header is a label and cannot satisfy this policy."
                    .to_string(),
            );
        }
        return Ok(IdentityAudit::Clean);
    };

    if config.allow_unverified_agent_identity {
        // Legacy behaviour, reachable only by explicit opt-in: the declared
        // label may satisfy both controls. It still never outranks a proven
        // principal — that path is not reached from here. And it matches only
        // a `declared` entry: turning the hatch on does not re-point an
        // `mtls` or `jwt` row at self-declaration, so an operator restoring
        // legacy behaviour re-declares those entries and the config records
        // which ones they are.
        if !config.known_agents.is_empty()
            && !config
                .known_agents
                .iter()
                .any(|entry| entry.source == AgentSourceKey::Declared && entry.id == declared.id)
        {
            return Err(format!(
                "Agent label {} is not in the known_agents allowlist as a declared entry",
                quoted(&declared.id)
            ));
        }
        return Ok(IdentityAudit::Clean);
    }

    if config.require_id {
        return Err(format!(
            "Request rejected: agent_identity.require_id is true and {} was only declared (via \
             {}), not proven. A declared label carries no privilege; set \
             agent_identity.allow_unverified_agent_identity to restore the legacy behaviour.",
            quoted(&declared.id),
            declared.source
        ));
    }
    if !config.known_agents.is_empty() {
        return Err(format!(
            "Agent {} was only declared (via {}) and cannot satisfy the known_agents allowlist, \
             which admits proven principals only. An allowlist satisfied by self-declaration is \
             not a control.",
            quoted(&declared.id),
            declared.source
        ));
    }

    // No control is engaged; the label is recorded as telemetry only.
    Ok(IdentityAudit::Clean)
}

/// Is the declared label consistent with the principal that was proven?
///
/// One ordered match; the first arm that fires decides. **The order is the
/// control.** An earlier version of this comment listed the mTLS
/// accept-and-audit arm *ahead* of the mapping arm — which is the ordering
/// that made a per-principal mTLS entry unreachable in every configuration,
/// described here as though it were the design. It is corrected rather than
/// deleted, because the next reader needs to know the ordering is load-bearing
/// and not incidental.
///
/// 1. **Exact match — accept.** A principal is always permitted to declare its
///    own name: the one label that cannot be a lie, so it is a member of its
///    own set by construction and never has to be listed. **First**, ahead of
///    every arm that can emit a mismatch — an earlier order put the hatch arm
///    above it and recorded a caller naming itself as a mismatch, a false
///    positive in the record the criterion requires.
/// 0. **Operator-listed under the hatch — accept and audit.** A `declared`
///    allowlist entry is an explicit statement that this label may be
///    presented. Refusing it as a contradiction would re-open the lockout one
///    step past the allowlist, so proving more would still grant less. Reached
///    only when the label genuinely differs from the proven id.
/// 2. **Operator mapping decides, for EITHER proof source.** Ahead of the mTLS
///    fallback deliberately. `principal_labels` is keyed by `(source, id)` and
///    accepts both variants of [`super::ProofSource`], so an operator who can name a
///    certificate subject gets the contradiction refusal the criterion
///    promises. This arm is why the mTLS refusal path is live config rather
///    than dead code.
/// 3. **Waived namespace — accept and audit.** Reached only when the operator
///    has listed the proof source in `incomparable_proof_sources`, declaring
///    that a SAN URI and a short label cannot be compared in their deployment.
///    An opt-in, never a default: the ruling says a contradicting label is a
///    refusal, and accepting by proof source alone is the silent override it
///    names.
/// 4. **Unmapped JWT — refuse.** The label namespace and the `client_id`
///    namespace are the same kind of name, so a differing label is comparable,
///    and a missing mapping is never read as permission.
fn check_declared_label(
    proven: &ProvenPrincipal,
    declared: Option<&DeclaredLabel>,
    config: &AgentIdentityConfig,
) -> Result<IdentityAudit, String> {
    let Some(declared) = declared else {
        return Ok(IdentityAudit::Clean);
    };

    // Arm 1 — a principal may always declare its own name. The one label that
    // cannot be a lie, so it is a member of its own set by construction.
    //
    // FIRST, ahead of every arm that can emit a mismatch. An earlier order put
    // the hatch arm above this one, so a caller declaring its own true
    // identity — with that name also listed as a `declared` entry — was
    // recorded as `DeclaredLabelMismatch`. That is a false positive in the
    // exact record the criterion requires, and a mismatch signal that fires on
    // non-mismatches degrades the thing the clause exists to produce. Exact
    // equality can never be a lie, so deciding it first weakens nothing below.
    if declared.id == proven.id() {
        return Ok(IdentityAudit::Clean);
    }

    // Arm 0 — the operator wrote this label down.
    //
    // Under the migration hatch, a `declared` allowlist entry is an explicit
    // operator statement that this label may be presented. Refusing it as a
    // contradiction would re-open the lockout one step past the allowlist:
    // the hatch would admit the caller and the contradiction rule would then
    // refuse it, so proving more would still grant less. The mismatch is
    // audited rather than ignored, because by this point the label genuinely
    // differs from the proven id — which is what makes it a real
    // proved-A-claimed-B signal rather than a caller naming itself.
    if config.allow_unverified_agent_identity && admits_declared(&config.known_agents, &declared.id)
    {
        return Ok(IdentityAudit::DeclaredLabelMismatch);
    }

    // Arm 2 — an operator-written mapping decides, for EITHER proof source.
    //
    // This runs ahead of the mTLS fallback deliberately. With the order
    // reversed, an mTLS principal short-circuited to "accepted and audited"
    // before the mapping was consulted, which made a per-principal entry for a
    // certificate subject unreachable in every configuration — the criterion
    // says a contradicting label "is refused rather than silently applied",
    // and for mTLS callers it never was. An operator who can name a subject
    // can now get that refusal; one who cannot waives the namespace instead
    // below.
    if let Some(entry) = config
        .principal_labels
        .iter()
        .find(|entry| entry.source == proven.proof() && entry.id == proven.id())
    {
        if entry.labels.iter().any(|label| label == &declared.id) {
            return Ok(IdentityAudit::Clean);
        }
        return Err(contradiction(declared, proven));
    }

    // Arm 3 — the operator has WAIVED this namespace as incomparable.
    //
    // Gated on the waiver, not on the proof source. An unconditional version
    // of this arm is how the ruling got inverted: it says a contradicting
    // label "is a REFUSAL, not a silent override", and accepting every
    // unmapped mTLS mismatch by default is the silent override it names. The
    // design's acceptance was always conditioned on a waiver — that condition
    // is what makes the reasoning valid, because incomparability is a claim
    // only the operator can make about their own deployment.
    //
    // With the waiver, a SAN URI and a short label genuinely cannot be
    // compared, so nothing *contradicts* and the mismatch is recorded as a
    // detection signal. Without it, this falls through and refuses.
    if config.incomparable_proof_sources.contains(&proven.proof()) {
        return Ok(IdentityAudit::DeclaredLabelMismatch);
    }

    // Arm 4 — unmapped JWT: the label namespace and the `client_id` namespace
    // are the same kind of name, so a differing label is comparable, and a
    // missing mapping is never read as permission.
    Err(contradiction(declared, proven))
}

/// Render a caller-supplied value safely for a refusal message.
///
/// The refusal string reaches an operator's log and the identity audit record.
/// A raw `X-Agent-ID` carrying a newline can therefore forge a log line inside
/// the audit trail — which is worse than leaking the label, because the record
/// this criterion exists to make trustworthy is the thing being falsified.
///
/// `escape_debug` renders control characters as escapes and leaves ordinary
/// text readable, so an operator still sees the label they configured.
fn quoted(value: &str) -> String {
    format!("'{}'", value.escape_debug())
}

/// The refusal a contradicting declared label earns.
///
/// The caller-supplied value is rendered inside single quotes and is the only
/// untrusted text here; it reaches an operator log and a JSON-RPC error
/// message, never a shell or a query.
fn contradiction(declared: &DeclaredLabel, proven: &ProvenPrincipal) -> String {
    format!(
        "Request rejected: the declared agent label {} (via {}) contradicts the proven \
         principal {} (via {}). Add it to agent_identity.principal_labels for that principal \
         if this caller is entitled to declare it.",
        quoted(&declared.id),
        declared.source,
        quoted(proven.id()),
        proven.proof()
    )
}
