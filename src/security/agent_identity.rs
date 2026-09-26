// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Per-agent identity verification (OWASP ASI03 — Identity and Privilege Abuse).
//!
//! Closes the gap where any valid session token grants the same access regardless
//! of which agent is calling.  This module provides identity *plumbing*: extraction,
//! optional enforcement, and structured audit logging.  Full IAM is out of scope.
//!
//! # Proof outranks assertion
//!
//! Three inputs, two kinds. The **proven** principal is whichever of these the
//! request established, ranked by [`ProofSource`]'s `Ord` and not by the order
//! anything is checked in:
//!
//! 1. mTLS client-certificate subject — first SAN URI, else CN, else no mTLS
//!    principal at all.
//! 2. Verified JWT `sub`, taken from a token the agent-auth middleware already
//!    validated against registered key material.
//!
//! The **declared** label is the `X-Agent-ID` header, else the `agent_id` query
//! parameter. It is telemetry and cost attribution only. It can never become
//! the principal, never satisfy `require_id`, and never satisfy `known_agents`
//! — an allowlist satisfied by self-declaration is not a control.
//!
//! A declared label that **contradicts** the proven principal is refused, for
//! either proof source. Acceptance is reachable only where the operator has
//! declared the namespaces incomparable, which is a claim about their own
//! deployment that only they can make.
//!
//! There is deliberately no unsigned-token rung. A base64 decode of a JWT
//! payload with no signature check is not proof of anything; it is the caller's
//! own assertion in a format that looks authoritative, which is worse than an
//! unadorned header because it reads as verified.
//!
//! # Configuration
//!
//! ```yaml
//! security:
//!   agent_identity:
//!     enabled: false       # opt-in; enforcement is a no-op when false
//!     require_id: false    # when true, requests that prove no agent are rejected
//!     known_agents: []     # optional allowlist of accepted PROVEN principals
//!     allow_unverified_agent_identity: false  # legacy: a label may satisfy the above
//!     principal_labels: []                    # opt-in: extra labels a principal may declare
//!     incomparable_proof_sources: []          # opt-in: namespaces a label cannot be compared to
//! ```
//!
//! `known_agents` is a **proven-principal** allowlist: when non-empty, a proven
//! principal outside the list is rejected, independently of `require_id`, which
//! governs only the no-proof case. An anonymous caller is unaffected by a
//! non-empty `known_agents` — that has never been a refusal and is not one now.

use serde::{Deserialize, Serialize};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Per-agent identity configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentIdentityConfig {
    /// Enable agent identity extraction and enforcement.  Default: `false`.
    pub enabled: bool,
    /// When `true`, requests without a resolvable `agent_id` are rejected.
    /// Only meaningful when `enabled = true`.  Default: `false`.
    pub require_id: bool,
    /// Allowlist of accepted **proven principals**, keyed by `(source, id)`.
    ///
    /// Keyed by the pair, never the bare identifier. An mTLS subject and a JWT
    /// `sub` that happen to stringify the same are **not** the same principal:
    /// string equality across two namespaces is a coincidence, never an
    /// identity. Both namespaces are live in one deployment — a verified JWT
    /// can ride behind an mTLS certificate — so a bare-identifier allowlist
    /// lets whichever namespace is easier to obtain inherit the other's
    /// access.
    ///
    /// A bare-string entry is a **load error** naming the source it must
    /// declare, never a silently widened match.
    #[serde(default)]
    pub known_agents: Vec<KnownAgent>,
    /// Restore the pre-4.0.0 behaviour in which a caller-supplied label may
    /// satisfy `require_id` and `known_agents`.  Default: `false`.
    ///
    /// The gateway warns at startup when this is set, naming the control it
    /// weakens.  It restores exactly one behaviour and **not**
    /// header-over-proof: with this set a declared label still never outranks a
    /// proven principal, and a contradiction is still a refusal.
    #[serde(default)]
    pub allow_unverified_agent_identity: bool,
    /// Labels a proven principal is permitted to declare, beyond its own name.
    ///
    /// Opt-in widening, not a mandatory census: a principal with no entry may
    /// declare only its own id, which is the one label that cannot be a lie.
    ///
    /// Keyed by `(source, id)`, and **both proof sources may be keyed here** —
    /// an earlier version of this doc said the mTLS namespace "is never keyed
    /// here", which contradicted the implementation and made the mTLS refusal
    /// path dead config: an operator reading it would never write the row that
    /// enables it.
    ///
    /// An mTLS subject with no entry is **refused** on a differing label, the
    /// same as an unmapped JWT principal, unless the operator has waived the
    /// namespace via `incomparable_proof_sources`. An earlier version of this
    /// doc called acceptance "the default", which was the widening this field
    /// exists to undo: no authority above the code ever made it one. The id
    /// must be the **selected** proven id — first SAN URI, else CN — never a
    /// DN fragment: `id = "CN=runner"` mints a row that can never match.
    #[serde(default)]
    pub principal_labels: Vec<PrincipalLabels>,
    /// Proof sources whose identifiers the operator declares **incomparable**
    /// with a declared label.
    ///
    /// Empty by default, and the emptiness is the point. The ruling this
    /// module implements says a declared label contradicting a proven one
    /// "is a REFUSAL, not a silent override", with no proof-source
    /// qualification. The design narrowed that to "accepted **under a
    /// namespace waiver**", which is sound — if two namespaces are genuinely
    /// incomparable then nothing *contradicts* and the clause does not bite —
    /// but it is conditioned on a waiver the operator grants.
    ///
    /// An earlier implementation dropped the condition and made acceptance the
    /// default for mTLS. The chain ran **refuse → refuse unless waived →
    /// accept by default**: each step small, the composition inverting the
    /// ruling, and a waiver an operator *grants* becoming one they must
    /// *override*. This field restores the condition.
    ///
    /// Listing `mtls` here states that a SAN URI and a short label cannot be
    /// compared, so a mismatch is recorded as a detection signal rather than
    /// refused. It is per-source: waiving one namespace never waives the
    /// other.
    #[serde(default)]
    pub incomparable_proof_sources: Vec<ProofSource>,
}

/// One allowlist entry: a proof source and the identifier it admits.
///
/// Deserialized from `{ source = "mtls" | "jwt" | "declared", id = "..." }`.
/// The three-valued key is deliberately **not** [`ProofSource`], which has two
/// variants because only two things constitute proof. `Declared` exists solely
/// so the migration hatch has something to match against, and it is a load
/// error unless `allow_unverified_agent_identity` is set — an operator cannot
/// reach declared-label matching without also setting the flag that warns
/// about it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "serde_json::Value")]
pub struct KnownAgent {
    /// Which namespace the identifier belongs to.
    pub source: AgentSourceKey,
    /// The identifier, within that namespace.
    pub id: String,
}

/// The accepted shape, parsed after the bare-string check below.
#[derive(Deserialize)]
struct QualifiedKnownAgent {
    source: AgentSourceKey,
    id: String,
}

impl TryFrom<serde_json::Value> for KnownAgent {
    type Error = String;

    /// A bare string would otherwise fail as serde's generic "expected struct",
    /// which does not say what to write instead.
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        if let serde_json::Value::String(id) = &value {
            return Err(format!(
                "known_agents entry {id:?} must declare its proof source: write \
                 {{source: mtls, id: {id:?}}} or {{source: jwt, id: {id:?}}}"
            ));
        }
        let QualifiedKnownAgent { source, id } =
            serde_json::from_value(value).map_err(|e| format!("known_agents entry: {e}"))?;
        Ok(Self { source, id })
    }
}

impl AgentIdentityConfig {
    /// A `declared` allowlist entry is enforceable only under the hatch, so
    /// with enforcement on and the hatch off it refuses load rather than
    /// sitting inert until a request finds it. With enforcement off it is
    /// dormant and only warned about.
    pub(crate) fn validate(&self) -> crate::Result<()> {
        let declared: Vec<&str> = self
            .known_agents
            .iter()
            .filter(|entry| entry.source == AgentSourceKey::Declared)
            .map(|entry| entry.id.as_str())
            .collect();
        if declared.is_empty() || self.allow_unverified_agent_identity {
            return Ok(());
        }
        if !self.enabled {
            tracing::warn!(
                entries = ?declared,
                "agent_identity.known_agents has declared entries, dormant while agent_identity \
                 is disabled; enabling it without allow_unverified_agent_identity refuses them"
            );
            return Ok(());
        }
        Err(crate::Error::ConfigValidation(format!(
            "agent_identity.known_agents entries {declared:?} use source: declared, which only \
             agent_identity.allow_unverified_agent_identity: true admits; key them by mtls or \
             jwt, or set the flag"
        )))
    }
}

/// The namespace an allowlist entry names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentSourceKey {
    /// An mTLS client-certificate subject.
    Mtls,
    /// A verified JWT `sub`.
    Jwt,
    /// A caller-supplied label. Reachable only under the migration hatch, and
    /// unrepresentable anywhere authorization reads proof.
    Declared,
}

impl AgentSourceKey {
    /// Does this key name the namespace a proven principal came from?
    fn matches(self, proof: ProofSource) -> bool {
        matches!(
            (self, proof),
            (Self::Mtls, ProofSource::MutualTls) | (Self::Jwt, ProofSource::VerifiedJwtSubject)
        )
    }
}

/// The declared labels one proven principal may present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalLabels {
    /// Which namespace [`Self::id`] belongs to.
    ///
    /// Present for the same reason `known_agents` is keyed by a pair: an mTLS
    /// subject and a JWT `sub` that stringify the same are two principals, and
    /// an entry naming one must not widen the other.
    pub source: ProofSource,
    /// The proven principal this entry governs.
    pub id: String,
    /// Labels this principal may declare in addition to its own id.
    #[serde(default)]
    pub labels: Vec<String>,
}

// ── Extraction ────────────────────────────────────────────────────────────────

/// Resolve the calling agent's identity from what the request proved and what
/// it merely claimed.
///
/// Always returns a value: "no identity at all" is `AgentIdentity::default()`,
/// which removes the `Option<Option<..>>` awkwardness at the call sites and
/// makes the refusal logic a total match.
///
/// # Ranking
///
/// Proof outranks assertion, and stronger proof outranks weaker, by
/// [`ProofSource`]'s `Ord` rather than by the order these branches are written
/// in. The declared label never becomes the principal.
///
/// The mTLS subject is selected here rather than by the caller so the selection
/// rule lives in one place: first SAN URI, else CN, else no mTLS principal.
/// **Crate-private by design.** The `verified_jwt_subject` parameter is a raw
/// `&str`, so a public version of this function would mint a
/// `ProvenPrincipal` from any string an external caller chose — bypassing the
/// private constructor entirely. Making the constructor private while leaving
/// the public function that calls it open would close one door and leave the
/// next one ajar, which is the shape this module has already had to fix twice.
///
/// The contract, not the call site, is what binds an external caller: "this
/// gateway never passes a caller-supplied string here" is true of the two
/// router sites and says nothing about anyone else.
#[must_use]
pub(crate) fn extract_agent_identity(
    headers: &axum::http::HeaderMap,
    query: Option<&str>,
    cert_identity: Option<&crate::mtls::identity::CertIdentity>,
    verified_jwt_subject: Option<&str>,
) -> AgentIdentity {
    // Proven rungs. Both inputs are already verified: `cert_identity` comes
    // from the TLS handshake's peer chain, and `verified_jwt_subject` is the
    // `sub` of a token `validate_agent_token` accepted. Neither is parsed out
    // of a caller-supplied string here, which is the whole point.
    let mtls = cert_identity
        .and_then(select_mtls_subject)
        .map(|id| ProvenPrincipal::new(id, ProofSource::MutualTls));
    let jwt = verified_jwt_subject
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| ProvenPrincipal::new(s.to_string(), ProofSource::VerifiedJwtSubject));

    // Rank by the type, not by position: swapping these two bindings must not
    // change the outcome, which is what `ProofSource: Ord` buys.
    let (proven, secondary_proof) = match (mtls, jwt) {
        (Some(a), Some(b)) => {
            if a.proof() >= b.proof() {
                (Some(a), Some(b))
            } else {
                (Some(b), Some(a))
            }
        }
        (Some(only), None) | (None, Some(only)) => (Some(only), None),
        (None, None) => (None, None),
    };

    // Declared label: header first, then query. That order is still correct
    // *within* the declared label, which is the only place it now applies.
    let declared = extract_from_header(headers)
        .map(|id| DeclaredLabel {
            id,
            source: DeclaredSource::Header,
        })
        .or_else(|| {
            query.and_then(extract_from_query).map(|id| DeclaredLabel {
                id,
                source: DeclaredSource::QueryParam,
            })
        });

    AgentIdentity {
        proven,
        secondary_proof,
        declared,
    }
}

/// The mTLS principal a certificate resolves to, if any.
///
/// Total and fixed: first SAN URI, else CN, else `None`. A certificate carrying
/// neither is not an mTLS identity, and such a request falls to the other rungs
/// rather than acquiring a synthesised name. `display_name` is deliberately not
/// consulted — it is a cosmetic audit label, and an unnameable certificate must
/// not silently become an allowlist key.
fn select_mtls_subject(cert: &crate::mtls::identity::CertIdentity) -> Option<String> {
    cert.san_uris
        .iter()
        .map(String::as_str)
        .chain(cert.common_name.as_deref())
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(String::from)
}

/// Outcome of a successful validation, for the caller's audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAudit {
    /// Nothing to report beyond the identity itself.
    Clean,
    /// A proven principal and a declared label are both present and differ, in
    /// a namespace the gateway cannot compare (mTLS). Accepted deliberately;
    /// emitted so a proved-A-claimed-B mismatch is alertable rather than
    /// invisible. This is the detection half of funded change 4.
    DeclaredLabelMismatch,
}

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
///    accepts both variants of [`ProofSource`], so an operator who can name a
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

// ── Private helpers ───────────────────────────────────────────────────────────

fn extract_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn extract_from_query(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == "agent_id").then_some(v)
        })
        .filter(|s| !s.is_empty())
        .map(percent_decode)
}

/// Percent-decode a query parameter value (`%XX` sequences only; `+` kept as-is).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push((hi << 4 | lo) as char);
            i += 3;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Audit ─────────────────────────────────────────────────────────────────────

/// Emit the ASI03 identity audit record for one request.
///
/// Records proven and declared as **distinct fields**, always. A record that
/// collapses them cannot distinguish "agent-a proved it" from "someone said
/// agent-a", which is the property this whole module exists to create.
///
/// `refusal` is `Some` on the refusal arm. Both call sites pass it, because
/// before this existed a contradiction refusal returned a 403 and left no audit
/// trace at all — putting the detection signal only on the accept path, which
/// is the path an attacker is least likely to be on.
///
/// Shared by both dispatch routes so the field set cannot drift between them.
pub(crate) fn log_agent_identity(
    identity: &AgentIdentity,
    audit: IdentityAudit,
    refusal: Option<&str>,
) {
    let proven = identity.proven_id();
    let proof = identity.proven.as_ref().map(|p| p.proof().to_string());
    let secondary = identity.secondary_proof.as_ref().map(ProvenPrincipal::id);
    let secondary_proof = identity
        .secondary_proof
        .as_ref()
        .map(|p| p.proof().to_string());
    let declared = identity.declared_id();
    let declared_source = identity.declared.as_ref().map(|d| d.source.to_string());

    if let Some(reason) = refusal {
        tracing::warn!(
            agent_proven = proven,
            agent_proof = proof.as_deref(),
            agent_secondary_proof = secondary,
            agent_secondary_proof_source = secondary_proof.as_deref(),
            agent_declared_source = declared_source.as_deref(),
            refused = true,
            reason = reason,
            "agent identity refused"
        );
        return;
    }

    let mismatch = audit == IdentityAudit::DeclaredLabelMismatch;
    if mismatch {
        // The ruling's "turning the vulnerability into detection": a proven
        // principal and a label that differ, in a namespace the operator has
        // been told is incomparable. Accepted, and alertable.
        tracing::warn!(
            agent_proven = proven,
            agent_proof = proof.as_deref(),
            agent_secondary_proof = secondary,
            agent_secondary_proof_source = secondary_proof.as_deref(),
            agent_declared = declared,
            agent_declared_source = declared_source.as_deref(),
            declared_label_mismatch = true,
            "agent declared a label that differs from its proven principal"
        );
        return;
    }

    tracing::debug!(
        agent_proven = proven,
        agent_proof = proof.as_deref(),
        agent_secondary_proof = secondary,
        agent_secondary_proof_source = secondary_proof.as_deref(),
        agent_declared = declared,
        agent_declared_source = declared_source.as_deref(),
        declared_label_mismatch = false,
        "agent identity resolved"
    );
}

mod principal;

pub use principal::{
    AgentIdentity, DeclaredAgentLabel, DeclaredLabel, DeclaredSource, OwnedProvenAgentId,
    ProofSource, ProvenAgentId, ProvenPrincipal,
};

#[cfg(test)]
#[path = "agent_identity_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "agent_identity_falsifier_tests.rs"]
mod falsifier_tests;

#[cfg(test)]
#[path = "agent_identity_load_tests.rs"]
mod load_tests;

#[cfg(test)]
#[path = "agent_identity_audit_tests.rs"]
mod audit_tests;
