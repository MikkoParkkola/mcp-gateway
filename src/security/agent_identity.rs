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
    /// Keyed by the verified JWT `sub` (the registered `client_id`) — the mTLS
    /// namespace is incomparable and is never keyed here.
    #[serde(default)]
    pub principal_labels: Vec<PrincipalLabels>,
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
pub struct KnownAgent {
    /// Which namespace the identifier belongs to.
    pub source: AgentSourceKey,
    /// The identifier, within that namespace.
    pub id: String,
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
#[must_use]
pub fn extract_agent_identity(
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
pub fn validate_agent_identity(
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
    if !config.known_agents.is_empty()
        && !config
            .known_agents
            .iter()
            .any(|entry| entry.source.matches(proven.proof()) && entry.id == proven.id())
    {
        return Err(format!(
            "Agent '{}' (proven via {}) is not in the known_agents allowlist, which admits \
             proven principals only and matches on the (source, id) pair",
            proven.id(),
            proven.proof()
        ));
    }

    check_declared_label(proven, identity.declared.as_ref(), config)
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
                "Agent label '{}' is not in the known_agents allowlist as a declared entry",
                declared.id
            ));
        }
        return Ok(IdentityAudit::Clean);
    }

    if config.require_id {
        return Err(format!(
            "Request rejected: agent_identity.require_id is true and '{}' was only declared (via \
             {}), not proven. A declared label carries no privilege; set \
             agent_identity.allow_unverified_agent_identity to restore the legacy behaviour.",
            declared.id, declared.source
        ));
    }
    if !config.known_agents.is_empty() {
        return Err(format!(
            "Agent '{}' was only declared (via {}) and cannot satisfy the known_agents allowlist, \
             which admits proven principals only. An allowlist satisfied by self-declaration is \
             not a control.",
            declared.id, declared.source
        ));
    }

    // No control is engaged; the label is recorded as telemetry only.
    Ok(IdentityAudit::Clean)
}

/// Is the declared label consistent with the principal that was proven?
///
/// One ordered match; the first arm that fires decides.
///
/// 1. **Exact match — accept.** A principal is always permitted to declare its
///    own name: it is the one label that cannot be a lie, so it is a member of
///    its own set by construction and never has to be listed. This arm is
///    deliberately ahead of arm 2.
/// 2. **mTLS — accept and audit.** An mTLS subject and a short label live in
///    namespaces the gateway cannot compare without inventing an ordering, and
///    an invented ordering later reads as a security guarantee. So the mismatch
///    is a detection signal, not a refusal. Contradiction refusal for a *named*
///    certificate subject is MIK-7529.
/// 3. **Mapped, else refuse.** For a JWT principal the label namespace and the
///    `client_id` namespace are the same kind of name, so a differing label is
///    comparable. `principal_labels` is an opt-in widening; a principal with no
///    entry may declare only its own name, which arm 1 already allowed.
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
    if declared.id == proven.id() {
        return Ok(IdentityAudit::Clean);
    }

    // Arm 2 — an operator-written mapping decides, for EITHER proof source.
    //
    // This runs ahead of the mTLS fallback deliberately. With the order
    // reversed, an mTLS principal short-circuited to "accepted and audited"
    // before the mapping was consulted, which made a per-principal entry for a
    // certificate subject unreachable in every configuration — the criterion
    // says a contradicting label "is refused rather than silently applied",
    // and for mTLS callers it never was. An operator who can name a subject
    // can now get that refusal; one who cannot keeps the incomparable default
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

    // Arm 3 — unmapped mTLS: the namespaces are incomparable, so the mismatch
    // is a detection signal rather than a refusal. A SAN URI and a short label
    // cannot be compared without inventing an ordering, and an invented
    // ordering later reads as a security guarantee.
    if proven.proof() == ProofSource::MutualTls {
        return Ok(IdentityAudit::DeclaredLabelMismatch);
    }

    // Arm 4 — unmapped JWT: the label namespace and the `client_id` namespace
    // are the same kind of name, so a differing label is comparable, and a
    // missing mapping is never read as permission.
    Err(contradiction(declared, proven))
}

/// The refusal a contradicting declared label earns.
///
/// The caller-supplied value is rendered inside single quotes and is the only
/// untrusted text here; it reaches an operator log and a JSON-RPC error
/// message, never a shell or a query.
fn contradiction(declared: &DeclaredLabel, proven: &ProvenPrincipal) -> String {
    format!(
        "Request rejected: the declared agent label '{}' (via {}) contradicts the proven \
         principal '{}' (via {}). Add it to agent_identity.principal_labels for that principal \
         if this caller is entitled to declare it.",
        declared.id,
        declared.source,
        proven.id(),
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
pub fn log_agent_identity(identity: &AgentIdentity, audit: IdentityAudit, refusal: Option<&str>) {
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
            agent_declared = declared,
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
