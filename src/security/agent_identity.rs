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
    /// Optional allowlist of accepted agent IDs.
    ///
    /// When non-empty, any resolved `agent_id` outside this list is rejected —
    /// independently of `require_id`, which governs only the absent-ID case.
    /// When empty the allowlist check is skipped entirely.
    #[serde(default)]
    pub known_agents: Vec<String>,
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

/// The declared labels one proven principal may present.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalLabels {
    /// The verified JWT `sub` this entry governs.
    pub id: String,
    /// Labels this principal may declare in addition to its own id.
    #[serde(default)]
    pub labels: Vec<String>,
}

// ── AgentIdentity ─────────────────────────────────────────────────────────────

/// Resolved identity for the calling agent.
///
/// Two independent facts, never merged: who the caller PROVED they are, and
/// what they merely SAY they are. Authorization reads [`Self::proven`] only.
///
/// Sibling types, different questions — cross-referenced so a later reader does
/// not merge them: `identity_propagation::caller_proof::CallerProof` asks
/// whether a request established the operator, and
/// `personal_accounts::identity::Principal` asks whose stored OAuth grants are
/// being served. This type asks which agent is calling and how well that is
/// known.
///
/// `Default` is "no proof and no label", so anything that does not know refuses
/// rather than mints — the same doctrine as
/// `CallerProvenance::Anonymous` being its own `Default`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentIdentity {
    /// Cryptographically established principal. `None` when the caller
    /// presented no proof. NEVER populated from a caller-supplied header,
    /// query parameter, or unverified token payload.
    pub proven: Option<ProvenPrincipal>,
    /// A weaker proof presented alongside [`Self::proven`] and outranked by it
    /// — a verified JWT riding behind an mTLS certificate. Audited, never
    /// authorized on, and never compared against [`Self::declared`]: one
    /// principal, one comparison.
    pub secondary_proof: Option<ProvenPrincipal>,
    /// Caller-supplied tag. Telemetry and attribution only; carries no
    /// privilege and can never satisfy an authorization control.
    pub declared: Option<DeclaredLabel>,
}

/// A principal the request cryptographically established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenPrincipal {
    /// The principal's identifier: the selected mTLS subject, or the verified
    /// JWT `sub`.
    ///
    /// For mTLS the selection is fixed and total, never best-effort: first SAN
    /// URI, else CN, else **no mTLS principal is constructed at all**. A
    /// certificate carrying neither is not an mTLS identity. `CertIdentity`'s
    /// `display_name` is a cosmetic label computed for audit logs and is
    /// deliberately unreachable from here — routing it into this field would
    /// make a human-readable string an allowlist key.
    pub id: String,
    /// What established it.
    pub proof: ProofSource,
}

/// Ordered by strength. Ranking is the discriminant order, not a call order.
///
/// `Ord` is derived so "rank by proof" is a comparison on the type rather than
/// a hand-written chain a later edit can reorder. The defect this replaces was
/// precisely a precedence encoded as statement order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofSource {
    /// Verified JWT `sub`, from a token `validate_agent_token` accepted.
    VerifiedJwtSubject,
    /// mTLS client-certificate subject, from the TLS handshake.
    MutualTls,
}

/// A label the caller asserted about itself. Carries no privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredLabel {
    /// The caller-supplied value.
    pub id: String,
    /// Where it was read from.
    pub source: DeclaredSource,
}

/// Where a declared label arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredSource {
    /// The `X-Agent-ID` HTTP header.
    Header,
    /// The `agent_id` query parameter.
    QueryParam,
}

impl std::fmt::Display for ProofSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifiedJwtSubject => f.write_str("jwt"),
            Self::MutualTls => f.write_str("mtls"),
        }
    }
}

impl std::fmt::Display for DeclaredSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header => f.write_str("header"),
            Self::QueryParam => f.write_str("query_param"),
        }
    }
}

/// An agent id that authorization is permitted to read.
///
/// The inner field is private and there is **no public constructor**, so a
/// value of this type can only be obtained from
/// [`AgentIdentity::proven_agent_id`] — which returns one only when a principal
/// was cryptographically established. A caller-supplied string cannot be turned
/// into one anywhere outside this module.
///
/// That is the whole point, and it is deliberately stronger than a field name.
/// Two `Option<&str>` fields called `proven` and `declared` would leave the
/// wrong value perfectly representable at every call site: the compiler would
/// not care which one was passed, and a type carrying a distinction nothing
/// enforces is documentation that reads as a guarantee. Passing a declared
/// label where authorization is expected must **fail to compile**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenAgentId<'a>(&'a str);

impl<'a> ProvenAgentId<'a> {
    /// The underlying identifier, for comparison and audit.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Build one directly, for fixtures only.
    ///
    /// `#[cfg(test)]`, so it does not exist in a production build and cannot
    /// become the escape hatch that re-opens the conflation. The compile-time
    /// guarantee is checked against a non-test build (`cargo check --lib`),
    /// where this constructor is absent.
    #[cfg(test)]
    pub(crate) fn for_test(id: &'a str) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for ProvenAgentId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// An owned [`ProvenAgentId`], for a caller snapshot that outlives its request.
///
/// The durable task worker rebuilds a caller context after the request is gone,
/// so it needs an owned copy. Storing a bare `String` there would have thrown
/// away the guarantee one dispatch later — the longest-lived copy of the caller
/// is exactly where the conflation used to survive.
///
/// The only constructor is [`From<ProvenAgentId>`], so an owned proven id can
/// still only originate from a principal that was actually proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProvenAgentId(String);

impl From<ProvenAgentId<'_>> for OwnedProvenAgentId {
    fn from(id: ProvenAgentId<'_>) -> Self {
        Self(id.as_str().to_string())
    }
}

impl OwnedProvenAgentId {
    /// Borrow it back as the authorization-bearing type.
    #[must_use]
    pub fn as_proven(&self) -> ProvenAgentId<'_> {
        ProvenAgentId(&self.0)
    }

    /// The underlying identifier, for audit.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A caller-supplied agent tag. Telemetry and cost attribution only.
///
/// Distinct from [`ProvenAgentId`] so the two cannot be interchanged by
/// accident. There is no conversion into `ProvenAgentId`, by design: that
/// conversion is exactly the defect this criterion removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredAgentLabel<'a>(&'a str);

impl<'a> DeclaredAgentLabel<'a> {
    /// The underlying tag, for attribution and audit.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for DeclaredAgentLabel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl AgentIdentity {
    /// The id authorization is allowed to read, if any.
    #[must_use]
    pub fn proven_id(&self) -> Option<&str> {
        self.proven.as_ref().map(|p| p.id.as_str())
    }

    /// The authorization-bearing id, in the type that authorization consumes.
    ///
    /// The only way to obtain a [`ProvenAgentId`]. Anything downstream that
    /// makes an access decision takes this type, so handing it a caller-supplied
    /// label is a compile error rather than a code-review catch.
    #[must_use]
    pub fn proven_agent_id(&self) -> Option<ProvenAgentId<'_>> {
        self.proven.as_ref().map(|p| ProvenAgentId(p.id.as_str()))
    }

    /// The caller-supplied tag, in the type that attribution consumes.
    #[must_use]
    pub fn declared_agent_label(&self) -> Option<DeclaredAgentLabel<'_>> {
        self.declared
            .as_ref()
            .map(|d| DeclaredAgentLabel(d.id.as_str()))
    }

    /// The caller-supplied tag, for attribution and tracing only.
    #[must_use]
    pub fn declared_id(&self) -> Option<&str> {
        self.declared.as_ref().map(|d| d.id.as_str())
    }

    /// Attribution value: the caller's own tag when it sent one, else the
    /// proven id. Cost attribution wants the caller's tag, and a caller that
    /// lies about its tag mis-attributes its own costs and no one else's.
    ///
    /// NEVER used for an authorization decision — see [`Self::proven_id`].
    #[must_use]
    pub fn attribution_id(&self) -> Option<&str> {
        self.declared_id().or_else(|| self.proven_id())
    }
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
        .map(|id| ProvenPrincipal {
            id,
            proof: ProofSource::MutualTls,
        });
    let jwt = verified_jwt_subject
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| ProvenPrincipal {
            id: s.to_string(),
            proof: ProofSource::VerifiedJwtSubject,
        });

    // Rank by the type, not by position: swapping these two bindings must not
    // change the outcome, which is what `ProofSource: Ord` buys.
    let (proven, secondary_proof) = match (mtls, jwt) {
        (Some(a), Some(b)) => {
            if a.proof >= b.proof {
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

    // The allowlist is a PROVEN-PRINCIPAL allowlist. The declared label is not
    // consulted, so self-declared membership is unrepresentable.
    if !config.known_agents.is_empty() && !config.known_agents.contains(&proven.id) {
        return Err(format!(
            "Agent '{}' (proven via {}) is not in the known_agents allowlist, which admits \
             proven principals only",
            proven.id, proven.proof
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
        // principal — that path is not reached from here.
        if !config.known_agents.is_empty() && !config.known_agents.contains(&declared.id) {
            return Err(format!(
                "Agent label '{}' is not in the known_agents allowlist",
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

    // Arm 1.
    if declared.id == proven.id {
        return Ok(IdentityAudit::Clean);
    }

    // Arm 2.
    if proven.proof == ProofSource::MutualTls {
        return Ok(IdentityAudit::DeclaredLabelMismatch);
    }

    // Arm 3.
    let permitted = config
        .principal_labels
        .iter()
        .find(|entry| entry.id == proven.id)
        .is_some_and(|entry| entry.labels.contains(&declared.id));
    if permitted {
        return Ok(IdentityAudit::Clean);
    }

    Err(format!(
        "Request rejected: the declared agent label '{}' (via {}) contradicts the proven \
         principal '{}' (via {}). Add '{}' to agent_identity.principal_labels for '{}' if this \
         caller is entitled to declare it.",
        declared.id, declared.source, proven.id, proven.proof, declared.id, proven.id
    ))
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
    let proof = identity.proven.as_ref().map(|p| p.proof.to_string());
    let secondary = identity.secondary_proof.as_ref().map(|p| p.id.as_str());
    let secondary_proof = identity
        .secondary_proof
        .as_ref()
        .map(|p| p.proof.to_string());
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::*;

    fn cfg(enabled: bool, require_id: bool, known: &[&str]) -> AgentIdentityConfig {
        AgentIdentityConfig {
            enabled,
            require_id,
            known_agents: known.iter().map(|a| (*a).to_string()).collect(),
            ..AgentIdentityConfig::default()
        }
    }

    fn header(name: &str, value: &str) -> HeaderMap {
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

    fn proven(id: &str, proof: ProofSource) -> AgentIdentity {
        AgentIdentity {
            proven: Some(ProvenPrincipal {
                id: id.to_string(),
                proof,
            }),
            ..AgentIdentity::default()
        }
    }

    // ── Extraction: the declared label ────────────────────────────────────────

    /// Anchor: funded change 1. A header value is a DECLARED label, never a
    /// principal.
    #[test]
    fn header_yields_a_declared_label_and_no_proof() {
        let identity =
            extract_agent_identity(&header("x-agent-id", "agent-abc-123"), None, None, None);
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
            identity.proven.as_ref().map(|p| p.proof),
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
            identity.proven.as_ref().map(|p| p.proof),
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
        let identity =
            extract_agent_identity(&HeaderMap::new(), None, Some(&cert(&[], None)), None);
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
            identity.secondary_proof.as_ref().map(|p| p.id.as_str()),
            Some("svc-b")
        );
        assert_eq!(
            identity.secondary_proof.as_ref().map(|p| p.proof),
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
        let identity =
            extract_agent_identity(&header("x-agent-id", "agent-allowed"), None, None, None);
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
            id: "svc-a".to_string(),
            labels: vec!["billing".to_string()],
        }];
        let reason =
            validate_agent_identity(&identity, &config).expect_err("contradiction accepted");
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
        let identity = with_label(
            proven(
                "spiffe://cluster/ns/agents/sa/runner",
                ProofSource::MutualTls,
            ),
            "runner",
        );
        assert_eq!(
            validate_agent_identity(&identity, &cfg(true, true, &[]))
                .expect("mTLS mismatch refused"),
            IdentityAudit::DeclaredLabelMismatch,
            "the mismatch was accepted but not signalled"
        );
    }

    // ── Validation: the migration hatch ───────────────────────────────────────

    /// Anchor: the operator ruling's migration clause.
    #[test]
    fn the_hatch_restores_declared_only_matching() {
        let identity =
            extract_agent_identity(&header("x-agent-id", "agent-allowed"), None, None, None);
        let mut config = cfg(true, true, &["agent-allowed"]);
        config.allow_unverified_agent_identity = true;
        assert!(validate_agent_identity(&identity, &config).is_ok());
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

    fn to_base64url(input: &[u8]) -> String {
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
}
