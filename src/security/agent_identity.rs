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

impl AgentIdentity {
    /// The id authorization is allowed to read, if any.
    #[must_use]
    pub fn proven_id(&self) -> Option<&str> {
        self.proven.as_ref().map(|p| p.id.as_str())
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
        .is_some_and(|entry| entry.labels.iter().any(|l| *l == declared.id));
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
pub fn log_agent_identity(
    identity: &AgentIdentity,
    audit: IdentityAudit,
    refusal: Option<&str>,
) {
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

    // ── extract_agent_identity ────────────────────────────────────────────────

    #[test]
    fn extract_from_x_agent_id_header() {
        // GIVEN: request with X-Agent-ID header
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "agent-abc-123".parse().unwrap());
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: identity is extracted from header
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-abc-123".to_string(),
                source: IdentitySource::Header,
            })
        );
    }

    #[test]
    fn extract_no_agent_id_returns_none() {
        // GIVEN: request with no agent identification
        let headers = HeaderMap::new();
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: no identity
        assert_eq!(identity, None);
    }

    #[test]
    fn extract_from_query_param() {
        // GIVEN: request with agent_id query parameter
        let headers = HeaderMap::new();
        // WHEN: extract identity from query string
        let identity = extract_agent_identity(&headers, Some("agent_id=agent-q1&other=val"), None);
        // THEN: identity extracted from query
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-q1".to_string(),
                source: IdentitySource::QueryParam,
            })
        );
    }

    #[test]
    fn extract_header_takes_precedence_over_query() {
        // GIVEN: both header and query param set
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "header-agent".parse().unwrap());
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, Some("agent_id=query-agent"), None);
        // THEN: header wins
        let resolved = identity.unwrap();
        assert_eq!(resolved.source, IdentitySource::Header);
        assert_eq!(resolved.id, "header-agent");
    }

    #[test]
    fn extract_whitespace_only_header_returns_none() {
        // GIVEN: X-Agent-ID header with only whitespace (trimmed to empty by our logic)
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "   ".parse().unwrap());
        // WHEN: extract
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: treated as absent (our extractor trims and rejects blank values)
        assert_eq!(identity, None);
    }

    #[test]
    fn extract_from_jwt_claim() {
        // GIVEN: a JWT with agent_id claim (header.payload.signature)
        // payload = {"agent_id": "agent-jwt-1", "sub": "test"}
        let payload = r#"{"agent_id":"agent-jwt-1","sub":"test"}"#;
        let b64 = to_base64url(payload.as_bytes());
        let token = format!("eyJhbGciOiJub25lIn0.{b64}.signature");
        let headers = HeaderMap::new();
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, Some(&token));
        // THEN: extracted from JWT claim
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-jwt-1".to_string(),
                source: IdentitySource::JwtClaim,
            })
        );
    }

    #[test]
    fn extract_jwt_without_agent_id_claim() {
        // GIVEN: JWT with no agent_id claim
        let payload = r#"{"sub":"user","iat":1234567890}"#;
        let b64 = to_base64url(payload.as_bytes());
        let token = format!("eyJhbGciOiJub25lIn0.{b64}.sig");
        let headers = HeaderMap::new();
        // WHEN: extract
        let identity = extract_agent_identity(&headers, None, Some(&token));
        // THEN: none
        assert_eq!(identity, None);
    }

    // ── validate_agent_identity ───────────────────────────────────────────────

    #[test]
    fn validate_passes_when_feature_disabled() {
        // GIVEN: agent_identity.enabled = false
        let config = AgentIdentityConfig {
            enabled: false,
            ..Default::default()
        };
        // WHEN: validate with no identity
        // THEN: always passes
        assert!(validate_agent_identity(None, &config).is_ok());
    }

    #[test]
    fn validate_anonymous_allowed_when_require_id_false() {
        // GIVEN: enabled, require_id = false
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: false,
            ..Default::default()
        };
        // WHEN: no identity
        // THEN: allowed (anonymous mode)
        assert!(validate_agent_identity(None, &config).is_ok());
    }

    #[test]
    fn validate_rejects_when_require_id_and_no_identity() {
        // GIVEN: enabled, require_id = true
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            ..Default::default()
        };
        // WHEN: no identity provided
        let result = validate_agent_identity(None, &config);
        // THEN: rejected with descriptive error
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("require_id"));
    }

    #[test]
    fn validate_known_agents_allowlist_passes_for_listed_agent() {
        // GIVEN: known_agents allowlist with one entry
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec!["agent-allowed".to_string()],
        };
        let identity = AgentIdentity {
            id: "agent-allowed".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: validate known agent
        // THEN: passes
        assert!(validate_agent_identity(Some(&identity), &config).is_ok());
    }

    #[test]
    fn validate_known_agents_allowlist_rejects_unknown_agent() {
        // GIVEN: non-empty allowlist
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec!["agent-allowed".to_string()],
        };
        let identity = AgentIdentity {
            id: "rogue-agent".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: validate agent not in allowlist
        let result = validate_agent_identity(Some(&identity), &config);
        // THEN: rejected
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rogue-agent"));
    }

    #[test]
    fn validate_empty_known_agents_skips_allowlist_check() {
        // GIVEN: enabled, require_id = true, known_agents = []
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
        };
        let identity = AgentIdentity {
            id: "any-agent".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: any agent ID is presented with empty allowlist
        // THEN: passes (no filter applied)
        assert!(validate_agent_identity(Some(&identity), &config).is_ok());
    }

    // ── percent_decode ────────────────────────────────────────────────────────

    #[test]
    fn percent_decode_handles_encoded_chars() {
        assert_eq!(percent_decode("agent%2Dv2"), "agent-v2");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
    }

    // ── test helpers ─────────────────────────────────────────────────────────

    /// Minimal base64url encoder for test fixture construction.
    fn to_base64url(input: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(alphabet[((b0 >> 2) & 0x3F) as usize] as char);
            out.push(alphabet[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            out.push(alphabet[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize] as char);
            out.push(alphabet[(b2 & 0x3F) as usize] as char);
        }
        // Strip padding and convert base64 → base64url
        out.trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }
}
