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
        // The entry is not echoed: a value typed into the wrong place may be a
        // secret, and this message reaches stderr and the reload log (MIK-8375).
        if matches!(value, serde_json::Value::String(_)) {
            return Err(
                "a known_agents entry is a bare string; it must declare its proof \
                 source: write {source: mtls, id: <id>} or {source: jwt, id: <id>}"
                    .to_owned(),
            );
        }
        let QualifiedKnownAgent { source, id } = serde_json::from_value(value).map_err(|e| {
            format!(
                "known_agents entry: {}",
                crate::config::load_error::redact_message(&e.to_string())
            )
        })?;
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
            // Once per entry list per process: every reload validates.
            if crate::config::log_once::first_time(&format!("agent_identity:{declared:?}")) {
                tracing::warn!(
                    entries = ?declared,
                    "agent_identity.known_agents has declared entries, dormant while \
                     agent_identity is disabled; enabling it without \
                     allow_unverified_agent_identity refuses them"
                );
            }
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
    // Verbatim: a proven identifier is compared as proven. Trimming would let
    // `" admin "` resolve as the distinct principal `admin` (#2243).
    let jwt = verified_jwt_subject
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

// ── Private helpers (agent_identity/extract.rs) ───────────────────────────────

mod validate;
pub(crate) use validate::validate_agent_identity;

mod extract;
#[cfg(test)]
use extract::percent_decode;
use extract::{extract_from_header, extract_from_query};

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

#[cfg(test)]
#[path = "agent_identity_falsifier_tests.rs"]
mod falsifier_tests;

#[cfg(test)]
#[path = "agent_identity_load_tests.rs"]
mod load_tests;

#[cfg(test)]
#[path = "agent_identity_audit_tests.rs"]
mod audit_tests;
