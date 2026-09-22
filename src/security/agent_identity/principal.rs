// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a request established about the calling agent, as types.
//!
//! Split from the resolution path deliberately: constructing a proven
//! principal, and the guarantees that make one unforgeable, is a different
//! concern from the extraction and enforcement that consume them. Keeping
//! them apart is what lets the guarantees be read in one sitting.
//!
//! The load-bearing property lives here: [`ProvenAgentId`] has a private
//! field and no public constructor, so a caller-supplied string cannot be
//! turned into an authorization input anywhere outside this module.

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
