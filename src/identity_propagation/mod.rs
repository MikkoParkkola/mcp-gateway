// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! End-user identity propagation to backend MCP servers (MIK-6704 / ADR-007).
//!
//! The gateway authenticates the end user (OIDC) and authorizes them at the
//! gateway. This module lets the gateway additionally propagate that identity
//! to a backend MCP server so the backend can act as the *real user* rather
//! than a shared service account — the enterprise multitenant requirement.
//!
//! # Architecture (ADR-007, framework-first)
//!
//! A strategy-agnostic [`IdentityPropagation`] trait produces a
//! [`PropagatedCredential`] (outbound headers + the metadata caches and audit
//! need) for a `(VerifiedIdentity, BackendDescriptor)` pair, or a typed
//! [`PropagationError`]. The trait is **async** so future strategies
//! (RFC 8693 token-exchange, per-user vault — MIK-6729/6730) that call an
//! external identity provider or storage fit without churn. This slice ships the trait, the metadata-rich
//! credential + error taxonomy, the per-backend config with **fail-closed
//! validation**, and the [`SignedAssertionStrategy`] reference implementation
//! for first-party / gateway-trusting backends.
//!
//! # Safety invariants (see ADR-007)
//!
//! - IDP.2 fail-closed: a strategy that cannot mint a per-user credential
//!   returns [`PropagationError::Refuse`]; callers MUST NOT downgrade to a
//!   shared static credential.
//! - IDP.3 tenant-isolation: a credential is bound to `(subject, audience)` via
//!   [`PropagatedCredential::cache_binding`]; callers key caches on it so one
//!   user's credential/result is never presented for another.
//! - IDP.6 credential hygiene: minted credentials carry a short TTL with
//!   `exp`/`nbf`/`jti` and an explicit audience.
//! - IDP.7 session isolation: [`IdentityPropagationConfig::validate`] refuses a
//!   configuration where a propagation-required backend reuses a shared MCP
//!   session (would leak backend-side state across users).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::gateway::oauth::GatewayKeyPair;
use crate::key_server::oidc::VerifiedIdentity;

mod account_strategies;
mod caller_proof;
mod token_exchange;

pub(crate) use account_strategies::{
    AccountCredential, AccountStrategyRegistry, InstalledAccount, Minter, PreparedAccountCredential,
};
pub(crate) use caller_proof::{CallerProof, CallerProvenance};
pub use token_exchange::TokenExchangeStrategy;

#[cfg(test)]
#[path = "audit_fail_closed_tests.rs"]
mod audit_fail_closed;
#[cfg(test)]
mod token_exchange_live_tests;

/// A backend an identity credential is being minted for.
#[derive(Debug, Clone, Default)]
pub struct BackendDescriptor {
    /// Stable backend id (matches the gateway backend registry key).
    pub id: String,
    /// The audience the credential must be scoped to (the backend's expected
    /// `aud`). Distinct backends MUST have distinct audiences for IDP.3. Also
    /// used as the RFC 8693 `resource` for [`TokenExchangeStrategy`]
    /// (MIK-6729): one field serves both roles since a token-exchange
    /// downstream token is scoped to the same backend the assertion would be.
    pub audience: String,
    /// RFC 8693 token-exchange endpoint (MIK-6729). `None` unless the backend
    /// is configured for [`PropagationStrategyKind::TokenExchange`].
    pub token_exchange_endpoint: Option<String>,
    /// Optional RFC 8693 `scope` to request from the token-exchange endpoint.
    pub token_exchange_scope: Option<String>,
}

/// A per-user credential to present to a backend, plus the metadata caches and
/// audit require. Returned by [`IdentityPropagation::propagate`].
///
/// `Debug` is implemented manually to REDACT header values: the headers carry a
/// live bearer token/assertion, and the derived `Debug` would leak it through
/// any `tracing!(?cred)`, error context, or test-failure dump (MIK-6728 review
/// / IDP.4 — propagation must never log the token). Header names are shown;
/// values are replaced with `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct PropagatedCredential {
    /// Outbound headers to add to the backend request (e.g.
    /// `Authorization: Bearer <assertion>`). Never logged verbatim — see the
    /// redacting `Debug` impl below.
    pub headers: Vec<(String, String)>,
    /// Unix-seconds expiry of the credential (IDP.6). Callers may pre-emptively
    /// refuse to use an expired credential.
    pub expires_at: i64,
    /// Stable per-user key (the caller identity) — the isolation anchor.
    pub subject_key: String,
    /// Audience the credential is scoped to.
    pub audience: String,
    /// Scopes granted (may be empty for a bare identity assertion).
    pub scopes: Vec<String>,
    /// The value identity-aware caches MUST key on so a cached backend result
    /// is never served across users/audiences (IDP.3 / IDP.8). Derived from
    /// `(subject_key, audience)`.
    pub cache_binding: String,
}

impl std::fmt::Debug for PropagatedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact header VALUES (they carry the live token); show names only.
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("PropagatedCredential")
            .field("headers", &format_args!("{header_names:?} = <redacted>"))
            .field("expires_at", &self.expires_at)
            .field("subject_key", &self.subject_key)
            .field("audience", &self.audience)
            .field("scopes", &self.scopes)
            .field("cache_binding", &self.cache_binding)
            .finish()
    }
}

/// Why a propagation attempt did not yield a credential.
///
/// The taxonomy separates a **refuse** (the caller MUST fail the request
/// closed, IDP.2) from a **misconfiguration** (an operator setup error). Both
/// are fail-closed for a propagation-required backend; the distinction is for
/// diagnostics, not for any silent-downgrade path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropagationError {
    /// A per-user credential could not be obtained for this identity/backend.
    /// The call MUST be refused — never downgraded to a shared credential.
    Refuse(String),
    /// The store ANSWERED "absent": no grant exists for this principal and
    /// backend. Separate from [`Self::Refuse`] so the `idp_refuse` audit record
    /// can tell absence from revocation from a busy custody, which used to
    /// arrive as one string. Carries no URL itself: only a dispatch site may
    /// turn it into a connect offer (MIK-6745 design §9.2, BC-1).
    AccountNotConnected(String),
    /// Revoked or reconnect-required; displays exactly as the `Refuse` it was.
    AccountReconnectRequired(String),
    /// The propagation configuration is invalid (operator error).
    Misconfigured(String),
    /// The tamper-evident transparency-log audit write failed.
    ///
    /// Fail-closed hardening (operator decision, regulated-buyer posture): a
    /// minted credential MUST NOT be used when its `idp_mint` audit record
    /// could not be durably written, so the mint path treats this as fatal.
    /// See [`audit_identity_propagation`] for the full contract.
    AuditFailed(String),
}

impl std::fmt::Display for PropagationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refuse(m) | Self::AccountReconnectRequired(m) => {
                write!(f, "identity propagation refused (fail-closed): {m}")
            }
            Self::AccountNotConnected(m) => write!(f, "no connected account (fail-closed): {m}"),
            Self::Misconfigured(m) => write!(f, "identity propagation misconfigured: {m}"),
            Self::AuditFailed(m) => write!(
                f,
                "identity-propagation audit write failed (fail-closed): {m}"
            ),
        }
    }
}

impl std::error::Error for PropagationError {}

/// Strategy that turns a verified end-user identity into a backend credential.
///
/// Async so future strategies (token-exchange `IdP` round-trip, vault storage +
/// refresh) fit without changing the trait. Object-safe (`dyn`-usable) so a
/// backend can hold `Arc<dyn IdentityPropagation>`.
#[async_trait::async_trait]
pub trait IdentityPropagation: Send + Sync {
    /// Produce a per-user credential for `identity` to call `backend`.
    ///
    /// # Errors
    /// [`PropagationError::Refuse`] when no per-user credential can be minted
    /// (the call must fail closed); [`PropagationError::Misconfigured`] on an
    /// operator setup error.
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError>;
}

/// How a backend handles MCP session affinity — the IDP.7 session-isolation
/// contract. An identity-propagating backend must not reuse one shared MCP
/// session across users (a backend that binds state to the session would leak
/// it), so the operator must declare how isolation is achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// The backend keeps no per-session state; one transport is safe to share
    /// across users because identity is carried per-request in the credential.
    Stateless,
    /// The gateway must use a distinct transport/session per
    /// `(backend, user, audience)`.
    PerUser,
}

/// Which propagation strategy a backend uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropagationStrategyKind {
    /// Gateway-signed identity assertion (first-party / gateway-trusting
    /// backends). Reference strategy shipped in this slice.
    SignedAssertion,
    /// Client-supplied passthrough (ADR-008 rung 2, MIK-6746). The caller
    /// attaches its OWN backend credential per request; the gateway forwards it
    /// verbatim and stores/mints NOTHING (INV-4). The primary path for capable
    /// MCP clients that run their own OAuth flow.
    Passthrough,
    /// RFC 8693 OAuth token-exchange (MIK-6729, fast-follow).
    TokenExchange,
    /// Per-user credential vault (MIK-6730, demand-gated).
    Vault,
}

/// Per-backend identity-propagation configuration (opt-in). Absent on a backend
/// means today's static-credential behavior is unchanged (IDP.5).
///
/// `PartialEq`/`Eq` because an `accounts.descriptors` entry now embeds one as
/// its `external_strategy`, and the descriptor DTO compares by value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPropagationConfig {
    /// The strategy to use.
    pub strategy: PropagationStrategyKind,
    /// The backend's expected audience (the credential `aud`).
    pub audience: String,
    /// When true, a request without a propagable identity is refused
    /// (fail-closed, IDP.2). When false, propagation is best-effort and a
    /// request without identity falls through to static-credential behavior.
    #[serde(default)]
    pub required: bool,
    /// The backend's MCP-session isolation contract (IDP.7).
    pub session_mode: SessionMode,
    /// RFC 8693 token-exchange endpoint URL. Required when `strategy` is
    /// [`PropagationStrategyKind::TokenExchange`] (MIK-6729); ignored otherwise.
    #[serde(default)]
    pub token_exchange_endpoint: Option<String>,
    /// Optional RFC 8693 `scope` requested from the token-exchange endpoint.
    #[serde(default)]
    pub token_exchange_scope: Option<String>,
}

impl IdentityPropagationConfig {
    /// Validate a backend's propagation config, failing closed on any setup
    /// that could leak identity or silently downgrade.
    ///
    /// # Errors
    /// Returns [`PropagationError::Misconfigured`] when:
    /// - the audience is empty (a credential with no audience defeats IDP.3);
    /// - the strategy is one not yet implemented in this build (fail-closed,
    ///   never silently skip propagation for a required backend);
    /// - the strategy is `token_exchange` and `token_exchange_endpoint` is
    ///   absent or empty (MIK-6729) — this is checked unconditionally, not
    ///   only when `required`, since a `token_exchange` entry with no
    ///   endpoint can never mint anything and is never a valid config.
    ///
    /// Note IDP.7: a `required` backend is only accepted with an explicit
    /// [`SessionMode`]; there is no implicit shared-session default, so a
    /// misconfigured backend cannot fall back to reusing one session.
    pub fn validate(&self) -> Result<(), PropagationError> {
        if self.audience.trim().is_empty() {
            return Err(PropagationError::Misconfigured(
                "identity_propagation.audience must be non-empty (IDP.3)".to_string(),
            ));
        }
        if self.strategy == PropagationStrategyKind::TokenExchange
            && self
                .token_exchange_endpoint
                .as_deref()
                .is_none_or(|e| e.trim().is_empty())
        {
            return Err(PropagationError::Misconfigured(
                "strategy token_exchange requires a non-empty token_exchange_endpoint \
                 (MIK-6729)"
                    .to_string(),
            ));
        }
        // Every strategy kind is implemented (signed-assertion, passthrough,
        // token-exchange, vault), so a required backend has no unimplemented
        // strategy to refuse here. The match has no wildcard on purpose: a new
        // kind does not compile until someone decides, here, whether a
        // required backend may use it or must fail closed (IDP.2) rather than
        // silently run without propagation.
        //
        // `Vault` joined the list when managed personal-account custody became
        // the strategy behind it: a `personal_managed` descriptor compiles to
        // this kind, and the gateway installs a per-backend vault strategy
        // whose custody handle is claimed before Serving. A vault config that
        // reaches dispatch without that installation still refuses, at the
        // resolver, which is where "no strategy is configured" is decided.
        match self.strategy {
            PropagationStrategyKind::SignedAssertion
            | PropagationStrategyKind::Passthrough
            | PropagationStrategyKind::TokenExchange
            | PropagationStrategyKind::Vault => Ok(()),
        }
    }
}

/// Compute the isolation cache-binding for a `(subject, audience)` pair.
#[must_use]
fn cache_binding(subject_key: &str, audience: &str) -> String {
    // Length-prefixed so distinct (subject, audience) pairs never collide even
    // if a component contains the separator (mirrors stable_actor_id, MIK-6702).
    format!(
        "idp:{}:{}:{}:{}",
        subject_key.len(),
        subject_key,
        audience.len(),
        audience
    )
}

/// The binding PREFIX a grant revocation evicts on, reconstructed from the
/// grant subject (MIK-7530, `MIK-7334.CATALOGUE.1` revocation conjunct).
///
/// It lands HERE, beside [`cache_binding`], because this is the only place the
/// two formulas may meet: restating either one in `config_reload` would bind a
/// person the gateway never authenticated.
///
/// The prefix pins the subject and leaves the audience free
/// (`docs/internal/design/2026-09-22-identity-keyed-slot-eviction.md` §E1).
/// Leaving the audience free is not looseness: on the token-exchange path the
/// pool key is [`token_exchange::exchange_cache_key`]'s *widened* string, so an
/// exact match would silently evict nothing there. The length prefix makes the
/// subject boundary unambiguous, so the prefix cannot reach into another
/// subject either — C7 pins both directions.
///
/// `None` when the authority is not an issuer. The test is POSITIVE — the
/// authority must parse as an absolute URL, which is what OIDC requires of
/// `iss` — rather than a denylist of the three literal authorities
/// `grant_subject_from_verified_identity`'s siblings set (`trusted_header`,
/// `mtls`, `agent_oauth`). A denylist would admit every authority invented
/// after it was written; a positive test refuses those by construction. The
/// blank-issuer fallback (`"oidc"`) fails it too, which is correct: a blank
/// `iss` reaches the binding as `oidc:0::…` and no reconstruction can match it.
///
/// Returning `None` loses nothing. A slot on this path only exists for a
/// caller who had a `VerifiedIdentity`, whose grant subject therefore carries
/// the issuer — so a non-issuer authority means no `idp:` slot exists to evict.
#[must_use]
pub(crate) fn identity_binding_prefix(
    subject: &crate::identity_grants::GrantSubject,
) -> Option<String> {
    if !url::Url::parse(&subject.authority).is_ok_and(|url| url.has_host()) {
        return None;
    }
    // Built through `stable_actor_id` rather than restated, so the two cannot
    // drift: the pool binding is derived from that same method.
    // Through `checked`: a subject that names no one has no slot to evict.
    let subject_key = VerifiedIdentity::checked(
        subject.authority.clone(),
        subject.subject.clone(),
        String::new(),
        None,
        Vec::new(),
    )?
    .stable_actor_id();
    Some(format!("idp:{}:{subject_key}:", subject_key.len()))
}

/// Reference strategy: mint a short-lived gateway-signed JWT (ES256) asserting
/// the end-user identity. For first-party / gateway-trusting backends that
/// verify the gateway's JWKS key (ADR-001 / the gateway `GatewayKeyPair`).
pub struct SignedAssertionStrategy {
    key: Arc<GatewayKeyPair>,
    /// Credential lifetime in seconds (IDP.6 short TTL).
    ttl_secs: i64,
}

/// Claims in the signed identity assertion.
#[derive(Debug, Serialize)]
struct AssertionClaims {
    /// Subject — the end user's OIDC subject.
    sub: String,
    /// Email (informational).
    email: String,
    /// Issuer — the gateway.
    iss: String,
    /// Audience — the backend.
    aud: String,
    /// Original OIDC issuer that authenticated the user (tenant context).
    tenant: String,
    /// Groups (informational).
    groups: Vec<String>,
    /// Issued-at (unix seconds).
    iat: i64,
    /// Not-before (unix seconds).
    nbf: i64,
    /// Expiry (unix seconds).
    exp: i64,
    /// Unique token id (replay defense).
    jti: String,
}

impl SignedAssertionStrategy {
    /// Gateway issuer value in the minted assertion.
    const ISSUER: &'static str = "mcp-gateway";

    /// Create a strategy signing with the gateway key pair. `ttl_secs` is
    /// clamped to a sane short bound (>=1s, <=1h) to keep replay windows small.
    #[must_use]
    pub fn new(key: Arc<GatewayKeyPair>, ttl_secs: i64) -> Self {
        Self {
            key,
            ttl_secs: ttl_secs.clamp(1, 3600),
        }
    }

    /// Current unix-seconds. Isolated so tests document the time source.
    /// A clock before 1970 refuses (MIK-8202): nothing is minted on it and no
    /// expiry is judged by it.
    fn now_secs() -> Result<i64, PropagationError> {
        crate::clock::utc_now()
            .map(|now| now.timestamp())
            .map_err(|_| PropagationError::Refuse("the gateway clock reads before 1970".into()))
    }

    /// Mint a short-lived gateway-signed identity assertion for `identity`,
    /// scoped to `audience`. Returns `(token, exp)`.
    ///
    /// Shared by [`Self::propagate`] (the assertion IS the backend credential)
    /// and by [`TokenExchangeStrategy`] (MIK-6729), which presents this same
    /// assertion as the RFC 8693 `subject_token` at a token-exchange
    /// endpoint — one minting implementation, two consumers, no crypto
    /// duplication.
    ///
    /// # Errors
    /// [`PropagationError::Refuse`] if the gateway signing key cannot be used
    /// or JWT encoding fails.
    fn mint(
        &self,
        identity: &VerifiedIdentity,
        audience: &str,
    ) -> Result<(String, i64), PropagationError> {
        let now = Self::now_secs()?;
        let exp = now + self.ttl_secs;
        let claims = AssertionClaims {
            sub: identity.subject.clone(),
            email: identity.email.clone(),
            iss: Self::ISSUER.to_string(),
            aud: audience.to_string(),
            tenant: identity.issuer.clone(),
            groups: identity.groups.clone(),
            iat: now,
            nbf: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = sign_es256_jwt(&self.key, &claims)?;
        Ok((token, exp))
    }
}

/// Sign `claims` as an ES256 JWT using the gateway's own signing key.
///
/// Shared by [`SignedAssertionStrategy`] (end-user identity assertions) and
/// [`TokenExchangeStrategy`] (RFC 7523 `private_key_jwt` client assertions,
/// MIK-6729) — one signing code path, never duplicated.
///
/// # Errors
/// [`PropagationError::Refuse`] if the gateway signing key is unusable or
/// encoding fails.
fn sign_es256_jwt<T: Serialize>(
    key: &GatewayKeyPair,
    claims: &T,
) -> Result<String, PropagationError> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    let key_info = key.key_info();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_info.kid.clone());
    let encoding = EncodingKey::from_ec_pem(key_info.private_key_pem.as_bytes())
        .map_err(|e| PropagationError::Refuse(format!("gateway signing key unusable: {e}")))?;
    jsonwebtoken::encode(&header, claims, &encoding)
        .map_err(|e| PropagationError::Refuse(format!("JWT signing failed: {e}")))
}

#[async_trait::async_trait]
impl IdentityPropagation for SignedAssertionStrategy {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        if backend.audience.trim().is_empty() {
            return Err(PropagationError::Misconfigured(
                "backend audience is empty (IDP.3)".to_string(),
            ));
        }

        let subject_key = identity.stable_actor_id();
        let (token, exp) = self.mint(identity, &backend.audience)?;

        Ok(PropagatedCredential {
            headers: vec![("Authorization".to_string(), format!("Bearer {token}"))],
            expires_at: exp,
            cache_binding: cache_binding(&subject_key, &backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// Fail-closed reason shared between the two dispatch chokepoints that guard
/// against a `required` backend running unauthenticated over a
/// header-incapable transport (MIK-6710):
/// `MetaMcp::resolve_caller_credential` (minting path — meta-tool dispatch
/// and the direct route's non-passthrough branch) and the direct backend
/// route's passthrough branch (`backend_handlers::ensure_transport_carries_identity_headers`
/// caller). Only HTTP transports apply `extra_headers` on the wire
/// (`Transport::carries_identity_headers`); stdio and websocket transports
/// inherit the trait default and silently drop them, which would otherwise
/// let a `required` backend run unauthenticated while the audit log records
/// a successful mint or passthrough resolution.
pub(crate) const TRANSPORT_CANNOT_CARRY_HEADERS: &str = "its transport cannot carry identity-propagation headers (only HTTP transports forward \
     per-request headers; stdio and websocket transports silently drop them)";

/// Fail-closed gate for [`TRANSPORT_CANNOT_CARRY_HEADERS`]: refuse dispatch
/// for a `required` backend whose transport cannot carry the resolved
/// credential, BEFORE that credential is minted (or, for passthrough,
/// before the caller's own credential is even read) — never mint/resolve
/// successfully and let the header be dropped on the wire afterwards.
///
/// `Ok(())` when dispatch may proceed: either the transport is capable, or
/// propagation is not `required` for this backend (best-effort, matching the
/// existing non-required fallback elsewhere in this module).
///
/// Returns the bare [`TRANSPORT_CANNOT_CARRY_HEADERS`] fact plus a ticket
/// reference — deliberately WITHOUT an "identity propagation required for
/// backend X but ..." prefix — so each of the two call sites can fold it
/// into their own existing refusal-message framing without duplicating that
/// phrase.
///
/// # Errors
///
/// Returns an error containing [`TRANSPORT_CANNOT_CARRY_HEADERS`] and the
/// `MIK-6710` ticket reference when `required` is `true` and
/// `transport_carries_headers` is `false`.
pub(crate) fn ensure_transport_carries_identity_headers(
    required: bool,
    transport_carries_headers: bool,
) -> Result<(), String> {
    if required && !transport_carries_headers {
        return Err(format!(
            "{TRANSPORT_CANNOT_CARRY_HEADERS} (MIK-6710, fail-closed)"
        ));
    }
    Ok(())
}

/// Stable actor id for an identity-propagation audit entry (MIK-6740). Uses the
/// same `issuer`+`subject` derivation as the control-plane governance audit
/// (`stable_actor_id`) so the two audit trails describe the same actor under the
/// same id. `"unauthenticated"` covers the non-`required` path, where a
/// mint/refuse decision can be reached with no verified identity.
pub(crate) fn audit_subject(verified_identity: Option<&VerifiedIdentity>) -> String {
    verified_identity.map_or_else(
        || "unauthenticated".to_string(),
        VerifiedIdentity::stable_actor_id,
    )
}

/// Record an identity-propagation credential decision (`idp_mint` /
/// `idp_refuse`) into the tamper-evident transparency log (MIK-6740, IDP4).
///
/// Both the direct backend route (`backend_handlers`) and the Meta-MCP
/// `gateway_invoke` route (`meta_mcp::invoke`) call this so every mint and every
/// fail-closed refusal is audited identically, regardless of entry path.
///
/// Takes the logger directly (rather than `&AppState`) so this function is
/// independently unit-testable against a real [`crate::security::TransparencyLogger`]
/// over a tempfile, with no need to construct a full `AppState`. `logger` is
/// `None` when the transparency log is disabled — the call is then a no-op.
///
/// Redaction is the load-bearing property here: only `subject`, `backend`,
/// `audience`, `action`, `reason`, and `timestamp` are ever passed to
/// [`crate::security::TransparencyLogger::append_event`] — never the resolved
/// credential header value or a raw assertion.
///
/// ponytail: hardened from best-effort for regulated-buyer posture — a write
/// failure now returns `Err(PropagationError::AuditFailed)` as well as
/// `warn!`ing, so a minted credential cannot reach the wire unaudited.
///
/// - **`idp_mint` callers MUST fail-closed**: propagate the `Err` and abort
///   the mint/request. No mint without a durable audit record.
/// - **`idp_refuse` callers**: the request is already being refused on other
///   grounds, so the `Err` does not need to change the outcome, but MUST NOT
///   be silently dropped (log or propagate as fits the call site).
///
/// # Errors
/// [`PropagationError::AuditFailed`] when
/// [`crate::security::TransparencyLogger::append_event`] fails (e.g. disk
/// full, permission revoked, filesystem gone read-only underneath the
/// gateway), or when the bounded append times out on a stalled disk (F20).
pub(crate) async fn audit_identity_propagation(
    logger: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
    action: &'static str,
    subject: &str,
    backend: &str,
    audience: Option<&str>,
    reason: Option<&str>,
) -> Result<(), PropagationError> {
    let Some(logger) = logger else {
        return Ok(());
    };

    let mut fields = serde_json::Map::new();
    fields.insert("action".into(), action.into());
    fields.insert("subject".into(), subject.into());
    fields.insert("backend".into(), backend.into());
    fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
    if let Some(audience) = audience {
        fields.insert("audience".into(), audience.into());
    }
    if let Some(reason) = reason {
        fields.insert("reason".into(), reason.into());
    }

    let envelope = crate::security::audit::AuditEnvelope::identity_propagation(action, subject);
    // F20: on the blocking pool under the append bound, so a stalled disk
    // cannot pin a runtime worker on the mint path.
    logger
        .append_bounded(move |l| l.append_event(fields, &envelope))
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::warn!(
                backend,
                action, error = %e,
                "Failed to write identity-propagation audit entry (transparency log); \
                 fail-closed on idp_mint"
            );
            PropagationError::AuditFailed(format!(
                "transparency-log write failed for action '{action}' on backend '{backend}': {e}"
            ))
        })
}

#[cfg(test)]
mod audience_tests;

#[cfg(test)]
mod tests;
