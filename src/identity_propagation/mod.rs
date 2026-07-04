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
//!
//! Wiring the framework into the live request path (carrying the full
//! `VerifiedIdentity` through dispatch, per-user transport/session scoping,
//! identity-aware cache keys) is the follow-up slice.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::gateway::oauth::GatewayKeyPair;
use crate::key_server::oidc::VerifiedIdentity;

/// A backend an identity credential is being minted for.
#[derive(Debug, Clone)]
pub struct BackendDescriptor {
    /// Stable backend id (matches the gateway backend registry key).
    pub id: String,
    /// The audience the credential must be scoped to (the backend's expected
    /// `aud`). Distinct backends MUST have distinct audiences for IDP.3.
    pub audience: String,
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
pub enum PropagationError {
    /// A per-user credential could not be obtained for this identity/backend.
    /// The call MUST be refused — never downgraded to a shared credential.
    Refuse(String),
    /// The propagation configuration is invalid (operator error).
    Misconfigured(String),
}

impl std::fmt::Display for PropagationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refuse(m) => write!(f, "identity propagation refused (fail-closed): {m}"),
            Self::Misconfigured(m) => write!(f, "identity propagation misconfigured: {m}"),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl IdentityPropagationConfig {
    /// Validate a backend's propagation config, failing closed on any setup
    /// that could leak identity or silently downgrade.
    ///
    /// # Errors
    /// Returns [`PropagationError::Misconfigured`] when:
    /// - the audience is empty (a credential with no audience defeats IDP.3);
    /// - the strategy is one not yet implemented in this build (fail-closed,
    ///   never silently skip propagation for a required backend).
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
        // Only signed-assertion and passthrough are implemented; a required
        // backend configured for an unimplemented strategy must fail closed, not
        // silently run without propagation.
        if self.required
            && !matches!(
                self.strategy,
                PropagationStrategyKind::SignedAssertion | PropagationStrategyKind::Passthrough
            )
        {
            return Err(PropagationError::Misconfigured(format!(
                "strategy {:?} is not implemented yet; a required backend cannot fall back \
                 (IDP.2). Use signed_assertion or track the strategy's ticket.",
                self.strategy
            )));
        }
        Ok(())
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
    fn now_secs() -> i64 {
        chrono::Utc::now().timestamp()
    }
}

#[async_trait::async_trait]
impl IdentityPropagation for SignedAssertionStrategy {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        if backend.audience.trim().is_empty() {
            return Err(PropagationError::Misconfigured(
                "backend audience is empty (IDP.3)".to_string(),
            ));
        }

        let subject_key = identity.stable_actor_id();
        let now = Self::now_secs();
        let exp = now + self.ttl_secs;
        let claims = AssertionClaims {
            sub: identity.subject.clone(),
            email: identity.email.clone(),
            iss: Self::ISSUER.to_string(),
            aud: backend.audience.clone(),
            tenant: identity.issuer.clone(),
            groups: identity.groups.clone(),
            iat: now,
            nbf: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let key_info = self.key.key_info();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_info.kid.clone());
        let encoding = EncodingKey::from_ec_pem(key_info.private_key_pem.as_bytes())
            .map_err(|e| PropagationError::Refuse(format!("gateway signing key unusable: {e}")))?;
        let token = jsonwebtoken::encode(&header, &claims, &encoding)
            .map_err(|e| PropagationError::Refuse(format!("assertion signing failed: {e}")))?;

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
pub(crate) fn audit_subject(
    verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
) -> String {
    verified_identity.map_or_else(
        || "unauthenticated".to_string(),
        crate::key_server::oidc::VerifiedIdentity::stable_actor_id,
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
/// ponytail: audit is best-effort, not fail-closed — a write failure is
/// `warn!`'d and the caller's request proceeds/fails on its own merits,
/// mirroring how `TransparencyLogger::log_invocation` failures are handled
/// elsewhere in the gateway. A regulated buyer that needs "no mint without a
/// durable audit record" would need this gated fail-closed instead; tracked as
/// a possible future hardening, not required for MIK-6740.
pub(crate) fn audit_identity_propagation(
    logger: Option<&crate::security::TransparencyLogger>,
    action: &'static str,
    subject: &str,
    backend: &str,
    audience: Option<&str>,
    reason: Option<&str>,
) {
    let Some(logger) = logger else {
        return;
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

    if let Err(e) = logger.append_event(fields) {
        tracing::warn!(
            backend,
            action, error = %e,
            "Failed to write identity-propagation audit entry (transparency log)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a JWT's payload claims WITHOUT signature verification (the backend
    /// verifies the signature against the gateway JWKS; the test only asserts
    /// the claims we minted). Avoids coupling the test to a `DecodingKey` whose
    /// format must match ES256.
    fn decode_claims(token: &str) -> serde_json::Value {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload = token.split('.').nth(1).expect("jwt has a payload segment");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload is base64url");
        serde_json::from_slice(&bytes).expect("payload is json")
    }

    // IDP.4 (MIK-6728 review) — Debug output MUST NOT leak the token. The
    // header value carries a live bearer assertion; Debug shows names + a
    // <redacted> marker only.
    #[tokio::test]
    async fn debug_redacts_the_token() {
        let s = strategy();
        let cred = s
            .propagate(&identity("dave", "https://idp"), &backend())
            .await
            .unwrap();
        let token = cred.headers[0]
            .1
            .strip_prefix("Bearer ")
            .unwrap()
            .to_string();
        assert!(!token.is_empty());
        let dbg = format!("{cred:?}");
        assert!(
            !dbg.contains(&token),
            "Debug must not contain the raw token"
        );
        assert!(dbg.contains("<redacted>"), "Debug must mark redaction");
        assert!(dbg.contains("Authorization"), "header names may show");
    }

    fn identity(subject: &str, issuer: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@corp"),
            name: None,
            groups: vec!["eng".to_string()],
            issuer: issuer.to_string(),
        }
    }

    fn strategy() -> SignedAssertionStrategy {
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        SignedAssertionStrategy::new(key, 300)
    }

    fn backend() -> BackendDescriptor {
        BackendDescriptor {
            id: "memory".to_string(),
            audience: "https://memory.internal".to_string(),
        }
    }

    // IDP.1 — a call from user U yields a credential scoped to U: a Bearer
    // assertion whose verified claims carry U's subject + the backend audience.
    #[tokio::test]
    async fn signed_assertion_carries_user_identity_and_audience() {
        let s = strategy();
        let id = identity("alice", "https://idp");
        let cred = s.propagate(&id, &backend()).await.expect("propagate ok");

        assert_eq!(cred.headers.len(), 1);
        let (h, v) = &cred.headers[0];
        assert_eq!(h, "Authorization");
        let token = v.strip_prefix("Bearer ").expect("bearer prefix");

        // Decode WITHOUT signature verification just to assert the claims we
        // minted. The backend is responsible for verifying the ES256 signature
        // against the gateway JWKS; here we only prove the payload carries the
        // caller's identity + the backend audience. We parse the payload
        // segment directly rather than via jsonwebtoken::decode, because a
        // DecodingKey must format-match the ES256 algorithm even when signature
        // validation is disabled (an HMAC key would fail with InvalidKeyFormat).
        let data_claims = decode_claims(token);
        assert_eq!(data_claims["sub"], "alice");
        assert_eq!(data_claims["aud"], "https://memory.internal");
        assert_eq!(data_claims["tenant"], "https://idp");
        assert_eq!(data_claims["iss"], "mcp-gateway");
        assert_eq!(cred.audience, "https://memory.internal");
        assert_eq!(cred.subject_key, id.stable_actor_id());
    }

    // IDP.6 — credential hygiene: exp/nbf/jti present, short TTL bounded.
    #[tokio::test]
    async fn signed_assertion_has_hygiene_fields() {
        let s = strategy();
        let cred = s
            .propagate(&identity("bob", "https://idp"), &backend())
            .await
            .unwrap();
        let token = cred.headers[0].1.strip_prefix("Bearer ").unwrap();
        // Parse the payload directly (see decode_claims rationale above).
        let claims = decode_claims(token);
        let exp = claims["exp"].as_i64().unwrap();
        let nbf = claims["nbf"].as_i64().unwrap();
        assert!(exp > nbf, "exp must be after nbf");
        assert!(exp - nbf <= 3600, "TTL bounded to <=1h");
        assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
    }

    // IDP.6 — TTL is clamped to a short bound even if misconfigured huge/zero.
    #[tokio::test]
    async fn ttl_is_clamped() {
        let key = Arc::new(GatewayKeyPair::generate().unwrap());
        let huge = SignedAssertionStrategy::new(Arc::clone(&key), 999_999);
        let cred = huge
            .propagate(&identity("c", "https://idp"), &backend())
            .await
            .unwrap();
        assert!(cred.expires_at - SignedAssertionStrategy::now_secs() <= 3600);
    }

    // IDP.3 — cache_binding distinguishes users AND audiences, collision-safe.
    #[test]
    fn cache_binding_isolates_users_and_audiences() {
        let a = cache_binding("oidc:11:https://idp:1:a", "https://mem");
        let b = cache_binding("oidc:11:https://idp:1:b", "https://mem");
        let c = cache_binding("oidc:11:https://idp:1:a", "https://mail");
        assert_ne!(a, b, "different users must not share a binding");
        assert_ne!(a, c, "different audiences must not share a binding");
    }

    // IDP.3 — the assertion refuses an empty audience.
    #[tokio::test]
    async fn empty_audience_is_refused() {
        let s = strategy();
        let bad = BackendDescriptor {
            id: "x".to_string(),
            audience: "  ".to_string(),
        };
        assert!(matches!(
            s.propagate(&identity("a", "https://idp"), &bad).await,
            Err(PropagationError::Misconfigured(_))
        ));
    }

    // IDP.7 / IDP.2 — config validation fails closed.
    #[test]
    fn config_validation_is_fail_closed() {
        // Empty audience rejected.
        let cfg = IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: String::new(),
            required: true,
            session_mode: SessionMode::Stateless,
        };
        assert!(cfg.validate().is_err());

        // A required backend on an unimplemented strategy is rejected (no silent
        // downgrade).
        let cfg = IdentityPropagationConfig {
            strategy: PropagationStrategyKind::TokenExchange,
            audience: "https://mail".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
        };
        assert!(cfg.validate().is_err());

        // A valid signed-assertion config passes.
        let cfg = IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
        };
        assert!(cfg.validate().is_ok());
    }

    // MIK-6710 — a `required` backend on a transport that cannot carry
    // per-request headers (stdio, websocket) must be refused, not silently
    // downgraded to an unauthenticated dispatch.
    #[test]
    fn required_backend_on_incapable_transport_is_refused() {
        let err = ensure_transport_carries_identity_headers(true, false)
            .expect_err("required + incapable transport must refuse");
        assert!(err.contains("cannot carry"), "error: {err}");
        assert!(err.contains("MIK-6710"), "error: {err}");
    }

    // A `required` backend on a header-capable (HTTP) transport is unaffected.
    #[test]
    fn required_backend_on_capable_transport_proceeds() {
        assert!(ensure_transport_carries_identity_headers(true, true).is_ok());
    }

    // A non-required backend proceeds regardless of transport capability —
    // best-effort, matching the static-credential fallback used elsewhere in
    // this module for a non-required backend with no identity/strategy.
    #[test]
    fn non_required_backend_ignores_transport_capability() {
        assert!(ensure_transport_carries_identity_headers(false, false).is_ok());
        assert!(ensure_transport_carries_identity_headers(false, true).is_ok());
    }
}
