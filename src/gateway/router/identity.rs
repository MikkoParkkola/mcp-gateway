// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who the caller is, as a grant subject, from the identities a request carries.
//!
//! Shared by the meta route (`handlers`) and the direct backend route
//! (`backend_handlers`), so both resolve one caller the same way. `pub(super)`:
//! nothing outside `router` needs the resolver.

use std::net::SocketAddr;

use axum::http::{HeaderMap, StatusCode};

use tracing::warn;

use crate::config::KeyServerOidcConfig;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::identity_grants::GrantSubject;
use crate::key_server::OidcVerifier;
use crate::key_server::TokenAgeCap;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::security::caller_identity::{CallerIdentityConfig, CallerIdentityMode};

const HEADER_GATEWAY_IDENTITY: &str = "x-gateway-identity";
const HEADER_GATEWAY_IDENTITY_AUTHORITY: &str = "x-gateway-identity-authority";
const HEADER_GATEWAY_IDENTITY_LABEL: &str = "x-gateway-identity-label";
const HEADER_GATEWAY_IDENTITY_SUBJECT: &str = "x-gateway-identity-subject";
const HEADER_CF_ACCESS_EMAIL: &str = "cf-access-authenticated-user-email";
const HEADER_CF_ACCESS_USER_ID: &str = "cf-access-authenticated-user-id";
const HEADER_CF_ACCESS_JWT: &str = "cf-access-jwt-assertion";
const HEADER_IDENTITY_MAX_LEN: usize = 512;
/// A signed Access assertion carries an RS256 signature and Cloudflare's claim
/// set, typically 800-2000+ bytes, so it gets its own, larger bound.
const HEADER_CF_ACCESS_JWT_MAX_LEN: usize = 8 * 1024;

/// Why a request's identity headers were refused. Each maps to one status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityHeaderRefusal {
    /// `trusted_proxy`: an identity header from a peer not in `trusted_proxies`.
    UntrustedPeer,
    /// `X-Gateway-Identity` or `X-Gateway-Identity-Authority`, both removed.
    RemovedHeader,
    /// Repeated, not UTF-8, or over 512 bytes.
    Malformed,
    /// `cloudflare_access`: an `X-Gateway-Identity-*` header.
    WrongModeHeader,
    /// `cloudflare_access`: user headers with no assertion, or a bad assertion.
    AccessAssertion,
}

impl IdentityHeaderRefusal {
    pub(super) const fn status(self) -> StatusCode {
        match self {
            Self::UntrustedPeer => StatusCode::FORBIDDEN,
            Self::RemovedHeader | Self::Malformed | Self::WrongModeHeader => {
                StatusCode::BAD_REQUEST
            }
            Self::AccessAssertion => StatusCode::UNAUTHORIZED,
        }
    }

    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::UntrustedPeer => "untrusted_peer",
            Self::RemovedHeader => "removed_header",
            Self::Malformed => "malformed",
            Self::WrongModeHeader => "wrong_mode_header",
            Self::AccessAssertion => "access_assertion",
        }
    }
}

/// The HTTP answer to a refused identity header. The header value is never
/// echoed: the reason names the rule, not the input.
pub(super) fn identity_refusal_response(
    refusal: IdentityHeaderRefusal,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    super::helpers::build_http_error_response(
        None,
        -32600,
        format!("caller identity header refused: {}", refusal.reason()),
        refusal.status(),
    )
}

/// Resolve the caller's grant subject. Precedence: verified OIDC > header
/// identity > mTLS > OAuth agent.
///
/// The header identity is checked FIRST, even when OIDC will win: a spoofed
/// or malformed header is refused whatever else the request proves, and an
/// outranked valid one is counted, not silently dropped.
///
/// # Errors
///
/// An [`IdentityHeaderRefusal`] when the headers break the mode's rules.
/// Every refusal is counted and logged without the header value.
pub(super) async fn caller_grant_subject(
    verified_identity: Option<&VerifiedIdentity>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &CallerIdentityConfig,
    access_verifier: Option<&OidcVerifier>,
    cert_identity: Option<&CertIdentity>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
) -> Result<Option<GrantSubject>, IdentityHeaderRefusal> {
    let header_identity = match config.mode {
        CallerIdentityMode::Off => Ok(None),
        CallerIdentityMode::TrustedProxy => trusted_proxy_identity(headers, peer, config),
        CallerIdentityMode::CloudflareAccess => {
            cloudflare_access_identity(headers, access_verifier).await
        }
    }
    .inspect_err(|refusal| {
        telemetry_metrics::counter!(
            "mcp_identity_header_refused_total",
            "reason" => refusal.reason()
        )
        .increment(1);
        // Computed before the macro so its count is graded (MIK-7725).
        let (mode, reason) = (&config.mode, refusal.reason());
        warn!(mode = ?mode, reason, "caller identity header refused");
    })?;

    if let Some(verified) = verified_identity.and_then(grant_subject_from_verified_identity) {
        if header_identity.is_some() {
            ignored("oidc_precedence");
        }
        return Ok(Some(verified));
    }
    Ok(header_identity
        .or_else(|| cert_identity.and_then(grant_subject_from_cert_identity))
        .or_else(|| oauth_agent_identity.and_then(grant_subject_from_oauth_agent)))
}

fn ignored(reason: &'static str) {
    telemetry_metrics::counter!("mcp_identity_header_ignored_total", "reason" => reason)
        .increment(1);
}

const GATEWAY_IDENTITY_HEADERS: [&str; 4] = [
    HEADER_GATEWAY_IDENTITY,
    HEADER_GATEWAY_IDENTITY_AUTHORITY,
    HEADER_GATEWAY_IDENTITY_LABEL,
    HEADER_GATEWAY_IDENTITY_SUBJECT,
];

fn any_present(headers: &HeaderMap, names: &[&str]) -> bool {
    names.iter().any(|name| headers.contains_key(*name))
}

/// `trusted_proxy`: subject and label from a peer in `trusted_proxies`,
/// under the configured authority. `Cf-Access-*` is not read here.
fn trusted_proxy_identity(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &CallerIdentityConfig,
) -> Result<Option<GrantSubject>, IdentityHeaderRefusal> {
    if any_present(headers, &[HEADER_CF_ACCESS_USER_ID, HEADER_CF_ACCESS_EMAIL]) {
        ignored("cf_access_in_trusted_proxy");
    }
    if !any_present(headers, &GATEWAY_IDENTITY_HEADERS) {
        return Ok(None);
    }
    // No `ConnectInfo` is no proven peer (the reading of `auth.rs`).
    let trusted = peer.is_some_and(|peer| {
        let peer = peer.ip().to_canonical();
        config
            .trusted_proxies
            .iter()
            .any(|entry| entry.to_canonical() == peer)
    });
    if !trusted {
        return Err(IdentityHeaderRefusal::UntrustedPeer);
    }
    if any_present(
        headers,
        &[HEADER_GATEWAY_IDENTITY, HEADER_GATEWAY_IDENTITY_AUTHORITY],
    ) {
        return Err(IdentityHeaderRefusal::RemovedHeader);
    }
    let label = strict_header(
        headers,
        HEADER_GATEWAY_IDENTITY_LABEL,
        HEADER_IDENTITY_MAX_LEN,
    )?;
    Ok(strict_header(
        headers,
        HEADER_GATEWAY_IDENTITY_SUBJECT,
        HEADER_IDENTITY_MAX_LEN,
    )?
    .and_then(|subject| GrantSubject::checked(config.authority.clone(), subject, label)))
}

/// `cloudflare_access`: the identity is a verified `Cf-Access-Jwt-Assertion`
/// and nothing else. It stays a grant subject: it never becomes a
/// `VerifiedIdentity`, so it cannot reach propagation or key-server policy.
async fn cloudflare_access_identity(
    headers: &HeaderMap,
    verifier: Option<&OidcVerifier>,
) -> Result<Option<GrantSubject>, IdentityHeaderRefusal> {
    if any_present(headers, &GATEWAY_IDENTITY_HEADERS) {
        return Err(IdentityHeaderRefusal::WrongModeHeader);
    }
    let Some(assertion) =
        strict_header(headers, HEADER_CF_ACCESS_JWT, HEADER_CF_ACCESS_JWT_MAX_LEN)?
    else {
        return if any_present(headers, &[HEADER_CF_ACCESS_USER_ID, HEADER_CF_ACCESS_EMAIL]) {
            Err(IdentityHeaderRefusal::AccessAssertion)
        } else {
            Ok(None)
        };
    };
    // A missing verifier is a wiring fault; it refuses rather than trusts.
    let verifier = verifier.ok_or(IdentityHeaderRefusal::AccessAssertion)?;
    let age = KeyServerOidcConfig {
        token_age: TokenAgeCap::ExpOnly,
    };
    let identity = verifier
        .verify(&assertion, &age)
        .await
        .map_err(|_| IdentityHeaderRefusal::AccessAssertion)?;
    grant_subject_from_verified_identity(&identity)
        .map(Some)
        .ok_or(IdentityHeaderRefusal::AccessAssertion)
}

/// One identity header, strictly: absent or blank is `None`; repeated, not
/// UTF-8, or over `max_len` bytes is refused, never
/// truncated or first-wins.
fn strict_header(
    headers: &HeaderMap,
    name: &str,
    max_len: usize,
) -> Result<Option<String>, IdentityHeaderRefusal> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.len() > max_len {
        return Err(IdentityHeaderRefusal::Malformed);
    }
    let text = value
        .to_str()
        .map_err(|_| IdentityHeaderRefusal::Malformed)?
        .trim();
    Ok((!text.is_empty()).then(|| text.to_string()))
}

/// Build the grant subject an OIDC-verified caller is authorized as.
///
/// `pub(crate)` ON PURPOSE — do not narrow it back. The
/// `MIK-7334.CATALOGUE.1` C10a/C10b cells drive THIS function.
///
/// THE ISSUER AND SUBJECT ARE STORED RAW, and that is the whole point.
/// `trimmed_non_empty` is correct for HEADER-sourced identity — untrusted
/// operator input that needs a bound — and wrong here: a `VerifiedIdentity`
/// came from a validated token, and these exact bytes are what
/// `VerifiedIdentity::stable_actor_id` length-prefixes into the per-user pool
/// binding. Trimming, or truncating to 512 CHARACTERS against a BYTE length
/// prefix, made the stored subject differ from the one in the binding, so a
/// revocation reconstructed nothing, evicted nothing, and reported success.
/// Applying header hygiene to verified claims was the defect; it predates the
/// eviction work.
///
/// A blank issuer or subject now REFUSES rather than substituting `"oidc"`:
/// a substituted authority can never match a binding that carries the blank
/// issuer as `oidc:0::…`, so the substitution only ever produced a grant that
/// authorized nobody and could not be revoked.
pub(crate) fn grant_subject_from_verified_identity(
    identity: &VerifiedIdentity,
) -> Option<GrantSubject> {
    if identity.subject.is_empty() || identity.issuer.is_empty() {
        return None;
    }
    // The label is operator-facing display text, never a key, so it keeps the
    // hygiene bound.
    let label = trimmed_non_empty(&identity.email)
        .or_else(|| identity.name.as_deref().and_then(trimmed_non_empty));

    GrantSubject::checked(identity.issuer.clone(), identity.subject.clone(), label)
}

/// A certificate's grant subject: the subject it names, or none. A
/// certificate with neither a SAN URI nor a CN names nobody; its display name
/// is then the placeholder every such certificate shares, so it is never a
/// subject (MIK-8286: authorization and every key built from it would merge
/// all such callers). The TLS layer refuses such a certificate before this
/// runs; this is the layer behind it.
fn grant_subject_from_cert_identity(identity: &CertIdentity) -> Option<GrantSubject> {
    let subject = cert_subject_id(identity)?;
    let label = trimmed_non_empty(&identity.display_name);

    GrantSubject::checked(MTLS_AUTHORITY, subject, label)
}

/// The authority every certificate-derived grant subject carries.
const MTLS_AUTHORITY: &str = "mtls";

/// A certificate's subject, verbatim: its first non-empty SAN URI, else its CN
/// — the rule `select_mtls_subject` applies for agent identity, so one
/// certificate is one principal on both paths (#2285). `None` when it has
/// neither — never its display name, which can be a constant every such
/// certificate shares.
fn cert_subject_id(identity: &CertIdentity) -> Option<String> {
    identity.subject_id().map(String::from)
}

/// The `Subject(authority, id)` half of `caller_key`, in every build: session
/// ownership keys on it too. `None` when no subject resolved, or when a
/// certificate-derived subject is not the subject the certificate names.
pub(super) fn subject_key(
    subject: Option<&GrantSubject>,
    cert: Option<&CertIdentity>,
) -> Option<String> {
    let subject = subject?;
    let from_cert = cert.is_some_and(|cert| is_this_certificates(subject, cert));
    let id = if from_cert {
        cert.and_then(cert_subject_id)?
    } else {
        subject.subject.clone()
    };
    Some(format!(
        "subject:{}:{}:{}:{id}",
        subject.authority.len(),
        subject.authority,
        id.len()
    ))
}

/// Whether `subject` is the one `cert` stands for: the subject it names, or
/// (MIK-8286) the display-name placeholder a certificate naming no subject
/// shows, which the certificate source no longer makes but which must still
/// never become a key if handed over with that certificate.
fn is_this_certificates(subject: &GrantSubject, cert: &CertIdentity) -> bool {
    subject.authority == MTLS_AUTHORITY
        && match cert.subject_id() {
            Some(id) => subject.subject == id,
            None => {
                trimmed_non_empty(&cert.display_name).as_deref() == Some(subject.subject.as_str())
            }
        }
}

/// The key the per-caller firewall controls (anomaly, tenant, budget) score on:
/// the hardened design's `CallerKey`.
///
/// `Subject(authority, id)` when the caller resolved a grant subject, else
/// `Credential(digest)` for an authenticated API key, else empty (no identity;
/// the firewall refuses rather than pools). A subject outranks the credential,
/// so one person keeps one bucket across credentials and token exchanges.
/// The meta route's A/B arm and prefetch hints key on it too (G4), so it
/// exists in every build.
///
/// Length-prefixed, with a tag per variant, so no two distinct callers can
/// encode to one key. A certificate subject is re-derived from the certificate
/// itself, so only the subject the certificate names can become a key
/// (MIK-8286: a certificate naming nobody has no subject at all).
pub(super) fn caller_key(
    subject: Option<&GrantSubject>,
    cert: Option<&CertIdentity>,
    client: Option<&AuthenticatedClient>,
) -> String {
    if let Some(key) = subject_key(subject, cert) {
        return key;
    }
    client
        .filter(|c| c.authenticated && !c.principal.is_empty())
        .map_or_else(String::new, |c| {
            format!("credential:{}:{}", c.principal.len(), c.principal)
        })
}

/// The key every keyless legacy caller shares when its request resumed no
/// session the gateway issued (MIK-7971): authentication off, or on with the
/// path public (the shipped presets list `/mcp`).
///
/// A gateway-internal constant, like `AUTH_DISABLED_TASK_OWNER`: a minted
/// session id is new on every such request, so keying on it gave the tenant
/// guard, anomaly detector and call budget a first call every time. One shared
/// bucket is stricter than that, and nothing tells keyless callers apart
/// anyway. It cannot collide with a caller key (`subject:`, `credential:`) or
/// a session id (`gw-`).
#[cfg(feature = "firewall")]
pub(super) const ANONYMOUS_SESSION_LESS_CALLER: &str = "local:anonymous:session-less:v1";

/// The key the per-caller controls score on: the caller key; else, with no
/// key, the session id when the request resumed it (`presented`); else, for a
/// legacy request on a session minted just now, [`ANONYMOUS_SESSION_LESS_CALLER`].
/// A modern request has no session (`session_id` empty) and stays empty:
/// refused unattributed.
#[cfg(feature = "firewall")]
pub(super) fn control_identity(
    caller_key: String,
    session_id: &str,
    presented: Option<&str>,
) -> String {
    if !caller_key.is_empty() || session_id.is_empty() {
        return caller_key;
    }
    if presented == Some(session_id) {
        return session_id.to_owned();
    }
    ANONYMOUS_SESSION_LESS_CALLER.to_owned()
}

/// The verified agent JWT `sub` is the subject verbatim, as on the OIDC path:
/// never trimmed or truncated, so `" admin "` stays a different principal from
/// `admin` (#2279). Only the display label is trimmed.
fn grant_subject_from_oauth_agent(identity: &OAuthAgentIdentity) -> Option<GrantSubject> {
    let subject = Some(identity.client_id.clone()).filter(|id| !id.is_empty())?;
    let label = trimmed_non_empty(&identity.agent_name);

    GrantSubject::checked("agent_oauth", subject, label)
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(HEADER_IDENTITY_MAX_LEN).collect())
    }
}

#[cfg(test)]
#[path = "identity_header_tests.rs"]
mod tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "identity_control_tests.rs"]
mod control_tests;

#[cfg(test)]
#[path = "identity_cf_edge_tests.rs"]
mod cf_edge_tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "caller_key_tests.rs"]
mod caller_key_tests;
