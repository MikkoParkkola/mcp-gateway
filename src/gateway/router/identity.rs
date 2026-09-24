// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who the caller is, as a grant subject, from the identities a request carries.
//!
//! Shared by the meta route (`handlers`) and the direct backend route
//! (`backend_handlers`), so both resolve one caller the same way. `pub(super)`:
//! nothing outside `router` needs the resolver.

use axum::http::HeaderMap;

use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

const HEADER_GATEWAY_IDENTITY: &str = "x-gateway-identity";
const HEADER_GATEWAY_IDENTITY_AUTHORITY: &str = "x-gateway-identity-authority";
const HEADER_GATEWAY_IDENTITY_LABEL: &str = "x-gateway-identity-label";
const HEADER_GATEWAY_IDENTITY_SUBJECT: &str = "x-gateway-identity-subject";
const HEADER_CF_ACCESS_EMAIL: &str = "cf-access-authenticated-user-email";
const HEADER_CF_ACCESS_USER_ID: &str = "cf-access-authenticated-user-id";
const HEADER_IDENTITY_MAX_LEN: usize = 512;

pub(super) fn caller_grant_subject(
    verified_identity: Option<&VerifiedIdentity>,
    headers: &HeaderMap,
    trust_identity_headers: bool,
    cert_identity: Option<&CertIdentity>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
) -> Option<GrantSubject> {
    verified_identity
        .and_then(grant_subject_from_verified_identity)
        .or_else(|| {
            trust_identity_headers
                .then(|| grant_subject_from_trusted_headers(headers))
                .flatten()
        })
        .or_else(|| cert_identity.and_then(grant_subject_from_cert_identity))
        .or_else(|| oauth_agent_identity.and_then(grant_subject_from_oauth_agent))
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

    Some(GrantSubject::new(
        identity.issuer.clone(),
        identity.subject.clone(),
        label,
    ))
}

fn grant_subject_from_trusted_headers(headers: &HeaderMap) -> Option<GrantSubject> {
    let explicit_subject = header_text(headers, HEADER_GATEWAY_IDENTITY_SUBJECT)
        .or_else(|| header_text(headers, HEADER_GATEWAY_IDENTITY));
    let cloudflare_subject = header_text(headers, HEADER_CF_ACCESS_USER_ID)
        .or_else(|| header_text(headers, HEADER_CF_ACCESS_EMAIL));

    let subject = explicit_subject.or(cloudflare_subject)?;
    let authority = header_text(headers, HEADER_GATEWAY_IDENTITY_AUTHORITY)
        .unwrap_or_else(|| "trusted_header".to_string());
    let label = header_text(headers, HEADER_GATEWAY_IDENTITY_LABEL)
        .or_else(|| header_text(headers, HEADER_CF_ACCESS_EMAIL));

    Some(GrantSubject::new(authority, subject, label))
}

fn grant_subject_from_cert_identity(identity: &CertIdentity) -> Option<GrantSubject> {
    let subject = identity
        .san_uris
        .first()
        .and_then(|value| trimmed_non_empty(value))
        .or_else(|| identity.common_name.as_deref().and_then(trimmed_non_empty))
        .or_else(|| trimmed_non_empty(&identity.display_name))?;
    let label = trimmed_non_empty(&identity.display_name);

    Some(GrantSubject::new("mtls", subject, label))
}

fn grant_subject_from_oauth_agent(identity: &OAuthAgentIdentity) -> Option<GrantSubject> {
    let subject = trimmed_non_empty(&identity.client_id)?;
    let label = trimmed_non_empty(&identity.agent_name);

    Some(GrantSubject::new("agent_oauth", subject, label))
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(trimmed_non_empty)
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
mod caller_identity_tests {
    use super::*;

    #[test]
    fn trusted_identity_headers_are_ignored_until_enabled() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_GATEWAY_IDENTITY, "user-123".parse().unwrap());

        let subject = caller_grant_subject(None, &headers, false, None, None);

        assert!(subject.is_none());
    }

    #[test]
    fn trusted_identity_headers_build_grant_subject_when_enabled() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_GATEWAY_IDENTITY_SUBJECT, "user-123".parse().unwrap());
        headers.insert(
            HEADER_GATEWAY_IDENTITY_AUTHORITY,
            "cloudflare_access".parse().unwrap(),
        );
        headers.insert(
            HEADER_GATEWAY_IDENTITY_LABEL,
            "owner@example.com".parse().unwrap(),
        );

        let subject = caller_grant_subject(None, &headers, true, None, None).unwrap();

        assert_eq!(subject.authority, "cloudflare_access");
        assert_eq!(subject.subject, "user-123");
        assert_eq!(subject.label.as_deref(), Some("owner@example.com"));
    }

    #[test]
    fn verified_identity_precedes_trusted_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_GATEWAY_IDENTITY_SUBJECT,
            "spoofed-user".parse().unwrap(),
        );
        let verified = VerifiedIdentity {
            subject: "oidc-subject".to_string(),
            email: "owner@example.com".to_string(),
            name: Some("Owner".to_string()),
            groups: Vec::new(),
            issuer: "https://issuer.example".to_string(),
        };

        let subject = caller_grant_subject(Some(&verified), &headers, true, None, None).unwrap();

        assert_eq!(subject.authority, "https://issuer.example");
        assert_eq!(subject.subject, "oidc-subject");
        assert_eq!(subject.label.as_deref(), Some("owner@example.com"));
    }
}
