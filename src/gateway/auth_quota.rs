// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Opaque authenticated identity used only for bounded nonce admission.

use std::sync::Arc;

use sha2::{Digest, Sha256};

/// A verified credential's quota bucket, independent of display/audit names.
///
/// Derived only from something authentication has already validated — a
/// resolved configured secret, a session this process issued, or a verified
/// OIDC identity — and published only after that validation. Callers cannot
/// construct one from request labels.
#[derive(Clone, PartialEq, Eq)]
pub struct QuotaPrincipal(Arc<str>);

impl std::fmt::Debug for QuotaPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuotaPrincipal(<redacted>)")
    }
}

impl QuotaPrincipal {
    pub(crate) fn configured_bearer(secret: &str) -> Self {
        Self::credential(b"configured-bearer", secret.as_bytes())
    }

    pub(crate) fn api_key(secret: &str) -> Self {
        Self::credential(b"api-key", secret.as_bytes())
    }

    /// The one bucket every validated dashboard session shares.
    ///
    /// Deliberately constant: the session handle is a per-browser cookie, so
    /// deriving from it would hand each redemption a fresh quota and make the
    /// bound meaningless. The operator behind them is one identity.
    pub(crate) fn dashboard_session() -> Self {
        Self::credential(b"dashboard-session", b"")
    }

    /// The one bucket a verified OIDC issuer/subject owns.
    ///
    /// `actor_id` is `VerifiedIdentity::stable_actor_id` — the collision-safe
    /// length-prefixed issuer+subject pair, and nothing else. Display email,
    /// name and audience are absent from it by construction, so two people
    /// behind identical labels stay separate and one person under two issuers
    /// does not collapse into one bucket.
    ///
    /// The kind is constant across mechanisms on purpose: an opaque token from
    /// `/auth/token` and a delegated bearer verified off the JWKS resolve to
    /// the same identity, so they must resolve to the same quota. Deriving
    /// from token bytes instead would hand every fresh exchange a fresh cap,
    /// which is the bound this type exists to enforce.
    pub(crate) fn oidc_identity(actor_id: &str) -> Self {
        Self::credential(b"oidc-identity", actor_id.as_bytes())
    }

    /// The one bucket a registered inbound OAuth client owns.
    ///
    /// `client_id` is the registry's own identifier for the client whose token
    /// `validate_agent_token` has just accepted — not the token bytes and not
    /// the display name. Token bytes would hand every fresh JWT a fresh cap,
    /// which is the bound this type exists to enforce; the display name is
    /// operator-chosen and two registered clients may share one, so it cannot
    /// carry authority.
    pub(crate) fn oauth_client(client_id: &str) -> Self {
        Self::credential(b"oauth-client", client_id.as_bytes())
    }

    /// The one bucket a client certificate owns.
    ///
    /// Derived from the whole certificate DER, so two certificates with an
    /// identical CN or display name stay separate and the same certificate
    /// presented on many connections shares one bucket.
    ///
    /// Trust boundary: in production this is reached only from
    /// `CertIdentity::from_der` on a peer chain Rustls has already verified.
    /// Parsing a certificate proves nothing on its own — a caller that parses
    /// unverified bytes would mint an attacker-chosen bucket.
    pub(crate) fn client_certificate(der: &[u8]) -> Self {
        Self::credential(b"client-certificate", der)
    }

    fn credential(kind: &[u8], secret: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"mcp-gateway/nonce-quota/v1\0");
        for component in [kind, secret] {
            hash.update((component.len() as u64).to_be_bytes());
            hash.update(component);
        }
        Self(Arc::from(hex::encode(hash.finalize())))
    }

    pub(crate) fn as_store_key(&self) -> &str {
        &self.0
    }
}
