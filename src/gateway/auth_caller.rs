// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who the caller is, once authenticated: the one API-key and caller-principal
//! predicates, and [`AuthenticatedClient`], the identity a request carries
//! (moved from `auth.rs`).

use super::{CredentialKind, QuotaPrincipal};
use crate::gateway::record_principal::InternalPrincipal;

/// The one API-key predicate: a caller's API-key name iff it authenticated with an API key.
pub(in crate::gateway) fn api_key_name(
    authenticated: bool,
    kind: CredentialKind,
    name: Option<&str>,
) -> Option<&str> {
    if authenticated && kind == CredentialKind::ApiKey {
        name
    } else {
        None
    }
}

/// What the caller-principal predicate needs of a principal: whether it is
/// the empty one. Implemented by the opaque [`InternalPrincipal`] (so its bytes
/// never leave through the predicate) and by the `&str` the
/// caller contexts carry.
pub(in crate::gateway) trait Principal {
    /// Whether this is the empty principal of a caller with no credential.
    fn is_empty(&self) -> bool;
}

impl Principal for str {
    fn is_empty(&self) -> bool {
        str::is_empty(self)
    }
}

impl Principal for InternalPrincipal {
    fn is_empty(&self) -> bool {
        InternalPrincipal::is_empty(self)
    }
}

/// The one caller-principal predicate: the principal iff the caller authenticated and it is non-empty.
pub(in crate::gateway) fn authenticated_principal<P: Principal + ?Sized>(
    authenticated: bool,
    principal: Option<&P>,
) -> Option<&P> {
    if authenticated {
        principal.filter(|p| !p.is_empty())
    } else {
        None
    }
}

/// Whether `client` holds the gateway-wide admin powers: the one spelling of
/// that question for an optional caller.
///
/// Admin access follows a credential: the bearer, an API key with `admin: true`,
/// or an SSO identity while a `role: admin` mapping rule matches it (E1),
/// scoped to every backend: a backend-scoped admin has no gateway-wide admin
/// standing. No client is never an admin, and the identity used when
/// authentication is disabled is not one either: an unauthenticated gateway
/// cannot tell its operator from any other caller that reaches the port.
#[must_use]
pub(in crate::gateway) fn is_gateway_admin(client: Option<&AuthenticatedClient>) -> bool {
    client.is_some_and(AuthenticatedClient::is_gateway_admin)
}

/// Information about an authenticated client
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// Client name
    pub name: String,
    /// Rate limit (0 = unlimited)
    pub rate_limit: u32,
    /// Allowed backends (`["*"]` = all; empty = none)
    pub backends: Vec<String>,
    /// Allowed tools (allowlist if Some): exact names or a trailing `prefix*`.
    pub allowed_tools: Option<Vec<String>>,
    /// Denied tools (blocklist if Some): exact names or a trailing `prefix*`.
    pub denied_tools: Option<Vec<String>>,
    /// Admin-level UI and management tool access.
    pub admin: bool,
    /// Stable identifier for the principal behind this identity.
    ///
    /// A digest of the validated secret, not the display name: `name` is
    /// operator-chosen and two API keys may share one, which would let them
    /// attach to each other's sessions. Empty for an identity that presented
    /// no credential.
    pub(crate) principal: InternalPrincipal,
    /// Authenticated nonce-quota authority; never derived from audit labels.
    pub quota_principal: Option<QuotaPrincipal>,
    /// Whether a credential was actually presented and validated.
    ///
    /// False for the anonymous identity used when authentication is disabled,
    /// and for the identity given to a public path. Authorization must test
    /// this rather than compare `name` against `"public"` or `"anonymous"`: a
    /// name is data, and a rule written against one silently admits any client
    /// configured with a different name.
    pub authenticated: bool,
    /// How the credential was presented, for the audit record's `who`
    /// (4.0.0 item D1-c). Set at each mint site; it has no `Default`.
    // ci-allow-secret-debug: an enum naming how a credential was presented; it holds no secret bytes.
    pub credential_kind: CredentialKind,
}

impl AuthenticatedClient {
    /// This client's admin standing: with the rule in
    /// [`crate::gateway::authz::admin_standing`], the one reader of `admin`
    /// for authorization. Gateway-wide powers need `Gateway`; admin breadth
    /// inside the scope reads `InScope` too.
    #[must_use]
    pub(crate) fn admin_standing(&self) -> crate::gateway::authz::AdminStanding {
        crate::gateway::authz::admin_standing(self.admin, &self.backends)
    }

    /// Whether this client holds the gateway-wide admin powers: an admin
    /// scoped to every backend.
    #[must_use]
    pub(crate) fn is_gateway_admin(&self) -> bool {
        self.admin_standing().is_gateway()
    }

    /// Check if this client can access a backend
    #[must_use]
    pub fn can_access_backend(&self, backend: &str) -> bool {
        self.backends.iter().any(|b| b == "*" || b == backend)
    }

    /// The API key's name when this client authenticated with an API key,
    /// else `None`: the identity-grant fallback subject.
    #[must_use]
    pub(crate) fn api_key_identity(&self) -> Option<&str> {
        api_key_name(self.authenticated, self.credential_kind, Some(&self.name))
    }

    /// The record principal of `client`, keyed: what a record
    /// of its request writes as `who.principal`. No client is no credential.
    pub(crate) fn record_principal_of(
        client: Option<&Self>,
        key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> crate::gateway::record_principal::RecordPrincipal {
        client.map_or_else(
            || InternalPrincipal::default().record_form(key),
            |c| c.principal.record_form(key),
        )
    }

    /// The validated credential principal iff this client authenticated with a non-empty one.
    #[must_use]
    pub(in crate::gateway) fn credential_principal(&self) -> Option<&InternalPrincipal> {
        authenticated_principal(self.authenticated, Some(&self.principal))
    }

    /// The refusal text when this client may not reach `backend`.
    ///
    /// An empty grant names that cause and not the backend, so the answer is
    /// the same whether or not the backend exists.
    pub(crate) fn backend_refusal(&self, backend: &str) -> String {
        if self.backends.is_empty() {
            format!(
                "Client '{}' has no backends granted: an empty `backends` list reaches none \
                 (docs/UPGRADING-4.0.md section 32)",
                self.name
            )
        } else {
            format!(
                "Client '{}' not authorized for backend '{backend}'",
                self.name
            )
        }
    }

    /// Check if this client can access a tool (per-client scope).
    ///
    /// Logic:
    /// - If `allowed_tools` is Some, only tools matching the allowlist are permitted.
    /// - If `denied_tools` is Some, tools matching the denylist are blocked.
    /// - If both are None, fall back to global policy (caller's responsibility).
    ///
    /// Returns `Ok(())` if allowed, `Err(message)` if denied.
    pub fn check_tool_scope(&self, server: &str, tool: &str) -> std::result::Result<(), String> {
        let qualified = format!("{server}:{tool}");

        // If allowlist is set, ONLY tools in the list are permitted
        if let Some(ref allowed) = self.allowed_tools
            && !crate::config::tool_pattern_matches(allowed, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is not in the allowlist for client '{}'",
                self.name
            ));
        }

        // If denylist is set, tools in the list are blocked
        if let Some(ref denied) = self.denied_tools
            && crate::config::tool_pattern_matches(denied, tool, &qualified)
        {
            return Err(format!(
                "Tool '{tool}' on server '{server}' is blocked by client '{}' policy",
                self.name
            ));
        }

        Ok(())
    }
}
