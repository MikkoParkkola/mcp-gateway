// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who may read Activity, and how much of it.
//!
//! Admin credentials read everything. An OIDC identity reads by the role a
//! `role_mapping` rule gives it, and only when a rule matched: the control
//! plane's least-privilege Auditor fallback is not a grant here, so an
//! unmapped identity and a non-admin key are refused.

use crate::control_plane::ControlPlaneRole;
use crate::control_plane::role_mapping::ControlPlaneRoleMappingConfig;
use crate::gateway::auth::AuthenticatedClient;
use crate::key_server::oidc::VerifiedIdentity;

/// What a caller may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gateway::ui) enum Access {
    /// Every listed row.
    All,
    /// Only calls made under this verified `(issuer, subject)`.
    Own { issuer: String, subject: String },
}

/// Why a caller may not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gateway::ui) enum Refused {
    /// No credential was presented: 401.
    Unauthenticated,
    /// A credential with no Activity role: 403.
    Forbidden,
}

pub(in crate::gateway::ui) fn resolve(
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
    mapping: &ControlPlaneRoleMappingConfig,
) -> Result<Access, Refused> {
    let Some(client) = client.filter(|c| c.authenticated) else {
        return Err(Refused::Unauthenticated);
    };
    if client.admin {
        return Ok(Access::All);
    }
    let Some(identity) = identity else {
        return Err(Refused::Forbidden);
    };
    match mapping.resolve_role(identity) {
        Some(ControlPlaneRole::Admin | ControlPlaneRole::Auditor) => Ok(Access::All),
        Some(ControlPlaneRole::Developer)
            if !identity.issuer.is_empty() && !identity.subject.is_empty() =>
        {
            Ok(Access::Own {
                issuer: identity.issuer.clone(),
                subject: identity.subject.clone(),
            })
        }
        _ => Err(Refused::Forbidden),
    }
}
