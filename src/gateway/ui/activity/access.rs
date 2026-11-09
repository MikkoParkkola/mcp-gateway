// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who may read Activity, and how much of it.
//!
//! Admin credentials read everything. An OIDC identity reads by the role a
//! `role_mapping` rule gives it, and only when a rule matched: the control
//! plane's least-privilege Auditor fallback is not a grant here, so an
//! unmapped identity and a non-admin key are refused.
//!
//! A credential's backend scope bounds every role: the role sets how much
//! of the scope a caller reads, never past it. An admin or Auditor key
//! scoped to A reads A's calls only, and nothing gateway-wide.

use super::reader::Line;
use super::rows::{Kind, in_scope, owned_by};
use crate::control_plane::ControlPlaneRole;
use crate::control_plane::role_mapping::ControlPlaneRoleMappingConfig;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::authz::BackendGrant;
use crate::key_server::oidc::VerifiedIdentity;

/// What a caller may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gateway::ui) enum Access {
    /// Every listed row.
    All,
    /// Only calls made under this verified `(issuer, subject)`.
    Own { issuer: String, subject: String },
    /// Only calls on these backends, and with `owner` only that verified
    /// `(issuer, subject)`'s: a credential whose `backends` is not `*`.
    Scoped {
        owner: Option<(String, String)>,
        backends: Vec<String>,
    },
}

impl Access {
    /// Whether this caller reads `line`, of `kind`.
    pub(super) fn admits(&self, line: &Line, kind: Kind) -> bool {
        match self {
            Self::All => true,
            Self::Own { issuer, subject } => owned_by(line, kind, issuer, subject),
            Self::Scoped { owner, backends } => {
                in_scope(line, kind, backends)
                    && owner
                        .as_ref()
                        .is_none_or(|(issuer, subject)| owned_by(line, kind, issuer, subject))
            }
        }
    }
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
    breadth(client, identity, mapping).map(|breadth| within(breadth, client))
}

/// How much a caller reads, before its backend scope: by the admin flag, else
/// by its identity's mapped role.
fn breadth(
    client: &AuthenticatedClient,
    identity: Option<&VerifiedIdentity>,
    mapping: &ControlPlaneRoleMappingConfig,
) -> Result<Access, Refused> {
    // Admin breadth inside the scope: `within` bounds it
    // to the caller's backends, so an in-scope admin reads all of its own.
    if client.admin_standing() != crate::gateway::authz::AdminStanding::None {
        return Ok(Access::All);
    }
    let Some(identity) = identity else {
        return Err(Refused::Forbidden);
    };
    match mapping.resolve_role(identity) {
        Some(ControlPlaneRole::Admin | ControlPlaneRole::Auditor) => Ok(Access::All),
        Some(ControlPlaneRole::Developer)
            if !identity.issuer().is_empty() && !identity.subject().is_empty() =>
        {
            Ok(Access::Own {
                issuer: identity.issuer().to_owned(),
                subject: identity.subject().to_owned(),
            })
        }
        _ => Err(Refused::Forbidden),
    }
}

/// `breadth` bounded by the credential's UI scope ([`BackendGrant::for_ui`]):
/// unchanged for `*`, and for an admin key with an empty list.
fn within(breadth: Access, client: &AuthenticatedClient) -> Access {
    if BackendGrant::for_ui(Some(client)) == BackendGrant::Unscoped {
        return breadth;
    }
    let owner = match breadth {
        Access::Own { issuer, subject } => Some((issuer, subject)),
        Access::All | Access::Scoped { .. } => None,
    };
    Access::Scoped {
        owner,
        backends: client.backends.clone(),
    }
}
