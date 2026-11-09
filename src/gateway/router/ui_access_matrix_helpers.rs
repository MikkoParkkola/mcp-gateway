// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Credential and role fixtures for the access matrix.

use super::{ApiKeyConfig, ISSUER};
use crate::control_plane::{ControlPlaneRole, role_mapping::ControlPlaneRoleRule};

pub(super) fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

pub(super) fn rule(group: &str, role: ControlPlaneRole) -> ControlPlaneRoleRule {
    ControlPlaneRoleRule {
        issuer: ISSUER.to_string(),
        group: Some(group.to_string()),
        email: None,
        domain: None,
        role,
    }
}
