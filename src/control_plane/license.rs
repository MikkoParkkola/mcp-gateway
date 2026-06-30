// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Enterprise license boundary enforcement.
//!
//! AC.7: Enterprise license boundary is enforced and documented:
//! - free/core exposes only local read-only status/summary surfaces
//! - grant/policy/server mutation, durable evidence export, OIDC-backed RBAC,
//!   and external storage are gated as Enterprise.
//!
//! CHECK: `cargo test --all-features control_plane_license_gate` exits 0
//! AND file `docs/DEPLOYMENT.md` contains `ControlPlaneUI`

use serde::{Deserialize, Serialize};

/// License tier for the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseTier {
    /// Free / open-source tier: read-only local status/summary surfaces only.
    Free,
    /// Enterprise tier: full control plane with mutations, RBAC, evidence export.
    Enterprise,
}

impl LicenseTier {
    /// Check if this tier is Enterprise.
    #[must_use]
    pub fn is_enterprise(&self) -> bool {
        matches!(self, Self::Enterprise)
    }

    /// Check if this tier is Free.
    #[must_use]
    pub fn is_free(&self) -> bool {
        matches!(self, Self::Free)
    }
}

/// Gated features that require Enterprise license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatedFeature {
    /// Mutate grants (create, update, delete).
    GrantMutation,
    /// Mutate policies (create, update, delete).
    PolicyMutation,
    /// Register/remove servers.
    ServerMutation,
    /// Durable evidence export (NDJSON + JSON bundle).
    EvidenceExport,
    /// OIDC-backed RBAC (beyond local admin token).
    OidcRbac,
    /// External storage backend (Postgres).
    ExternalStorage,
    /// Create approval requests on behalf of others.
    ApprovalWorkflow,
}

impl GatedFeature {
    /// Human-readable description of the gated feature.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::GrantMutation => "Grant creation, update, and deletion",
            Self::PolicyMutation => "Policy binding creation, update, and deletion",
            Self::ServerMutation => "Server registration and removal",
            Self::EvidenceExport => "Durable evidence export (NDJSON + JSON bundle)",
            Self::OidcRbac => "OIDC-backed RBAC with external identity providers",
            Self::ExternalStorage => "External storage backend (Postgres)",
            Self::ApprovalWorkflow => "Approval workflow for grant/policy changes",
        }
    }
}

/// License gate — checks whether a feature is available for the current tier.
pub struct LicenseGate {
    tier: LicenseTier,
}

impl LicenseGate {
    /// Create a new license gate for the given tier.
    #[must_use]
    pub fn new(tier: LicenseTier) -> Self {
        Self { tier }
    }

    /// Return the current license tier.
    #[must_use]
    pub fn tier(&self) -> &LicenseTier {
        &self.tier
    }

    /// Check if a feature is gated.
    /// Returns `Ok(())` if allowed, `Err(message)` if gated.
    #[must_use]
    pub fn check(&self, feature: &GatedFeature) -> Result<(), String> {
        if self.tier.is_enterprise() {
            return Ok(());
        }

        // Free tier gates:
        match feature {
            GatedFeature::GrantMutation
            | GatedFeature::PolicyMutation
            | GatedFeature::ServerMutation
            | GatedFeature::EvidenceExport
            | GatedFeature::OidcRbac
            | GatedFeature::ExternalStorage
            | GatedFeature::ApprovalWorkflow => Err(format!(
                "Feature '{}' ({}) requires Enterprise license. Current tier: Free.",
                format!("{feature:?}"),
                feature.description()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.7: Enterprise license boundary is enforced and documented.
    /// CHECK: `cargo test --all-features control_plane_license_gate` exits 0
    #[test]
    fn control_plane_license_gate() {
        let enterprise = LicenseGate::new(LicenseTier::Enterprise);
        let free = LicenseGate::new(LicenseTier::Free);

        // Enterprise: all features allowed
        let enterprise_features = [
            GatedFeature::GrantMutation,
            GatedFeature::PolicyMutation,
            GatedFeature::ServerMutation,
            GatedFeature::EvidenceExport,
            GatedFeature::OidcRbac,
            GatedFeature::ExternalStorage,
            GatedFeature::ApprovalWorkflow,
        ];
        for feature in &enterprise_features {
            assert!(
                enterprise.check(feature).is_ok(),
                "Enterprise must allow feature: {feature:?}"
            );
        }

        // Free: all mutation/export features are gated
        for feature in &enterprise_features {
            let result = free.check(feature);
            assert!(
                result.is_err(),
                "Free tier must gate feature: {feature:?}"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("Enterprise"),
                "Error message for {feature:?} must mention Enterprise: {err}"
            );
        }
    }

    #[test]
    fn license_tier_serialization() {
        let enterprise = LicenseTier::Enterprise;
        let json = serde_json::to_string(&enterprise).expect("serialize");
        assert_eq!(json, "\"Enterprise\"");

        let free = LicenseTier::Free;
        let json = serde_json::to_string(&free).expect("serialize");
        assert_eq!(json, "\"Free\"");
    }

    #[test]
    fn license_tier_is_checks() {
        assert!(LicenseTier::Enterprise.is_enterprise());
        assert!(!LicenseTier::Enterprise.is_free());
        assert!(LicenseTier::Free.is_free());
        assert!(!LicenseTier::Free.is_enterprise());
    }
}