// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    DiscoveredServer, HashMap, HashSet, Path, SHADOW_ENTERPRISE_BOUNDARY_SCHEMA_VERSION,
    SHADOW_HANDOFF_SCHEMA_VERSION, SHADOW_REPORT_SCHEMA_VERSION, ShadowAsset, ShadowAuthExposure,
    ShadowConsumerHandoff, ShadowControlPlaneAsset, ShadowDoctorFinding, ShadowEnterpriseBoundary,
    ShadowEnterpriseCapability, ShadowEvidence, ShadowEvidenceExportContract, ShadowLicenseTier,
    ShadowRemediation, ShadowRemediationAction, ShadowRiskFinding, ShadowRiskSeverity,
    ShadowScanActivity, ShadowScanBoundary, ShadowScanCapability, ShadowScanMode, ShadowScanReport,
    ShadowScanSummary, ShadowTransport, ShadowTrustCardInput, ShadowTrustStatus,
    build_action_groups, classify_data_risk, classify_ownership, classify_remediation,
    classify_severity, ensure_unique_ids, risk_reasons, stable_shadow_id,
};

impl ShadowScanReport {
    /// Build a passive local report from discovered servers.
    #[must_use]
    pub fn from_discovered(
        discovered: &[DiscoveredServer],
        registered_names: &HashSet<String>,
        gateway_config_path: Option<&Path>,
    ) -> Self {
        let discovered_total = discovered.len();
        let managed_total = discovered
            .iter()
            .filter(|server| registered_names.contains(&server.name))
            .count();
        let gateway_config = gateway_config_path.map(|path| path.display().to_string());

        let mut assets: Vec<ShadowAsset> = discovered
            .iter()
            .filter(|server| !registered_names.contains(&server.name))
            .map(|server| ShadowAsset::from_server(server, gateway_config.as_deref()))
            .collect();

        assets.sort_by(|left, right| left.id.cmp(&right.id).then(left.name.cmp(&right.name)));
        mark_duplicate_ports(&mut assets);
        ensure_unique_ids(&mut assets);
        for asset in &mut assets {
            asset.refresh_schema_aliases();
        }

        let high_or_critical_total = assets
            .iter()
            .filter(|asset| {
                matches!(
                    asset.severity,
                    ShadowRiskSeverity::High | ShadowRiskSeverity::Critical
                )
            })
            .count();
        let adoptable_total = assets
            .iter()
            .filter(|asset| asset.remediation.action == ShadowRemediationAction::AdoptIntoGateway)
            .count();
        let network_exposed_total = assets
            .iter()
            .filter(|asset| asset.auth_exposure == ShadowAuthExposure::NetworkHttpNoAuthMetadata)
            .count();
        let action_groups = build_action_groups(&assets);

        Self {
            schema_version: SHADOW_REPORT_SCHEMA_VERSION.to_string(),
            license_tier: ShadowLicenseTier::FreeCore,
            mode: ShadowScanMode::LocalPassive,
            passive: true,
            tools_invoked: false,
            summary: ShadowScanSummary {
                discovered_total,
                managed_total,
                unmanaged_total: assets.len(),
                high_or_critical_total,
                adoptable_total,
                network_exposed_total,
            },
            assets,
            action_groups,
        }
    }

    /// Build typed handoff feeds for `TrustCard`, doctor, and control-plane UI consumers.
    #[must_use]
    pub fn consumer_handoff(&self) -> ShadowConsumerHandoff {
        ShadowConsumerHandoff {
            schema_version: SHADOW_HANDOFF_SCHEMA_VERSION.to_string(),
            source_report_schema: self.schema_version.clone(),
            passive: self.passive,
            tools_invoked: self.tools_invoked,
            trustcard_inputs: self
                .assets
                .iter()
                .map(ShadowTrustCardInput::from_asset)
                .collect(),
            doctor_findings: self
                .assets
                .iter()
                .map(ShadowDoctorFinding::from_asset)
                .collect(),
            control_plane_assets: self
                .assets
                .iter()
                .map(ShadowControlPlaneAsset::from_asset)
                .collect(),
            enterprise_boundary: self.enterprise_boundary(),
        }
    }

    /// Return the enterprise-only extension contract for this local report.
    #[must_use]
    pub fn enterprise_boundary(&self) -> ShadowEnterpriseBoundary {
        ShadowEnterpriseBoundary::local_passive(&self.summary)
    }
}

impl ShadowEnterpriseBoundary {
    /// Build an enterprise boundary from a local passive report summary.
    #[must_use]
    pub fn local_passive(summary: &ShadowScanSummary) -> Self {
        Self {
            schema_version: SHADOW_ENTERPRISE_BOUNDARY_SCHEMA_VERSION.to_string(),
            free_core_scan: ShadowScanBoundary {
                license_tier: ShadowLicenseTier::FreeCore,
                mode: ShadowScanMode::LocalPassive,
                activity: ShadowScanActivity::Passive,
                allowed_capabilities: Vec::new(),
                denied_capabilities: vec![
                    ShadowScanCapability::NetworkRangeScan,
                    ShadowScanCapability::ScheduledScan,
                    ShadowScanCapability::FleetScope,
                    ShadowScanCapability::ToolInvocation,
                    ShadowScanCapability::ConfigMutation,
                ],
            },
            enterprise_scan: ShadowScanBoundary {
                license_tier: ShadowLicenseTier::Enterprise,
                mode: ShadowScanMode::EnterpriseFleet,
                activity: ShadowScanActivity::Passive,
                allowed_capabilities: vec![
                    ShadowScanCapability::NetworkRangeScan,
                    ShadowScanCapability::ScheduledScan,
                    ShadowScanCapability::FleetScope,
                ],
                denied_capabilities: vec![
                    ShadowScanCapability::ToolInvocation,
                    ShadowScanCapability::ConfigMutation,
                ],
            },
            enterprise_capabilities: vec![
                ShadowEnterpriseCapability::NetworkRangeScan,
                ShadowEnterpriseCapability::ScheduledFleetInventory,
                ShadowEnterpriseCapability::DriftEvidence,
                ShadowEnterpriseCapability::SiemExport,
                ShadowEnterpriseCapability::OwnerAssignment,
                ShadowEnterpriseCapability::PolicyRemediation,
            ],
            evidence_exports: vec![
                ShadowEvidenceExportContract {
                    capability: ShadowEnterpriseCapability::SiemExport,
                    schema_version: "shadow_radar.siem_export.v1".to_string(),
                    target: "siem".to_string(),
                    requires_enterprise_license: true,
                    sensitive_values_included: false,
                    payload_scope: vec![
                        "asset_id".to_string(),
                        "severity".to_string(),
                        "risk_reasons".to_string(),
                        "sanitized_endpoint".to_string(),
                        "owner_or_group".to_string(),
                        "evidence_refs".to_string(),
                    ],
                },
                ShadowEvidenceExportContract {
                    capability: ShadowEnterpriseCapability::DriftEvidence,
                    schema_version: "shadow_radar.drift_evidence.v1".to_string(),
                    target: "control_plane".to_string(),
                    requires_enterprise_license: true,
                    sensitive_values_included: false,
                    payload_scope: vec![
                        "asset_id".to_string(),
                        "previous_report_digest".to_string(),
                        "current_report_digest".to_string(),
                        "first_seen".to_string(),
                        "last_seen".to_string(),
                        "state_change".to_string(),
                    ],
                },
            ],
            local_unmanaged_total: summary.unmanaged_total,
            local_network_exposed_total: summary.network_exposed_total,
            audit_required: true,
            human_approval_required: true,
        }
    }
}

impl ShadowAsset {
    fn from_server(server: &DiscoveredServer, gateway_config: Option<&str>) -> Self {
        let transport = ShadowTransport::from_transport(&server.transport);
        let auth_exposure = ShadowAuthExposure::from_server(server);
        let data_risk = classify_data_risk(server);
        let ownership = classify_ownership(server);
        let severity = classify_severity(&auth_exposure, &data_risk);
        let remediation = classify_remediation(
            server,
            &auth_exposure,
            &data_risk,
            &ownership,
            gateway_config,
        );
        let evidence =
            ShadowEvidence::from_server(server, gateway_config, transport.endpoint.as_deref());
        let risk_reasons = risk_reasons(server, &auth_exposure, &data_risk, &ownership);
        let id = stable_shadow_id(server, &transport);
        let risks = build_risks(&risk_reasons, &severity);
        let remediation_hints = remediation_hints(&remediation);

        Self {
            asset_id: id.clone(),
            id,
            kind: "mcp_server".to_string(),
            name: server.name.clone(),
            description: server.description.clone(),
            source: server.source.clone(),
            ownership,
            transport,
            auth_exposure,
            trust_status: ShadowTrustStatus::Unmanaged,
            management_status: "unmanaged".to_string(),
            data_risk,
            severity,
            evidence,
            remediation,
            risk_reasons,
            risks,
            remediation_hints,
        }
    }

    fn refresh_schema_aliases(&mut self) {
        self.asset_id.clone_from(&self.id);
        self.management_status = match self.trust_status {
            ShadowTrustStatus::Unmanaged => "unmanaged".to_string(),
        };
        self.risks = build_risks(&self.risk_reasons, &self.severity);
        self.remediation_hints = remediation_hints(&self.remediation);
    }
}

fn mark_duplicate_ports(assets: &mut [ShadowAsset]) {
    let mut counts = HashMap::<u16, usize>::new();
    for port in assets.iter().filter_map(|asset| asset.evidence.port) {
        *counts.entry(port).or_insert(0) += 1;
    }

    for asset in assets {
        if asset
            .evidence
            .port
            .is_some_and(|port| counts.get(&port).copied().unwrap_or_default() > 1)
            && !asset
                .risk_reasons
                .iter()
                .any(|reason| reason == "duplicate_port")
        {
            asset.risk_reasons.push("duplicate_port".to_string());
        }
    }
}

fn build_risks(reasons: &[String], severity: &ShadowRiskSeverity) -> Vec<ShadowRiskFinding> {
    reasons
        .iter()
        .map(|reason| ShadowRiskFinding {
            code: reason.clone(),
            severity: severity.clone(),
            detail: risk_detail(reason).to_string(),
        })
        .collect()
}

fn risk_detail(code: &str) -> &'static str {
    match code {
        "unmanaged_server" => "Server is not managed by the compared gateway configuration.",
        "not_registered_in_gateway_config" => {
            "Server name is absent from the compared gateway configuration."
        }
        "missing_trust_metadata" => "Gateway-owned trust metadata is absent.",
        "unauthenticated_http_endpoint" => "HTTP transport lacks passive authentication metadata.",
        "http_auth_header_configured" => "Client configuration sends an authentication header.",
        "server_auth_unverified" => {
            "Passive evidence cannot verify the server enforces the header."
        }
        "local_http_without_auth_metadata" => {
            "Loopback HTTP transport lacks passive authentication metadata."
        }
        "network_http_without_auth_metadata" => {
            "Non-loopback HTTP transport lacks passive authentication metadata."
        }
        "local_stdio_process" => "Local stdio transport was found in passive evidence.",
        "sensitive_data_domain" => "Passive evidence indicates access to sensitive data domains.",
        "high_privilege_domain" => "Passive evidence indicates high-privilege local access.",
        "source_client_config" => "Evidence came from a local client configuration.",
        "source_local_process" => "Evidence came from a local process.",
        "source_environment" => "Evidence came from environment configuration.",
        "unknown_owner" => "Passive evidence does not identify an owner.",
        "unknown_provenance" => "Passive evidence does not identify provenance.",
        "command_arguments_redacted" => {
            "Command existed, but arguments were omitted from evidence."
        }
        "personal_access_reference" => "Passive evidence referenced personal access material.",
        "stale_binary" => "Passive evidence suggests legacy, deprecated, or stale binary use.",
        "duplicate_port" => "Multiple unmanaged assets reported the same local port.",
        _ => "Unmanaged MCP asset risk signal.",
    }
}

fn remediation_hints(remediation: &ShadowRemediation) -> Vec<String> {
    let mut hints = vec![
        remediation.verification_step.clone(),
        remediation.rollback_step.clone(),
    ];
    if let Some(command) = &remediation.dry_run_command {
        hints.push(command.clone());
    }
    if let Some(command) = &remediation.apply_command {
        hints.push(command.clone());
    }
    hints
}
