// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::discovery::DiscoverySource;

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
    /// Build a passive local report from discovered servers, its asset ids
    /// keyed by the gateway's record key: `config`'s
    /// `security.record_principal_key` reference when set, else the key file
    /// in `data_dir`. Both are only read: with neither, the ids are keyed for
    /// this report alone and [`Self::ids_note`] says so. Nothing is written.
    #[must_use]
    pub fn from_discovered(
        discovered: &[DiscoveredServer],
        registered_names: &HashSet<String>,
        gateway_config_path: Option<&Path>,
        config: Option<&crate::config::Config>,
        data_dir: &Path,
    ) -> Self {
        let configured = config
            .and_then(|config| config.security.record_principal_key.as_ref())
            .map(crate::config::RecordPrincipalKeyRef::as_str);
        let one_run = |why: &str| {
            (
                crate::gateway::record_principal::one_run_key(),
                Some(format!(
                    "asset ids of URL finds are for this run only: {why}"
                )),
            )
        };
        let (key, ids_note) = match crate::gateway::record_principal::read_key(configured, data_dir)
        {
            Ok(Some(key)) => (key, None),
            Ok(None) => one_run("no record key was found"),
            Err(e) => {
                // The error names the key file's full path: the log has it,
                // the report does not.
                tracing::warn!(error = %e, "the record key could not be read");
                one_run("the record key could not be read (see the log)")
            }
        };
        let mut report =
            Self::from_discovered_keyed(discovered, registered_names, gateway_config_path, &key);
        report.ids_note = ids_note;
        report
    }

    /// Build a report with asset ids keyed by `key`. One name found in a
    /// client config, the environment and a process is one asset: the
    /// client config's, then the environment's, as discovery has always
    /// preferred.
    pub(crate) fn from_discovered_keyed(
        discovered: &[DiscoveredServer],
        registered_names: &HashSet<String>,
        gateway_config_path: Option<&Path>,
        key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> Self {
        let unique = unique_by_name(discovered);
        let managed_total = unique
            .iter()
            .filter(|server| registered_names.contains(&server.name))
            .count();
        let gateway_config = gateway_config_path.map(|path| path.display().to_string());
        let assets = unique
            .iter()
            .filter(|server| !registered_names.contains(&server.name))
            .map(|server| ShadowAsset::from_server(server, gateway_config.as_deref(), key))
            .collect();
        Self::from_assets(assets, unique.len(), managed_total)
    }

    /// The control-plane radar's report: the client-file rows the shared
    /// discovery cache classified at scan time, plus `others` (the
    /// environment's and processes' finds), each name once, a client file's
    /// first.
    #[cfg(feature = "webui")]
    pub(crate) fn from_cached_and_found(
        client: Vec<ShadowAsset>,
        others: &[DiscoveredServer],
        registered_names: &HashSet<String>,
        gateway_config_path: Option<&Path>,
        key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> Self {
        let gateway_config = gateway_config_path.map(|path| path.display().to_string());
        let mut seen: HashSet<String> = HashSet::new();
        let mut kept: Vec<ShadowAsset> = Vec::new();
        for asset in client {
            if seen.insert(asset.name.clone()) {
                kept.push(asset.with_gateway_config(gateway_config.as_deref()));
            }
        }
        for server in unique_by_name(others) {
            if seen.insert(server.name.clone()) {
                kept.push(ShadowAsset::from_server(
                    server,
                    gateway_config.as_deref(),
                    key,
                ));
            }
        }
        let discovered_total = kept.len();
        let (managed, unmanaged): (Vec<ShadowAsset>, Vec<ShadowAsset>) = kept
            .into_iter()
            .partition(|asset| registered_names.contains(&asset.name));
        Self::from_assets(unmanaged, discovered_total, managed.len())
    }

    /// A report over finished assets: sorted, ports and ids made unique, and
    /// totalled.
    pub(crate) fn from_assets(
        mut assets: Vec<ShadowAsset>,
        discovered_total: usize,
        managed_total: usize,
    ) -> Self {
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
            ids_note: None,
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
    pub(crate) fn from_server(
        server: &DiscoveredServer,
        gateway_config: Option<&str>,
        key: &crate::gateway::record_principal::RecordPrincipalKey,
    ) -> Self {
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
        let id = stable_shadow_id(server, &transport, key);
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
        "needs_client_only_secret" => {
            "Not adoptable: the client config holds a setting the gateway would not reproduce. \
             Move it into a gateway setting or remove it, then rescan."
        }
        "literal_default" => {
            "Not adoptable: a variable default would be written into gateway.yaml as text. \
             Move the whole value into a variable or secret, then rescan."
        }
        "literal_in_template" => {
            "Not adoptable: literal text sits beside a variable and would reach gateway.yaml \
             as text. Move the whole value into a variable or secret, then rescan."
        }
        "credential_in_url" => {
            "Not adoptable: the URL has a query, a fragment or a user name, which could hold a \
             credential. Move query parameters into headers or the server's config, then rescan."
        }
        "cleartext_credential" => {
            "Not adoptable: credentials go in cleartext to a host off this machine. Use TLS, \
             then rescan."
        }
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

/// Each name once: a client config's find first, then the environment's,
/// then a process's, each keeping discovery's order within its kind.
fn unique_by_name(discovered: &[DiscoveredServer]) -> Vec<&DiscoveredServer> {
    let rank = |server: &&DiscoveredServer| match server.source {
        DiscoverySource::Environment => 1,
        DiscoverySource::RunningProcess => 2,
        _ => 0,
    };
    let mut ranked: Vec<&DiscoveredServer> = discovered.iter().collect();
    ranked.sort_by_key(rank);
    let mut seen = HashSet::new();
    ranked
        .into_iter()
        .filter(|server| seen.insert(server.name.as_str()))
        .collect()
}
