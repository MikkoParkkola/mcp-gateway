// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustLab` baseline files and the on-disk baseline registry.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use chrono::Utc;
use mcp_gateway::trust::{TrustCard, lab::TrustLabBaseline};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const TRUST_LAB_BASELINE_REGISTRY_VERSION: &str = "trust_lab.baseline_registry.v1";
pub(super) const TRUST_LAB_BASELINE_REGISTRY_MANIFEST: &str = "manifest.json";
pub(super) const TRUST_LAB_BASELINE_REGISTRY_DIR: &str = "baselines";

pub(super) async fn read_lab_baseline(path: &Path) -> Result<TrustLabBaseline, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read TrustLab baseline {}: {e}", path.display()))?;
    serde_json::from_str::<TrustLabBaseline>(&content)
        .or_else(|_| serde_yaml::from_str::<TrustLabBaseline>(&content))
        .map_err(|e| format!("failed to parse TrustLab baseline {}: {e}", path.display()))
}

pub(super) async fn write_lab_baseline(
    baseline: &TrustLabBaseline,
    output: &Path,
) -> Result<(), String> {
    let body = serde_json::to_string_pretty(baseline)
        .map_err(|e| format!("failed to serialize TrustLab baseline: {e}"))?;
    tokio::fs::write(output, format!("{body}\n"))
        .await
        .map_err(|e| {
            format!(
                "failed to write TrustLab baseline {}: {e}",
                output.display()
            )
        })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TrustLabBaselineRegistryManifest {
    pub(super) schema_version: String,
    #[serde(default)]
    pub(super) entries: BTreeMap<String, TrustLabBaselineRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TrustLabBaselineRegistryEntry {
    pub(super) baseline_id: String,
    pub(super) file: String,
    pub(super) digest_sha256: String,
    pub(super) tool_schema_count: usize,
    pub(super) server_names: Vec<String>,
    pub(super) updated_at: String,
}

pub(super) async fn read_lab_registry_baseline(
    registry: &Path,
    baseline_id: &str,
) -> Result<Option<TrustLabBaseline>, String> {
    let baseline_path = lab_registry_baseline_path(registry, baseline_id)?;
    if !baseline_path.exists() {
        return Ok(None);
    }
    read_lab_baseline(&baseline_path).await.map(Some)
}

pub(super) async fn write_lab_registry_baseline(
    registry: &Path,
    baseline_id: &str,
    cards: &[TrustCard],
) -> Result<PathBuf, String> {
    let baseline = lab_baseline_from_cards(baseline_id, cards);
    let baseline_path = lab_registry_baseline_path(registry, baseline_id)?;
    let Some(parent) = baseline_path.parent() else {
        return Err(format!(
            "failed to resolve TrustLab registry baseline parent for {}",
            baseline_path.display()
        ));
    };
    tokio::fs::create_dir_all(parent).await.map_err(|e| {
        format!(
            "failed to create TrustLab baseline registry {}: {e}",
            parent.display()
        )
    })?;
    write_lab_baseline(&baseline, &baseline_path).await?;

    let mut manifest = read_lab_registry_manifest(registry).await?;
    manifest.schema_version = TRUST_LAB_BASELINE_REGISTRY_VERSION.to_string();
    manifest.entries.insert(
        baseline.baseline_id.clone(),
        TrustLabBaselineRegistryEntry {
            baseline_id: baseline.baseline_id.clone(),
            file: lab_registry_baseline_relative_path(&baseline.baseline_id)?,
            digest_sha256: lab_baseline_digest(&baseline)?,
            tool_schema_count: baseline.tool_schema_digests.len(),
            server_names: cards.iter().map(|card| card.server.name.clone()).collect(),
            updated_at: Utc::now().to_rfc3339(),
        },
    );
    write_lab_registry_manifest(registry, &manifest).await?;

    Ok(baseline_path)
}

pub(super) async fn read_lab_registry_manifest(
    registry: &Path,
) -> Result<TrustLabBaselineRegistryManifest, String> {
    let manifest_path = registry.join(TRUST_LAB_BASELINE_REGISTRY_MANIFEST);
    if !manifest_path.exists() {
        return Ok(TrustLabBaselineRegistryManifest {
            schema_version: TRUST_LAB_BASELINE_REGISTRY_VERSION.to_string(),
            entries: BTreeMap::default(),
        });
    }
    let content = tokio::fs::read_to_string(&manifest_path)
        .await
        .map_err(|e| {
            format!(
                "failed to read TrustLab baseline registry manifest {}: {e}",
                manifest_path.display()
            )
        })?;
    serde_json::from_str::<TrustLabBaselineRegistryManifest>(&content).map_err(|e| {
        format!(
            "failed to parse TrustLab baseline registry manifest {}: {e}",
            manifest_path.display()
        )
    })
}

pub(super) async fn write_lab_registry_manifest(
    registry: &Path,
    manifest: &TrustLabBaselineRegistryManifest,
) -> Result<(), String> {
    tokio::fs::create_dir_all(registry).await.map_err(|e| {
        format!(
            "failed to create TrustLab baseline registry {}: {e}",
            registry.display()
        )
    })?;
    let manifest_path = registry.join(TRUST_LAB_BASELINE_REGISTRY_MANIFEST);
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("failed to serialize TrustLab baseline registry manifest: {e}"))?;
    tokio::fs::write(&manifest_path, format!("{body}\n"))
        .await
        .map_err(|e| {
            format!(
                "failed to write TrustLab baseline registry manifest {}: {e}",
                manifest_path.display()
            )
        })
}

pub(super) fn lab_registry_baseline_path(
    registry: &Path,
    baseline_id: &str,
) -> Result<PathBuf, String> {
    Ok(registry.join(lab_registry_baseline_relative_path(baseline_id)?))
}

pub(super) fn lab_registry_baseline_relative_path(baseline_id: &str) -> Result<String, String> {
    let file_name = lab_registry_baseline_file_name(baseline_id)?;
    Ok(format!("{TRUST_LAB_BASELINE_REGISTRY_DIR}/{file_name}"))
}

pub(super) fn lab_registry_baseline_file_name(baseline_id: &str) -> Result<String, String> {
    if baseline_id.is_empty() || baseline_id == "." || baseline_id == ".." {
        return Err("TrustLab baseline id must be non-empty and cannot be '.' or '..'".to_string());
    }
    if baseline_id.starts_with('.') {
        return Err("TrustLab baseline id cannot start with '.'".to_string());
    }
    if !baseline_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "TrustLab baseline id '{baseline_id}' is not registry-safe; use only ASCII letters, numbers, '.', '-', or '_'"
        ));
    }
    Ok(format!("{baseline_id}.json"))
}

pub(super) fn lab_baseline_digest(baseline: &TrustLabBaseline) -> Result<String, String> {
    let value = serde_json::to_value(baseline)
        .map_err(|e| format!("failed to serialize TrustLab baseline for digest: {e}"))?;
    let canonical = serde_json::to_string(&value)
        .map_err(|e| format!("failed to canonicalize TrustLab baseline for digest: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn lab_baseline_from_cards(baseline_id: &str, cards: &[TrustCard]) -> TrustLabBaseline {
    let mut baseline = TrustLabBaseline {
        baseline_id: baseline_id.to_string(),
        tool_schema_digests: std::collections::BTreeMap::default(),
    };
    for card in cards {
        let card_baseline = TrustLabBaseline::from_card(baseline_id, card);
        baseline
            .tool_schema_digests
            .extend(card_baseline.tool_schema_digests);
    }
    baseline
}
