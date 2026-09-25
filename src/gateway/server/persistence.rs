// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::fmt::Display;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

#[cfg(feature = "cost-governance")]
use crate::cost_accounting::{
    config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
};
#[cfg(feature = "cost-governance")]
use std::sync::Arc;

pub(super) fn standard_data_dir() -> PathBuf {
    crate::config_persistence::gateway_data_dir()
}

pub(super) fn ensure_data_dir(path: &Path) {
    if let Err(e) = std::fs::create_dir_all(path) {
        warn!(error = %e, "Failed to create data directory");
    }
}

pub(super) fn load_if_exists<F, E>(
    path: &Path,
    load: F,
    error_message: &'static str,
    success_message: &'static str,
) where
    F: FnOnce(&Path) -> Result<(), E>,
    E: Display,
{
    if path.exists() {
        if let Err(e) = load(path) {
            warn!(error = %e, "{error_message}");
        } else {
            info!("{success_message}");
        }
    }
}

pub(super) fn save_with_logging<F, E>(
    path: &Path,
    save: F,
    error_message: &'static str,
    success_message: &'static str,
) where
    F: FnOnce(&Path) -> Result<(), E>,
    E: Display,
{
    if let Err(e) = save(path) {
        warn!(error = %e, "{error_message}");
    } else {
        info!("{success_message}");
    }
}

/// Build the cost registry and budget enforcer when governance is enabled,
/// seeded from `costs.json` in `data_dir` so a restart keeps today's spend.
///
/// `costs.json` is per-process state: every replica keeps its own copy.
#[cfg(feature = "cost-governance")]
pub(super) fn boot_cost_governance(
    cfg: &CostGovernanceConfig,
    data_dir: &Path,
) -> (Option<Arc<CostRegistry>>, Option<Arc<BudgetEnforcer>>) {
    use crate::cost_accounting::persistence;

    if !cfg.enabled {
        return (None, None);
    }
    let registry = Arc::new(CostRegistry::new(cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg.clone(), Arc::clone(&registry)));
    load_if_exists(
        &data_dir.join("costs.json"),
        |path| persistence::load(path).map(|persisted| enforcer.restore(&persisted)),
        "Failed to load persisted cost data",
        "Loaded persisted cost data",
    );
    let restored = enforcer.snapshot();
    info!(
        global_daily_usd = restored.global_daily_usd,
        tools = restored.tool_daily.len(),
        keys = restored.key_daily.len(),
        "Cost governance enabled"
    );
    (Some(registry), Some(enforcer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn standard_data_dir_uses_gateway_subdir() {
        match std::env::var("MCP_GATEWAY_CONFIG_DIR") {
            Ok(path) => assert_eq!(standard_data_dir(), PathBuf::from(path)),
            Err(_) => assert_eq!(
                standard_data_dir()
                    .file_name()
                    .and_then(|name| name.to_str()),
                Some(".mcp-gateway")
            ),
        }
    }

    #[test]
    fn load_if_exists_skips_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let called = Cell::new(false);

        load_if_exists(
            &path,
            |_| {
                called.set(true);
                Ok::<(), std::io::Error>(())
            },
            "load failed",
            "loaded",
        );

        assert!(!called.get());
    }

    #[test]
    fn save_with_logging_runs_callback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let called = Cell::new(false);

        save_with_logging(
            &path,
            |_| {
                called.set(true);
                Ok::<(), std::io::Error>(())
            },
            "save failed",
            "saved",
        );

        assert!(called.get());
    }
}
