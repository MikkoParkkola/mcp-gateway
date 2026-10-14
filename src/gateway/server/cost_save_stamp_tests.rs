// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b B2save (AC.2; test plan r3, kimi fold): a cost save dates
//! `saved_at` from the save's own clock reading. Green on base (the save
//! path already reads `crate::clock` through `snapshot_for_save`): a guard
//! that the r4 retyping (UI `taken_at` becomes `Option`, the save keeps a
//! concrete reading) keeps the persisted date.

use std::sync::Arc;

use super::persistence::save_costs;
use crate::clock::test_clock::at_secs;
use crate::cost_accounting::config::CostGovernanceConfig;
use crate::cost_accounting::enforcer::BudgetEnforcer;
use crate::cost_accounting::persistence;
use crate::cost_accounting::registry::CostRegistry;

/// Under `at_secs(T)` a save writes `saved_at == T`, read back from the file.
/// Mutant B2m (`saved_at` written from another field, or as 0): killed at
/// `assert_eq!(loaded.saved_at, T)`.
#[test]
fn a_cost_save_stamps_saved_at_with_its_own_reading() {
    const T: u64 = 1_800_000_000;
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let enforcer = BudgetEnforcer::new(cfg.clone(), Arc::new(CostRegistry::new(&cfg)));
    enforcer.record_spend("tool", Some("key"), 0.25);
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let _clock = at_secs(T);
        save_costs(&enforcer, dir.path());
    }
    let loaded = persistence::load(&dir.path().join("costs.json")).expect("load");
    assert_eq!(loaded.saved_at, T);
}
