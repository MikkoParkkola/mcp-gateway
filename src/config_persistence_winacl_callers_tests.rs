// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The runtime state saves keep an owner-only file
//! owner-only on Windows, through each caller rather than the writer alone.
//! Each folder hands Everyone full access to its children.

use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir, plant_owner_only};

/// C2: the skill registry.
#[test]
fn the_skill_registry_save_keeps_an_owner_only_file_owner_only() {
    let row = "WINACL-C2";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("registry.json");
    crate::skills::SkillRegistry::new().save(&path).unwrap();
    plant_owner_only(row, &path);
    crate::skills::SkillRegistry::new().save(&path).unwrap();
    assert_owner_only(row, &path, false);
}

/// C4: the cost ledger.
#[cfg(feature = "cost-governance")]
#[test]
fn the_cost_ledger_save_keeps_an_owner_only_file_owner_only() {
    use crate::cost_accounting::persistence::{PersistedCosts, save};
    let row = "WINACL-C4";
    let dir = everyone_full_dir(row);
    let path = dir.path().join("costs.json");
    save(&path, &PersistedCosts::default()).unwrap();
    plant_owner_only(row, &path);
    save(&path, &PersistedCosts::default()).unwrap();
    assert_owner_only(row, &path, false);
}
