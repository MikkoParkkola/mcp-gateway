// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hidden config keys: INTERNAL and AUTO rows of `docs/design/surface-4.0.md`.
//!
//! A hidden key is still read and validated, so a value an operator set keeps
//! applying; it is only left out of the reference, `init` and the examples.
//! `doctor` names every hidden key a config file sets, so it stays findable.
//! `scripts/release/check_surface_inventory.py` fails when this table and the
//! inventory disagree.

use std::path::Path;

use super::CheckResult;

/// Hidden config keys in inventory form: `<name>` matches any map key and a
/// `[]` suffix steps into every list item.
pub(super) const HIDDEN_CONFIG_KEYS: &[&str] = &[];

/// Hidden keys that `raw` sets, in table order.
pub(super) fn set_hidden_keys(_raw: &serde_yaml::Value) -> Vec<&'static str> {
    Vec::new()
}

/// The `doctor` row listing the hidden keys the config file at `path` sets.
pub(super) fn check_hidden_keys(_path: &Path) -> Option<CheckResult> {
    None
}

#[cfg(test)]
#[path = "hidden_keys_tests.rs"]
mod tests;
