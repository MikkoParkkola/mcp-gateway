// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2248: an `accounts` block's `file:` secrets are read only once the block
//! has passed structural validation, and not at all for a disabled block with
//! no adapter: that block resolves no secret at runtime, so reading its files
//! at load only opened files nothing would use. An adapter runs with the store
//! disabled, so its references are still recorded (`tests/openwebui_adapter_config.rs`).
//!
//! The observable is the set of `file:` secrets the evaluation recorded as
//! read: a recorded path is a file the load opened and read.

use std::path::Path;

use super::Config;
use super::env_overlay::EnvOverlay;

fn write_secret(path: &Path) {
    crate::gateway::test_helpers::write_owner_only(path, "k".repeat(48)).unwrap();
}

/// GIVEN a disabled `accounts` block whose key is a readable `file:` reference
/// WHEN the config is loaded
/// THEN the load succeeds and the file was not read.
#[test]
fn a_disabled_accounts_block_reads_no_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("account.key");
    write_secret(&key);
    let config_path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &config_path,
        format!(
            "accounts:\n  schema_version: accounts.v1\n  enabled: false\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {store:?}\n  authority_dir: {authority:?}\n  current_key_id: current\n  keys:\n    current: \"file:{key}\"\n",
            store = dir.path().join("store"),
            authority = dir.path().join("authority"),
            key = key.display(),
        ),
    )
    .unwrap();

    let evaluated = Config::load_evaluated(Some(&config_path)).expect("a disabled block loads");

    let read = evaluated.overlay.rotated_secret_files(&EnvOverlay::none());
    assert!(
        read.is_empty(),
        "a disabled accounts block had its secret files read: {read:?}"
    );
}
