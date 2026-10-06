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
            "accounts:\n  schema_version: accounts.v1\n  enabled: false\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {store:?}\n  authority_dir: {authority:?}\n  current_key_id: current\n  keys:\n    current: 'file:{key}'\n",
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

/// A disabled block with one `OpenWebUI` adapter, its store keys given verbatim.
fn disabled_block_with_adapter(dir: &Path, keys: &str) -> std::path::PathBuf {
    let config_path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &config_path,
        format!(
            "accounts:\n  schema_version: accounts.v1\n  enabled: false\n  deployment: single_process\n  instance_id: gateway-a\n  store_dir: {store:?}\n  authority_dir: {authority:?}\n  current_key_id: current\n  keys:\n{keys}  adapters:\n    - kind: openwebui_signed_header\n      installation_id: owui-1\n      header: X-OpenWebUI-Assertion\n      issuer: open-webui\n      hmac_secret_ref: env:MIK_7714_ADAPTER_HMAC\n      allowed_api_key_names:\n        - owui-gateway-key\n",
            store = dir.join("store"),
            authority = dir.join("authority"),
        ),
    )
    .unwrap();
    config_path
}

/// MIK-7714: an adapter runs with the store disabled, so its block's `file:`
/// keys are read at load; every key's shape is checked first.
///
/// GIVEN a disabled block with an adapter, one readable `file:` key and one
/// literal (malformed) key
/// WHEN the config is loaded
/// THEN the load is refused naming the malformed key, before any file is read.
#[test]
fn a_disabled_block_with_an_adapter_refuses_a_malformed_key_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("account.key");
    write_secret(&key);
    let keys = format!(
        "    current: 'file:{key}'\n    legacy: not-a-reference\n",
        key = key.display()
    );
    let config_path = disabled_block_with_adapter(dir.path(), &keys);

    let Err(refusal) = Config::load_evaluated(Some(&config_path)) else {
        panic!("a malformed key in a block whose references are read must refuse the load");
    };
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("accounts.keys[legacy]"),
        "refusal names the malformed key: {refusal}"
    );
}

/// Control for the test above: without the malformed key the same block loads
/// and its `file:` key IS read, so the refusal above is what keeps it unread.
#[test]
fn a_disabled_block_with_an_adapter_records_its_file_keys() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("account.key");
    write_secret(&key);
    let keys = format!("    current: 'file:{key}'\n", key = key.display());
    let config_path = disabled_block_with_adapter(dir.path(), &keys);

    let evaluated = Config::load_evaluated(Some(&config_path)).expect("a well-formed block loads");

    let read = evaluated.overlay.rotated_secret_files(&EnvOverlay::none());
    assert!(
        !read.is_empty(),
        "an adapter's block has its file: keys recorded"
    );
}
