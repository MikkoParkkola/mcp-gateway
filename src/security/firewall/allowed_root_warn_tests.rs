// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Load-warning rows: best-effort signals at config load that never refuse
//! the config; the per-call refusal stays the guarantee (L9, L10). Batch 4a.

fn load_warnings(yaml: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let (loaded, warnings) =
        crate::test_log_capture::capture_warnings(|| crate::config::Config::load(Some(&path)));
    loaded.unwrap_or_else(|e| panic!("a warning never refuses the config: {e}"));
    warnings
}

fn config(secret_key: &str, root: &str) -> String {
    format!(
        "backends:\n  fs:\n    command: \"true\"\n    secrets:\n      - name: fs_token\n        \
         credential_type: api_key\n        value: \"x\"\n        inject_as: argument\n        \
         inject_key: {secret_key}\n        tools: [\"*\"]\nsecurity:\n  firewall:\n    \
         enabled: true\n    rules:\n      - {{match: \"read_file\", servers: [\"fs\"], action: \
         block, allowed_roots: [\"{root}\"], path_args: [\"path\"]}}\n"
    )
}

/// L9: a secret rule owning a declared path argument is named at load;
/// control: one owning `token` is not.
#[test]
fn l9_secret_owning_a_path_argument_is_warned() {
    let dir = tempfile::tempdir().expect("root");
    let root = dir.path().to_string_lossy().into_owned();
    let warned = load_warnings(&config("path", &root));
    assert!(
        warned.contains("fs_token"),
        "names the secret rule: {warned}"
    );
    assert!(warned.contains("path_args"), "names the overlap: {warned}");
    let quiet = load_warnings(&config("token", &root));
    assert!(
        !quiet.contains("path_args"),
        "no overlap, no warning: {quiet}"
    );
}

/// L10: an `allowed_roots` entry that does not canonicalise at load is
/// named, by key path and never by value; the config still loads.
#[test]
fn l10_unresolvable_root_is_warned_not_refused() {
    let dir = tempfile::tempdir().expect("root");
    let gone = dir.path().join("SENTINEL-8939-gone");
    let warned = load_warnings(&config("token", &gone.to_string_lossy()));
    assert!(
        warned.contains("security.firewall.rules[0].allowed_roots[0]"),
        "names the key path: {warned}"
    );
    assert!(
        !warned.contains("SENTINEL-8939"),
        "never the value: {warned}"
    );
    let present = dir.path().to_string_lossy().into_owned();
    let quiet = load_warnings(&config("token", &present));
    assert!(
        !quiet.contains("allowed_roots[0]"),
        "a resolving root is quiet: {quiet}"
    );
}
