// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Doctor never prints a configured key's digest, current or previous
//! (ADR-022): not in a row of a loaded config, not in a load refusal.
use super::*;

/// Every doctor check that reads the config file or the loaded config, as the
/// JSON report doctor prints. The checks that probe the network are left out:
/// they read backends, never auth.
fn report(path: &Path) -> String {
    let (config_row, config) = check_config(Some(path), false);
    let mut rows = vec![config_row];
    rows.extend(hidden_keys::check_hidden_keys(path));
    if let Some(config) = config {
        rows.push(posture::check_security_posture(&config));
        rows.extend(provenance::check_remote_provenance(&config));
    }
    doctor_report_json_value(&rows).to_string()
}

fn digest(secret: &str) -> String {
    mcp_gateway::config::api_key_digest_spec(secret.as_bytes())
}

/// A config whose one key carries `key_sha256` and `previous_key_sha256`, with
/// `extra` lines appended to the key.
fn rotated_config(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("gateway.yaml");
    let body = format!(
        "auth:\n  enabled: true\n  api_keys:\n    - name: ops\n      key_sha256: \"{}\"\n      previous_key_sha256: \"{}\"\n{extra}\
         security:\n  transparency_log:\n    enabled: true\n    path: '{}'\n",
        digest("doctor-current-key"),
        digest("doctor-previous-key"),
        dir.join("audit.jsonl").display(),
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, body).expect("write config");
    path
}

fn assert_no_digest(report: &str) {
    for secret in ["doctor-current-key", "doctor-previous-key"] {
        let spec = digest(secret);
        let hex = spec.strip_prefix("sha256:").expect("a digest spec");
        assert!(
            !report.contains(hex),
            "a key digest reached doctor: {report}"
        );
    }
}

#[test]
fn doctor_shows_no_key_digest_of_a_loaded_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = rotated_config(
        dir.path(),
        "      previous_expires_at: \"2999-01-01T00:00:00Z\"\n",
    );
    let (_, config) = check_config(Some(&path), false);
    assert!(config.is_some(), "control: the rotated config loads");
    assert_no_digest(&report(&path));
}

#[test]
fn doctor_shows_no_key_digest_of_a_refused_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A previous digest without its expiry is refused at load.
    let path = rotated_config(dir.path(), "");
    let (row, config) = check_config(Some(&path), false);
    assert!(config.is_none(), "control: the config is refused");
    assert!(row.detail.contains("previous_key_sha256"), "{}", row.detail);
    assert_no_digest(&report(&path));
}
