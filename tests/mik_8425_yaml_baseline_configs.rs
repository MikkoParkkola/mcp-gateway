// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2 step 2 (P13, MIG.3 Config identity): the `Config` each
//! shipped gateway config, and each rendered Helm `ConfigMap`, extracts to
//! through the adapter's `figment_data`, recorded with the current backend
//! before the swap.
//!
//! Two goldens. `configs.tsv` extracts through `figment_data` alone over the
//! defaults: what the YAML backend hands `Config`, before the provider's own
//! `url` rewrite (`config/config_file.rs`), so a config that writes a
//! backend `url` is refused there. The parity suite drives this one against
//! the new backend. `configs_loaded.tsv` loads each config through the
//! gateway's own `Config::load_literal`, the path the gateway reads it by.
//! `configs.tsv` layers no environment, so its digests are the same on every
//! machine. `configs_loaded.tsv` does: `load_literal` merges `MCP_GATEWAY_`
//! variables, so a row (the Helm `credential.yaml`, which needs
//! `MCP_GATEWAY_TOKEN`) reads differently where one is set. A refusal row
//! keeps its whole text; an allowed wording change is a `deviations.tsv` row.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

use mcp_gateway::config::Config;

#[path = "mik_8425_yaml_baseline_configs/report.rs"]
mod report;

use report::{CONFIGS, helm_gateway_yaml, reading, report};

/// The `Config` the gateway's loader builds from `text`, written where no
/// env file it names exists.
fn loaded(text: &str) -> String {
    let text = helm_gateway_yaml(text).unwrap_or_else(|| text.to_owned());
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("gateway.yaml");
    // Owner-only, as the loader requires of a config it reads (CONFIG.2).
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, text).expect("write the config");
    match Config::load_literal(Some(&path)) {
        Ok(config) => match golden::canonical_digest(&config) {
            Ok(digest) => digest,
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!(
            "ERR {}",
            golden::one_line(&error.to_string())
                .replace(&dir.path().display().to_string(), "<dir>")
        ),
    }
}

/// Every shipped config extracts to the recorded `Config`. Every row must be
/// comparable: an edited config is re-recorded on purpose, never skipped.
#[test]
fn every_shipped_config_extracts_as_recorded() {
    golden::assert_keyed_golden("configs.tsv", CONFIGS.len(), reading);
}

/// Prints the golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/configs.tsv; run with --ignored --nocapture"]
fn record_configs_golden() {
    print!(
        "----- BEGIN configs.tsv -----\n{}----- END configs.tsv -----\n",
        report()
    );
}

/// Every shipped config loads through the gateway's loader to the recorded
/// `Config`.
#[test]
fn every_shipped_config_loads_as_recorded() {
    golden::assert_keyed_golden("configs_loaded.tsv", CONFIGS.len(), loaded);
}

/// Prints the loaded golden for review; never part of a normal run.
#[test]
#[ignore = "records tests/fixtures/mik_8425_yaml/configs_loaded.tsv; run with --ignored --nocapture"]
fn record_configs_loaded_golden() {
    let paths: Vec<String> = CONFIGS.iter().map(|p| (*p).to_owned()).collect();
    print!(
        "----- BEGIN configs_loaded.tsv -----\n{}----- END configs_loaded.tsv -----\n",
        golden::keyed_rows(&paths, loaded)
    );
}
