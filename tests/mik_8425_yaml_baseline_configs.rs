// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2 step 2 (P13, MIG.3 Config identity): the `Config` each
//! shipped gateway config, and each rendered Helm ConfigMap, extracts to
//! through the adapter's `figment_data`, recorded with the current backend
//! before the swap.
//!
//! Two goldens. `configs.tsv` extracts through `figment_data` alone over the
//! defaults: what the YAML backend hands `Config`, before the provider's own
//! `url` rewrite (`config/config_file.rs`), so a config that writes a
//! backend `url` is refused there. The parity suite drives this one against
//! the new backend. `configs_loaded.tsv` loads each config through the
//! gateway's own `Config::load_literal`, the path the gateway reads it by.
//! Neither layers the environment, so the digests are the same on every
//! machine. A refusal row keeps its text; a later stage compares refusal
//! against refusal.

#[path = "common/mik_8425_golden.rs"]
mod golden;

#[path = "common/yaml.rs"]
mod yaml;

use figment::value::{Dict, Map};
use figment::{Figment, Metadata, Profile, Provider};
use mcp_gateway::config::Config;

/// The adapter's `figment_data` as a figment `Provider`.
struct AdapterYaml(String);

impl Provider for AdapterYaml {
    fn metadata(&self) -> Metadata {
        Metadata::named("adapter yaml")
    }
    fn data(&self) -> figment::Result<Map<Profile, Dict>> {
        yaml::figment_data(&self.0)
    }
}

/// Gateway configs shipped in the repository (the files `Config::load` is
/// documented against).
const CONFIGS: &[&str] = &[
    "gateway.example.yaml",
    "examples/gateway-full.yaml",
    "examples/servers.yaml",
    "examples/per-client-tool-scopes.yaml",
    "examples/config-bundles.yaml",
    "examples/config-fulcrum.yaml",
    "examples/gateway-minimal.yaml",
    "examples/minimal.yaml",
    "examples/token-exchange-live.yaml",
    "benchmarks/workload/gateway.workload.yaml",
    "benchmarks/workload/gateway.workload.mixed.yaml",
    "tests/fixtures/helm-golden/credential.yaml",
    "tests/fixtures/helm-golden/mesh.yaml",
];

/// The `gateway.yaml` a rendered Helm manifest's ConfigMap carries, when
/// `text` is such a manifest: the chart's configs are extracted as the
/// gateway reads them once mounted.
fn helm_gateway_yaml(text: &str) -> Option<String> {
    yaml::documents(text).find_map(|document| {
        let document = document.ok()?;
        if document.get("kind")?.as_str()? != "ConfigMap" {
            return None;
        }
        Some(
            document
                .get("data")?
                .get("gateway.yaml")?
                .as_str()?
                .to_owned(),
        )
    })
}

fn reading(text: &str) -> String {
    let text = helm_gateway_yaml(text).unwrap_or_else(|| text.to_owned());
    let extracted = Figment::from(figment::providers::Serialized::defaults(Config::default()))
        .merge(AdapterYaml(text.to_owned()))
        .extract::<Config>();
    match extracted {
        Ok(config) => match golden::canonical_digest(&config) {
            Ok(digest) => digest,
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        Err(error) => format!("ERR {}", golden::one_line(&error.to_string())),
    }
}

/// The `Config` the gateway's loader builds from `text`, written where no
/// env file it names exists.
fn loaded(text: &str) -> String {
    let text = helm_gateway_yaml(text).unwrap_or_else(|| text.to_owned());
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, text).expect("write the config");
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

fn report() -> String {
    let paths: Vec<String> = CONFIGS.iter().map(|p| (*p).to_owned()).collect();
    golden::keyed_rows(&paths, reading)
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
