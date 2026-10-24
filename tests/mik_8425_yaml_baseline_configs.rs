// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8425 MIG.2 step 2 (P13, MIG.3 Config identity): the `Config` each
//! shipped gateway config extracts to through the adapter's `figment_data`,
//! recorded with the current backend before the swap.
//!
//! The extract uses `figment_data` alone over the defaults, with no
//! environment overlay, so the digest is the same on every machine. A
//! refusal row keeps its text; a later stage compares refusal against
//! refusal.

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
    "benchmarks/workload/gateway.workload.yaml",
    "benchmarks/workload/gateway.workload.mixed.yaml",
];

fn reading(text: &str) -> String {
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
