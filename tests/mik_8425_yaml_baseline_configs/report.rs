// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `configs.tsv` readings, over whichever backend the including crate
//! binds as `crate::yaml`: the adapter in `mik_8425_yaml_baseline_configs`,
//! `yaml::next` in `mik_8425_mig2_parity` (MIK-8425 MIG.2).
#![allow(
    dead_code,
    reason = "each including crate uses a different part of the report"
)]

use figment::value::{Dict, Map};
use figment::{Figment, Metadata, Profile, Provider};
use mcp_gateway::config::Config;

use crate::{golden, yaml};

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
pub(crate) const CONFIGS: &[&str] = &[
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
pub(crate) fn helm_gateway_yaml(text: &str) -> Option<String> {
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

pub(crate) fn reading(text: &str) -> String {
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

pub(crate) fn report() -> String {
    let paths: Vec<String> = CONFIGS.iter().map(|p| (*p).to_owned()).collect();
    golden::keyed_rows(&paths, reading)
}
