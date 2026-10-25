// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `capabilities.tsv` reading, over whichever backend the including
//! crate binds as `crate::yaml`: the adapter in
//! `mik_8425_yaml_baseline_capabilities`, `yaml::next` in
//! `mik_8425_mig2_parity` (MIK-8425 MIG.2).
//!
//! `parse_capability` reads through the library's own adapter, which a test
//! binding cannot reach, so this reading repeats what it does: a typed read
//! of `CapabilityDefinition` and the same error wrapping. The baseline crate
//! holds this reading to the same golden as `parse_capability` itself.

use mcp_gateway::capability::CapabilityDefinition;

use crate::{golden, yaml};

pub(crate) fn reading(text: &str) -> String {
    match yaml::from_str::<CapabilityDefinition>(text) {
        Ok(definition) => match golden::canonical_digest(&definition) {
            Ok(digest) => digest,
            Err(error) => format!("JSON-ERR {}", golden::one_line(&error.to_string())),
        },
        // `parse_capability`'s `Error::Config` wrapping, as it displays.
        Err(error) => format!(
            "ERR {}",
            golden::one_line(&format!(
                "Configuration error: Failed to parse capability YAML: {error}"
            ))
        ),
    }
}
