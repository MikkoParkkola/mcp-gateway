// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `redaction.txt` capability rows, over whichever backend the including
//! crate binds as `crate::yaml`: the adapter in
//! `mik_8425_yaml_baseline_redaction`, the same adapter in `mik_8425_mig2_parity`, which bound `yaml::next`
//! until the MIK-8425 MIG.2 switch. The config rows stay in the
//! baseline: `Config::load` reads through the library's own adapter.
#![allow(
    dead_code,
    reason = "each including crate uses a different part of the report"
)]

use std::fmt::Write as _;

use mcp_gateway::capability::CapabilityDefinition;

use crate::yaml;

/// Stands in for a secret typed into the wrong field. Not shaped like any
/// real credential, so secret scanners do not flag the test.
pub(crate) const SENTINEL: &str = "MIK8425-SENTINEL-7f3a";

pub(crate) fn capability(provider_timeout: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: g2_probe\ndescription: G2 probe.\nschema:\n  input:\n    \
         type: object\n    properties: {{}}\nproviders:\n  primary:\n    service: rest\n    \
         timeout: {provider_timeout}\n    config:\n      base_url: https://api.example.test\n      \
         path: /x\n      method: GET\n"
    )
}

/// One case: input with the sentinel, the same input corrected, and a
/// fragment the refusal must contain to prove it is refused for the reason
/// the case names (the key path, or a location for a syntax error).
pub(crate) struct Case {
    pub(crate) name: &'static str,
    pub(crate) bad: String,
    pub(crate) good: String,
    pub(crate) names: &'static str,
}

/// `refused names=<bool> leaks=<bool> control=<loads|refused>`: a refusal
/// counts only if it names the expected key or place, and only if the
/// corrected input loads, so an unrelated refusal cannot pass as redaction.
pub(crate) fn outcome(case: &Case, load: impl Fn(&str) -> Result<(), String>) -> String {
    let control = if load(&case.good).is_ok() {
        "loads"
    } else {
        "refused"
    };
    match load(&case.bad) {
        Ok(()) => format!("accepted control={control}"),
        Err(message) => format!(
            "refused names={} leaks={} control={control}",
            message.contains(case.names),
            message.contains(SENTINEL)
        ),
    }
}

/// `parse_capability` over this crate's binding: the same typed read and the
/// same `Error::Config` wrapping, as it displays and as it debugs.
pub(crate) fn load_capability_bound(text: &str) -> Result<(), String> {
    yaml::from_str::<CapabilityDefinition>(text)
        .map(|_| ())
        .map_err(|e| {
            let message = format!("Failed to parse capability YAML: {e}");
            format!("Configuration error: {message} Config({message:?})")
        })
}

pub(crate) fn capability_rows(out: &mut String, load: impl Fn(&str) -> Result<(), String>) {
    let cases = [
        Case {
            name: "capability/type-error",
            bad: capability(SENTINEL),
            good: capability("30"),
            names: "providers.primary: invalid type: string",
        },
        Case {
            name: "capability/syntax-error",
            bad: format!("name: \"unterminated {SENTINEL}\n"),
            good: capability("30"),
            names: "quoted text is not closed, or continues with too little indentation",
        },
    ];
    for case in &cases {
        let _ = writeln!(out, "{}\t{}", case.name, outcome(case, &load));
    }
}
