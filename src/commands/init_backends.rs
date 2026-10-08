// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The starter backends `mcp-gateway init` writes (MIK-7787): every registry
//! entry that needs no login, has bounded reach and nothing to configure
//! (`RegistryEntry::default_enabled`), enabled.

use std::fmt::Write as _;

use mcp_gateway::registry::server_registry::{self, Transport};

/// The `backends:` block for the starter set, and one line per entry left out
/// because its launcher (`npx`, `uvx`) is not on PATH: a backend written
/// without its launcher would fail on every start.
pub(super) fn starter_backends(launcher_present: impl Fn(&str) -> bool) -> (String, Vec<String>) {
    let mut yaml = String::from(concat!(
        "# Servers that need no account, enabled. Browse the rest with\n",
        "# `mcp-gateway list --available`; turn one on with `mcp-gateway add <name>`.\n",
        "backends:\n",
    ));
    let mut skipped = Vec::new();
    // A JSON string is a valid YAML double-quoted scalar.
    let quoted = |s: &str| serde_json::to_string(s).unwrap_or_default();
    for entry in server_registry::all()
        .iter()
        .filter(|e| e.default_enabled())
    {
        let transport = match entry.transport {
            Transport::Stdio => {
                let launcher = entry.command.split_whitespace().next().unwrap_or_default();
                if !launcher_present(launcher) {
                    skipped.push(format!(
                        "Skipped '{name}': `{launcher}` is not on PATH. Install it, then run \
                         `mcp-gateway add {name} --config <this file>`.",
                        name = entry.name
                    ));
                    continue;
                }
                format!("    command: {}\n", quoted(entry.command))
            }
            // `url` only: the transport is detected at connect (POST first,
            // the SSE handshake on a 4xx), so the registry's flavour is not
            // written as the hidden `streamable_http` key.
            Transport::Http { default_url, .. } => {
                format!("    url: {}\n", quoted(default_url))
            }
        };
        // Writing to a String cannot fail.
        let _ = write!(
            yaml,
            "  {}:\n{transport}    description: {}\n",
            entry.name,
            quoted(entry.description)
        );
    }
    (yaml, skipped)
}

#[cfg(test)]
mod tests {
    use super::starter_backends;
    use mcp_gateway::config::{Config, TransportConfig};
    use mcp_gateway::registry::server_registry;

    fn starter_names() -> Vec<&'static str> {
        server_registry::all()
            .iter()
            .filter(|e| e.default_enabled())
            .map(|e| e.name)
            .collect()
    }

    #[test]
    fn every_starter_server_is_written_enabled_and_loads() {
        let (yaml, skipped) = starter_backends(|_| true);
        assert!(skipped.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, &yaml).unwrap();
        let config = Config::load(Some(&path)).expect("the starter block loads");
        let mut written: Vec<_> = config.backends.keys().map(String::as_str).collect();
        written.sort_unstable();
        let mut expected = starter_names();
        expected.sort_unstable();
        assert_eq!(written, expected);
        assert!(config.backends.values().all(|b| b.enabled));
        match &config.backends["context7"].transport {
            TransportConfig::Http {
                streamable_http, ..
            } => assert_eq!(*streamable_http, None, "detected at connect, not pinned"),
            other => panic!("context7 is http, got {other:?}"),
        }
    }

    #[test]
    fn a_server_whose_launcher_is_missing_is_skipped_with_a_message() {
        let (yaml, skipped) = starter_backends(|launcher| launcher != "npx");
        assert!(!yaml.contains("memory:"), "{yaml}");
        assert!(yaml.contains("context7:"), "http entries need no launcher");
        assert!(
            skipped
                .iter()
                .any(|s| s.contains("'memory'") && s.contains("npx")),
            "{skipped:?}"
        );
    }
}
