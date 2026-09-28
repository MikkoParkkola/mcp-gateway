// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` finding for remote backends that run without signed provenance
//! (#1943). The message is the library's startup warning verbatim, so the log
//! and the report cannot disagree.

use mcp_gateway::config::Config;

use super::CheckResult;

/// One warning row when a remote backend runs unverified; none otherwise.
pub(super) fn check_remote_provenance(config: &Config) -> Vec<CheckResult> {
    config
        .remote_provenance_warning()
        .map(|warning| {
            CheckResult::warn("Remote provenance", warning)
                .with_category("remote_provenance")
                .with_hint(
                    "Set security.remote_server_signing.require_for_remote_backends: true and \
                     add signed metadata for each remote backend under \
                     security.remote_server_signing.backends",
                )
                .with_risk("unverified_remote_backend")
        })
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::CheckStatus;
    use super::*;

    fn config(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("test config parses")
    }

    #[test]
    fn an_unverified_remote_backend_is_a_warning_with_the_startup_text() {
        let config = config("backends:\n  api:\n    http_url: https://api.example.test/mcp\n");
        let rows = check_remote_provenance(&config);
        assert_eq!(rows.len(), 1, "one row: {rows:?}");
        assert_eq!(rows[0].status, CheckStatus::Warn);
        assert_eq!(rows[0].category, "remote_provenance");
        assert_eq!(
            Some(rows[0].detail.clone()),
            config.remote_provenance_warning()
        );
    }

    #[test]
    fn no_row_when_nothing_runs_unverified() {
        let stdio_only = config("backends:\n  local:\n    command: npx some-server\n");
        assert!(check_remote_provenance(&stdio_only).is_empty());
        let required = config(
            "security:\n  remote_server_signing:\n    require_for_remote_backends: true\n\
             backends:\n  api:\n    http_url: https://api.example.test/mcp\n",
        );
        assert!(check_remote_provenance(&required).is_empty());
    }
}
