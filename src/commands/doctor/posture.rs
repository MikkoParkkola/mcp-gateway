// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` row `security-posture`: a multi-user deployment running the
//! `standard` posture. Same predicate as the startup warning.

use mcp_gateway::config::Config;

use super::CheckResult;

/// Design row 15: the library's auth-shape table, the one the startup warning
/// test reads, so the two rows cannot drift apart.
#[cfg(test)]
#[path = "../../security/posture_auth_shapes.rs"]
mod auth_shapes;

pub(super) fn check_security_posture(config: &Config) -> CheckResult {
    let warning = mcp_gateway::security::unhardened_multi_user_warning(config);
    let row = if let Some(warning) = warning {
        CheckResult::warn("security-posture", warning)
            .with_manual_fix("set security.posture: hardened in gateway.yaml, then restart")
    } else {
        CheckResult::pass("security-posture", pass_detail(config))
    };
    row.with_category("security")
}

/// Under hardened, also the refusal an operator meets first (M5): the
/// dashboard's MCP calls need an identity-provider or Access subject.
fn pass_detail(config: &Config) -> String {
    let name = posture_name(config);
    if config.security.posture == mcp_gateway::security::SecurityPosture::Hardened {
        format!(
            "security.posture={name}: HTTP MCP callers need a per-caller identity; dashboard MCP \
             calls are refused (403) without an IdP or Access subject"
        )
    } else {
        format!("security.posture={name}")
    }
}

fn posture_name(config: &Config) -> String {
    serde_json::to_value(config.security.posture)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::CheckStatus;
    use super::auth_shapes::auth_shapes;
    use super::*;
    use mcp_gateway::security::{SecurityPosture, unhardened_multi_user_warning};

    #[test]
    fn doctor_row_matches_unhardened_table() {
        for (shape, mut config, multi_user) in auth_shapes() {
            for posture in [SecurityPosture::Standard, SecurityPosture::Hardened] {
                config.security.posture = posture;
                let expected = multi_user && posture == SecurityPosture::Standard;
                let warning = unhardened_multi_user_warning(&config);
                assert_eq!(warning.is_some(), expected, "{shape} {posture:?}");
                let row = check_security_posture(&config);
                if let Some(warning) = warning {
                    assert_eq!(row.detail, warning, "the startup text, verbatim");
                }
                assert_eq!(row.label, "security-posture");
                assert_eq!(row.category, "security");
                let status = if expected {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Pass
                };
                assert_eq!(row.status, status, "{shape} under {posture:?}");
                assert_eq!(
                    row.detail.contains("dashboard MCP calls are refused (403)"),
                    posture == SecurityPosture::Hardened,
                    "{shape} under {posture:?}: {}",
                    row.detail
                );
            }
        }
    }
}
