// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` row `security-posture`: a multi-user deployment running the
//! `standard` posture. Same predicate as the startup warning.

use mcp_gateway::config::Config;

use super::CheckResult;

pub(super) fn check_security_posture(config: &Config) -> CheckResult {
    let row = if mcp_gateway::security::posture::unhardened_multi_user(config) {
        CheckResult::warn(
            "security-posture",
            "multi-user deployment running security.posture=standard",
        )
        .with_hint("set security.posture: hardened (restart required)")
        .with_manual_fix("set security.posture: hardened in gateway.yaml, then restart")
    } else {
        CheckResult::pass(
            "security-posture",
            format!("security.posture={}", posture_name(config)),
        )
    };
    row.with_category("security")
}

fn posture_name(config: &Config) -> String {
    serde_json::to_value(config.security.posture)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use mcp_gateway::security::posture::{SecurityPosture, unhardened_multi_user};
    use serde_json::json;

    use super::super::CheckStatus;
    use super::*;

    /// The auth-shape table from the library's `startup_warn_matches_unhardened_table`.
    fn auth_shapes() -> Vec<(&'static str, Config, bool)> {
        let key = |name: &str| serde_json::from_value(json!({ "name": name })).unwrap();
        let mut shapes = Vec::new();
        let mut disabled = Config::default();
        disabled.auth.api_keys = vec![key("a"), key("b")];
        shapes.push(("auth disabled, two keys", disabled, false));
        let mut one_key = Config::default();
        one_key.auth.enabled = true;
        one_key.auth.api_keys = vec![key("a")];
        shapes.push(("one key", one_key.clone(), true));
        let mut solo = one_key.clone();
        solo.auth.single_user = true;
        shapes.push(("one key, single_user", solo.clone(), false));
        let mut two_keys = solo.clone();
        two_keys.auth.api_keys.push(key("b"));
        shapes.push(("two keys, single_user", two_keys, true));
        let mut oidc = solo;
        oidc.key_server.oidc =
            vec![serde_json::from_value(json!({ "issuer": "https://idp.example" })).unwrap()];
        shapes.push(("one key, single_user, OIDC", oidc, true));
        let mut bearer = Config::default();
        bearer.auth.enabled = true;
        bearer.auth.bearer_token = Some("t".repeat(40));
        shapes.push(("bearer only", bearer, true));
        shapes
    }

    #[test]
    fn doctor_row_matches_unhardened_table() {
        for (shape, mut config, multi_user) in auth_shapes() {
            for posture in [SecurityPosture::Standard, SecurityPosture::Hardened] {
                config.security.posture = posture;
                let expected = multi_user && posture == SecurityPosture::Standard;
                assert_eq!(
                    unhardened_multi_user(&config),
                    expected,
                    "{shape} {posture:?}"
                );
                let row = check_security_posture(&config);
                assert_eq!(row.label, "security-posture");
                assert_eq!(row.category, "security");
                let status = if expected {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Pass
                };
                assert_eq!(row.status, status, "{shape} under {posture:?}");
            }
        }
    }
}
