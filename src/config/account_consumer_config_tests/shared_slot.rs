// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8962 SHARED.4: which compiled backends refuse a shared session, judged
//! through the real load path and the account compiler, for every binding
//! syntax. A required binding with per-user sessions refuses it; a backend
//! that may share keeps it.

use super::*;

/// The backends a config loads with, after the account compiler applied each
/// `account:` reference.
fn effective(
    dir: &Path,
    port: u16,
    descriptors: &str,
    backends: &str,
) -> std::collections::BTreeMap<String, crate::config::BackendConfig> {
    let env_path = write_env(dir);
    let body = format!(
        "env_files:\n  - {}\nserver:\n  port: {port}\naccounts:\n{}  descriptors:\n{descriptors}{backends}",
        quoted(&env_path),
        store_block(dir),
    );
    let path = dir.join(format!("config-{port}.yaml"));
    crate::gateway::test_helpers::write_owner_only(&path, body).unwrap();
    let evaluated = Config::load_evaluated(Some(path.as_path())).expect("config loads");
    crate::config::account_bindings::effective_backends(&evaluated.config)
}

fn refuses_shared(config: &crate::config::BackendConfig) -> bool {
    crate::backend::Backend::new(
        "probe",
        config.clone(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .shared_slot_refused()
}

fn propagated(strategy: &str, required: bool, session_mode: &str) -> String {
    let endpoint = if strategy == "token_exchange" {
        "      token_exchange_endpoint: https://issuer.example.invalid/exchange\n"
    } else {
        ""
    };
    format!(
        "    http_url: https://backend.example.invalid/mcp\n    \
         identity_propagation:\n      strategy: {strategy}\n      \
         audience: https://backend.example.invalid/\n      \
         required: {required}\n      session_mode: {session_mode}\n{endpoint}"
    )
}

#[test]
fn every_binding_syntax_refuses_a_shared_session_only_when_required_per_user() {
    let root = tempfile::TempDir::new().unwrap();
    let descriptors = format!(
        "{}{}{}{}",
        managed_descriptor("work", "google"),
        external_descriptor("ext-stateless", "partner", "token_exchange"),
        external_descriptor("ext-per-user", "partner", "token_exchange")
            .replace("session_mode: stateless", "session_mode: per_user"),
        shared_descriptor("team", "partner"),
    );
    let mut backends = String::from("backends:\n");
    let mut want = Vec::new();
    for (name, body, refused) in [
        (
            "signed",
            propagated("signed_assertion", true, "per_user"),
            true,
        ),
        (
            "exchanged",
            propagated("token_exchange", true, "per_user"),
            true,
        ),
        (
            "signed-stateless",
            propagated("signed_assertion", true, "stateless"),
            false,
        ),
        (
            "signed-optional",
            propagated("signed_assertion", false, "per_user"),
            false,
        ),
        (
            "managed",
            "    http_url: https://backend.example.invalid/mcp\n    account: work\n".to_string(),
            true,
        ),
        (
            "external-per-user",
            "    http_url: https://backend.example.invalid/mcp\n    account: ext-per-user\n"
                .to_string(),
            true,
        ),
        (
            "external-stateless",
            "    http_url: https://backend.example.invalid/mcp\n    account: ext-stateless\n"
                .to_string(),
            false,
        ),
        (
            "shared-account",
            "    http_url: https://backend.example.invalid/mcp\n    account: team\n".to_string(),
            false,
        ),
        (
            "plain",
            "    http_url: https://backend.example.invalid/mcp\n".to_string(),
            false,
        ),
    ] {
        backends.push_str(&format!("  {name}:\n{body}"));
        want.push((name, refused));
    }
    let compiled = effective(root.path(), 18962, &descriptors, &backends);
    for (name, refused) in want {
        let config = compiled
            .get(name)
            .unwrap_or_else(|| panic!("{name} compiled: {:?}", compiled.keys()));
        assert_eq!(refuses_shared(config), refused, "{name}");
    }
}
