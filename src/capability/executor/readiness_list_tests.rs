// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787: `cap list` says why a keyed capability is not served.

use std::sync::Arc;

use super::super::CapabilityExecutor;
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn executor_holding(vars: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, vars).expect("write env file");
    let env = Arc::new(LiveEnv::new(
        Arc::new(EnvOverlay::from_paths(&[path])),
        ResolvedEnvFiles::default(),
    ));
    (dir, CapabilityExecutor::new().with_env(env))
}

fn cap(name: &str, key: &str) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        "name: {name}\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: bearer\n  key: \"{key}\"\n"
    );
    crate::capability::parse_capability(&yaml).unwrap()
}

#[test]
fn a_capability_whose_key_is_missing_is_marked_off_and_names_the_key() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("gone", "env:MIK7787_ABSENT_KEY"));
    assert_eq!(
        line,
        "  gone - Keyed [bearer] off: needs MIK7787_ABSENT_KEY"
    );
}

#[test]
fn a_capability_whose_key_is_set_is_listed_plainly() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("here", "env:MIK7787_PRESENT"));
    assert_eq!(line, "  here - Keyed [bearer]");
}

#[test]
fn an_oauth_capability_without_a_login_says_which_login() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("login", "oauth:mik7787-no-such-provider"));
    assert_eq!(
        line,
        "  login - Keyed [bearer] off: needs a mik7787-no-such-provider login"
    );
}

/// A config declaring one shared and one per-caller (personal) account.
fn config_with_accounts() -> crate::config::Config {
    let yaml = "accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: gw\n  store_dir: /nonexistent/s\n  \
         authority_dir: /nonexistent/a\n  current_key_id: current\n  \
         keys:\n    current: env:UNUSED\n  \
         descriptors:\n    \
         mine:\n      mode: personal_managed\n      provider: p\n      \
         resource: https://api.example.invalid/\n      \
         issuer: https://issuer.example.invalid\n      \
         authorization_endpoint: https://issuer.example.invalid/authorize\n      \
         token_endpoint: https://issuer.example.invalid/token\n      \
         client_id: c\n      redirect_uri: https://gw.example.invalid/cb\n      \
         scopes: [s]\n      send_resource_parameter: true\n    \
         ours:\n      mode: shared\n      provider: p\n";
    serde_yaml::from_str(yaml).expect("config parses")
}

#[test]
fn a_shared_account_key_is_checked_and_a_per_caller_one_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, "MIK7787_PRESENT=x\n").unwrap();
    let env = Arc::new(LiveEnv::new(
        Arc::new(EnvOverlay::from_paths(&[path])),
        ResolvedEnvFiles::default(),
    ));
    let executor = CapabilityExecutor::for_listing(&config_with_accounts(), env);
    let with_account = |name: &str, account: &str| {
        let mut def = cap(name, "env:MIK7787_ABSENT_KEY");
        def.auth.account = Some(account.to_string());
        def
    };
    assert_eq!(
        executor.list_line(&with_account("shared", "ours")),
        "  shared - Keyed [bearer] off: needs MIK7787_ABSENT_KEY"
    );
    assert_eq!(
        executor.list_line(&with_account("personal", "mine")),
        "  personal - Keyed [bearer]"
    );
}
