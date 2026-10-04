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

// MIK-7856.OAUTH.1 and .4: an oauth capability is listed while a usable token
// exists (cached, or in the token file), and not for an expired token that
// cannot be refreshed, or one that cannot be read.

fn oauth_cap(endpoint: bool) -> crate::capability::CapabilityDefinition {
    let endpoint = if endpoint {
        "  token_endpoint: https://issuer.invalid/token\n"
    } else {
        ""
    };
    let yaml = format!(
        "name: oauthy\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: oauth\n  key: \"oauth:mik7856\"\n{endpoint}"
    );
    crate::capability::parse_capability(&yaml).unwrap()
}

fn token(expires_in: i64, refresh: bool) -> crate::oauth::TokenInfo {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut token: crate::oauth::TokenInfo =
        serde_json::from_value(serde_json::json!({"access_token": "t"})).unwrap();
    token.expires_at = Some(u64::try_from(now + expires_in).unwrap());
    token.refresh_token = refresh.then(|| "r".to_string());
    token
}

fn executor_with_storage() -> (
    tempfile::TempDir,
    Arc<crate::oauth::TokenStorage>,
    CapabilityExecutor,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(crate::oauth::TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let executor = CapabilityExecutor::with_token_storage(Arc::clone(&storage));
    (dir, storage, executor)
}

fn off(executor: &CapabilityExecutor, endpoint: bool) -> bool {
    executor
        .missing_credential(
            &oauth_cap(endpoint).auth,
            &mut std::collections::HashMap::new(),
        )
        .is_some()
}

#[test]
fn a_cached_token_and_a_token_file_each_turn_an_oauth_capability_on() {
    let (_dir, storage, executor) = executor_with_storage();
    assert!(off(&executor, false), "no login yet");
    storage
        .save("mik7856", "mik7856", &token(3600, false))
        .unwrap();
    assert!(!off(&executor, false), "a valid token file lists it");

    let (_dir, _storage, cached) = executor_with_storage();
    cached
        .oauth_tokens
        .read()
        .insert("mik7856".to_string(), token(3600, false));
    assert!(!off(&cached, false), "a valid cached token lists it");
}

#[test]
fn an_expired_token_that_cannot_be_refreshed_does_not_list_the_capability() {
    let (_dir, storage, executor) = executor_with_storage();
    storage
        .save("mik7856", "mik7856", &token(-3600, false))
        .unwrap();
    assert!(
        off(&executor, false),
        "an expired file token is not a login"
    );
    // A refresh token needs the capability's token endpoint to be usable.
    storage
        .save("mik7856", "mik7856", &token(-3600, true))
        .unwrap();
    assert!(off(&executor, false), "refresh token without an endpoint");
    assert!(!off(&executor, true), "refreshable: still listed");

    let (_dir, _storage, cached) = executor_with_storage();
    cached
        .oauth_tokens
        .read()
        .insert("mik7856".to_string(), token(-3600, false));
    assert!(
        off(&cached, false),
        "an expired cached token is not a login"
    );
}

#[test]
fn an_unreadable_token_file_does_not_list_the_capability() {
    let (_dir, storage, executor) = executor_with_storage();
    let path = storage.token_path("mik7856", "mik7856");
    crate::gateway::test_helpers::write_owner_only(&path, "{not json").unwrap();
    assert!(off(&executor, false));
}

#[test]
fn a_cached_expired_refreshable_token_is_no_login_and_endpoints_are_judged_apart() {
    let (_dir, _storage, cached) = executor_with_storage();
    cached
        .oauth_tokens
        .read()
        .insert("mik7856".to_string(), token(-3600, true));
    assert!(off(&cached, true), "the cache is never refreshed");

    let (_dir, storage, shared) = executor_with_storage();
    storage
        .save("mik7856", "mik7856", &token(-3600, true))
        .unwrap();
    let (no_endpoint, with_endpoint) = (oauth_cap(false), oauth_cap(true));
    let mut seen = std::collections::HashMap::new();
    for _ in 0..2 {
        assert!(
            shared
                .missing_credential(&no_endpoint.auth, &mut seen)
                .is_some()
        );
        assert!(
            shared
                .missing_credential(&with_endpoint.auth, &mut seen)
                .is_none()
        );
    }
}
