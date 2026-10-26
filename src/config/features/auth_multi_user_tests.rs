// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether the auth configuration could have more than one human behind it.

use super::*;

fn api_key(name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(super::super::api_key::api_key_digest_spec(
            format!("k-{name}").as_bytes(),
        )),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

#[test]
fn disabled_auth_is_never_multi_user() {
    let cfg = AuthConfig::default(); // enabled=false
    assert!(!cfg.implies_multi_user(false));
    assert!(
        !cfg.implies_multi_user(true),
        "no auth boundary = nothing to isolate"
    );
}

#[test]
fn single_shared_api_key_fails_closed_to_multi_user() {
    // The MIK-6752 fix: one API key handed to a team must NOT read as single-user.
    let cfg = AuthConfig {
        enabled: true,
        api_keys: vec![api_key("team")],
        ..AuthConfig::default()
    };
    assert!(
        cfg.implies_multi_user(false),
        "a single shared API key is treated as multi-user unless explicitly declared single_user"
    );
}

#[test]
fn shared_bearer_only_fails_closed_to_multi_user() {
    // Previously the bearer-token path was ignored entirely by count-based detection.
    let cfg = AuthConfig {
        enabled: true,
        bearer_token: Some("shared-secret".to_string()),
        api_keys: Vec::new(),
        ..AuthConfig::default()
    };
    assert!(
        cfg.implies_multi_user(false),
        "a shared bearer with no api_keys still fails closed"
    );
}

#[test]
fn explicit_single_user_opts_out() {
    let cfg = AuthConfig {
        enabled: true,
        api_keys: vec![api_key("me")],
        single_user: true,
        ..AuthConfig::default()
    };
    assert!(
        !cfg.implies_multi_user(false),
        "operator may declare a genuine single-user deployment"
    );
}

#[test]
fn multiple_api_keys_are_hard_multi_user_even_if_single_user_set() {
    let cfg = AuthConfig {
        enabled: true,
        api_keys: vec![api_key("a"), api_key("b")],
        single_user: true, // contradictory hint is overridden by the hard signal
        ..AuthConfig::default()
    };
    assert!(
        cfg.implies_multi_user(false),
        ">1 API key is a hard multi-user signal"
    );
}

#[test]
fn oidc_is_hard_multi_user_even_if_single_user_set() {
    let cfg = AuthConfig {
        enabled: true,
        single_user: true,
        ..AuthConfig::default()
    };
    assert!(
        cfg.implies_multi_user(true),
        "any OIDC issuer means many end users"
    );
}
