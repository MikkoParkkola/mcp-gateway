// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Valid shapes for API key names.

use super::*;
use crate::config::Config;

fn config_with_key_names(names: &[&str]) -> Config {
    let mut config = Config::default();
    config.auth.api_keys = names
        .iter()
        .enumerate()
        .map(|(index, name)| ApiKeyConfig {
            key: None,
            key_sha256: Some(super::super::api_key::api_key_digest_spec(
                format!("secret-{index}").as_bytes(),
            )),
            expires_at: None,
            name: (*name).to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        })
        .collect();
    config
}

// A key's name is its identity-grant subject (`api_key:<name>`), so two
// keys sharing a name would hold each other's grants and a nameless key
// could hold none. Both are refused at load, whether or not auth is on.
#[test]
fn duplicate_api_key_names_are_refused_at_load() {
    let err = config_with_key_names(&["ops", "laptop", "ops"])
        .validate()
        .expect_err("two keys named 'ops' would share one grant identity");
    assert!(err.to_string().contains("ops"), "{err}");
}

#[test]
fn an_empty_api_key_name_is_refused_at_load() {
    for blank in ["", "  "] {
        let err = config_with_key_names(&["laptop", blank])
            .validate()
            .expect_err("a nameless key has no grant identity");
        assert!(err.to_string().contains("name"), "{err}");
    }
}

// `alice ` would be a distinct subject from `alice`, so a grant written
// for `api_key:alice` would silently never match the padded key.
#[test]
fn a_padded_api_key_name_is_refused_at_load() {
    for padded in ["alice ", " alice", "\talice"] {
        let err = config_with_key_names(&[padded])
            .validate()
            .expect_err("a padded name is not the subject a grant names");
        assert!(err.to_string().contains("whitespace"), "{err}");
    }
}

#[test]
fn unique_named_api_keys_load() {
    config_with_key_names(&["laptop", "phone"])
        .validate()
        .expect("distinct non-empty names are the valid shape");
}
