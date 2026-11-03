// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! BACKENDGRANT.1: an API key reaches only the backends it names. An empty
//! (or absent) `backends` list grants none; `"*"` is the only wildcard.

use super::ResolvedAuthConfig;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::test_log_capture::capture_warnings;

fn key(name: &str, backends: &[&str], admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(
            format!("{name}-secret").as_bytes(),
        )),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn resolved(keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    ResolvedAuthConfig::try_from_config(
        &AuthConfig {
            enabled: true,
            api_keys: keys,
            ..AuthConfig::default()
        },
        &no_env(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("literal keys resolve")
}

#[test]
fn api_key_without_backends_reaches_no_backend() {
    let config = resolved(vec![key("bare", &[], false)]);
    let client = config.validate_token("bare-secret").expect("key is valid");
    assert!(
        !client.can_access_backend("brave"),
        "a key that lists no backends must reach none"
    );
}

#[test]
fn wildcard_and_list_scoping() {
    let config = resolved(vec![
        key("all", &["*"], false),
        key("listed", &["tavily", "brave"], false),
    ]);
    let all = config.validate_token("all-secret").expect("key is valid");
    assert!(all.can_access_backend("tavily"));
    assert!(all.can_access_backend("added-next-week"));

    let listed = config
        .validate_token("listed-secret")
        .expect("key is valid");
    assert!(listed.can_access_backend("tavily"));
    assert!(listed.can_access_backend("brave"));
    assert!(!listed.can_access_backend("context7"));
}

#[test]
fn api_key_with_backends_omitted_from_yaml_reaches_no_backend() {
    // The field left out entirely, not `[]`: serde's default must also be none.
    let auth: AuthConfig = crate::yaml::from_str(
        "enabled: true\napi_keys:\n  - key_sha256: sha256:411525617cc97c2811e4b9cf0ce326619095bec63da7ef4d342d18de8c3ef086\n    name: omitted\n",
    )
    .expect("auth YAML parses");
    assert!(auth.api_keys[0].backends.is_empty());
    let config = ResolvedAuthConfig::try_from_config(
        &auth,
        &no_env(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("literal key resolves");
    let client = config
        .validate_token("omitted-secret")
        .expect("key is valid");
    assert!(!client.can_access_backend("brave"));
    assert!(!client.can_access_backend("*"));
}

#[test]
fn key_without_backends_warns_once() {
    let (_, logs) = capture_warnings(|| {
        resolved(vec![
            key("bare", &[], false),
            key("root", &[], true),
            key("scoped", &["tavily"], false),
        ])
    });
    // An admin key is warned too: a UI-only admin key may ignore it, and the
    // wording says when it matters.
    for name in ["bare", "root"] {
        let line = format!("auth.api_keys['{name}'] lists no backends and reaches none");
        assert_eq!(
            logs.matches(&line).count(),
            1,
            "one WARN for {name}: {logs}"
        );
    }
    assert!(
        logs.contains("if this key needs backend access"),
        "the WARN says when it can be ignored: {logs}"
    );
    assert!(
        !logs.contains("'scoped'"),
        "no WARN for a key that lists backends: {logs}"
    );
}

/// No env files: these fixtures hold literal keys only.
fn no_env() -> crate::config::EnvOverlay {
    crate::config::EnvOverlay::none()
}

/// The UI's scope for each key shape: an admin key with an empty list is a
/// UI-wide admin that calls no backend; a non-empty list without `*` narrows
/// the UI, admin or not; a non-admin empty list reaches nothing.
#[cfg(feature = "webui")]
#[test]
fn the_ui_scope_of_each_key_shape() {
    use crate::gateway::authz::BackendGrant;
    let table = resolved(vec![
        key("admin-empty", &[], true),
        key("admin-alpha", &["alpha"], true),
        key("plain-empty", &[], false),
    ]);
    let ui = |name: &str| {
        let client = table
            .validate_token(&format!("{name}-secret"))
            .expect("key is valid");
        (
            BackendGrant::for_ui(Some(&client)).admits("alpha"),
            BackendGrant::for_ui(Some(&client)).admits("beta"),
            client.can_access_backend("alpha"),
        )
    };
    assert_eq!(
        ui("admin-empty"),
        (true, true, false),
        "UI-wide, calls none"
    );
    assert_eq!(ui("admin-alpha"), (true, false, true), "narrowed to alpha");
    assert_eq!(ui("plain-empty"), (false, false, false), "reaches nothing");
}

/// The UI's membership test and MCP dispatch's agree for every grant shape,
/// so the two cannot drift apart while dispatch keeps its own.
#[cfg(feature = "webui")]
#[test]
fn grant_admits_agrees_with_can_access_backend() {
    use crate::gateway::authz::BackendGrant;
    let shapes: [&[&str]; 5] = [&["*"], &[], &["alpha"], &["alpha", "beta"], &["alpha", "*"]];
    let keys = shapes
        .iter()
        .enumerate()
        .flat_map(|(i, shape)| {
            [false, true].map(|admin| key(&format!("shape{i}-{admin}"), shape, admin))
        })
        .collect::<Vec<_>>();
    let names: Vec<String> = keys.iter().map(|k| k.name.clone()).collect();
    let table = resolved(keys);
    for name in names {
        let client = table
            .validate_token(&format!("{name}-secret"))
            .expect("key is valid");
        for backend in ["alpha", "beta", "gamma", "*", ""] {
            assert_eq!(
                BackendGrant::of(Some(&client)).admits(backend),
                client.can_access_backend(backend),
                "{name} ({:?}) on {backend:?}",
                client.backends
            );
        }
    }
}
