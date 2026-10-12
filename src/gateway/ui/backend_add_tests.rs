// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787: `add <registry name>` writes the whole backend — login stanza,
//! header or env templates, transport flavour — and never writes an enabled
//! backend the next config load would refuse.
//!
//! Environment-sensitive cases go through an `env_files` entry, which the
//! overlay prefers over the process environment, so a developer's own
//! `TAVILY_API_KEY` cannot change a verdict here.

use std::collections::HashMap;
use std::path::PathBuf;

use super::*;
use crate::config::{Config, TransportConfig};

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn registry(name: &str, user_env: &[(&str, &str)]) -> ResolvedBackend {
    resolve_backend(name, None, None, None, env(user_env)).expect("registry entry")
}

/// A config whose `env_files` sets `vars`, kept alive by the returned dir.
fn config_with_env_file(vars: &str) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let path: PathBuf = dir.path().join("secrets.env");
    // Owner-only: a group- or world-readable env file is refused (CONFIG.2),
    // which would fall back to the process environment.
    crate::gateway::test_helpers::write_owner_only(&path, vars).unwrap();
    let config = Config {
        env_files: vec![path.display().to_string()],
        ..Config::default()
    };
    (dir, config)
}

#[test]
fn an_oauth_entry_is_written_with_an_enabled_oauth_stanza_over_streamable_http() {
    let resolved = registry("notion", &[]);
    let oauth = resolved
        .backend
        .oauth
        .as_ref()
        .expect("notion must carry an oauth stanza so the existing login flow runs");
    assert!(oauth.enabled);
    assert!(
        oauth.client_id.is_none(),
        "no client_id: dynamic registration"
    );
    match &resolved.backend.transport {
        TransportConfig::Http {
            http_url,
            streamable_http,
            ..
        } => {
            assert_eq!(http_url, "https://mcp.notion.com/mcp");
            assert_eq!(
                *streamable_http,
                Some(true),
                "notion speaks Streamable HTTP"
            );
        }
        other => panic!("expected http, got {other:?}"),
    }
}

#[test]
fn an_sse_entry_keeps_the_legacy_handshake() {
    match registry("asana", &[]).backend.transport {
        TransportConfig::Http {
            streamable_http, ..
        } => assert_eq!(streamable_http, Some(false), "asana is an /sse endpoint"),
        other => panic!("expected http, got {other:?}"),
    }
}

#[test]
fn a_header_entry_writes_the_template_and_no_env() {
    let resolved = registry("github", &[]);
    assert_eq!(
        resolved
            .backend
            .headers
            .get("Authorization")
            .map(String::as_str),
        Some("Bearer ${GITHUB_TOKEN}")
    );
    assert!(
        resolved.backend.env.is_empty(),
        "an http backend has no child env"
    );
}

#[test]
fn a_header_variable_given_with_dash_e_goes_into_the_header() {
    // An env: entry cannot feed a header: expansion reads the overlay, not
    // backend.env. So the supplied value is put where it is used.
    let resolved = registry("github", &[("GITHUB_TOKEN", "ghp_test")]);
    assert_eq!(
        resolved
            .backend
            .headers
            .get("Authorization")
            .map(String::as_str),
        Some("Bearer ghp_test")
    );
    assert!(!resolved.backend.env.contains_key("GITHUB_TOKEN"));
}

#[test]
fn a_stdio_entry_writes_a_template_for_each_required_variable() {
    // The child environment is cleared (transport/stdio.rs), so without this
    // the server starts with no key at all.
    let resolved = registry("tavily", &[]);
    assert_eq!(
        resolved
            .backend
            .env
            .get("TAVILY_API_KEY")
            .map(String::as_str),
        Some("${TAVILY_API_KEY}")
    );
    let given = registry("tavily", &[("TAVILY_API_KEY", "tvly-x")]);
    assert_eq!(
        given.backend.env.get("TAVILY_API_KEY").map(String::as_str),
        Some("tvly-x")
    );
}

#[test]
fn an_arbitrary_reach_entry_is_added_disabled_with_its_reason() {
    let mut config = Config::default();
    let notes = add_backend(&mut config, "playwright", registry("playwright", &[])).unwrap();
    assert!(!config.backends["playwright"].enabled);
    assert!(
        notes.iter().any(|n| n.contains("can open any address")),
        "the reason must be shown: {notes:?}"
    );
}

#[test]
fn a_required_variable_the_loader_cannot_resolve_adds_the_backend_disabled() {
    let (_dir, mut config) = config_with_env_file("TAVILY_API_KEY=\n");
    let notes = add_backend(&mut config, "tavily", registry("tavily", &[])).unwrap();
    assert!(
        !config.backends["tavily"].enabled,
        "an empty value is unset (C4): enabled would make the next load fail"
    );
    assert!(
        notes.iter().any(|n| n.contains("TAVILY_API_KEY")),
        "the note names the variable: {notes:?}"
    );
}

#[test]
fn a_required_variable_set_in_an_env_file_adds_the_backend_enabled() {
    let (_dir, mut config) = config_with_env_file("TAVILY_API_KEY=tvly-x\n");
    let notes = add_backend(&mut config, "tavily", registry("tavily", &[])).unwrap();
    assert!(config.backends["tavily"].enabled, "notes: {notes:?}");
}

#[test]
fn an_explicit_command_is_added_enabled_with_nothing_to_say() {
    let mut config = Config::default();
    let resolved =
        resolve_backend("mine", Some("node server.js"), None, None, HashMap::new()).unwrap();
    let notes = add_backend(&mut config, "mine", resolved).unwrap();
    assert!(config.backends["mine"].enabled);
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn enabling_a_backend_with_an_unresolved_reference_is_refused() {
    let (_dir, mut config) = config_with_env_file("TAVILY_API_KEY=\n");
    add_backend(&mut config, "tavily", registry("tavily", &[])).unwrap();
    let refused = update_backend(
        &mut config,
        "tavily",
        BackendUpdate {
            enabled: Some(true),
            ..BackendUpdate::default()
        },
    );
    let message = refused.expect_err("enabling would write a config the next load refuses");
    assert!(message.contains("TAVILY_API_KEY"), "{message}");
    assert!(!config.backends["tavily"].enabled);
}

#[test]
fn what_add_writes_survives_the_config_file_and_loads() {
    // Disabled-with-unresolved and enabled-with-header must both persist and
    // load: the point of the readiness rule is a file the gateway accepts.
    let (dir, mut config) = config_with_env_file("TAVILY_API_KEY=\n");
    add_backend(&mut config, "tavily", registry("tavily", &[])).unwrap();
    add_backend(
        &mut config,
        "github",
        registry("github", &[("GITHUB_TOKEN", "ghp_roundtrip")]),
    )
    .unwrap();
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_config_fixture(&path, &config).unwrap();
    let loaded = Config::load(Some(&path)).expect("the written config loads");
    assert!(!loaded.backends["tavily"].enabled);
    assert!(loaded.backends["github"].enabled);
    assert_eq!(
        loaded.backends["github"]
            .headers
            .get("Authorization")
            .map(String::as_str),
        Some("Bearer ghp_roundtrip")
    );
}

#[test]
fn an_optional_variable_the_gateway_holds_is_forwarded_and_an_unset_one_is_left_out() {
    let (_dir, mut config) = config_with_env_file("AWS_PROFILE=work\nAWS_REGION=\n");
    add_backend(&mut config, "aws", registry("aws", &[])).unwrap();
    let aws = &config.backends["aws"];
    assert!(aws.enabled, "optional variables never block enabling");
    assert_eq!(
        aws.env.get("AWS_PROFILE").map(String::as_str),
        Some("${AWS_PROFILE}"),
        "a profile chosen in the gateway environment must reach the cleared child"
    );
    assert!(
        !aws.env.contains_key("AWS_REGION"),
        "an empty optional variable is not forwarded"
    );
}

/// MIK-7816.FIX.3: an empty `-e VAR=` for a required variable is not a value.
/// The reference stays, the unresolved check sees it, and the backend is added
/// disabled with the variable named, on the stdio and the header path alike.
#[test]
fn an_empty_value_for_a_required_variable_is_unresolved() {
    for (name, var) in [
        ("tavily", "TAVILY_API_KEY"),
        ("stripe", "STRIPE_SECRET_KEY"),
    ] {
        let (_dir, mut config) = config_with_env_file(&format!("{var}=\n"));
        let notes = add_backend(&mut config, name, registry(name, &[(var, "")])).unwrap();
        assert!(!config.backends[name].enabled, "{name}: {notes:?}");
        assert!(
            notes.iter().any(|n| n.contains(var)),
            "{name}: the note names the variable: {notes:?}"
        );
    }
}

/// MIK-7816.FIX.2: an entry that needs arguments appended to its command is
/// added disabled, with what to append, since the registry path takes none.
#[test]
fn an_entry_that_needs_arguments_is_added_disabled() {
    let mut config = Config::default();
    let notes = add_backend(&mut config, "filesystem", registry("filesystem", &[])).unwrap();
    assert!(!config.backends["filesystem"].enabled, "{notes:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("the directories it may access")),
        "the note says what to append: {notes:?}"
    );
}

/// MIK-7816.FIX.1 (server side): an OAuth entry is added enabled and still
/// carries its login note; the UI tells the two apart by `enabled`.
#[test]
fn an_oauth_entry_is_added_enabled_with_its_login_note() {
    let mut config = Config::default();
    let notes = add_backend(&mut config, "linear", registry("linear", &[])).unwrap();
    assert!(config.backends["linear"].enabled, "{notes:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("Logs in through your browser")),
        "{notes:?}"
    );
}
