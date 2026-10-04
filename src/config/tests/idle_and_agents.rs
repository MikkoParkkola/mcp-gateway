// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Idle-stop ownership, duration parsing and agent key material.

use super::*;

// ── GW.IDLE.3 — ownership validation ────────────────────────────────────────
//
// `stop_when_idle_for` promises the gateway will stop a process. It can only
// honour that where it started the process. Accepting it elsewhere would repeat
// nowhere, trusted by operators.

#[test]
fn stop_when_idle_for_is_accepted_on_a_gateway_started_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 5m\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("stdio backend may opt in");
    let backend = cfg
        .backends
        .get("owned")
        .expect("backend must survive parsing");
    assert_eq!(
        backend.stop_when_idle_for,
        Some(std::time::Duration::from_secs(300)),
        "the duration must round-trip, not silently default"
    );
}

#[test]
fn stop_when_idle_for_is_rejected_on_a_backend_the_gateway_does_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // A LOCAL http backend: locality does not grant ownership. The gateway did
    // not start this server and cannot stop it.
    write_owner_only(
        &path,
        "backends:\n  external:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    stop_when_idle_for: 5m\n",
    )
    .expect("write");

    let err =
        Config::load(Some(&path)).expect_err("the gateway cannot stop a process it did not start");
    let msg = err.to_string();
    assert!(
        msg.contains("external"),
        "the error must name the offending backend, got: {msg}"
    );
    assert!(
        msg.contains("stop_when_idle_for"),
        "the error must name the setting, got: {msg}"
    );
}

#[test]
fn omitting_stop_when_idle_for_leaves_a_backend_running_indefinitely() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, "backends:\n  owned:\n    command: \"echo hi\"\n").expect("write");

    let cfg = Config::load(Some(&path)).expect("load");
    assert_eq!(
        cfg.backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        None,
        "absent must mean never stop - no magic default that changes behaviour on upgrade"
    );
}

#[test]
fn an_http_backend_without_the_setting_still_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  external:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("http backends are fine without the setting");
    assert!(
        cfg.backends.contains_key("external"),
        "control: the validation must reject only the setting, not the transport"
    );
}

#[test]
fn duration_parser_handles_milliseconds() {
    // Regression: the parser tested the "s" suffix BEFORE "ms", so "100ms" took
    // the seconds branch and failed to parse "100m" as an integer. Every ms value
    // in every duration field was rejected.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  owned:\n    command: \"echo hi\"\n    stop_when_idle_for: 1500ms\n",
    )
    .expect("write");

    let cfg = Config::load(Some(&path)).expect("ms suffix must parse");
    assert_eq!(
        cfg.backends
            .get("owned")
            .expect("backend")
            .stop_when_idle_for,
        Some(std::time::Duration::from_millis(1500))
    );
}

/// The key's NAME inside a value is not a use of the key: a description
/// quoting `idle_timeout:` must not make the config refuse to load.
#[test]
fn retired_key_name_inside_a_value_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(
        &path,
        "backends:\n  demo:\n    command: \"echo hi\"\n    description: |\n      idle_timeout: 10m is no longer supported\n",
    )
    .expect("write config");
    Config::load(Some(&path)).expect("a key name inside a block scalar is text, not a set key");
}

// -------------------------------------------------------------------------
// Agent key material (MIK-7258)
//
// `DecodingKey::from_secret(b"")` is a valid key anyone can sign for, so an
// agent whose HS256 secret is empty verifies a token from any caller while the
// config reads as authenticated. Nothing rejected it, and the network-posture
// refusal then treated `agent_auth.enabled` as proof the tools demand a
// credential — an exemption meant to recognise security, recognising none.
//
// The check lives here rather than in that refusal because three attempts to
// judge key strength there each missed the next case.
// -------------------------------------------------------------------------

/// A config with agent auth on and one agent holding `secret`.
fn agent_config(secret: Option<&str>, rsa: Option<&str>) -> Config {
    let mut c = Config::default();
    c.agent_auth.enabled = true;
    c.agent_auth.agents = vec![crate::config::AgentDefinitionConfig {
        client_id: "svc".to_string(),
        name: "svc".to_string(),
        hs256_secret: secret.map(str::to_string),
        rs256_public_key: rsa.map(str::to_string),
        scopes: Vec::new(),
        issuer: None,
        // An agent with no audience is refused before the key checks below
        // ever run, so a key-material fixture has to set one or it would
        // assert against the audience refusal instead.
        audience: Some("mcp-gateway-test".to_string()),
    }];
    c
}

#[test]
fn an_agent_secret_that_could_not_reject_anybody_fails_validation() {
    for (label, secret) in [
        ("empty", ""),
        ("one character", "x"),
        (
            "thirty-one bytes, one short of the floor",
            &"k".repeat(31)[..],
        ),
    ] {
        let err = agent_config(Some(secret), None)
            .validate()
            .expect_err(&format!("an agent secret that is {label} was accepted"));
        let msg = err.to_string();
        assert!(
            msg.contains("svc") && msg.contains("hs256_secret"),
            "the message must name the agent and the field: {msg}"
        );
    }
}

#[test]
fn a_usable_agent_secret_validates() {
    agent_config(Some(&"k".repeat(32)), None)
        .validate()
        .expect("a 32-byte secret is the documented minimum and must be accepted");
    agent_config(
        None,
        Some("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"),
    )
    .validate()
    .expect("an RSA public key needs no shared secret");
}

#[test]
fn an_agent_with_no_key_material_at_all_fails_validation() {
    let err = agent_config(None, None)
        .validate()
        .expect_err("an agent that can verify nothing was accepted");
    assert!(
        err.to_string().contains("can verify nothing"),
        "the message must say what is wrong: {err}"
    );
}

#[test]
fn one_sound_agent_does_not_excuse_a_forgeable_sibling() {
    // A caller forges the WEAKEST agent's token and gets that agent's scopes,
    // so every enabled agent has to hold up. An earlier version of this check
    // asked whether ANY agent was sound, which is exactly backwards.
    let mut c = agent_config(Some(&"k".repeat(32)), None);
    c.agent_auth
        .agents
        .push(crate::config::AgentDefinitionConfig {
            client_id: "weak".to_string(),
            name: "weak".to_string(),
            hs256_secret: Some(String::new()),
            rs256_public_key: None,
            scopes: Vec::new(),
            issuer: None,
            audience: Some("mcp-gateway-test".to_string()),
        });
    let err = c
        .validate()
        .expect_err("a forgeable agent beside a sound one was accepted");
    assert!(
        err.to_string().contains("weak"),
        "the message must name the agent that is wrong, not the sound one: {err}"
    );
}

/// An agent with a sound key but no audience is still refused, and the refusal
/// covers RS256 as well as HS256 — the RSA branch exits the loop early, so a
/// guard placed after it would leave every RS256 agent audience-less.
#[test]
fn an_agent_with_no_audience_fails_validation_whichever_key_it_holds() {
    const RSA: &str =
        "-----BEGIN PUBLIC KEY-----\nunused-by-config-validation\n-----END PUBLIC KEY-----";
    for (label, secret, rsa) in [
        ("hs256", Some(&"k".repeat(32)[..]), None),
        ("rs256", None, Some(RSA)),
    ] {
        let mut c = agent_config(secret, rsa);
        c.agent_auth.agents[0].audience = None;
        let err = c
            .validate()
            .expect_err(&format!("a {label} agent with no audience was accepted"));
        let err = err.to_string();
        assert!(
            err.contains("svc") && err.contains("audience"),
            "the {label} refusal must name the agent and the missing audience: {err}"
        );
    }
}

#[test]
fn agent_auth_disabled_ignores_key_material_entirely() {
    let mut c = agent_config(Some(""), None);
    // Deliberate, not incidental: a disabled block skips the audience guard as
    // well as the key checks, which is why `None` is still reachable at the
    // verifier and why that layer is not redundant with this one.
    c.agent_auth.agents[0].audience = None;
    c.agent_auth.enabled = false;
    c.validate()
        .expect("a disabled agent_auth block verifies nothing and gates nothing");
}

#[test]
fn an_agent_holding_both_key_types_fails_validation() {
    // The algorithm is read from the TOKEN HEADER (src/gateway/oauth/jwt.rs:120),
    // so a caller chooses which of the two keys verifies its token. An agent
    // configured with both is therefore only as strong as its WEAKER key, while
    // the operator who added an RSA key believes RSA is what is in force.
    // `AgentDefinition` already documents "exactly one"; nothing enforced it.
    let err = agent_config(
        Some("short"),
        Some("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"),
    )
    .validate()
    .expect_err("an agent holding both key types was accepted");
    let msg = err.to_string();
    assert!(
        msg.contains("svc") && msg.contains("both"),
        "the message must name the agent and the ambiguity: {msg}"
    );
}
