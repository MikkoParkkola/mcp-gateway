// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F10 T6: `server.idempotency_key` is a closed enum, checked at load.

use mcp_gateway::config::{Config, IdempotencyKeyMode};

fn load(body: &str) -> mcp_gateway::Result<Config> {
    let dir = tempfile::tempdir().expect("a private config directory");
    let path = dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, body)
        .expect("the fixture config must be writable");
    Config::load(Some(&path))
}

#[test]
fn t6_a_bogus_idempotency_key_mode_is_a_load_error() {
    assert!(
        load("server:\n  idempotency_key: bogus\n").is_err(),
        "a mode outside the enum must not load as the default"
    );
}

#[test]
fn t6_both_modes_load_and_the_default_is_optional() {
    for (text, mode) in [
        ("optional", IdempotencyKeyMode::Optional),
        ("required", IdempotencyKeyMode::Required),
    ] {
        let config = load(&format!("server:\n  idempotency_key: {text}\n")).expect(text);
        assert_eq!(config.server.idempotency_key, mode);
    }
    let config = load("server:\n  port: 39400\n").expect("an omitted key loads");
    assert_eq!(config.server.idempotency_key, IdempotencyKeyMode::Optional);
}
