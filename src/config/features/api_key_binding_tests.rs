// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! B1 (CLI login, binding): a CLI key records the admin key that approved it
//! as `approved_by` (the approver's stable principal and the full tag of the
//! digest it presented) plus the host the CLI reported. Load checks only the
//! binding's syntax: an approver that is gone leaves a loadable, inert key.

use std::fmt::Write as _;

use crate::config::Config;

const PRINCIPAL: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TAG: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn digest_of(key: &str) -> String {
    format!("sha256:{}", crate::hashing::sha256_hex(key.as_bytes()))
}

/// Load a config whose only key carries `binding` (YAML lines under the key,
/// already indented). Auth stays disabled so only the binding rules decide.
fn load(binding: &str) -> (tempfile::TempDir, crate::Result<Config>) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut yaml = String::from("auth:\n  enabled: false\n  api_keys:\n");
    writeln!(
        yaml,
        "    - name: cli:laptop:a1\n      key_sha256: \"{}\"\n      admin: true\n{binding}",
        digest_of("child-secret")
    )
    .expect("String write");
    let path = dir.path().join("config.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("config file");
    let loaded = Config::load(Some(&path));
    (dir, loaded)
}

fn binding(principal: &str, tag: &str) -> String {
    format!(
        "      cli_host: laptop\n      approved_by:\n        quota_principal: \"{principal}\"\n        digest_tag: \"{tag}\"\n"
    )
}

#[test]
fn a_well_formed_binding_loads_and_round_trips() {
    let (_dir, loaded) = load(&binding(PRINCIPAL, TAG));
    let config = loaded.expect("a well-formed binding loads");
    let key = &config.auth.api_keys[0];
    let bound = key.approved_by.as_ref().expect("binding kept");
    assert_eq!(bound.quota_principal, PRINCIPAL);
    assert_eq!(bound.digest_tag, TAG);
    assert_eq!(key.cli_host.as_deref(), Some("laptop"));
    let written = crate::yaml::to_string(key).expect("serialise");
    let back: crate::config::ApiKeyConfig = crate::yaml::from_str(&written).expect("reparse");
    assert_eq!(
        back.approved_by.as_ref().map(|b| b.digest_tag.as_str()),
        Some(TAG)
    );
}

#[test]
fn a_key_without_a_binding_is_unchanged() {
    let (_dir, loaded) = load("");
    let config = loaded.expect("an ordinary key loads");
    assert!(config.auth.api_keys[0].approved_by.is_none());
    assert!(config.auth.api_keys[0].cli_host.is_none());
}

#[test]
fn a_malformed_binding_is_refused_at_load() {
    let short = &PRINCIPAL[..63];
    let upper = PRINCIPAL.replace('1', "A");
    let cases = [
        ("63-hex principal", binding(short, TAG)),
        (
            "non-hex principal",
            binding(&PRINCIPAL.replace('1', "g"), TAG),
        ),
        ("uppercase principal", binding(&upper, TAG)),
        ("63-hex tag", binding(PRINCIPAL, &TAG[..63])),
        (
            "missing tag",
            format!("      approved_by:\n        quota_principal: \"{PRINCIPAL}\"\n"),
        ),
        (
            "unknown field",
            format!("{}        extra: 1\n", binding(PRINCIPAL, TAG)),
        ),
    ];
    for (case, body) in cases {
        let (_dir, loaded) = load(&body);
        let error = match loaded {
            Ok(_) => panic!("{case}: a malformed binding must not load"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains("approved_by"), "{case}: {error}");
    }
}

#[test]
fn a_binding_whose_approver_is_absent_still_loads() {
    // The approver named by PRINCIPAL/TAG is not in this config at all: load
    // checks syntax only; liveness is judged at authorization.
    let (_dir, loaded) = load(&binding(PRINCIPAL, TAG));
    assert!(loaded.is_ok(), "an absent approver leaves a loadable key");
}
