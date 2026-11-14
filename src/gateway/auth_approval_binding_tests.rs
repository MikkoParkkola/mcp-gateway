// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! B2 (CLI login, binding): a CLI key is live only while the admin key that
//! approved it is. The child records the approver's stable principal and the
//! tag of the digest it approved with; at every authorization exactly one
//! named, unscoped, unexpired, non-CLI gateway admin must match that
//! principal and still accept that digest (current, or previous inside its
//! grace). A key with no binding takes exactly today's path.

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};

use super::ResolvedAuthConfig;
use crate::config::{ApiKeyBinding, ApiKeyConfig, AuthConfig};
use crate::gateway::auth::runtime::AuthRuntime;

const ROOT_A: &str = "binding-root-secret-a";
const ROOT_B: &str = "binding-root-secret-b";
const OTHER: &str = "binding-other-secret";
const CHILD: &str = "binding-child-secret";
const P1: &str = "b1b2b3b4b5b6";
const P2: &str = "c1c2c3c4c5c6";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 9, 12, 0, 0)
        .single()
        .expect("time")
}

fn digest(secret: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into()
}

fn key(name: &str, secret: &str, principal: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        name: name.to_string(),
        admin: true,
        principal: principal.map(str::to_owned),
        backends: vec!["*".to_string()],
        ..Default::default()
    }
}

fn table(keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    let config = AuthConfig {
        enabled: true,
        api_keys: keys,
        ..AuthConfig::default()
    };
    ResolvedAuthConfig::from_config(&config, crate::gateway::record_principal::TEST_RECORD_KEY)
        .with_runtime(Arc::new(AuthRuntime::default()))
}

/// The binding a login approved by `secret` on `approver_table` records: the
/// approver's stable limit key and the full tag of the digest it presented.
fn binding_of(approver_table: &ResolvedAuthConfig, secret: &str) -> ApiKeyBinding {
    let client = approver_table
        .validate_token_at(secret, now())
        .expect("premise: the approver validates");
    let quota = client
        .quota_principal
        .expect("an API key carries a quota principal");
    ApiKeyBinding {
        quota_principal: quota.limit_store_key().to_owned(),
        digest_tag: super::digest_tag_of(&digest(secret)),
    }
}

fn child(bound: ApiKeyBinding) -> ApiKeyConfig {
    ApiKeyConfig {
        approved_by: Some(bound),
        cli_host: Some("laptop".to_owned()),
        ..key("cli:laptop:a1", CHILD, None)
    }
}

fn root() -> ApiKeyConfig {
    key("root", ROOT_A, Some(P1))
}

fn bound_to_root() -> ApiKeyBinding {
    binding_of(&table(vec![root()]), ROOT_A)
}

fn child_live(keys: Vec<ApiKeyConfig>, at: DateTime<Utc>) -> bool {
    table(keys).validate_token_at(CHILD, at).is_some()
}

#[test]
fn a_child_is_live_while_its_approver_is() {
    assert!(child_live(vec![root(), child(bound_to_root())], now()));
}

#[test]
fn a_key_without_a_binding_is_judged_as_today() {
    let plain = key("plain", CHILD, None);
    assert!(
        child_live(vec![plain], now()),
        "an unbound key lost its standing"
    );
}

#[test]
fn removing_the_approver_ends_the_child() {
    assert!(
        !child_live(vec![child(bound_to_root())], now()),
        "a child outlived its approver's removal"
    );
}

#[test]
fn the_child_follows_the_approving_digest_through_its_grace_only() {
    let bound = bound_to_root();
    let grace_end = now() + crate::duration_bound::delta!(seconds, 60);
    let mut rotated = key("root", ROOT_B, Some(P1));
    rotated.previous_key_sha256 = Some(crate::config::api_key_digest_spec(ROOT_A.as_bytes()));
    rotated.previous_expires_at = Some(grace_end);
    let keys = || vec![rotated.clone(), child(bound.clone())];
    assert!(
        child_live(
            keys(),
            grace_end - crate::duration_bound::delta!(seconds, 1)
        ),
        "a routine rotation ended the child inside the grace"
    );
    assert!(
        !child_live(keys(), grace_end),
        "the child outlived the approving digest's grace"
    );
    assert!(
        table(keys()).validate_token_at(ROOT_B, grace_end).is_some(),
        "premise: the rotated root stays usable"
    );
}

#[test]
fn a_new_root_of_the_same_name_does_not_inherit_consent() {
    let fresh = key("root", OTHER, Some(P2));
    assert!(!child_live(vec![fresh, child(bound_to_root())], now()));
}

#[test]
fn the_same_principal_on_a_new_secret_does_not_inherit_consent() {
    // Same stable principal, different digest: the approving tag is gone.
    let replaced = key("root", OTHER, Some(P1));
    assert!(!child_live(vec![replaced, child(bound_to_root())], now()));
}

/// Two keys sharing the approver's stable principal cannot be running: the
/// table is refused at load. The binding check's "exactly one approver" rule
/// stays as a defensive refusal behind that.
#[test]
fn two_keys_matching_the_approver_cannot_be_running() {
    let twin = key("root-twin", OTHER, Some(P1));
    let config = AuthConfig {
        enabled: true,
        api_keys: vec![root(), twin, child(bound_to_root())],
        ..AuthConfig::default()
    };
    let built = ResolvedAuthConfig::try_from_config(
        &config,
        &crate::config::EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    assert!(
        built.is_err(),
        "a table with two keys of one principal loaded"
    );
}

#[test]
fn an_approver_that_is_not_a_whole_gateway_admin_denies() {
    let bound = bound_to_root();
    let mut scoped = root();
    scoped.backends = vec!["one-backend".to_string()];
    assert!(
        !child_live(vec![scoped, child(bound.clone())], now()),
        "scoped"
    );
    let mut plain = root();
    plain.admin = false;
    assert!(
        !child_live(vec![plain, child(bound.clone())], now()),
        "non-admin"
    );
    let mut expired = root();
    expired.expires_at = Some(now());
    assert!(!child_live(vec![expired, child(bound)], now()), "expired");
}

#[test]
fn an_approver_that_is_itself_a_cli_key_denies() {
    let bound = bound_to_root();
    let mut cli_root = root();
    cli_root.approved_by = Some(ApiKeyBinding {
        quota_principal: "0".repeat(64),
        digest_tag: "0".repeat(64),
    });
    assert!(!child_live(vec![cli_root, child(bound)], now()));
}

#[test]
fn a_self_binding_denies_without_recursion() {
    let probe = table(vec![key("cli:laptop:a1", CHILD, Some(P2))]);
    let own = binding_of(&probe, CHILD);
    let mut looped = key("cli:laptop:a1", CHILD, Some(P2));
    looped.approved_by = Some(own);
    assert!(!child_live(vec![looped], now()));
}

#[test]
fn background_resolvers_judge_the_binding_too() {
    let bound = bound_to_root();
    let live = table(vec![root(), child(bound.clone())]);
    let principal = live.api_keys()[1].principal().storage_form().to_owned();
    let tag = super::digest_tag_of(&digest(CHILD));
    let watch = super::KeyBinding::Secret(&tag);
    assert!(
        live.client_for_key_at("cli:laptop:a1", &principal, watch, now())
            .is_some(),
        "premise: a watch opened by the child resolves while its approver is live"
    );
    let dead = table(vec![child(bound)]);
    assert!(
        dead.client_for_key_at(
            "cli:laptop:a1",
            &principal,
            super::KeyBinding::Secret(&tag),
            now()
        )
        .is_none(),
        "a watch held by the child survived its approver's removal"
    );
}
