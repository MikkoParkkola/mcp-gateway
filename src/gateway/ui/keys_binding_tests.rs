// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! B3 (CLI login, Keys screen): a CLI key's entry shows the host it reported
//! and its expiry, and `live` is its effective liveness: a key whose approver
//! is gone stays listed with `live: false`. The binding itself (principal,
//! tag) never reaches the answer.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use serde_json::Value;

use super::{file_entry, live_entry};
use crate::config::{ApiKeyBinding, ApiKeyConfig, AuthConfig};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::auth::runtime::AuthRuntime;

const ROOT: &str = "keys-binding-root";
const CHILD: &str = "keys-binding-child";
const HOSTILE: &str = "<img src=x onerror=alert(1)>";

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

fn table(keys: &[ApiKeyConfig]) -> ResolvedAuthConfig {
    let config = AuthConfig {
        enabled: true,
        api_keys: keys.to_vec(),
        ..AuthConfig::default()
    };
    ResolvedAuthConfig::from_config(&config, crate::gateway::record_principal::TEST_RECORD_KEY)
        .with_runtime(Arc::new(AuthRuntime::default()))
}

fn root() -> ApiKeyConfig {
    key("root", ROOT, Some("d1d2d3d4d5d6"))
}

fn child(host: &str) -> ApiKeyConfig {
    let probe = table(&[root()]);
    let quota = probe
        .validate_token(ROOT)
        .expect("premise: the root validates")
        .quota_principal
        .expect("an API key carries a quota principal");
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(ROOT.as_bytes()).into();
    ApiKeyConfig {
        approved_by: Some(ApiKeyBinding {
            quota_principal: quota.limit_store_key().to_owned(),
            digest_tag: crate::gateway::auth::digest_tag_of(&digest),
        }),
        cli_host: Some(host.to_owned()),
        expires_at: Some(
            Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0)
                .single()
                .expect("time"),
        ),
        ..key("cli:laptop:a1", CHILD, None)
    }
}

fn file_answer(keys: &[ApiKeyConfig], name: &str) -> Value {
    let auth = table(keys);
    let live = auth.api_keys();
    let key = keys.iter().find(|k| k.name == name).expect("listed");
    file_entry(&auth, &live, key)
}

/// The fields an entry may carry, and nothing else.
const ALLOWED: [&str; 11] = [
    "name",
    "backends",
    "allowed_tools",
    "denied_tools",
    "admin",
    "expires_at",
    "previous_expires_at",
    "rate_limit",
    "last_used",
    "live",
    "cli_host",
];

#[test]
fn a_cli_key_shows_its_host_and_expiry_and_is_live_with_its_approver() {
    let entry = file_answer(&[root(), child("laptop")], "cli:laptop:a1");
    assert_eq!(entry["cli_host"], "laptop");
    assert_eq!(entry["expires_at"], "2099-01-01T00:00:00Z");
    assert_eq!(entry["live"], true);
}

#[test]
fn a_cli_key_whose_approver_is_gone_stays_listed_and_not_live() {
    let entry = file_answer(&[child("laptop")], "cli:laptop:a1");
    assert_eq!(entry["name"], "cli:laptop:a1", "the orphan is still listed");
    assert_eq!(
        entry["live"], false,
        "liveness followed the key's own expiry, not its approver"
    );
}

#[test]
fn the_live_table_answer_judges_the_approver_too() {
    let auth = table(&[child("laptop")]);
    let live = auth.api_keys();
    let entry = live_entry(&auth, &live[0]);
    assert_eq!(entry["live"], false);
}

#[test]
fn a_hostile_host_is_carried_as_plain_text() {
    let entry = file_answer(&[root(), child(HOSTILE)], "cli:laptop:a1");
    assert_eq!(entry["cli_host"], HOSTILE, "the host is data, never markup");
}

#[test]
fn no_entry_carries_the_binding() {
    for keys in [vec![root(), child("laptop")], vec![child("laptop")]] {
        let entry = file_answer(&keys, "cli:laptop:a1");
        let fields: Vec<&str> = entry
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        for field in &fields {
            assert!(ALLOWED.contains(field), "unexpected field {field}");
        }
        let text = entry.to_string();
        let bound = child("laptop").approved_by.expect("bound");
        assert!(!text.contains(&bound.quota_principal), "principal leaked");
        assert!(!text.contains(&bound.digest_tag), "tag leaked");
    }
}

#[test]
fn an_ordinary_key_has_a_null_host() {
    let entry = file_answer(&[root()], "root");
    assert_eq!(entry["cli_host"], Value::Null);
    assert_eq!(entry["live"], true);
}
