// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Held CLI clients judge expiry, grace and approval on one reading.

use chrono::{DateTime, Utc};

use super::{KeyBinding, ResolvedAuthConfig};
use crate::clock::test_clock;
use crate::config::{ApiKeyBinding, ApiKeyConfig, AuthConfig};
use crate::gateway::auth::digest_tag_of;

fn table(keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    ResolvedAuthConfig::from_config(
        &AuthConfig {
            enabled: true,
            api_keys: keys,
            ..Default::default()
        },
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
}

#[test]
fn a_cli_key_is_judged_on_one_reading() {
    let first = DateTime::<Utc>::from_timestamp(100, 0).expect("first reading");
    let expiry = DateTime::<Utc>::from_timestamp(150, 0).expect("expiry between readings");
    let second = DateTime::<Utc>::from_timestamp(200, 0).expect("second reading");
    let root = ApiKeyConfig {
        name: "root".to_owned(),
        key_sha256: Some(crate::config::api_key_digest_spec(b"one-reading-root")),
        admin: true,
        backends: vec!["*".to_owned()],
        expires_at: Some(expiry),
        ..Default::default()
    };
    let probe = table(vec![root.clone()]);
    let root_keys = probe.api_keys();
    let root_key = &root_keys[0];
    let previous: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"one-reading-previous").into();
    let child = ApiKeyConfig {
        name: "cli:laptop:a1".to_owned(),
        key_sha256: Some(crate::config::api_key_digest_spec(b"one-reading-child")),
        previous_key_sha256: Some(crate::config::api_key_digest_spec(b"one-reading-previous")),
        previous_expires_at: Some(expiry),
        expires_at: Some(expiry),
        approved_by: Some(ApiKeyBinding {
            quota_principal: root_key.quota_principal.limit_store_key().to_owned(),
            digest_tag: digest_tag_of(root_key.accepted_digests().0),
        }),
        ..Default::default()
    };
    let auth = table(vec![root, child]);
    let principal = auth.api_keys()[1].principal().storage_form().to_owned();
    let tag = digest_tag_of(&previous);
    let binding = KeyBinding::Secret(&tag);
    let expected = auth.client_for_key_at("cli:laptop:a1", &principal, binding, first);
    assert!(expected.is_some(), "the held previous digest is still live");
    assert!(
        auth.client_for_key_at("cli:laptop:a1", &principal, binding, second)
            .is_none(),
        "the second reading is past both expiries and the grace"
    );

    // A second read inside resolution would cross all three deadlines.
    let clock = test_clock::queued(&[Some(100), Some(200)]);
    let actual = auth.client_for_key("cli:laptop:a1", &principal, binding);
    assert_eq!(
        actual.map(|client| client.principal.storage_form().to_owned()),
        expected.map(|client| client.principal.storage_form().to_owned())
    );
    assert_eq!(crate::clock::utc_now(), Ok(second));
    drop(clock);

    let _clock = test_clock::before_epoch();
    assert!(
        auth.client_for_key("cli:laptop:a1", &principal, binding)
            .is_none(),
        "an unreadable clock refuses a bound key"
    );
}
