// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A session's validity and minting origin are one authentication decision.

use std::time::Duration;

use super::{
    Bound, DashboardBootstrap, MintingKey, Now, ResolvedAuthConfig, SessionCheck, SessionLimits,
    Touch,
};
use crate::config::{ApiKeyConfig, AuthConfig};

fn minting_table(now: Now) -> (ResolvedAuthConfig, MintingKey) {
    let secret = "session-origin-admin-secret";
    let keys = ResolvedAuthConfig::from_config(
        &AuthConfig {
            enabled: true,
            api_keys: vec![ApiKeyConfig {
                key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
                name: "session-origin-admin".to_owned(),
                admin: true,
                backends: vec!["*".to_owned()],
                ..Default::default()
            }],
            ..AuthConfig::default()
        },
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let quota = keys
        .validate_token_at(secret, chrono::DateTime::from(now.wall))
        .and_then(|client| client.quota_principal)
        .expect("the live admin key has a quota identity");
    let key = MintingKey {
        quota,
        digest_tag: super::secret_tag(secret),
    };
    (keys, key)
}

#[test]
fn a_valid_session_reports_its_minting_key_from_the_same_check() {
    let store = DashboardBootstrap::new();
    let now = Now::read();
    let limits = SessionLimits::default();
    let (keys, key) = minting_table(now);
    let bound = store.issue_session_until(
        now,
        &limits,
        Bound {
            not_after: None,
            key: Some(key.clone()),
        },
    );
    let bearer = store.issue_session_at(now, &limits);

    for touch in [Touch::No, Touch::Yes] {
        let checked = store.check_session_with_origin(&bound, now, &limits, touch, &keys);
        assert_eq!(checked, (SessionCheck::Valid, Some(key.clone())));
        assert_eq!(
            store.check_session_with_origin(&bearer, now, &limits, touch, &keys),
            (SessionCheck::Valid, None)
        );
        assert_eq!(
            store.check_session_with_origin("never-issued", now, &limits, touch, &keys),
            (SessionCheck::Unknown, None)
        );
    }

    let accepted = store.check_session_with_origin(&bound, now, &limits, Touch::No, &keys);
    assert!(store.revoke(&bound, now, &limits));
    // Logout after acceptance cannot erase the origin held by that request.
    assert_eq!(accepted, (SessionCheck::Valid, Some(key)));
    assert_eq!(
        store.check_session_with_origin(&bound, now, &limits, Touch::No, &keys),
        (SessionCheck::Unknown, None)
    );
}

#[test]
fn an_ended_session_reports_no_origin() {
    let store = DashboardBootstrap::new();
    let now = Now::read();
    let limits = SessionLimits::default();
    let (keys, key) = minting_table(now);
    let without_key = ResolvedAuthConfig::from_config(
        &AuthConfig::default(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let expired_at = Now {
        mono: now.mono + limits.idle + Duration::from_secs(1),
        wall: now.wall + limits.idle + Duration::from_secs(1),
    };

    for (at, pinned_keys) in [(now, &without_key), (expired_at, &keys)] {
        let handle = store.issue_session_until(
            now,
            &limits,
            Bound {
                not_after: None,
                key: Some(key.clone()),
            },
        );
        assert_eq!(
            store.check_session_with_origin(&handle, now, &limits, Touch::No, &keys),
            (SessionCheck::Valid, Some(key.clone()))
        );
        assert_eq!(
            store.check_session_with_origin(&handle, at, &limits, Touch::Yes, pinned_keys),
            (SessionCheck::Expired, None)
        );
        assert_eq!(
            store.check_session_with_origin(&handle, at, &limits, Touch::No, &keys),
            (SessionCheck::Unknown, None)
        );
    }
}

#[test]
fn an_unreadable_clock_reports_no_origin() {
    let store = DashboardBootstrap::new();
    let now = Now::read();
    let limits = SessionLimits::default();
    let (keys, key) = minting_table(now);
    let handle = store.issue_session_until(
        now,
        &limits,
        Bound {
            not_after: None,
            key: Some(key),
        },
    );
    // A wall clock before 1970 cannot date the session: no verdict, no origin.
    let before_epoch = Now {
        mono: now.mono,
        wall: std::time::UNIX_EPOCH - Duration::from_secs(1),
    };
    let checked = store.check_session_with_origin(&handle, before_epoch, &limits, Touch::No, &keys);
    assert_eq!(checked, (SessionCheck::ClockUnreadable, None));
}
