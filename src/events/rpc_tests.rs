// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[test]
fn subscription_id_is_canonical_over_arguments() {
    let a = subscription_id("p", "https://h/x", "e", &json!({"b": 1, "a": 1.0}));
    let b = subscription_id("p", "https://h/x", "e", &json!({"a": 1, "b": 1}));
    assert_eq!(a, b, "JCS: key order and 1.0 vs 1 are one key");
    assert!(a.starts_with("sub_") && a.len() == 36);
    for other in [
        subscription_id("q", "https://h/x", "e", &json!({"a": 1, "b": 1})),
        subscription_id("p", "https://h/y", "e", &json!({"a": 1, "b": 1})),
        subscription_id("p", "https://h/x", "f", &json!({"a": 1, "b": 1})),
        subscription_id("p", "https://h/x", "e", &json!({"a": 2, "b": 1})),
    ] {
        assert_ne!(a, other);
    }
}

/// MIK-7977 ID.1: integers past 2^53 are kept exactly, so arguments that
/// differ only there are two subscriptions.
#[test]
fn subscription_ids_keep_integers_past_2_pow_53() {
    let id = |n: Value| subscription_id("p", "https://h/x", "e", &json!({ "n": n }));
    assert_ne!(
        id(json!(9_007_199_254_740_993_u64)),
        id(json!(9_007_199_254_740_992_u64))
    );
    assert_ne!(
        id(json!(-9_007_199_254_740_993_i64)),
        id(json!(-9_007_199_254_740_992_i64))
    );
    assert_ne!(id(json!(u64::MAX)), id(json!(u64::MAX - 1)));
}

/// MIK-7977 ID.2: every id not touched by ID.1 is the one stored rows carry,
/// pinned here byte for byte (key order by UTF-16 units, escapes, floats,
/// exact integers at 2^53).
#[test]
fn subscription_ids_are_unchanged_below_2_pow_53() {
    for (arguments, want) in [
        (
            json!({"a": 1, "b": 1}),
            "sub_f1fac152263239e50e95e2db1d99474c",
        ),
        (
            json!({"\u{ff61}": 1, "\u{1f600}": 2, "x": [1.5, -0.25, null, true, "t\n\u{1f}\"\\"]}),
            "sub_82554c7b22ceab775cd8437e8449e28b",
        ),
        (
            json!({"big": 9_007_199_254_740_992_u64, "neg": -9_007_199_254_740_992_i64}),
            "sub_02d4bde3cd94901799fad5b83e10b043",
        ),
    ] {
        assert_eq!(
            subscription_id("p", "https://h/x", "e", &arguments),
            want,
            "{arguments}"
        );
    }
}

/// A source with every default: its lifecycle key is the core's.
struct Plain;

#[async_trait::async_trait]
impl crate::events::EventSource for Plain {
    fn kind(&self) -> crate::events::types::SourceKind {
        crate::events::types::SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        Vec::new()
    }
    fn matches(&self, _: &str, _: &Value, _: &crate::events::fanout::SourceEvent) -> bool {
        true
    }
}

/// MIK-7977 ID.3: the default lifecycle key is identity-bearing too (two
/// keys, two upstream starts), so it keeps integers past 2^53 the same way.
#[test]
fn default_lifecycle_keys_keep_integers_past_2_pow_53() {
    use crate::events::EventSource as _;
    let key = |n: u64| Plain.lifecycle_key("p", "e", &json!({ "n": n }));
    assert_ne!(key(9_007_199_254_740_993), key(9_007_199_254_740_992));
    assert_eq!(
        Plain.lifecycle_key("p", "e", &json!({"b": 1, "a": 1.0})),
        r#"["e",{"a":1,"b":1}]"#
    );
}

#[test]
fn callback_urls_must_be_absolute_https_with_a_host() {
    for bad in ["http://h/x", "ftp://h/x", "https://", "nope"] {
        assert!(callback_url(Some(&json!(bad))).is_err(), "{bad}");
    }
    assert!(callback_url(Some(&json!("https://h/x"))).is_ok());
    assert!(callback_url(None).is_err());
}

/// An unsubscribe answers only after an attempt already claimed for the
/// key has settled, whether or not this call removed the subscription (T23).
#[tokio::test]
async fn unsubscribe_waits_out_a_claimed_attempt() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let caller = Caller {
        principal: Some("p".to_owned()),
        read_key: None,
        credential: Credential {
            kind: crate::security::audit::CredentialKind::None,
            principal: String::new(),
            api_key: None,
            expires_at: None,
            binding: None,
        },
        visible_backends: std::collections::HashSet::new(),
        admin: false,
    };
    let url = "https://h.example/cb";
    let id = subscription_id("p", url, "e", &json!({}));
    hub.runtime.busy.lock().insert(id.clone());
    let release = std::sync::Arc::clone(&hub);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        release.runtime.busy.lock().remove(&id);
    });
    let started = std::time::Instant::now();
    let params = json!({"name": "e", "arguments": {}, "delivery": {"url": url}});
    hub.unsubscribe(&caller, Some(&params))
        .await
        .expect("answer");
    assert!(started.elapsed() >= std::time::Duration::from_millis(250));
}

/// Design F9 (MIK-7630 I2): a subscription made with any credential but an
/// API key ends no later than the credential and never runs unbounded.
#[test]
fn credentials_other_than_api_keys_bound_the_grant() {
    use crate::security::audit::CredentialKind;
    let now = Utc::now();
    let granted = Some(now + chrono::Duration::hours(1));
    let ends = now + chrono::Duration::minutes(5);
    let credential = |kind, expires_at| Credential {
        kind,
        principal: "p".to_owned(),
        api_key: None,
        expires_at,
        binding: None,
    };
    for kind in [
        CredentialKind::KeyServerToken,
        CredentialKind::OidcBearer,
        CredentialKind::StaticBearer,
        CredentialKind::DashboardSession,
    ] {
        let held = credential(kind, Some(ends));
        assert_eq!(
            bounded_by(&held, &json!({}), granted).expect("granted"),
            Some(ends),
            "{kind:?}: cut at the credential's expiry"
        );
        assert_eq!(
            bounded_by(&held, &json!({}), None).expect("granted"),
            Some(ends),
            "{kind:?}: an unbounded grant is bounded too"
        );
        let refused = bounded_by(&held, &json!({"ttlMs": null}), None).expect_err("refused");
        assert_eq!(refused.code, -32602, "{kind:?}: ttlMs null refused");
        let later = credential(kind, Some(now + chrono::Duration::hours(2)));
        assert_eq!(
            bounded_by(&later, &json!({}), granted).expect("ok"),
            granted
        );
    }
    let key = credential(CredentialKind::ApiKey, None);
    assert_eq!(
        bounded_by(&key, &json!({"ttlMs": null}), None).expect("ok"),
        None,
        "an API key is re-checked live instead"
    );
}

/// Operator-scoped types (backend health, the kill switch) are listed and
/// subscribable with admin standing only, which the transport sets.
#[test]
fn operator_types_are_seen_by_admins_only() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let descriptor = EventDescriptor {
        name: "gateway.kill_switch.changed".into(),
        description: String::new(),
        input_schema: json!({}),
        payload_schema: json!({}),
        scope: Visibility::Operator,
        kind: crate::events::types::SourceKind::GatewayOperational,
    };
    let caller = |admin| Caller {
        principal: Some("p".to_owned()),
        read_key: None,
        credential: Credential {
            kind: crate::security::audit::CredentialKind::ApiKey,
            principal: "p".to_owned(),
            api_key: None,
            expires_at: None,
            binding: None,
        },
        visible_backends: std::collections::HashSet::new(),
        admin,
    };
    assert!(caller(true).sees(&hub, &descriptor), "an admin sees it");
    assert!(
        !caller(false).sees(&hub, &descriptor),
        "a non-admin does not"
    );
}

/// MIK-7977 ID.2: within 2^53 the canonical form is the library's JCS, byte
/// for byte, for scalars, nesting, escapes and the integer boundaries.
#[test]
fn canonical_is_the_libraries_jcs_within_2_pow_53() {
    for value in [
        json!(0),
        json!(-0.0),
        json!(-1),
        json!(1.0),
        json!(1e21),
        json!(9_007_199_254_740_992_u64),
        json!(-9_007_199_254_740_992_i64),
        json!([[], {}, [null, false, 0.1, -2.5e-7, "\u{7f}\u{2028}é😀"]]),
        json!({"z": {"b": [1, {"\u{e000}": 2, "\u{10000}": 3}], "a": 1.5}, "": null}),
    ] {
        assert_eq!(
            String::from_utf8(canonical(&value)).expect("utf-8"),
            String::from_utf8(serde_json_canonicalizer::to_vec(&value).expect("jcs"))
                .expect("utf-8"),
            "{value}"
        );
    }
}
