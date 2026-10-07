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
/// A non-admin principal `p` holding no credential.
fn plain_caller() -> Caller {
    Caller {
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
    }
}

#[tokio::test]
async fn unsubscribe_waits_out_a_claimed_attempt() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let caller = plain_caller();
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
    let hour = Some(chrono::Duration::hours(1));
    let ends = now + chrono::Duration::minutes(5);
    let credential = |kind, expires_at| Credential {
        kind,
        principal: "p".to_owned(),
        api_key: None,
        expires_at,
        binding: None,
    };
    let grant = |held: &Credential, ttl| Grant {
        ttl,
        until: credential_ceiling(held, &json!({})).expect("granted"),
    };
    for kind in [
        CredentialKind::KeyServerToken,
        CredentialKind::OidcBearer,
        CredentialKind::StaticBearer,
        CredentialKind::DashboardSession,
    ] {
        let held = credential(kind, Some(ends));
        assert_eq!(
            grant(&held, hour).expires_at(now),
            Some(ends),
            "{kind:?}: cut at the credential's expiry"
        );
        assert_eq!(
            grant(&held, None).expires_at(now),
            Some(ends),
            "{kind:?}: an unbounded grant is bounded too"
        );
        assert_eq!(
            grant(&held, hour).expires_at(now + chrono::Duration::hours(2)),
            Some(ends),
            "{kind:?}: a late commit never runs past the credential"
        );
        let refused = credential_ceiling(&held, &json!({"ttlMs": null})).expect_err("refused");
        assert_eq!(refused.code, -32602, "{kind:?}: ttlMs null refused");
        let later = credential(kind, Some(now + chrono::Duration::hours(2)));
        assert_eq!(
            grant(&later, hour).expires_at(now),
            Some(now + chrono::Duration::hours(1))
        );
    }
    let key = credential(CredentialKind::ApiKey, None);
    assert_eq!(
        credential_ceiling(&key, &json!({"ttlMs": null})).expect("ok"),
        None,
        "an API key is re-checked live instead"
    );
    assert_eq!(grant(&key, None).expires_at(now), None, "no expiry");
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

/// The T16 hub: upstream events on `u` (unset key, never connected), `s`
/// (explicit SSE) and `c` (stdio), with the live services a commit reads.
async fn t16_hub() -> (
    Arc<EventsHub>,
    crate::config::EventsConfig,
    tempfile::TempDir,
) {
    use crate::backend::{Backend, BackendRegistry};
    use crate::config::{Config, EventsConfig, FailsafeConfig};

    let config: Config = serde_yaml::from_str(
        "backends:\n  u:\n    http_url: http://127.0.0.1:9/mcp\n  \
         s:\n    http_url: http://127.0.0.1:9/sse\n    streamable_http: false\n  \
         c:\n    command: echo\n",
    )
    .expect("config");
    let dir = tempfile::tempdir().expect("dir");
    let mut events = EventsConfig::default();
    events.sources.backend_notifications = true;
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let registry = Arc::new(BackendRegistry::new());
    for (name, raw) in &config.backends {
        assert!(registry.register(Arc::new(Backend::new(
            name,
            raw.clone(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ))));
    }
    let live = Arc::new(crate::config_reload::LiveConfig::new(config));
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["u".to_owned(), "s".to_owned(), "c".to_owned()]),
        Arc::clone(&registry),
        upstream::live_ineligible(Arc::clone(&live), registry),
    );
    let services = super::super::Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: super::super::LiveCredentials::default(),
    };
    assert!(hub.runtime.services.set(Arc::new(services)).is_ok());
    (hub, events, dir)
}

/// T16 (MIK-7969 H1/G2): the commit, under the lifecycle lock, admits an
/// upstream event only over a transport a live connection detected or one
/// that needs none. Unresolved (stopped, or never connected) answers the
/// backend error; a refusal names its reason; a removed backend is unknown.
#[tokio::test]
async fn the_commit_admits_only_a_detected_or_unneeded_transport() {
    let (hub, events, _dir) = t16_hub().await;
    let code = |name: &str| hub.upstream_admits(name).err().map(|e| e.code);
    assert_eq!(
        code("backend.u.resources_changed"),
        Some(-32000),
        "unresolved"
    );
    assert_eq!(code("backend.s.prompts_changed"), Some(-32014), "refused");
    assert_eq!(
        code("backend.c.resources_changed"),
        None,
        "stdio needs none"
    );
    assert_eq!(code("backend.u.tools_changed"), None, "gateway-generated");
    assert_eq!(
        code("backend.gone.resources_changed"),
        Some(-32011),
        "removed"
    );

    // The commit itself runs the check: nothing is stored.
    let record: Subscription = serde_json::from_value(json!({
        "v": 1, "id": "sub_t16", "principal": "p", "url": "https://p.example/cb",
        "name": "backend.u.resources_changed", "arguments": {}, "secret": "unused",
        "previous_secret": null, "previous_until": null,
        "granted_at": Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("record");
    let caps = Caps {
        per_principal: 10,
        global: 10,
    };
    let policy = crate::events::tail_policy(&events);
    let outcome = hub
        .commit_started(
            &record,
            Grant {
                ttl: None,
                until: None,
            },
            false,
            (caps, chrono::Duration::zero(), policy),
            Utc::now(),
            (
                &plain_caller(),
                &url::Url::parse("https://p.example/cb").expect("url"),
            ),
        )
        .await;
    assert_eq!(outcome.err().map(|e| e.code), Some(-32000));
    assert!(hub.store.subscriptions().is_empty(), "no row was committed");
}

/// T16: refused between the commit check and the start is never a silent start.
#[tokio::test]
async fn the_commit_admits_no_silent_start_after_its_check() {
    let (hub, _events, _dir) = t16_hub().await;
    let mut started = std::collections::HashSet::new();
    let refused = hub
        .start_key(&mut started, "p", "backend.s.resources_changed", &json!({}))
        .await;
    assert_eq!(
        refused.err().map(|e| e.code),
        Some(-32011),
        "no source offers it"
    );
    let source = hub
        .sources
        .read()
        .iter()
        .find(|s| s.kind() == super::super::types::SourceKind::BackendNotification)
        .cloned()
        .expect("upstream source");
    let first = |name: &'static str| {
        let source = Arc::clone(&source);
        async move { source.on_first_subscriber("k", "p", name, &json!({})).await }
    };
    assert_eq!(
        first("backend.s.resources_changed")
            .await
            .err()
            .map(|e| e.code),
        Some(-32012),
        "an ineligible backend gets no silent start"
    );
    assert!(
        first("backend.s.tools_changed").await.is_ok(),
        "tools_changed needs no listener"
    );
    assert_eq!(
        first("backend.gone.resources_changed")
            .await
            .err()
            .map(|e| e.code),
        Some(-32011),
        "a backend removed since the check gets no silent start"
    );
    assert!(first("backend.gone.tools_changed").await.is_ok());
}
