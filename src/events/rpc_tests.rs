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
        credential: Credential {
            kind: crate::security::audit::CredentialKind::None,
            principal: String::new(),
            api_key: None,
        },
        visible_backends: std::collections::HashSet::new(),
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
