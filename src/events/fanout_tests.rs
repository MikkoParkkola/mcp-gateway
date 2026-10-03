// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[test]
fn event_id_is_stable_and_distinct_per_subscription() {
    let a = event_id(SourceKind::Webhook, "github.push:d-1", "sub_a");
    assert_eq!(a, event_id(SourceKind::Webhook, "github.push:d-1", "sub_a"));
    assert_ne!(a, event_id(SourceKind::Webhook, "github.push:d-1", "sub_b"));
    assert_ne!(a, event_id(SourceKind::Webhook, "github.push:d-2", "sub_a"));
    assert!(a.starts_with("evt_") && a.len() == 36);
}

#[test]
fn body_carries_only_protocol_fields_and_data() {
    let event = SourceEvent {
        kind: SourceKind::Webhook,
        name: "webhook.c.r.received".into(),
        backend: "hooks".into(),
        upstream_id: "x".into(),
        occurred_at: Utc::now(),
        data: json!({"event_type": "t", "fields": {}}),
    };
    let receipt = json!({"receipt": {"subject_kind": "event"}});
    let body: Value =
        serde_json::from_slice(&body("evt_1", &event, &event.data, &receipt)).expect("json");
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["_meta", "cursor", "data", "eventId", "name", "timestamp"]
    );
    assert_eq!(body["_meta"], json!({ PROVENANCE_KEY: receipt }));
    assert_eq!(body["cursor"], Value::Null);
}

fn stored(id: &str, name: &str) -> Subscription {
    serde_json::from_value(json!({
        "v": 1, "id": id, "principal": "p", "url": format!("https://h/{id}"),
        "name": name, "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("subscription")
}

/// A reload that removes an event type deletes its subscriptions at once,
/// and only theirs (design §9).
#[test]
fn withdraw_deletes_only_the_removed_types() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let caps = super::super::store::Caps {
        per_principal: 10,
        global: 10,
    };
    for (id, name) in [("a", "gone"), ("b", "kept")] {
        hub.store
            .admit(
                stored(id, name),
                true,
                caps,
                chrono::Duration::zero(),
                Utc::now(),
                super::super::tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    hub.withdraw(&["gone".to_owned()]);
    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(left, ["b"]);
}

fn subscription(name: &str) -> super::super::records::Subscription {
    let now = Utc::now();
    super::super::records::Subscription {
        v: 1,
        id: format!("sub_{name}"),
        principal: "p".into(),
        api_key: None,
        credential_kind: None,
        credential_principal: None,
        binding: None,
        legacy_api_key_name: None,
        url: "https://h/cb".into(),
        name: name.into(),
        arguments: json!({}),
        secret: "whsec_x".into(),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + chrono::Duration::hours(1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
    }
}

/// MIK-7772: opening the hub withdraws nothing, because the catalogue is
/// partial until the capability scan has run; reconciling afterwards deletes
/// the subscriptions to webhook event types no source offers, and only those.
#[test]
fn reconcile_withdraws_only_unoffered_webhook_subscriptions_and_only_when_asked() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let (now, tail) = (Utc::now(), super::super::tail_policy(&config));
    let caps = super::super::store::Caps {
        per_principal: 10,
        global: 10,
    };
    for name in ["webhook.gone.route.received", "task.settled"] {
        hub.store
            .admit(
                subscription(name),
                true,
                caps,
                chrono::Duration::zero(),
                now,
                tail,
            )
            .expect("io")
            .expect("admitted");
    }
    assert_eq!(
        hub.store.subscriptions().len(),
        2,
        "open reconciles nothing"
    );
    assert!(
        !hub.runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
    );

    assert!(hub.reconcile_catalogue(Scan::Complete));

    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(
        left,
        ["task.settled"],
        "only the unoffered webhook type went"
    );
    assert!(
        hub.runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

/// MIK-7772: a partial scan proves nothing about a route's absence, so it
/// withdraws nothing, and still lets the worker start.
#[test]
fn a_partial_scan_keeps_every_subscription() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let (now, tail) = (Utc::now(), super::super::tail_policy(&config));
    let caps = super::super::store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            subscription("webhook.gone.route.received"),
            true,
            caps,
            chrono::Duration::zero(),
            now,
            tail,
        )
        .expect("io")
        .expect("admitted");

    assert!(hub.reconcile_catalogue(Scan::Partial));

    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
    assert!(
        hub.runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
    );
}
