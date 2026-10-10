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
        scope: Visibility::Backend("hooks".into()),
        owner: None,
        upstream_id: "x".into(),
        occurred_at: Utc::now(),
        data: json!({"event_type": "t", "fields": {}}),
        lifecycle_key: None,
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
        generation: 0,
        incarnation: 0,
        v: 1,
        id: format!("sub_{name}"),
        principal: "p".into(),
        api_key: None,
        credential_kind: None,
        credential_principal: None,
        binding: None,
        legacy_api_key_name: None,
        read_key: None,
        url: "https://h/cb".into(),
        name: name.into(),
        arguments: json!({}),
        secret: "whsec_x".into(),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + crate::duration_bound::delta!(hours, 1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
        payload_fields: Vec::new(),
        unoffered_since: None,
        held_until: None,
        watch_class: None,
    }
}

/// MIK-7772 under MIK-8057: opening the hub changes nothing; reconciling
/// afterwards holds the subscriptions to webhook event types no source
/// offers, and deletes none.
#[test]
fn reconcile_holds_unoffered_webhook_subscriptions() {
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

    assert!(hub.reconcile_catalogue(CatalogueScan::Complete));

    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(left.len(), 2, "nothing is deleted: {left:?}");
    let held: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .filter(|s| hub.store.held(&s.id).is_some())
        .map(|s| s.name)
        .collect();
    assert_eq!(
        held,
        ["webhook.gone.route.received"],
        "the webhook type is held"
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

    hub.set_webhook_registry(std::sync::Arc::new(parking_lot::RwLock::new(
        crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
    )));

    assert!(hub.reconcile_catalogue(CatalogueScan::Partial));

    assert_eq!(hub.store.subscriptions().len(), 1, "kept");
    assert!(
        hub.runtime
            .reconciled
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

/// With webhooks off no route is offered: the stored webhook subscriptions
/// are held and stamped, so they lapse; none is deleted (MIK-8057).
#[test]
fn webhooks_off_holds_and_stamps_webhook_subscriptions() {
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

    assert!(hub.reconcile_catalogue(CatalogueScan::Partial));

    let rows = hub.store.subscriptions();
    assert_eq!(rows.len(), 1, "held, not withdrawn");
    assert!(hub.store.held(&rows[0].id).is_some());
    assert!(rows[0].held_until.is_some(), "stamped, so it lapses");
}

/// MIK-7891: a startup reconcile that fails to remove a subscription says so
/// on every attempt, and finishes once the removal can succeed.
#[cfg(unix)]
#[test]
fn a_failed_reconcile_attempt_logs_a_warning_and_the_next_one_finishes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let caps = super::super::store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            subscription("backend.gone.tools_changed"),
            true,
            caps,
            chrono::Duration::zero(),
            Utc::now(),
            super::super::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    // The removal deletes a file in this directory, so it cannot succeed.
    let subs = dir.path().join("subs");
    std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(0o500)).expect("lock");
    if std::fs::File::create(subs.join("probe")).is_ok() {
        eprintln!("skipped: the directory mode does not bind this user");
        return;
    }

    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let unlock = subs.clone();
            let task = tokio::spawn({
                let hub = Arc::clone(&hub);
                async move {
                    hub.reconcile_until_done(
                        "test",
                        Arc::new(|| CatalogueScan::Complete),
                        std::time::Duration::from_millis(20),
                    )
                    .await;
                }
            });
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            std::fs::set_permissions(&unlock, std::fs::Permissions::from_mode(0o700))
                .expect("unlock");
            tokio::time::timeout(std::time::Duration::from_secs(10), task)
                .await
                .expect("the reconcile finishes once the removal can succeed")
                .expect("task");
        });
    });

    assert!(
        crate::test_log_capture::count(&records, "WARN", "startup reconcile could not remove") >= 1,
        "a failed attempt is logged: {records:?}"
    );
    assert!(hub.store.subscriptions().is_empty(), "then withdrawn");
}

use super::super::EventSource as _;

/// A source whose upstream work runs under each principal's own credential:
/// its lifecycle key includes the principal (design §4).
struct PerPrincipal;

#[async_trait::async_trait]
impl super::super::EventSource for PerPrincipal {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<super::super::types::EventDescriptor> {
        vec![super::super::types::EventDescriptor {
            name: "watch.cap.changed".into(),
            description: "test".into(),
            input_schema: json!({"type": "object"}),
            payload_schema: json!({"type": "object"}),
            scope: Visibility::Owner,
            kind: SourceKind::RestWatch,
        }]
    }
    fn matches(&self, _principal: &str, _arguments: &Value, _event: &SourceEvent) -> bool {
        true
    }
    fn lifecycle_key(&self, principal: &str, name: &str, arguments: &Value) -> String {
        json!([principal, name, arguments]).to_string()
    }
}

/// MIK-7811: two principals hold the same arguments under distinct lifecycle
/// keys; an occurrence carrying one key reaches only the subscription holding
/// it, even though the source's `matches` accepts both. An occurrence with no
/// key still reaches both.
#[tokio::test]
async fn an_occurrence_with_a_lifecycle_key_reaches_only_its_holders() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(PerPrincipal));
    let name = "watch.cap.changed";
    let arguments = json!({"arguments": {"q": "x"}});
    for principal in ["alice", "bob"] {
        let mut row = subscription(name);
        row.id = format!("sub_{principal}");
        row.principal = principal.into();
        row.arguments = arguments.clone();
        row.credential_kind = Some(crate::security::audit::CredentialKind::None);
        hub.store
            .admit(
                row,
                true,
                super::super::store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                Utc::now(),
                super::super::tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    let services = super::super::Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: super::super::LiveCredentials::default(),
    };
    let event = |upstream_id: &str, lifecycle_key: Option<String>| SourceEvent {
        kind: SourceKind::RestWatch,
        name: name.into(),
        backend: "cap".into(),
        scope: Visibility::Owner,
        owner: None,
        upstream_id: upstream_id.into(),
        occurred_at: Utc::now(),
        data: json!({}),
        lifecycle_key,
    };
    let alices = PerPrincipal.lifecycle_key("alice", name, &arguments);
    hub.fan_out(&services, &event("t1", Some(alices))).await;
    let outbox = |dir: &std::path::Path| -> Vec<String> {
        std::fs::read_dir(dir.join("outbox"))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| std::fs::read_to_string(e.path()).expect("read"))
                    .collect()
            })
            .unwrap_or_default()
    };
    let records = outbox(dir.path());
    assert_eq!(records.len(), 1, "alice's key reaches one subscription");
    assert!(records[0].contains("sub_alice"), "{}", records[0]);
    hub.fan_out(&services, &event("t2", None)).await;
    assert_eq!(
        outbox(dir.path()).len(),
        3,
        "a keyless occurrence reaches both"
    );
    hub.fan_out(&services, &event("t3", Some("no holder".into())))
        .await;
    assert_eq!(outbox(dir.path()).len(), 3, "an unknown key reaches no one");
}

/// Operator events (gateway health, the kill switch) need no backend grant
/// at delivery, as owner events do not: an admin whose key is scoped to some
/// backends keeps every operator event it holds.
#[tokio::test]
async fn an_operator_record_asks_no_backend_grant() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let sub = stored("op", "gateway.kill_switch.changed");
    let caps = super::super::store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            sub.clone(),
            true,
            caps,
            chrono::Duration::zero(),
            Utc::now(),
            super::super::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    let services = Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: super::super::LiveCredentials::default(),
    };
    let event = SourceEvent {
        kind: SourceKind::GatewayOperational,
        name: "gateway.kill_switch.changed".into(),
        backend: "alpha".into(),
        scope: Visibility::Operator,
        owner: None,
        upstream_id: "u".into(),
        occurred_at: Utc::now(),
        data: json!({}),
        lifecycle_key: None,
    };
    hub.offer(&services, &event, &sub).await;
    let due = hub
        .store
        .due(
            Utc::now(),
            &std::collections::HashSet::new(),
            hub.dead_policy(),
        )
        .expect("io");
    assert_eq!(due.ready.len(), 1);
    assert!(due.ready[0].owner_scoped, "no backend grant is asked");
}

/// MIK-8202: a clock before 1970 delivers nothing to a subscription whose lease
/// the real clock still holds live.
#[tokio::test]
async fn a_clock_before_the_epoch_delivers_nothing_on_a_live_lease() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(PerPrincipal));
    let name = "watch.cap.changed";
    // The fixture's lease ends one hour from now.
    let mut row = subscription(name);
    row.credential_kind = Some(crate::security::audit::CredentialKind::None);
    hub.store
        .admit(
            row,
            true,
            super::super::store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            Utc::now(),
            super::super::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    let services = Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: super::super::LiveCredentials::default(),
    };
    let event = |upstream_id: &str| SourceEvent {
        kind: SourceKind::RestWatch,
        name: name.into(),
        backend: "cap".into(),
        scope: Visibility::Owner,
        owner: None,
        upstream_id: upstream_id.into(),
        occurred_at: Utc::now(),
        data: json!({}),
        lifecycle_key: None,
    };
    let outbox = |dir: &std::path::Path| {
        std::fs::read_dir(dir.join("outbox")).map_or(0, |entries| entries.flatten().count())
    };
    hub.fan_out(&services, &event("t1")).await;
    assert_eq!(
        outbox(dir.path()),
        1,
        "control: a live lease receives the event on the real clock"
    );

    let _clock = crate::clock::test_clock::before_epoch();
    hub.fan_out(&services, &event("t2")).await;
    assert_eq!(
        outbox(dir.path()),
        1,
        "an unreadable clock delivered an event on a lease it cannot date"
    );
}

/// A task source admits a stored subscription at delivery even once the task
/// row has expired: fan-out matched the occurrence to its carried owner, and
/// asking the store now would refuse the owner's own settlement (MIK-7940).
/// Subscribing still asks the store.
#[tokio::test]
async fn a_task_source_admits_at_delivery_after_the_row_expired() {
    use crate::events::task_source::TaskSource;
    use crate::gateway::task_service::{StoreLimits, TaskService};
    let dir = tempfile::tempdir().expect("dir");
    let admission = crate::idempotency::admission::ExecutionAdmission::new(Arc::new(|| 1_000));
    let source = TaskSource {
        service: Arc::new(
            TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
                .await
                .expect("service"),
        ),
    };
    let mut sub = subscription("task.settled");
    sub.arguments = json!({"taskId": "task-gone"});
    assert_eq!(
        source
            .authorize(&sub.principal, &sub.name, &sub.arguments)
            .await
            .expect_err("subscribe asks the store")
            .code,
        -32012
    );
    source.authorize_row(&sub).await.expect("delivery admits");
}

/// What a reconcile left: each row's name, whether it is held, and whether
/// its hold is stamped to lapse.
fn reconciled_state(scan: CatalogueScan, webhooks_on: bool) -> Vec<(String, bool, bool)> {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let now = crate::clock::utc_now().expect("clock after 1970");
    let tail = super::super::tail_policy(&config);
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
    if webhooks_on {
        hub.set_webhook_registry(std::sync::Arc::new(parking_lot::RwLock::new(
            crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
        )));
    }
    assert!(hub.reconcile_catalogue(scan));
    let mut state: Vec<_> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| {
            let held = hub.store.held(&s.id).is_some();
            (s.name, held, s.held_until.is_some())
        })
        .collect();
    state.sort();
    state
}

/// MIK-8050 (superseded by MIK-8057): a partial catalogue only names itself in
/// the log. With webhooks on or off, a startup reconcile told `Partial`
/// leaves the same rows, holds and hold stamps as one told `Complete`; since
/// MIK-8057 neither withdraws a webhook type it does not see.
#[test]
fn a_partial_scan_leaves_what_a_complete_one_does() {
    for webhooks_on in [false, true] {
        let complete = reconciled_state(CatalogueScan::Complete, webhooks_on);
        let names: Vec<_> = complete.iter().map(|(name, ..)| name.as_str()).collect();
        assert_eq!(
            names,
            ["task.settled", "webhook.gone.route.received"],
            "premise: nothing deleted ({webhooks_on})"
        );
        assert_eq!(
            reconciled_state(CatalogueScan::Partial, webhooks_on),
            complete,
            "Partial changed what the reconcile left (webhooks on: {webhooks_on})"
        );
    }
}
