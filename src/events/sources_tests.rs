// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I4 source rows that need no gateway: the burst clause of T38 and the
//! terminal-status filter of T40.

use super::backend_source::QUIET;
use super::*;
use crate::protocol::tasks::TaskStatus;

fn hub() -> (Arc<EventsHub>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    (hub, dir)
}

fn drain(hub: &EventsHub) -> tokio::sync::mpsc::Receiver<fanout::SourceEvent> {
    hub.runtime.intake.lock().take().expect("intake")
}

/// T38, burst clause: five changes inside the quiet window are one event;
/// a change after the report is a second one.
#[tokio::test(start_paused = true)]
async fn a_burst_of_backend_changes_is_one_event() {
    let (hub, _dir) = hub();
    let mut events = drain(&hub);
    hub.install_backend_source(Arc::new(|| vec!["x".to_owned()]));
    for _ in 0..5 {
        hub.backend_tools_changed("x");
        tokio::time::sleep(QUIET / 5).await;
    }
    tokio::time::sleep(QUIET * 2).await;
    let first = events.try_recv().expect("one event for the burst");
    assert_eq!(first.name, "backend.x.tools_changed");
    assert_eq!(first.data, serde_json::json!({}));
    assert!(events.try_recv().is_err(), "and only one");
    hub.backend_tools_changed("x");
    tokio::time::sleep(QUIET * 2).await;
    assert!(events.try_recv().is_ok(), "a later change reports again");
    assert!(events.try_recv().is_err());
}

/// T40, status filter: only a terminal status emits, and the payload names
/// the task and status without any result.
#[tokio::test]
async fn only_terminal_task_statuses_emit() {
    let (hub, _dir) = hub();
    let mut events = drain(&hub);
    let now = chrono::Utc::now();
    for status in [TaskStatus::Working, TaskStatus::InputRequired] {
        hub.task_published("task-1", status, now, None);
    }
    assert!(
        events.try_recv().is_err(),
        "a non-terminal status is silent"
    );
    for (status, name) in [
        (TaskStatus::Completed, "completed"),
        (TaskStatus::Failed, "failed"),
        (TaskStatus::Cancelled, "cancelled"),
    ] {
        hub.task_published("task-1", status, now, None);
        let event = events.try_recv().expect("terminal status emits");
        assert_eq!(event.name, "task.settled");
        assert_eq!(event.data["taskId"], "task-1");
        assert_eq!(event.data["status"], name);
        let keys: Vec<&String> = event.data.as_object().expect("object").keys().collect();
        assert_eq!(keys.len(), 3, "taskId, status, settledAt only: {keys:?}");
    }
}

/// A backend that left the registry takes its event subscriptions with it.
#[tokio::test]
async fn a_removed_backend_withdraws_its_subscriptions() {
    let (hub, _dir) = hub();
    let names = Arc::new(parking_lot::Mutex::new(vec!["x".to_owned()]));
    let live = Arc::clone(&names);
    hub.install_backend_source(Arc::new(move || live.lock().clone()));
    let row: records::Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": "sub_x", "principal": "p", "url": "https://h/x",
        "name": "backend.x.tools_changed", "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    let config = crate::config::EventsConfig::default();
    hub.store
        .admit(
            row,
            true,
            store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            chrono::Utc::now(),
            tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
    hub.backend_tools_changed("x");
    assert_eq!(hub.store.subscriptions().len(), 1, "still offered: kept");
    names.lock().clear();
    hub.backend_tools_changed("x");
    assert!(
        hub.store.subscriptions().is_empty(),
        "withdrawn with the backend"
    );
}

/// A report still waiting when its backend leaves is not sent.
#[tokio::test(start_paused = true)]
async fn a_pending_report_does_not_outlive_its_backend() {
    let (hub, _dir) = hub();
    let mut events = drain(&hub);
    let names = Arc::new(parking_lot::Mutex::new(vec!["x".to_owned()]));
    let live = Arc::clone(&names);
    hub.install_backend_source(Arc::new(move || live.lock().clone()));
    hub.backend_tools_changed("x");
    names.lock().clear();
    hub.backend_tools_changed("x");
    tokio::time::sleep(QUIET * 2).await;
    assert!(events.try_recv().is_err(), "no event for a removed backend");
}

/// A settled task whose row the expiry sweep already removed still reaches its
/// owner, and only its owner: ownership rides on the occurrence, not on a read
/// of the record at fan-out.
#[tokio::test]
async fn a_settled_task_is_matched_by_its_carried_owner_after_expiry() {
    use crate::events::task_source::TaskSource;
    use crate::gateway::task_service::{StoreLimits, TaskService};
    let dir = tempfile::tempdir().expect("dir");
    let admission = crate::idempotency::admission::ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("service"),
    );
    let source = TaskSource {
        service: Arc::clone(&service),
    };
    let owner = service
        .owner("alice")
        .expect("owner")
        .as_digest()
        .to_owned();
    // The row is gone: the service holds no such task.
    let event = |owner: Option<String>| fanout::SourceEvent {
        kind: types::SourceKind::TaskSettled,
        name: "task.settled".into(),
        backend: "tasks".into(),
        scope: types::Visibility::Owner,
        owner,
        upstream_id: "task-gone:completed".into(),
        occurred_at: chrono::Utc::now(),
        data: serde_json::json!({"taskId": "task-gone", "status": "completed",
            "settledAt": "2026-10-03T00:00:00.000Z"}),
        lifecycle_key: None,
    };
    let args = serde_json::json!({});
    assert!(
        source.matches("alice", &args, &event(Some(owner.clone()))),
        "the owner hears a task whose row has expired"
    );
    assert!(
        !source.matches("bob", &args, &event(Some(owner))),
        "another principal does not"
    );
    assert!(
        !source.matches("alice", &args, &event(None)),
        "without a carried owner the store is asked, and the row is gone"
    );
}

/// After expiry, fan-out still queues the occurrence for a subscriber named on
/// the task and for an all-tasks subscriber: the carried owner stands in for
/// the deleted row, and neither subscription is revoked.
#[tokio::test]
async fn an_expired_tasks_event_reaches_named_and_all_task_subscribers() {
    use crate::events::task_source::TaskSource;
    use crate::gateway::task_service::{StoreLimits, TaskService};
    let dir = tempfile::tempdir().expect("dir");
    let admission = crate::idempotency::admission::ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("service"),
    );
    let events_dir = tempfile::tempdir().expect("events dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, events_dir.path()).expect("hub");
    hub.register_source(Arc::new(TaskSource {
        service: Arc::clone(&service),
    }));
    let owner = service
        .owner("alice")
        .expect("owner")
        .as_digest()
        .to_owned();
    for (id, arguments) in [
        ("sub_named", serde_json::json!({"taskId": "task-gone"})),
        ("sub_all", serde_json::json!({})),
    ] {
        let row: records::Subscription = serde_json::from_value(serde_json::json!({
            "v": 1, "id": id, "principal": "alice", "url": format!("https://h/{id}"),
            "name": "task.settled", "arguments": arguments, "secret": "whsec_x",
            "previous_secret": null, "previous_until": null,
            "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null,
            "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::None)
                .expect("kind"),
        }))
        .expect("row");
        hub.store
            .admit(
                row,
                true,
                store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                chrono::Utc::now(),
                tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    let event = fanout::SourceEvent {
        kind: types::SourceKind::TaskSettled,
        name: "task.settled".into(),
        backend: "tasks".into(),
        scope: types::Visibility::Owner,
        owner: Some(owner),
        upstream_id: "task-gone:completed".into(),
        occurred_at: chrono::Utc::now(),
        data: serde_json::json!({"taskId": "task-gone", "status": "completed",
            "settledAt": "2026-10-03T00:00:00.000Z"}),
        lifecycle_key: None,
    };
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
        credentials: LiveCredentials::default(),
    };
    hub.fan_out(&services, &event).await;
    let queued = std::fs::read_dir(events_dir.path().join("outbox")).map_or(0, Iterator::count);
    assert_eq!(queued, 2, "a record for each subscriber");
    assert_eq!(hub.store.subscriptions().len(), 2, "none was revoked");
}

struct WebhooksOn;

#[async_trait::async_trait]
impl EventSource for WebhooksOn {
    fn kind(&self) -> types::SourceKind {
        types::SourceKind::Webhook
    }
    fn descriptors(&self) -> Vec<types::EventDescriptor> {
        Vec::new()
    }
    fn matches(&self, _: &str, _: &serde_json::Value, _: &fanout::SourceEvent) -> bool {
        false
    }
}

/// Startup reconciliation withdraws subscriptions to backends the registry no
/// longer has, even when the capability scan was partial; the partial scan
/// still spares webhook subscriptions it cannot judge.
#[tokio::test]
async fn startup_reconcile_withdraws_absent_backends_on_a_partial_scan() {
    let (hub, _dir) = hub();
    hub.register_source(Arc::new(WebhooksOn));
    hub.install_backend_source(Arc::new(|| vec!["kept".to_owned(), "k.d".to_owned()]));
    let config = crate::config::EventsConfig::default();
    for (id, name) in [
        ("sub_gone", "backend.gone.tools_changed"),
        ("sub_kept", "backend.kept.tools_changed"),
        ("sub_kept_resource", "backend.kept.resource_updated"),
        ("sub_gone_resource", "backend.gone.resource_updated"),
        ("sub_dotted", "backend.k.d.resource_updated"),
        ("sub_hook", "webhook.cap.route.received"),
    ] {
        let row: records::Subscription = serde_json::from_value(serde_json::json!({
            "v": 1, "id": id, "principal": "p", "url": format!("https://h/{id}"),
            "name": name, "arguments": {}, "secret": "whsec_x",
            "previous_secret": null, "previous_until": null,
            "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null
        }))
        .expect("row");
        hub.store
            .admit(
                row,
                true,
                store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                chrono::Utc::now(),
                tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    assert!(hub.reconcile_catalogue(fanout::CatalogueScan::Partial));
    let mut left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.id)
        .collect();
    left.sort();
    assert_eq!(
        left,
        ["sub_dotted", "sub_hook", "sub_kept", "sub_kept_resource"],
        "only the absent backend's goes"
    );
}

/// A `resource_updated` subscription hears only its own URI; the list-changed
/// kinds carry no URI and match every subscriber.
#[test]
fn a_resource_update_matches_only_its_uri() {
    let source = backend_source::BackendSource {
        names: Arc::new(Vec::new),
        upstream: None,
    };
    let event = |name: &str, data: serde_json::Value| fanout::SourceEvent {
        kind: types::SourceKind::BackendNotification,
        name: name.to_owned(),
        backend: "x".to_owned(),
        scope: types::Visibility::Backend("x".to_owned()),
        owner: None,
        upstream_id: "id".to_owned(),
        occurred_at: chrono::Utc::now(),
        data,
        lifecycle_key: None,
    };
    let updated = event(
        "backend.x.resource_updated",
        serde_json::json!({"uri": "b"}),
    );
    assert!(!source.matches("p", &serde_json::json!({"uri": "a"}), &updated));
    assert!(source.matches("p", &serde_json::json!({"uri": "b"}), &updated));
    let listed = event("backend.x.resources_changed", serde_json::json!({}));
    assert!(source.matches("p", &serde_json::json!({}), &listed));
}

#[path = "reconcile_table_backend_tests.rs"]
mod reconcile_table;
