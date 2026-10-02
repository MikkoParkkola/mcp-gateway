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
        hub.task_published("task-1", status, now);
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
        hub.task_published("task-1", status, now);
        let event = events.try_recv().expect("terminal status emits");
        assert_eq!(event.name, "task.settled");
        assert_eq!(event.data["taskId"], "task-1");
        assert_eq!(event.data["status"], name);
        let keys: Vec<&String> = event.data.as_object().expect("object").keys().collect();
        assert_eq!(keys.len(), 3, "taskId, status, settledAt only: {keys:?}");
    }
}
