// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Caps, the guard's drop on each exit, the watcher refcount and the
//! generations the hub publishes.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tokio::task::JoinHandle;

use super::guard::{Guard, MAX_PER_CREDENTIAL, MAX_UI_STREAMS, Refusal, StreamHub};

fn idle_task() -> JoinHandle<()> {
    tokio::spawn(std::future::pending::<()>())
}

fn admit(hub: &StreamHub, who: &str) -> Result<Guard, Refusal> {
    hub.admit(who, idle_task)
}

#[tokio::test]
async fn the_global_cap_refuses_the_33rd_and_a_drop_admits_the_next() {
    let hub = StreamHub::new();
    let mut held: Vec<Guard> = (0..MAX_UI_STREAMS)
        .map(|i| admit(&hub, &format!("k{}", i / MAX_PER_CREDENTIAL)).expect("admitted"))
        .collect();
    assert_eq!(hub.open_streams(), MAX_UI_STREAMS);
    assert_eq!(admit(&hub, "other").err(), Some(Refusal::Global));
    held.pop();
    assert!(admit(&hub, "other").is_ok());
}

#[tokio::test]
async fn one_credential_holds_at_most_four() {
    let hub = StreamHub::new();
    let held: Vec<Guard> = (0..MAX_PER_CREDENTIAL)
        .map(|_| admit(&hub, "key").expect("admitted"))
        .collect();
    assert_eq!(admit(&hub, "key").err(), Some(Refusal::Credential));
    assert!(admit(&hub, "another").is_ok(), "other keys are unaffected");
    drop(held);
    assert!(admit(&hub, "key").is_ok());
}

#[tokio::test]
async fn the_watcher_starts_on_the_first_stream_and_stops_on_the_last() {
    let hub = StreamHub::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let start = |starts: &Arc<AtomicUsize>| {
        let starts = Arc::clone(starts);
        move || {
            starts.fetch_add(1, Ordering::SeqCst);
            idle_task()
        }
    };
    assert!(!hub.watcher_running());
    let a = hub.admit("a", start(&starts)).expect("first");
    let b = hub.admit("b", start(&starts)).expect("second");
    assert_eq!(
        starts.load(Ordering::SeqCst),
        1,
        "one watcher for two streams"
    );
    assert!(hub.watcher_running());
    drop(a);
    assert!(hub.watcher_running(), "a stream is still listening");
    drop(b);
    assert!(!hub.watcher_running());
    let _c = hub.admit("c", start(&starts)).expect("restart");
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_guard_returns_everything_when_its_task_panics() {
    let hub = StreamHub::new();
    let guard = admit(&hub, "key").expect("admitted");
    let task = tokio::spawn(async move {
        let _held = guard;
        panic!("a stream task dies");
    });
    assert!(task.await.is_err());
    assert_eq!(hub.open_streams(), 0);
    assert!(!hub.watcher_running());
    let again: Vec<Guard> = (0..MAX_PER_CREDENTIAL)
        .map(|_| admit(&hub, "key").expect("the slot came back"))
        .collect();
    assert_eq!(again.len(), MAX_PER_CREDENTIAL);
}

#[tokio::test]
async fn the_guard_returns_everything_when_its_task_is_aborted() {
    let hub = StreamHub::new();
    let guard = admit(&hub, "key").expect("admitted");
    let task = tokio::spawn(async move {
        let _held = guard;
        std::future::pending::<()>().await;
    });
    task.abort();
    let _ = task.await;
    assert_eq!(hub.open_streams(), 0);
}

#[tokio::test]
async fn boot_ids_differ_between_hubs() {
    assert_ne!(StreamHub::new().boot(), StreamHub::new().boot());
}

#[tokio::test]
async fn a_change_raises_the_status_generation_and_a_repeat_does_not() {
    let hub = StreamHub::new();
    let rx = hub.subscribe();
    hub.observe(json!({"a": 1, "uptime_secs": 1}), json!({}), false);
    let g1 = rx.borrow().status_gen;
    hub.observe(json!({"a": 1, "uptime_secs": 2}), json!({}), false);
    assert_eq!(rx.borrow().status_gen, g1, "uptime alone is not a change");
    hub.observe(json!({"a": 2, "uptime_secs": 3}), json!({}), false);
    assert!(rx.borrow().status_gen > g1);
}

#[tokio::test]
async fn counts_that_differ_only_in_uptime_are_not_a_change() {
    let hub = StreamHub::new();
    let rx = hub.subscribe();
    hub.observe(json!({"a": 1}), json!({"n": 1, "uptime_secs": 1}), false);
    let g1 = rx.borrow().counts_gen;
    hub.observe(json!({"a": 1}), json!({"n": 1, "uptime_secs": 2}), false);
    assert_eq!(rx.borrow().counts_gen, g1, "uptime alone is not a change");
    hub.observe(json!({"a": 1}), json!({"n": 2, "uptime_secs": 3}), false);
    assert!(rx.borrow().counts_gen > g1, "a real count change is one");
}

#[tokio::test]
async fn a_reload_raises_only_the_reload_generation() {
    let hub = StreamHub::new();
    let rx = hub.subscribe();
    hub.observe(json!({"a": 1}), json!({}), false);
    let (s, r) = (rx.borrow().status_gen, rx.borrow().reload_gen);
    hub.observe(json!({"a": 1}), json!({}), true);
    assert_eq!(rx.borrow().status_gen, s);
    assert!(rx.borrow().reload_gen > r);
}

#[tokio::test]
async fn generations_survive_a_watcher_restart() {
    let hub = StreamHub::new();
    let rx = hub.subscribe();
    let g = admit(&hub, "a").expect("admitted");
    hub.observe(json!({"a": 1}), json!({}), false);
    let before = rx.borrow().status_gen;
    drop(g);
    let _again = admit(&hub, "a").expect("admitted");
    assert_eq!(rx.borrow().status_gen, before, "a restart never resets it");
}
