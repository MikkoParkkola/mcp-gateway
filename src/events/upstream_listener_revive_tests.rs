// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for a tools listener that comes back with its backend (MIK-7944
//! D6.EVENTS_MISC.6): a `tools_changed` key held while the backend could not
//! be listened to gets a listener once it can, with no reload and no new
//! subscription.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::events::EventSource as _;
use crate::events::backend_source::{BackendSource, Upstream};
use crate::transport::upstream_tap::NoteKind;

/// Longer than one revive sweep.
const PAST_A_SWEEP: std::time::Duration = std::time::Duration::from_secs(31);

/// A backend `b` that is registered and never answers.
fn silent_backend() -> Arc<Backend> {
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_owned(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        timeout: std::time::Duration::from_secs(1),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "b",
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// The events source over `registry`, with `b` refused while `refused` holds.
fn source(registry: Arc<BackendRegistry>, refused: Arc<AtomicBool>) -> BackendSource {
    let ineligible: crate::events::backend_source::Ineligible = Arc::new(move || {
        if refused.load(Ordering::SeqCst) {
            std::iter::once("b".to_owned()).collect()
        } else {
            std::collections::BTreeSet::new()
        }
    });
    BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: Some(Upstream {
            listeners: UpstreamListeners::new(registry, Weak::new(), Arc::clone(&ineligible)),
            ineligible,
        }),
    }
}

fn listeners(source: &BackendSource) -> &UpstreamListeners {
    &source.upstream.as_ref().expect("upstream").listeners
}

fn starts(source: &BackendSource) -> usize {
    listeners(source).starts.load(Ordering::SeqCst)
}

/// Let one revive sweep run: the sweep task is polled once so its timer is
/// armed, the clock passes the sweep, and the sweep's pass runs.
async fn sweep() {
    tokio::task::yield_now().await;
    tokio::time::advance(PAST_A_SWEEP).await;
    tokio::task::yield_now().await;
}

/// The backend's entry is live and counts the held tools key.
fn assert_listened(source: &BackendSource) {
    let entry = listeners(source).backends.lock().get("b").cloned();
    let entry = entry.expect("listener");
    assert!(!entry.stop.is_cancelled(), "the listener runs");
    assert!(
        entry.need.lock().emits(NoteKind::ToolsChanged, None),
        "the tools key is still counted"
    );
}

async fn hold_tools(source: &BackendSource) {
    source
        .on_first_subscriber("k", "p", "backend.b.tools_changed", &serde_json::json!({}))
        .await
        .expect("tools_changed is admitted on every backend");
}

/// F6.1: a key admitted while the backend is refused gets a listener once
/// the backend is eligible again.
#[tokio::test(start_paused = true)]
async fn a_tools_key_held_while_refused_is_listened_to_once_eligible() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let refused = Arc::new(AtomicBool::new(true));
    let source = source(registry, Arc::clone(&refused));
    hold_tools(&source).await;
    sweep().await;
    assert_eq!(starts(&source), 0, "no task for a refused backend");
    refused.store(false, Ordering::SeqCst);
    sweep().await;
    assert_eq!(starts(&source), 1, "the held key got its listener");
    assert_listened(&source);
}

/// F6.6: a key admitted before the backend is registered gets a listener
/// once it is.
#[tokio::test(start_paused = true)]
async fn a_tools_key_held_before_registration_is_listened_to_once_registered() {
    let registry = Arc::new(BackendRegistry::new());
    let source = source(Arc::clone(&registry), Arc::new(AtomicBool::new(false)));
    hold_tools(&source).await;
    sweep().await;
    assert_eq!(starts(&source), 0, "no task for an unregistered backend");
    assert!(registry.register(silent_backend()));
    sweep().await;
    assert_eq!(starts(&source), 1, "the held key got its listener");
    assert_listened(&source);
}

/// F6.3, the control: a backend that stays refused never gets a task.
#[tokio::test(start_paused = true)]
async fn a_backend_that_stays_refused_gets_no_task() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let source = source(registry, Arc::new(AtomicBool::new(true)));
    hold_tools(&source).await;
    for _ in 0..3 {
        sweep().await;
    }
    assert_eq!(starts(&source), 0);
}

/// F6.2: a listener that ended because its backend turned ineligible, its
/// tools key still held, is started again once the backend is eligible.
#[tokio::test(start_paused = true)]
async fn a_listener_ended_as_ineligible_comes_back_once_eligible() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let refused = Arc::new(AtomicBool::new(false));
    let source = source(registry, Arc::clone(&refused));
    hold_tools(&source).await;
    assert_eq!(starts(&source), 1, "an eligible backend is listened to");
    refused.store(true, Ordering::SeqCst);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(600), async {
        loop {
            let stopped = listeners(&source)
                .backends
                .lock()
                .get("b")
                .is_some_and(|s| s.stop.is_cancelled());
            if stopped {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(ended.is_ok(), "the listener ended as ineligible");
    refused.store(false, Ordering::SeqCst);
    sweep().await;
    assert_eq!(starts(&source), 2, "the held key got its listener back");
    assert_listened(&source);
}

/// F6.4: the last held key leaving removes the ended entry, so a later
/// sweep starts nothing for it.
#[tokio::test(start_paused = true)]
async fn a_held_key_that_leaves_takes_its_entry_along() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let refused = Arc::new(AtomicBool::new(true));
    let source = source(registry, Arc::clone(&refused));
    hold_tools(&source).await;
    listeners(&source).remove("b", &Interest::ToolsChanged);
    assert!(!listeners(&source).backends.lock().contains_key("b"));
    refused.store(false, Ordering::SeqCst);
    sweep().await;
    assert_eq!(starts(&source), 0);
}

/// F6.8: the sweep holds the listeners weakly, so dropping their last owner
/// still cancels every task.
#[tokio::test(start_paused = true)]
async fn dropping_the_listeners_cancels_their_tasks_while_the_sweep_sleeps() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let none: crate::events::backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    let listeners = UpstreamListeners::new(registry, Weak::new(), none);
    listeners.add("b", &Interest::ToolsChanged).expect("room");
    let task = listeners
        .backends
        .lock()
        .get("b")
        .cloned()
        .expect("listener");
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    drop(listeners);
    assert!(
        task.stop.is_cancelled(),
        "a strong sweep kept the owner alive"
    );
    sweep().await;
}
