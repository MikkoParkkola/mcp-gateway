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
    tokio::time::advance(PAST_A_SWEEP).await;
    assert_eq!(starts(&source), 0, "no task for a refused backend");
    refused.store(false, Ordering::SeqCst);
    tokio::time::advance(PAST_A_SWEEP).await;
    tokio::task::yield_now().await;
    assert_eq!(starts(&source), 1, "the held key got its listener");
}

/// F6.6: a key admitted before the backend is registered gets a listener
/// once it is.
#[tokio::test(start_paused = true)]
async fn a_tools_key_held_before_registration_is_listened_to_once_registered() {
    let registry = Arc::new(BackendRegistry::new());
    let source = source(Arc::clone(&registry), Arc::new(AtomicBool::new(false)));
    hold_tools(&source).await;
    tokio::time::advance(PAST_A_SWEEP).await;
    assert_eq!(starts(&source), 0, "no task for an unregistered backend");
    assert!(registry.register(silent_backend()));
    tokio::time::advance(PAST_A_SWEEP).await;
    tokio::task::yield_now().await;
    assert_eq!(starts(&source), 1, "the held key got its listener");
}

/// F6.3, the control: a backend that stays refused never gets a task.
#[tokio::test(start_paused = true)]
async fn a_backend_that_stays_refused_gets_no_task() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(silent_backend()));
    let source = source(registry, Arc::new(AtomicBool::new(true)));
    hold_tools(&source).await;
    for _ in 0..3 {
        tokio::time::advance(PAST_A_SWEEP).await;
        tokio::task::yield_now().await;
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
    tokio::time::advance(PAST_A_SWEEP).await;
    tokio::task::yield_now().await;
    assert_eq!(starts(&source), 2, "the held key got its listener back");
}
