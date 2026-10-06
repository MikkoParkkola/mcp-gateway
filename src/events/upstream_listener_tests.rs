// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener map that need no backend: the catalogue verdict
//! that authorizes a URI and the counted interest.

use std::collections::HashSet;

use super::*;
use crate::backend::BackendRegistry;

fn listeners() -> Arc<UpstreamListeners> {
    UpstreamListeners::new(
        Arc::new(BackendRegistry::new()),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    )
}

fn watched(uri: &str) -> Interest {
    Interest::ResourceUpdated(uri.to_owned())
}

/// With a good snapshot the verdict is the snapshot's: a listed URI passes,
/// one absent from a complete read is refused `-32012`, an incomplete read
/// proves nothing.
#[tokio::test]
async fn a_good_snapshot_decides_authorization() {
    let hub = listeners();
    hub.add("b", &watched("file:///a")).expect("room");
    let set: HashSet<String> = ["file:///a".to_owned()].into();
    let read = |complete: bool| {
        hub.backends
            .lock()
            .get("b")
            .expect("listener")
            .snapshot
            .lock()
            .read(set.clone(), complete);
    };
    read(true);
    assert!(hub.authorize_uri("b", "file:///a").await.is_ok());
    let refused = hub
        .authorize_uri("b", "file:///missing")
        .await
        .expect_err("absent");
    assert_eq!(refused.code, -32012);
    read(false);
    assert!(hub.authorize_uri("b", "file:///missing").await.is_ok());
}

/// The last key to leave stops the task and forgets the backend.
#[tokio::test]
async fn the_last_interest_ends_the_listener() {
    let hub = listeners();
    hub.add("b", &watched("file:///a")).expect("room");
    hub.add("b", &Interest::PromptsChanged).expect("room");
    hub.remove("b", &watched("file:///a"));
    assert!(
        hub.backends.lock().contains_key("b"),
        "prompts still wanted"
    );
    hub.remove("b", &Interest::PromptsChanged);
    assert!(!hub.backends.lock().contains_key("b"));
}

/// MIK-7894: a task a reload ended (its backend became ineligible) is not
/// reused when interest returns; a fresh one replaces it.
#[tokio::test]
async fn a_listener_task_a_reload_ended_is_replaced_when_interest_returns() {
    let hub = listeners();
    hub.add("b", &Interest::ResourcesChanged).expect("room");
    let first = hub.backends.lock().get("b").cloned().expect("listener");
    first.stop.cancel();
    hub.add("b", &Interest::PromptsChanged).expect("room");
    let second = hub.backends.lock().get("b").cloned().expect("listener");
    assert!(!Arc::ptr_eq(&first, &second), "the ended task was reused");
    assert!(!second.stop.is_cancelled());
}

/// MIK-7894: the replacement keeps the interest the reload left standing (a
/// `tools_changed` key), so the newcomer leaving does not stop the listener
/// those subscribers still need.
#[tokio::test]
async fn a_replaced_listener_keeps_the_interest_that_stayed() {
    let hub = listeners();
    hub.add("b", &Interest::ToolsChanged).expect("room");
    hub.backends
        .lock()
        .get("b")
        .expect("listener")
        .stop
        .cancel();
    hub.add("b", &Interest::PromptsChanged).expect("room");
    hub.remove("b", &Interest::PromptsChanged);
    assert!(
        hub.backends.lock().contains_key("b"),
        "the tools_changed interest was lost"
    );
    hub.remove("b", &Interest::ToolsChanged);
    assert!(!hub.backends.lock().contains_key("b"));
}

/// MIK-7894 ELIG.2: authorization consults the live eligibility predicate,
/// so subscribe, fan-out and the worker (all three call it) refuse a backend
/// a reload made ineligible. The predicate wins over a snapshot that lists
/// the URI; `tools_changed` stays, since the gateway announces it itself.
#[tokio::test]
async fn authorize_refuses_an_ineligible_backend() {
    use crate::events::EventSource as _;
    use crate::events::backend_source::{BackendSource, Upstream};

    let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&refused);
    let ineligible: crate::events::backend_source::Ineligible = Arc::new(move || {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            std::iter::once("b".to_owned()).collect()
        } else {
            std::collections::BTreeSet::new()
        }
    });
    // `b` is registered: authorization refuses a backend that is not.
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(crate::backend::Backend::new(
        "b",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))));
    let listeners = UpstreamListeners::new(registry, Weak::new(), Arc::clone(&ineligible));
    listeners.add("b", &watched("file:///a")).expect("room");
    listeners
        .backends
        .lock()
        .get("b")
        .expect("listener")
        .snapshot
        .lock()
        .read(["file:///a".to_owned()].into(), true);
    let source = BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: Some(Upstream {
            listeners,
            ineligible,
        }),
    };
    let (uri, none) = (
        serde_json::json!({"uri": "file:///a"}),
        serde_json::json!({}),
    );

    // Control: eligible, every kind is admitted.
    for (name, args) in [
        ("backend.b.resource_updated", &uri),
        ("backend.b.resources_changed", &none),
    ] {
        assert!(source.authorize("p", name, args).await.is_ok(), "{name}");
    }

    refused.store(true, std::sync::atomic::Ordering::SeqCst);
    for (name, args) in [
        ("backend.b.resource_updated", &uri),
        ("backend.b.resources_changed", &none),
        ("backend.b.prompts_changed", &none),
    ] {
        let err = source.authorize("p", name, args).await.expect_err(name);
        assert_eq!(err.code, -32012, "{name}");
    }
    assert!(
        source
            .authorize("p", "backend.b.tools_changed", &none)
            .await
            .is_ok(),
        "tools_changed is the gateway's own announcement"
    );
}

/// What a reload does to backend `b` while its catalogue lookup waits.
#[derive(Clone, Copy)]
enum Reload {
    /// Nothing changes: the control, admitted under the offline rule.
    Nothing,
    /// The backend stays but turns ineligible.
    Ineligible,
    /// The backend leaves the registry.
    Removed,
}

/// MIK-7894: the catalogue lookup behind a `resource_updated` verdict waits
/// on the backend when no snapshot exists, so eligibility and the backend's
/// registration are read again once it returns. The backend here never
/// answers; `reload` is applied when its connection arrives, while the lookup
/// waits, so a check made only before the lookup admits.
async fn verdict_after_a_reload_during_the_lookup(reload: Reload) -> Result<(), RpcError> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
    use crate::events::EventSource as _;
    use crate::events::backend_source::{BackendSource, Upstream};
    use std::sync::atomic::{AtomicBool, Ordering};

    let reloaded = Arc::new(AtomicBool::new(false));
    let registry = Arc::new(BackendRegistry::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (flips, held_registry) = (Arc::clone(&reloaded), Arc::clone(&registry));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            if let Reload::Removed = reload {
                held_registry.remove("b");
            }
            flips.store(true, Ordering::SeqCst);
            held.push(stream);
        }
    });
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: format!("http://127.0.0.1:{port}/mcp"),
            streamable_http: Some(true),
            protocol_version: None,
        },
        timeout: std::time::Duration::from_secs(1),
        ..BackendConfig::default()
    };
    assert!(registry.register(Arc::new(Backend::new(
        "b",
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))));
    let turned = Arc::clone(&reloaded);
    let ineligible: crate::events::backend_source::Ineligible = Arc::new(move || {
        if matches!(reload, Reload::Ineligible) && turned.load(Ordering::SeqCst) {
            std::iter::once("b".to_owned()).collect()
        } else {
            std::collections::BTreeSet::new()
        }
    });
    let source = BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: Some(Upstream {
            listeners: UpstreamListeners::new(registry, Weak::new(), Arc::clone(&ineligible)),
            ineligible,
        }),
    };
    let verdict = source
        .authorize(
            "p",
            "backend.b.resource_updated",
            &serde_json::json!({"uri": "file:///a"}),
        )
        .await;
    assert!(
        reloaded.load(Ordering::SeqCst),
        "the lookup reached the backend"
    );
    verdict
}

#[tokio::test]
async fn a_backend_made_ineligible_during_the_lookup_is_refused() {
    let verdict = verdict_after_a_reload_during_the_lookup(Reload::Ineligible).await;
    assert_eq!(verdict.expect_err("refused").code, -32012);
}

#[tokio::test]
async fn a_backend_removed_during_the_lookup_is_refused() {
    let verdict = verdict_after_a_reload_during_the_lookup(Reload::Removed).await;
    assert_eq!(verdict.expect_err("refused").code, -32012);
}

/// The control: with no reload, the unreadable catalogue admits (offline rule).
#[tokio::test]
async fn a_backend_left_alone_during_the_lookup_is_admitted() {
    let verdict = verdict_after_a_reload_during_the_lookup(Reload::Nothing).await;
    assert!(verdict.is_ok(), "{verdict:?}");
}

fn offline(name: &str) -> Arc<crate::backend::Backend> {
    Arc::new(crate::backend::Backend::new(
        name,
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// D5 release point (r1 HIGH): a backend replaced in the config gets a fresh
/// ledger at the next admission; the interest still counted moves with it.
#[tokio::test]
async fn a_replaced_backend_gets_a_fresh_ledger_carrying_its_interest() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    let listeners = UpstreamListeners::new(
        Arc::clone(&registry),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    );
    listeners.add("b", &watched("file:///a")).expect("room");
    let first = listeners.backends.lock()["b"].ledger();
    assert!(registry.remove("b"));
    assert!(registry.register(offline("b")));
    listeners.add("b", &watched("file:///b")).expect("room");
    let second = listeners.backends.lock()["b"].ledger();
    assert!(!Arc::ptr_eq(&first, &second), "fresh ledger");
    assert_eq!(second.lock().size().0, 2, "a carried, b admitted");
}

/// While the registry holds the same backend, its ledger is kept.
#[tokio::test]
async fn the_same_backend_keeps_its_ledger() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    let listeners = UpstreamListeners::new(
        Arc::clone(&registry),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    );
    listeners.add("b", &watched("file:///a")).expect("room");
    let first = listeners.backends.lock()["b"].ledger();
    listeners.add("b", &watched("file:///b")).expect("room");
    assert!(Arc::ptr_eq(
        &first,
        &listeners.backends.lock()["b"].ledger()
    ));
}

/// D5 release point (d1 HIGH): a running task whose backend is replaced in
/// the config moves to the replacement's ledger at its next session start,
/// with no admission to trigger it; its counted interest moves along.
#[tokio::test]
async fn a_running_task_takes_the_replaced_backends_ledger_at_session_start() {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    let listeners = UpstreamListeners::new(
        Arc::clone(&registry),
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    );
    listeners.add("b", &watched("file:///a")).expect("room");
    let shared = Arc::clone(&listeners.backends.lock()["b"]);
    let first = shared.ledger();
    shared.refresh_ledger();
    assert!(
        Arc::ptr_eq(&first, &shared.ledger()),
        "same backend, same ledger"
    );
    assert!(registry.remove("b"));
    assert!(registry.register(offline("b")));
    shared.refresh_ledger();
    let second = shared.ledger();
    assert!(!Arc::ptr_eq(&first, &second), "fresh ledger");
    assert_eq!(
        second.lock().size().0,
        1,
        "the watched URI took a key there"
    );
    assert!(
        Arc::ptr_eq(&second, &listeners.ledger("b")),
        "the map and the task agree"
    );
}

#[path = "upstream_listener_revive_tests.rs"]
mod revive;
