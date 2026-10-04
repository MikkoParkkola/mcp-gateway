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
    let listeners = UpstreamListeners::new(
        Arc::new(BackendRegistry::new()),
        Weak::new(),
        Arc::clone(&ineligible),
    );
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

/// MIK-7894: the catalogue lookup behind a `resource_updated` verdict can wait
/// (up to 10s with no snapshot), so eligibility is read again once it returns.
/// The predicate here answers eligible once and ineligible after: a reload
/// landing during the lookup. The verdict is `-32012`, not the lookup's `Ok`.
#[tokio::test]
async fn a_reload_during_the_catalogue_lookup_refuses() {
    use crate::events::EventSource as _;
    use crate::events::backend_source::{BackendSource, Upstream};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let asked = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&asked);
    let ineligible: crate::events::backend_source::Ineligible = Arc::new(move || {
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            std::collections::BTreeSet::new()
        } else {
            std::iter::once("b".to_owned()).collect()
        }
    });
    let listeners = UpstreamListeners::new(
        Arc::new(BackendRegistry::new()),
        Weak::new(),
        Arc::clone(&ineligible),
    );
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
    asked.store(0, Ordering::SeqCst);
    let err = source
        .authorize(
            "p",
            "backend.b.resource_updated",
            &serde_json::json!({"uri": "file:///a"}),
        )
        .await
        .expect_err("refused after the lookup");
    assert_eq!(err.code, -32012);
    assert_eq!(asked.load(Ordering::SeqCst), 2, "asked before and after");
}
