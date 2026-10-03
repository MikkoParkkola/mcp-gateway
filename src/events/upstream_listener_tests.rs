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
