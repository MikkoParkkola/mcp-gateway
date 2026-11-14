// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A graceful handover that lands before or during a start: the start is
//! refused and nothing is installed. Helpers are the parent module's.
use super::*;

/// R2b.1 (HANDOVER.2, pin): a graceful handover that lands before a
/// transport's first start retires its slot, so that start spawns nothing and
/// no tree reaches the reaper.
#[tokio::test]
async fn a_graceful_handover_before_a_start_spawns_nothing() {
    let workspace = tempfile::tempdir().expect("workspace");
    std::fs::write(
        workspace.path().join("server.sh"),
        "echo spawned > spawned.mark\nwhile IFS= read -r l; do :; done\n",
    )
    .expect("write server");
    let t = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        Duration::from_secs(30),
        None,
    );
    crate::transport::LiveTree::hand_over_gracefully(&*t, Duration::from_secs(10));
    let refused = t.start().await;
    assert!(
        matches!(&refused, Err(crate::Error::BackendNotFound(m)) if m.contains("retired before it started")),
        "refused before the spawn: {refused:?}"
    );
    assert!(
        t.child.lock().outstanding().is_empty(),
        "a tree was spawned and handed to the reaper"
    );
    assert!(
        !workspace.path().join("spawned.mark").exists(),
        "the refused start spawned its backend"
    );
}

/// R2b.2 (HANDOVER.2, pin): a graceful handover that lands in
/// `start` between the spawn and the install refuses the start and installs
/// nothing, and every reap the slot started ends.
#[tokio::test]
async fn a_graceful_handover_between_spawn_and_install_refuses_the_start() {
    let (_w, t) = started("while IFS= read -r l; do :; done", None).await;
    t.hand_over_after_spawn_for_test(Duration::from_secs(10));
    let refused = t.start().await;
    assert!(
        matches!(&refused, Err(crate::Error::BackendNotFound(m)) if m.contains("while it started")),
        "refused at install: {refused:?}"
    );
    assert!(t.child.lock().tree.is_none(), "nothing was installed");
    tokio::time::timeout(Duration::from_secs(30), t.end_tree())
        .await
        .expect("every reap the slot started ends");
}
