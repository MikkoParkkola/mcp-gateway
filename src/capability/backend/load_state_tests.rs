// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! When a reload sends its tools-changed notice (MIK-8050).

use std::sync::Arc;

use super::super::{CapabilityBackend, CapabilityExecutor};
use super::Announce;

/// The capability the events tests load (`events_hook_tests::capability`).
const ALPHA: &str = "name: alpha\ndescription: one\nschema:\n  input: { type: object, properties: {} }\n  \
                     output: { type: object }\nproviders: {}\nwebhooks:\n  push:\n    path: /alpha/push\n    \
                     method: POST\n    transform:\n      event_type: \"alpha.push\"\n      data: { ref: \"{ref}\" }\n    \
                     event:\n      description: \"A push.\"\n      filters: [ref]\n";

/// A backend reading `dir`, with its notice channel.
async fn backend(
    dir: &std::path::Path,
) -> (
    CapabilityBackend,
    tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let backend = CapabilityBackend::new("hooks", Arc::new(CapabilityExecutor::new()));
    backend
        .load_from_directory(dir.to_str().expect("utf8"))
        .await
        .expect("load");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    backend.set_reload_notice(tx);
    (backend, rx)
}

#[tokio::test]
async fn a_rerun_over_unchanged_files_announces_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("alpha.yaml"), ALPHA).expect("write");
    let (backend, mut rx) = backend(dir.path()).await;
    assert_eq!(backend.list_capabilities().len(), 1, "the fixture loads");
    backend
        .reload_announcing(Announce::OnChange)
        .await
        .expect("reload");
    assert!(rx.try_recv().is_err(), "nothing changed, nothing announced");
}

#[tokio::test]
async fn a_rerun_that_edits_a_capability_announces_it() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("alpha.yaml"), ALPHA).expect("write");
    let (backend, mut rx) = backend(dir.path()).await;
    std::fs::write(
        dir.path().join("alpha.yaml"),
        ALPHA.replace("description: one", "description: two"),
    )
    .expect("edit");
    backend
        .reload_announcing(Announce::OnChange)
        .await
        .expect("reload");
    assert_eq!(rx.try_recv().ok().as_deref(), Some("hooks"));
}

#[tokio::test]
async fn a_watcher_reload_announces_every_time() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("alpha.yaml"), ALPHA).expect("write");
    let (backend, mut rx) = backend(dir.path()).await;
    backend.reload().await.expect("reload");
    assert_eq!(
        rx.try_recv().ok().as_deref(),
        Some("hooks"),
        "unchanged, still announced: it retries the events reconcile"
    );
}
