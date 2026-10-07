// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which events wake the rewatch task (MIK-8013). Each wake re-resolves the
//! config's whole link chain, so a write beside the config that cannot move
//! the chain must not cost one.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{ChainNames, resolve_chain};

fn canonical(path: &std::path::Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonical")
}

/// Before any resolve, and after a failed one, every event wakes the task.
#[test]
fn no_chain_wakes_on_any_path() {
    let names = ChainNames::default();
    assert!(names.may_move_chain(&[PathBuf::from("/x/unrelated")]));
}

/// A resolved chain wakes only on its own paths (Linux; elsewhere on every
/// path), and a pathless event always wakes.
#[test]
fn a_chain_wakes_on_its_paths_only() {
    let names = ChainNames::default();
    names.set(Some(BTreeSet::from([PathBuf::from("/c/gateway.yaml")])));
    assert!(names.may_move_chain(&[PathBuf::from("/c/gateway.yaml")]));
    assert!(names.may_move_chain(&[PathBuf::from("/c/.tmp"), PathBuf::from("/c/gateway.yaml")]));
    assert_eq!(
        names.may_move_chain(&[PathBuf::from("/c/perf.data")]),
        !cfg!(target_os = "linux")
    );
    assert!(names.may_move_chain(&[]));
}

/// A rescan means events were lost, so it wakes whatever path it carries.
#[test]
fn a_rescan_wakes_on_an_unrelated_path() {
    use notify::event::{Event, EventKind, Flag};
    let names = ChainNames::default();
    names.set(Some(BTreeSet::from([PathBuf::from("/c/gateway.yaml")])));
    let unrelated = Event::new(EventKind::Any).add_path(PathBuf::from("/c/perf.data"));
    assert_eq!(names.concerns(&unrelated), !cfg!(target_os = "linux"));
    assert!(names.concerns(&unrelated.set_flag(Flag::Rescan)));
}

/// A plain file's chain names the file, canonical, and nothing beside it.
#[test]
fn a_plain_file_names_itself() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    std::fs::write(&cfg, "a: 1\n").unwrap();
    let chain = resolve_chain(&cfg).expect("resolves");
    assert_eq!(chain.names, BTreeSet::from([canonical(&cfg)]));
}

/// A `ConfigMap` layout names the projected link, the `..data` directory link
/// and the file it ends at: the three paths an update touches.
#[cfg(unix)]
#[test]
fn a_configmap_chain_names_every_link_on_it() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().expect("root");
    let generation = root.path().join("..2026_10_07");
    std::fs::create_dir(&generation).unwrap();
    std::fs::write(generation.join("gateway.yaml"), "a: 1\n").unwrap();
    symlink("..2026_10_07", root.path().join("..data")).unwrap();
    symlink("..data/gateway.yaml", root.path().join("gateway.yaml")).unwrap();

    let chain = resolve_chain(&root.path().join("gateway.yaml")).expect("resolves");
    let real = canonical(root.path());
    assert_eq!(
        chain.names,
        BTreeSet::from([
            real.join("gateway.yaml"),
            real.join("..data"),
            real.join("..2026_10_07").join("gateway.yaml"),
        ])
    );
}

// Linux-only (W-L9): the real-watcher rows run on inotify.
#[cfg(target_os = "linux")]
mod real_watcher {
    use std::path::Path;
    use std::time::Duration;

    use super::super::tests::real_watcher::{Harness, start};

    /// Wait until the task has handled every wake it was sent: the count
    /// stops moving for half a second. Ten seconds of constant wakes fail.
    async fn settled_wakes(h: &Harness) -> usize {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut seen = h.wakes();
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let now = h.wakes();
                if now == seen {
                    return now;
                }
                seen = now;
            }
        })
        .await
        .expect("the rewatch task never stopped waking")
    }

    fn plain_config() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let cfg = root.path().join("gateway.yaml");
        std::fs::write(&cfg, "a: 1\n").expect("config");
        (root, cfg)
    }

    fn write_unrelated(dir: &Path, count: usize) {
        for i in 0..count {
            std::fs::write(dir.join(format!("perf-{i}.data")), "x").unwrap();
        }
    }

    /// MIK-8013.WATCH.2: 1000 files written beside the config run no chain
    /// re-resolution. The config edit after them is the barrier: notify
    /// delivers events in order and the callback wakes the task before it
    /// sends the reload, so once the reload arrives every earlier event was
    /// judged. Multi-threaded, so the rewatch task resolves while the files
    /// are written: on one thread every wake would coalesce after the writes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch2_unrelated_files_beside_the_config_resolve_nothing() {
        let (root, cfg) = plain_config();
        let mut h = start(&cfg);
        h.wait_wakes_above(0).await;
        h.drain_idle().await;
        let before = settled_wakes(&h).await;
        h.chain.names.passed.lock().clear();

        write_unrelated(root.path(), 1000);
        std::fs::write(&cfg, "a: 2\n").unwrap();
        assert!(h.triggered_within(10).await, "the config edit reloads");
        let resolves = settled_wakes(&h).await - before;

        // Only the edit's own events (truncate, write) passed the filter.
        let config = std::fs::canonicalize(&cfg).unwrap();
        let passed = h.chain.names.passed.lock().clone();
        assert!(
            !passed.is_empty() && passed.iter().all(|paths| paths.contains(&config)),
            "events that woke the task: {passed:?}"
        );
        assert!(
            resolves <= passed.len(),
            "{resolves} chain re-resolutions for {} waking events",
            passed.len()
        );
        let _ = h.shutdown.send(());
    }

    /// MIK-8013.WATCH.3: an atomic rename onto the config (write a temporary
    /// file, rename it over the config) still reloads.
    #[tokio::test]
    async fn watch3_an_atomic_rename_onto_the_config_reloads() {
        let (root, cfg) = plain_config();
        let mut h = start(&cfg);
        h.wait_wakes_above(0).await;
        h.drain_idle().await;

        let tmp = root.path().join(".gateway.yaml.tmp");
        std::fs::write(&tmp, "a: 2\n").unwrap();
        std::fs::rename(&tmp, &cfg).unwrap();
        assert!(h.triggered_within(10).await, "the rename reloads");
        let _ = h.shutdown.send(());
    }
}
