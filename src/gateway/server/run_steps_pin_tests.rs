// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability file whose bytes stopped matching their pin while the gateway
//! was down reaches To do after an HTTP startup: the startup scan records it
//! before readiness, and the decision set lists it as `capability_changed`.
//!
//! The rows read the decision set's `view()`, which is what
//! `GET /ui/api/decisions` serializes: the route adds only its admin guard
//! (src/gateway/ui/decisions.rs:51-68), which the existing route rows cover.

use std::sync::Arc;
use std::time::Duration;

use super::super::Gateway;
use crate::capability::{compute_capability_hash, rewrite_with_pin};
use crate::config::Config;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::webhooks::WebhookRegistry;

const CHANGED: &str = "
name: changed_tool
description: Trusted when it was pinned
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1
";

/// `CHANGED` pinned to its own hash, then edited so the pin no longer
/// matches: what a change made while the gateway was down leaves on disk.
fn changed_while_down(dir: &std::path::Path) -> String {
    let text = rewrite_with_pin(CHANGED, &compute_capability_hash(CHANGED))
        .replace("Trusted when it was pinned", "Changed while down");
    let path = dir.join("changed.yaml");
    std::fs::write(&path, text).expect("VOID: write the capability");
    path.display().to_string()
}

/// What an HTTP startup's capability step leaves running: the Meta-MCP it
/// installed into, the shutdown sender that ends its tasks, and the file
/// watcher, which stops watching when dropped.
struct Started {
    meta: Arc<MetaMcp>,
    shutdown: tokio::sync::broadcast::Sender<()>,
    _watcher: Option<crate::capability::CapabilityWatcher>,
}

/// An HTTP startup's capability step over `dirs`, as `run` performs it, on
/// the gateway's own Meta-MCP.
async fn http_startup(dirs: &[&std::path::Path], setup: impl FnOnce(&Gateway)) -> Started {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = dirs.iter().map(|d| d.display().to_string()).collect();
    let gateway = Gateway::new(config)
        .await
        .expect("VOID: the gateway builds");
    setup(&gateway);
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("VOID: the Meta-MCP builds")
        .meta_mcp;
    let webhooks = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        gateway.config.webhooks.clone(),
    )));
    let (shutdown, _) = tokio::sync::broadcast::channel(4);
    let watcher = Box::pin(gateway.start_capability_watcher(&meta, &webhooks, &shutdown))
        .await
        .expect("VOID: the capability step starts");
    Started {
        meta,
        shutdown,
        _watcher: watcher,
    }
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn recorded(meta: &MetaMcp) -> Vec<String> {
    meta.capabilities
        .read()
        .clone()
        .expect("VOID: the capability backend is installed")
        .rug_pull_records()
        .into_iter()
        .map(|record| record.file)
        .collect()
}

/// PIN.1a / PIN.2a / PIN.3: on the background-scan branch, the change is
/// recorded by the time the scan reports complete (readiness waits on it),
/// and the decision set lists it with no history.
/// Mutants: the HTTP startup detection dropped: no record, no item; moved
/// after `finish_initial_scan`: no record at readiness.
#[cfg(feature = "webui")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_capability_changed_while_down_reaches_the_decisions_after_http_startup() {
    use crate::discovery::config_scanner::ConfigScanner;
    use crate::discovery::config_scanner::client_scan::{ClientScan, Fingerprint};
    use crate::discovery::listing::ScanSource;
    use futures::future::BoxFuture;
    use serde_json::{Value, json};

    /// No client config files: the decision set's discovery source is empty.
    struct NoClients;

    impl ScanSource for NoClients {
        fn fingerprint(&self) -> Fingerprint {
            ConfigScanner::fingerprint(&[])
        }
        fn scan(&self) -> BoxFuture<'_, ClientScan> {
            Box::pin(async {
                ClientScan {
                    finds: Vec::new(),
                    fingerprint: ConfigScanner::fingerprint(&[]),
                    unreadable: Vec::new(),
                }
            })
        }
        fn now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }
    }

    let dir = tempfile::tempdir().expect("VOID: a temp dir");
    let changed = changed_while_down(dir.path());
    let steady = "name: steady_tool\ndescription: Pinned and unchanged\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.fixture.test\n      path: /v2\n";
    std::fs::write(
        dir.path().join("steady.yaml"),
        rewrite_with_pin(steady, &compute_capability_hash(steady)),
    )
    .expect("VOID: write the neighbour");
    let started = Box::pin(http_startup(&[dir.path()], |_| {})).await;
    let (meta, shutdown) = (&started.meta, &started.shutdown);
    let backend = meta.capabilities.read().clone().expect("VOID: installed");
    eventually("the startup scan completes", || {
        backend.initial_scan_complete()
    })
    .await;
    // Snapshotted inside `mark_initial_scan_complete`, before the flag is
    // visible: deterministic whatever the check's timing.
    assert_eq!(
        backend.records_at_scan_complete.get(),
        Some(&1),
        "recorded before the scan was marked complete"
    );
    assert_eq!(
        recorded(meta),
        vec![changed],
        "only the changed file is recorded"
    );
    assert!(
        backend.has_capability("steady_tool"),
        "the pinned neighbour is served"
    );
    assert!(
        !backend.has_capability("changed_tool"),
        "the changed file is not"
    );

    let _set = crate::gateway::ui::decisions::start_with_source(
        meta,
        None,
        shutdown.subscribe(),
        Arc::new(NoClients),
    );
    let item = |meta: &MetaMcp| -> Option<Value> {
        meta.decisions()?
            .view()
            .ok()?
            .decisions
            .into_iter()
            .find(|item| item["kind"] == json!("capability_changed"))
    };
    eventually("a capability_changed item", || item(meta).is_some()).await;
    let item = item(meta).expect("VOID: seen above");
    assert_eq!(
        item["trusted_name"],
        json!(false),
        "never loaded here: {item}"
    );
    assert_eq!(item["before"], Value::Null, "{item}");
    assert_eq!(item["before_reason"], json!("no_history"), "{item}");
}

/// A configured directory that fails to load still completes the scan, so
/// a later edit in another directory reloads (the watcher gate never holds
/// reloads forever on a failed scan).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_with_a_failed_directory_still_lets_a_later_edit_reload() {
    use std::os::unix::fs::PermissionsExt as _;
    let failing = tempfile::tempdir().expect("VOID: a temp dir");
    let locked = failing.path().join("locked");
    std::fs::create_dir(&locked).expect("VOID: a subdirectory");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("VOID: lock it");
    let good = tempfile::tempdir().expect("VOID: a temp dir");
    let yaml = |desc: &str| {
        format!(
            "name: a\ndescription: {desc}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.invalid\n      path: /k\n"
        )
    };
    std::fs::write(good.path().join("a.yaml"), yaml("v1")).expect("VOID: write v1");
    let started = Box::pin(http_startup(&[failing.path(), good.path()], |_| {})).await;
    let meta = &started.meta;
    let backend = meta.capabilities.read().clone().expect("VOID: installed");
    eventually("the startup scan completes", || {
        backend.initial_scan_complete()
    })
    .await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
        .expect("VOID: unlock it");
    assert!(
        !backend.initial_scan_loaded_every_directory(),
        "premise: a directory failed to load"
    );
    std::fs::write(good.path().join("a.yaml"), yaml("v2-much-longer")).expect("VOID: write v2");
    let description = || {
        backend
            .list_capabilities()
            .into_iter()
            .find(|cap| cap.name == "a")
            .map(|cap| cap.description)
    };
    eventually("the edit reloads", || {
        description().as_deref() == Some("v2-much-longer")
    })
    .await;
}

/// A startup scan that panics part way is still completed, marked partial,
/// by its exit guard, so a later edit reloads and readiness does not wait
/// forever. The panic is armed through the gateway's test seam before the
/// scan is spawned.
/// Mutant: the exit guard removed: the scan never completes, no reload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_startup_scan_that_panics_is_completed_and_a_later_edit_reloads() {
    let first = tempfile::tempdir().expect("VOID: a temp dir");
    let second = tempfile::tempdir().expect("VOID: a temp dir");
    let yaml = |desc: &str| {
        format!(
            "name: a\ndescription: {desc}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.invalid\n      path: /k\n"
        )
    };
    std::fs::write(first.path().join("a.yaml"), yaml("v1")).expect("VOID: write v1");
    // Set before the scan is spawned, through the gateway's test seam: no
    // race with the scan's settle. The feed hears the catalogue nudge the
    // exit guard sends as it completes the scan.
    let (feed, mut nudges) = tokio::sync::mpsc::unbounded_channel();
    let started = Box::pin(http_startup(&[first.path(), second.path()], |gateway| {
        gateway
            .test_seams
            .capability_scan_panics
            .store(true, std::sync::atomic::Ordering::Release);
        gateway.backends.set_change_feed(feed);
    }))
    .await;
    let meta = &started.meta;
    let backend = meta.capabilities.read().clone().expect("VOID: installed");
    eventually("the panicked scan is completed", || {
        backend.initial_scan_complete()
    })
    .await;
    assert!(
        !backend.initial_scan_loaded_every_directory(),
        "a scan that did not finish is marked partial"
    );
    // `finish_initial_scan` marks the scan complete, then nudges: wait for it.
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(nudge) = nudges.recv().await {
            if matches!(
                nudge,
                crate::backend::tools_nudge::ToolsNudge::Catalogue { .. }
            ) {
                return;
            }
        }
        panic!("the change feed closed with no catalogue nudge");
    })
    .await
    .expect("the guard announced the catalogue it completed");
    std::fs::write(first.path().join("a.yaml"), yaml("v2-much-longer")).expect("VOID: write v2");
    let description = || {
        backend
            .list_capabilities()
            .into_iter()
            .find(|cap| cap.name == "a")
            .map(|cap| cap.description)
    };
    eventually("the edit reloads", || {
        description().as_deref() == Some("v2-much-longer")
    })
    .await;
}
