// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8054`: the warm-start owner keeps one warmer per backend, follows the
//! published selection, stops the warmer of a removed or replaced backend,
//! admits nothing once sealed, and never acts on a newer instance.

use std::sync::Arc;
use std::time::Duration;

use super::{WarmStartMode, WarmerGuard};
use crate::backend::{Backend, BackendRegistry};
use crate::config::Config;
use crate::config_reload::RegisteredChange;

/// Refused at once (port 1 on loopback), so its warmer keeps retrying.
fn unreachable(name: &str) -> Arc<Backend> {
    let cfg = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:1/mcp".to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    };
    Arc::new(Backend::new(
        name,
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn registry(names: &[&str]) -> Arc<BackendRegistry> {
    let registry = Arc::new(BackendRegistry::new());
    for name in names {
        assert!(registry.register(unreachable(name)));
    }
    registry
}

fn change(registered: &[&str], removed: &[&str]) -> RegisteredChange {
    let owned = |names: &[&str]| names.iter().map(ToString::to_string).collect();
    RegisteredChange {
        registered: owned(registered),
        removed: owned(removed),
    }
}

fn selecting(names: &[&str]) -> Config {
    let mut config = Config::default();
    config.meta_mcp.warm_start = names.iter().map(ToString::to_string).collect();
    config
}

async fn finishes(task: &tokio::task::AbortHandle, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if task.is_finished() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn the_published_selection_decides_which_registered_backends_warm() {
    let backends = registry(&["a", "b"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    let both = change(&["a", "b"], &[]);
    assert_eq!(guard.0.apply(&both, &selecting(&["a"])), ["a"]);
    assert_eq!(guard.abort_handles().len(), 1);
    // An empty list selects every backend, as at boot.
    assert_eq!(guard.0.apply(&both, &selecting(&[])), ["a", "b"]);
}

#[tokio::test]
async fn a_second_replacement_leaves_one_warmer() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    assert_eq!(guard.warm(vec!["a".to_string()]), ["a"]);
    let first = guard.abort_handles().remove(0);
    guard.0.apply(&change(&["a"], &[]), &selecting(&[]));
    guard.0.apply(&change(&["a"], &[]), &selecting(&[]));
    assert_eq!(guard.abort_handles().len(), 1, "one warmer per backend");
    assert!(
        finishes(&first, 5).await,
        "the replaced warmer was not stopped"
    );
}

#[tokio::test]
async fn a_removed_backend_stops_its_warmer() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    guard.warm(vec!["a".to_string()]);
    let task = guard.abort_handles().remove(0);
    guard.0.apply(&change(&[], &["a"]), &selecting(&[]));
    assert!(guard.abort_handles().is_empty());
    assert!(
        finishes(&task, 5).await,
        "a removed backend kept its warmer"
    );
}

#[tokio::test]
async fn an_excluded_replacement_gets_no_warmer() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    guard.warm(vec!["a".to_string()]);
    let old = guard.abort_handles().remove(0);
    let scheduled = guard.0.apply(&change(&["a"], &[]), &selecting(&["other"]));
    assert!(scheduled.is_empty(), "{scheduled:?}");
    assert!(guard.abort_handles().is_empty());
    assert!(
        finishes(&old, 5).await,
        "the old warmer kept warming the replacement"
    );
}

#[tokio::test]
async fn nothing_is_admitted_after_cancel() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    let warmer = Arc::clone(&guard.0);
    guard.cancel().await;
    assert!(
        warmer
            .apply(&change(&["a"], &[]), &selecting(&[]))
            .is_empty()
    );
    assert!(warmer.lock().tasks.is_empty());
}

#[tokio::test]
async fn dropping_the_guard_cancels_warmers_while_a_hook_lives() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    let hook = guard.hook();
    guard.warm(vec!["a".to_string()]);
    let task = guard.abort_handles().remove(0);
    drop(guard);
    assert!(
        finishes(&task, 5).await,
        "a live hook kept the warmer running"
    );
    // The hook outlives the warmer and does nothing.
    hook(&change(&["a"], &[]), &selecting(&[]));
}

#[tokio::test]
async fn a_warmer_never_touches_a_newer_instance() {
    let backends = registry(&["a"]);
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    guard.warm(vec!["a".to_string()]);
    let task = guard.abort_handles().remove(0);
    // A newer instance under the same name, with no warmer of its own: the
    // old warmer must stop at its next attempt instead of warming it.
    assert!(backends.register(unreachable("a")));
    assert!(
        finishes(&task, 10).await,
        "the old warmer kept retrying against a newer instance"
    );
}

/// A warmer that fills a backend's cache announces it, so a client that
/// relisted on the registration (before the cache was filled) hears again once
/// the tools are there. Registration alone announces too early.
#[tokio::test]
async fn a_filled_cache_is_announced() {
    let backends = Arc::new(BackendRegistry::new());
    let (feed, mut heard) = tokio::sync::mpsc::unbounded_channel();
    backends.set_change_feed(feed);
    let url = super::hot_reload_tests::mock("announced_tool").await;
    let cfg = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: url,
            streamable_http: Some(false),
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    };
    assert!(backends.register(Arc::new(Backend::new(
        "a",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    assert_eq!(heard.recv().await.as_deref(), Some("a"), "registration");
    let guard = WarmerGuard::new(&backends, WarmStartMode::Http, None);
    guard.warm(vec!["a".to_string()]);
    let again = tokio::time::timeout(Duration::from_secs(10), heard.recv()).await;
    assert_eq!(
        again.ok().flatten().as_deref(),
        Some("a"),
        "the filled cache was never announced"
    );
    let cached = backends.get("a").unwrap().get_cached_tools_snapshot();
    assert!(cached.iter().any(|t| t.name == "announced_tool"));
}
