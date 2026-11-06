// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's `owner` is display only: a reload that changes only the owner
//! publishes it at once and leaves the running backend in place; any other
//! change still replaces the backend, as before.

use std::sync::Arc;
use std::time::Duration;

use super::{LiveConfig, ReloadContext, compute_diff};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, Config, TransportConfig};

const URL: &str = "http://127.0.0.1:9/mcp";

/// A gateway file with the backends in `entries` (YAML, already indented
/// under `backends:`).
fn file(entries: &str) -> String {
    format!("backends:\n{entries}")
}

fn svc(extra: &str) -> String {
    format!("  svc:\n    http_url: \"{URL}\"\n{extra}")
}

struct Gateway {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    live: Arc<LiveConfig>,
    registry: Arc<BackendRegistry>,
    ctx: ReloadContext,
}

impl Gateway {
    /// A gateway started empty, then reloaded to `first`.
    async fn reloaded_to(first: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        crate::gateway::test_helpers::write_owner_only(&path, first).expect("write");
        let registry = Arc::new(BackendRegistry::new());
        let live = Arc::new(LiveConfig::new(Config::default()));
        let ctx = ReloadContext::new(
            path.clone(),
            Arc::clone(&live),
            Arc::clone(&registry),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config");
        ctx.reload_outcome().await.expect("the first file applies");
        Self {
            _dir: dir,
            path,
            live,
            registry,
            ctx,
        }
    }

    async fn reload(&self, next: &str) {
        crate::gateway::test_helpers::write_owner_only(&self.path, next).expect("write");
        self.ctx.reload_outcome().await.expect("the file applies");
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "Test: identity of the registered backend before and after a reload"
    )]
    fn backend(&self, name: &str) -> Arc<Backend> {
        self.registry.get(name).expect("registered")
    }

    fn published_owner(&self, name: &str) -> Option<String> {
        self.live.generation().config().backends[name]
            .owner()
            .map(str::to_owned)
    }
}

/// O6, O6c: an owner added, replaced and removed by reloads is published at
/// once each time, and the same backend instance keeps serving.
#[tokio::test]
async fn o6_an_owner_only_reload_publishes_and_keeps_the_backend() {
    let gw = Gateway::reloaded_to(&file(&svc(""))).await;
    let first = gw.backend("svc");
    for (owner_line, expected) in [
        ("    owner: \"Team A\"\n", Some("Team A")),
        ("    owner: \"Team B\"\n", Some("Team B")),
        ("", None),
    ] {
        gw.reload(&file(&svc(owner_line))).await;
        assert_eq!(
            gw.published_owner("svc").as_deref(),
            expected,
            "{owner_line:?}"
        );
        assert!(
            Arc::ptr_eq(&first, &gw.backend("svc")),
            "an owner-only reload replaced the backend: {owner_line:?}"
        );
    }
}

/// O6b: an owner change together with another field still replaces the
/// backend.
#[tokio::test]
async fn o6b_an_owner_with_another_change_replaces_the_backend() {
    let gw = Gateway::reloaded_to(&file(&svc(""))).await;
    let first = gw.backend("svc");
    gw.reload(&file(&svc("    owner: \"Team A\"\n    timeout: 30s\n")))
        .await;
    assert!(
        !Arc::ptr_eq(&first, &gw.backend("svc")),
        "the timeout change was masked"
    );
    assert_eq!(gw.published_owner("svc").as_deref(), Some("Team A"));
}

/// O6d: a disabled backend's owner-only edit changes nothing the gateway
/// runs, so nothing is published; the next published change carries it.
#[tokio::test]
async fn o6d_a_disabled_backends_owner_waits_for_the_next_publish() {
    let off = |owner: &str| {
        format!("  off:\n    http_url: \"{URL}\"\n    enabled: false\n    owner: \"{owner}\"\n")
    };
    let gw = Gateway::reloaded_to(&file(&format!("{}{}", svc(""), off("Old")))).await;
    gw.reload(&file(&format!("{}{}", svc(""), off("New"))))
        .await;
    assert_eq!(gw.published_owner("off").as_deref(), Some("Old"));
    gw.reload(&file(&format!(
        "{}{}",
        svc("    timeout: 30s\n"),
        off("New")
    )))
    .await;
    assert_eq!(gw.published_owner("off").as_deref(), Some("New"));
}

/// O6e: an owner edit beside a runtime profile change still replaces the
/// backend that references the profile.
#[test]
fn o6e_a_runtime_profile_change_still_replaces_the_backend() {
    let mut old = Config::default();
    old.runtime.profiles.insert(
        "safe".to_string(),
        crate::config::RuntimeProfileConfig::default(),
    );
    old.backends.insert(
        "docs".to_string(),
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "node server.js".to_string(),
                cwd: None,
                protocol_version: None,
            },
            runtime_profile: Some("safe".to_string()),
            ..BackendConfig::default()
        },
    );
    let mut new = old.clone();
    new.runtime.profiles.insert(
        "safe".to_string(),
        crate::config::RuntimeProfileConfig {
            privileged: true,
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    new.backends.get_mut("docs").expect("docs").owner = Some("Team A".to_string());
    let patch = compute_diff(&old, &new);
    assert_eq!(
        patch
            .backends_modified
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>(),
        ["docs"]
    );
}
