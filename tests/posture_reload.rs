// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.posture` is restart-only: a reload that changes it is refused
//! before any live state is published.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{Config, LiveEnv};
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use serde_json::{Value, json};

const REFUSAL: &str = "config reload refused: security.posture requires restart";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    context: ReloadContext,
}

fn document(posture: &str, description: &str) -> Value {
    json!({
        "backends": {"keep": {"command": "echo keep", "enabled": true, "description": description}},
        "security": {"posture": posture}
    })
}

impl Fixture {
    fn new(posture: &str) -> Self {
        Self::from(&document(posture, "before"))
    }

    /// Register every backend in `start` on a caller-built registry, then hand
    /// that registry to a reload context, as an embedder would.
    fn from(start: &Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.yaml");
        let fixture_path = path.clone();
        let evaluated = {
            write(&path, start);
            Config::load_evaluated(Some(&path)).expect("valid startup fixture")
        };
        let registry = Arc::new(BackendRegistry::new());
        for (name, config) in &evaluated.config.backends {
            assert!(registry.register(Arc::new(Backend::new(
                name,
                config.clone(),
                &evaluated.config.failsafe,
                Duration::from_secs(60)
            ))));
        }
        let live = Arc::new(LiveConfig::new(evaluated.config.clone()));
        let env = Arc::new(LiveEnv::new(evaluated.overlay, evaluated.env_paths));
        let context = ReloadContext::new(
            path,
            live,
            registry,
            evaluated.config.failsafe,
            Duration::from_secs(60),
        )
        .with_env(env);
        Self {
            _directory: directory,
            path: fixture_path,
            context,
        }
    }
}

fn write(path: &std::path::Path, document: &Value) {
    mcp_gateway::gateway::test_helpers::write_owner_only(
        path,
        serde_yaml::to_string(document).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn reload_refuses_posture_change() {
    for (from, to) in [("standard", "hardened"), ("hardened", "standard")] {
        for description in ["before", "after"] {
            let fixture = Fixture::new(from);
            write(&fixture.path, &document(to, description));
            // A parse error cannot supply the expected refusal.
            Config::load_evaluated(Some(&fixture.path)).expect("valid candidate");
            let config = fixture.context.live_config.get();
            let overlay = fixture.context.live_env().get();
            let keep = fixture.context.registry.get("keep").unwrap();
            for _ in 0..2 {
                let error = fixture
                    .context
                    .reload_outcome()
                    .await
                    .expect_err("a posture change must be refused");
                assert_eq!(error, REFUSAL, "{from} -> {to}, {description}");
                assert!(Arc::ptr_eq(&config, &fixture.context.live_config.get()));
                assert!(Arc::ptr_eq(&overlay, &fixture.context.live_env().get()));
                let now = fixture.context.registry.get("keep").unwrap();
                assert!(Arc::ptr_eq(&keep, &now), "{from} -> {to}: backend replaced");
            }
        }
    }
}

#[tokio::test]
async fn reload_keeps_hardened_when_posture_is_unchanged() {
    let fixture = Fixture::new("hardened");
    write(&fixture.path, &document("hardened", "after"));
    fixture
        .context
        .reload_outcome()
        .await
        .expect("control: a benign edit under an unchanged posture reloads");
    assert_eq!(
        fixture.context.live_config.get().backends["keep"].description,
        "after"
    );
    let ci = &fixture.context.live_config.get().security.context_integrity;
    assert!(ci.non_bypassable, "the reloaded config keeps the floor");
    assert_eq!(
        ci.preset,
        mcp_gateway::config::ContextIntegrityPresetConfig::TeamShared
    );
}

// ── The destination policy reaches a caller-built registry (HARDEN 4b) ─────

/// A loopback listener that counts connections and drops each at once.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

fn local(port: u16) -> Value {
    json!({"http_url": format!("http://localhost:{port}/mcp"), "enabled": true, "timeout": "2s"})
}

fn with_backends(posture: &str, backends: Value) -> Value {
    json!({"backends": backends, "security": {"posture": posture}})
}

async fn assert_refused(fixture: &Fixture, name: &str, accepted: &AtomicUsize) {
    let backend = fixture.context.registry.get(name).expect(name);
    let error = backend.ensure_started().await.expect_err(name).to_string();
    assert!(error.contains("SSRF blocked"), "{name}: {error}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "{name}: nothing may connect"
    );
}

#[tokio::test]
async fn reload_context_enforces_hardened_on_caller_registry() {
    let (port, accepted) = counting_listener().await;
    let fixture = Fixture::from(&with_backends("hardened", json!({"local": local(port)})));
    assert_refused(&fixture, "local", &accepted).await;

    // Control: the same backend under standard reaches the listener.
    let (port, accepted) = counting_listener().await;
    let fixture = Fixture::from(&with_backends("standard", json!({"local": local(port)})));
    let backend = fixture.context.registry.get("local").unwrap();
    let _ = backend.ensure_started().await;
    assert!(accepted.load(Ordering::SeqCst) > 0, "standard connects");
}

#[tokio::test]
async fn reload_backend_is_pinned() {
    let (port, accepted) = counting_listener().await;
    let fixture = Fixture::new("hardened");
    write(
        &fixture.path,
        &with_backends(
            "hardened",
            json!({"keep": local(port), "added": local(port)}),
        ),
    );
    fixture
        .context
        .reload_outcome()
        .await
        .expect("adding and modifying backends reloads");
    assert_refused(&fixture, "added", &accepted).await;
    assert_refused(&fixture, "keep", &accepted).await;
}
