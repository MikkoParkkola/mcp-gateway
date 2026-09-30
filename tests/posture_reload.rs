// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.posture` is restart-only: a reload that changes it is refused
//! before any live state is published.

use std::path::PathBuf;
use std::sync::Arc;
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
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.yaml");
        let fixture_path = path.clone();
        let evaluated = {
            write(&path, &document(posture, "before"));
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
