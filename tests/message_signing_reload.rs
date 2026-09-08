// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.2: restart-only signing changes cannot publish partial live state.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{Config, LiveEnv};
use mcp_gateway::config_reload::{LiveConfig, ReloadContext, compute_diff};
use serde_json::{Value, json};

const CURRENT: &str = "reload-current-secret-sentinel-0123456789abcdef";
const PREVIOUS: &str = "reload-previous-secret-sentinel-0123456789abcdef";
const ROTATED: &str = "reload-rotated-secret-sentinel-0123456789abcdef";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    env_path: PathBuf,
    document: Value,
    current_name: String,
    previous_name: String,
    alias_name: String,
    previous_alias_name: String,
    live_name: String,
    context: ReloadContext,
}

impl Fixture {
    fn new(enabled: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let suffix: String = directory
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let current_name = format!("SIGNING_RELOAD_CURRENT_{suffix}");
        let previous_name = format!("SIGNING_RELOAD_PREVIOUS_{suffix}");
        let alias_name = format!("SIGNING_RELOAD_ALIAS_{suffix}");
        let previous_alias_name = format!("SIGNING_RELOAD_PREVIOUS_ALIAS_{suffix}");
        let live_name = format!("SIGNING_RELOAD_LIVE_{suffix}");
        for name in [
            &current_name,
            &previous_name,
            &alias_name,
            &previous_alias_name,
            &live_name,
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "fixture names are isolated"
            );
        }
        let env_path = directory.path().join("signing.env");
        std::fs::write(&env_path, format!(
            "{current_name}='{CURRENT}'\n{previous_name}='{PREVIOUS}'\n{alias_name}='{CURRENT}'\n{previous_alias_name}='{PREVIOUS}'\n{live_name}=before\n"
        )).unwrap();
        let path = directory.path().join("gateway.yaml");
        let document = json!({
            "env_files":[env_path],
            "backends":{
                "keep":{"command":"echo keep", "enabled":true, "description":"before"},
                "remove":{"command":"echo remove", "enabled":true}
            },
            "security":{"message_signing":{
                "enabled":enabled,"shared_secret":format!("env:{current_name}"),
                "previous_secret":format!("${{{previous_name}}}"),
                "key_id":"reload-current", "require_nonce":true, "replay_window":300
            }}
        });
        std::fs::write(&path, serde_yaml::to_string(&document).unwrap()).unwrap();
        let evaluated = Config::load_evaluated(Some(&path)).expect("valid startup fixture");
        if enabled {
            assert_eq!(
                evaluated.config.security.message_signing.shared_secret,
                CURRENT
            );
            assert_eq!(
                evaluated.config.security.message_signing.previous_secret,
                PREVIOUS
            );
        }
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
            path.clone(),
            live,
            registry,
            evaluated.config.failsafe,
            Duration::from_secs(60),
        )
        .with_env(env);
        Self {
            _directory: directory,
            path,
            env_path,
            document,
            current_name,
            previous_name,
            alias_name,
            previous_alias_name,
            live_name,
            context,
        }
    }

    fn write_candidate(&self, document: &Value) {
        std::fs::write(&self.path, serde_yaml::to_string(document).unwrap()).unwrap();
    }

    fn rotate_env(&self, current: &str, previous: &str) {
        std::fs::write(
            &self.env_path,
            format!(
                "{}='{current}'\n{}='{previous}'\n{}='{CURRENT}'\n{}='{PREVIOUS}'\n{}=after\n",
                self.current_name,
                self.previous_name,
                self.alias_name,
                self.previous_alias_name,
                self.live_name
            ),
        )
        .unwrap();
    }

    fn with_backend_changes(&self) -> Value {
        let mut candidate = self.document.clone();
        candidate["backends"]["keep"]["description"] = json!("after");
        candidate["backends"]
            .as_object_mut()
            .unwrap()
            .remove("remove");
        candidate["backends"]["added"] = json!({"command":"echo added", "enabled":true});
        candidate
    }

    async fn assert_refused_unchanged(&self, field: &str) {
        let config = self.context.live_config.get();
        let overlay = self.context.live_env().get();
        let keep = self.context.registry.get("keep").unwrap();
        let remove = self.context.registry.get("remove").unwrap();
        let disk = std::fs::read(&self.path).unwrap();
        let env_disk = std::fs::read(&self.env_path).unwrap();
        // A parse/config error cannot supply the expected behavioral refusal.
        let candidate = Config::load_evaluated(Some(&self.path)).expect("valid candidate control");
        candidate
            .config
            .validate_with_env(&candidate.overlay)
            .unwrap();
        for _ in 0..2 {
            let error =
                self.context.reload_outcome().await.expect_err(
                    "SIGNING.2 signing changes must refuse before publishing any state",
                );
            assert_eq!(
                error,
                format!("config reload refused: security.message_signing.{field} requires restart")
            );
            for secret in [
                CURRENT,
                PREVIOUS,
                ROTATED,
                self.current_name.as_str(),
                self.previous_name.as_str(),
                self.alias_name.as_str(),
            ] {
                assert!(!error.contains(secret), "field-only diagnostics");
            }
            assert!(
                Arc::ptr_eq(&config, &self.context.live_config.get()),
                "live config was published"
            );
            assert!(
                Arc::ptr_eq(&overlay, &self.context.live_env().get()),
                "environment was published"
            );
            assert_eq!(self.context.registry.all().len(), 2);
            assert!(
                Arc::ptr_eq(&keep, &self.context.registry.get("keep").unwrap()),
                "backend replaced"
            );
            assert!(
                Arc::ptr_eq(&remove, &self.context.registry.get("remove").unwrap()),
                "backend removed"
            );
            assert!(
                self.context.registry.get("added").is_none(),
                "backend added"
            );
            assert_eq!(
                std::fs::read(&self.path).unwrap(),
                disk,
                "refusal cannot rewrite the candidate"
            );
            assert_eq!(std::fs::read(&self.env_path).unwrap(), env_disk);
        }
        assert_eq!(
            self.context
                .live_env()
                .get()
                .resolve(&self.live_name)
                .as_deref(),
            Some("before")
        );
    }
}

macro_rules! signing_setting_refusal {
    ($name:ident, $enabled:expr, $field:literal, $value:expr) => {
        #[tokio::test]
        async fn $name() {
            let fixture = Fixture::new($enabled);
            let mut candidate = fixture.with_backend_changes();
            candidate["security"]["message_signing"][$field] = json!($value);
            fixture.write_candidate(&candidate);
            fixture.rotate_env(CURRENT, PREVIOUS);
            fixture.assert_refused_unchanged($field).await;
        }
    };
}

signing_setting_refusal!(signing_reload_enabled_to_disabled, true, "enabled", false);
signing_setting_refusal!(signing_reload_disabled_to_enabled, false, "enabled", true);
signing_setting_refusal!(
    signing_reload_current_literal_edit,
    true,
    "shared_secret",
    ROTATED
);
signing_setting_refusal!(
    signing_reload_previous_literal_edit,
    true,
    "previous_secret",
    ROTATED
);
signing_setting_refusal!(
    signing_reload_key_id_edit,
    true,
    "key_id",
    "different-key-id"
);
signing_setting_refusal!(
    signing_reload_required_nonce_edit,
    true,
    "require_nonce",
    false
);
signing_setting_refusal!(signing_reload_window_edit, true, "replay_window", 301);

#[tokio::test]
async fn signing_reload_current_env_rotation() {
    let fixture = Fixture::new(true);
    fixture.rotate_env(ROTATED, PREVIOUS);
    fixture.assert_refused_unchanged("shared_secret").await;
}

#[tokio::test]
async fn signing_reload_previous_env_rotation() {
    let fixture = Fixture::new(true);
    fixture.rotate_env(CURRENT, ROTATED);
    fixture.assert_refused_unchanged("previous_secret").await;
}

#[tokio::test]
async fn signing_reload_equivalent_reference_edit_precedes_empty_patch() {
    let fixture = Fixture::new(true);
    let mut candidate = fixture.document.clone();
    candidate["security"]["message_signing"]["shared_secret"] =
        json!(format!("env:{}", fixture.alias_name));
    fixture.write_candidate(&candidate);
    fixture.rotate_env(CURRENT, PREVIOUS);
    let evaluated = Config::load_evaluated(Some(&fixture.path)).unwrap();
    assert_eq!(
        evaluated.config.security.message_signing.shared_secret,
        CURRENT
    );
    assert!(
        compute_diff(&fixture.context.live_config.get(), &evaluated.config).is_empty(),
        "effective values are equal: the configured reference must close the empty-patch path"
    );
    fixture.assert_refused_unchanged("shared_secret").await;
}

#[tokio::test]
async fn signing_reload_previous_equivalent_reference_edit_precedes_empty_patch() {
    let fixture = Fixture::new(true);
    let mut candidate = fixture.document.clone();
    candidate["security"]["message_signing"]["previous_secret"] =
        json!(format!("${{{}}}", fixture.previous_alias_name));
    fixture.write_candidate(&candidate);
    assert_eq!(
        fixture
            .context
            .live_env()
            .startup()
            .resolve(&fixture.previous_alias_name)
            .as_deref(),
        Some(PREVIOUS)
    );
    let evaluated = Config::load_evaluated(Some(&fixture.path)).unwrap();
    assert_eq!(
        evaluated.config.security.message_signing.previous_secret,
        PREVIOUS
    );
    assert!(
        compute_diff(&fixture.context.live_config.get(), &evaluated.config).is_empty(),
        "equal previous-key bytes must not hide a configured-reference edit"
    );
    fixture.assert_refused_unchanged("previous_secret").await;
}

#[tokio::test]
async fn signing_reload_same_key_reference_to_literal_is_a_configured_change() {
    let fixture = Fixture::new(true);
    let mut candidate = fixture.document.clone();
    candidate["security"]["message_signing"]["shared_secret"] = json!(CURRENT);
    fixture.write_candidate(&candidate);
    fixture.assert_refused_unchanged("shared_secret").await;
}

#[tokio::test]
async fn signing_reload_unchanged_signing_allows_backend_and_env_updates() {
    let fixture = Fixture::new(true);
    let keep = fixture.context.registry.get("keep").unwrap();
    fixture.write_candidate(&fixture.with_backend_changes());
    fixture.rotate_env(CURRENT, PREVIOUS);
    let outcome = fixture
        .context
        .reload_outcome()
        .await
        .expect("unrelated reload must work");
    assert!(outcome.changes.contains("added backends"));
    assert!(!Arc::ptr_eq(
        &keep,
        &fixture.context.registry.get("keep").unwrap()
    ));
    assert!(fixture.context.registry.get("remove").is_none());
    assert!(fixture.context.registry.get("added").is_some());
    assert_eq!(
        fixture.context.live_config.get().backends["keep"].description,
        "after"
    );
    assert_eq!(
        fixture
            .context
            .live_env()
            .get()
            .resolve(&fixture.live_name)
            .as_deref(),
        Some("after")
    );
}

#[tokio::test]
async fn signing_reload_unchanged_signing_allows_empty_patch_env_updates() {
    let fixture = Fixture::new(true);
    let keep = fixture.context.registry.get("keep").unwrap();
    fixture.rotate_env(CURRENT, PREVIOUS);
    let outcome = fixture
        .context
        .reload_outcome()
        .await
        .expect("same signing bytes must work");
    assert!(outcome.changes.starts_with("no changes detected"));
    assert!(Arc::ptr_eq(
        &keep,
        &fixture.context.registry.get("keep").unwrap()
    ));
    assert_eq!(
        fixture
            .context
            .live_env()
            .get()
            .resolve(&fixture.live_name)
            .as_deref(),
        Some("after")
    );
}

#[tokio::test]
async fn signing_reload_disabled_unchanged_references_ignore_dormant_rotation() {
    let fixture = Fixture::new(false);
    fixture.rotate_env("short dormant value", "also dormant");
    let outcome = fixture
        .context
        .reload_outcome()
        .await
        .expect("disabled keys stay dormant");
    assert!(outcome.changes.starts_with("no changes detected"));
    assert_eq!(
        fixture
            .context
            .live_env()
            .get()
            .resolve(&fixture.current_name)
            .as_deref(),
        Some("short dormant value")
    );
}
