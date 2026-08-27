// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::collections::HashMap;

use super::*;
use crate::config::{BackendConfig, Config, ServerConfig, TransportConfig};
use notify::event::EventAttributes;

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn http_backend(url: &str) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        enabled: true,
        ..BackendConfig::default()
    }
}

fn disabled_backend(url: &str) -> BackendConfig {
    BackendConfig {
        enabled: false,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        ..BackendConfig::default()
    }
}

fn config_with_backends(backends: HashMap<String, BackendConfig>) -> Config {
    Config {
        backends,
        ..Config::default()
    }
}

// -------------------------------------------------------------------------
// compute_diff: no-op cases
// -------------------------------------------------------------------------

#[test]
fn diff_identical_configs_returns_empty_patch() {
    // GIVEN: two identical default configs
    let old = Config::default();
    let new = Config::default();
    // WHEN: diff is computed
    let patch = compute_diff(&old, &new);
    // THEN: patch is empty
    assert!(
        patch.is_empty(),
        "expected empty patch, got: {}",
        patch.summary()
    );
}

#[test]
fn diff_same_backends_returns_empty_patch() {
    // GIVEN: two configs with identical backends
    let mut backends = HashMap::new();
    backends.insert(
        "alpha".to_string(),
        http_backend("http://localhost:8001/mcp"),
    );
    let old = config_with_backends(backends.clone());
    let new = config_with_backends(backends);
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert!(patch.is_empty());
}

// -------------------------------------------------------------------------
// compute_diff: additions
// -------------------------------------------------------------------------

#[test]
fn diff_detects_added_backend() {
    // GIVEN: old has no backends, new has one
    let old = Config::default();
    let mut backends = HashMap::new();
    backends.insert(
        "new-svc".to_string(),
        http_backend("http://localhost:9000/mcp"),
    );
    let new = config_with_backends(backends);
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert_eq!(patch.backends_added.len(), 1);
    assert_eq!(patch.backends_added[0].0, "new-svc");
    assert!(patch.backends_removed.is_empty());
    assert!(patch.backends_modified.is_empty());
}

#[test]
fn diff_disabled_backend_not_treated_as_added() {
    // GIVEN: old has no backends, new has one but it is disabled
    let old = Config::default();
    let mut backends = HashMap::new();
    backends.insert(
        "ghost".to_string(),
        disabled_backend("http://localhost:9001/mcp"),
    );
    let new = config_with_backends(backends);
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN: disabled backends are invisible to the diff
    assert!(patch.backends_added.is_empty());
}

// -------------------------------------------------------------------------
// compute_diff: removals
// -------------------------------------------------------------------------

#[test]
fn diff_detects_removed_backend() {
    // GIVEN: old has a backend, new has none
    let mut backends = HashMap::new();
    backends.insert(
        "legacy".to_string(),
        http_backend("http://localhost:8002/mcp"),
    );
    let old = config_with_backends(backends);
    let new = Config::default();
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert_eq!(patch.backends_removed.len(), 1);
    assert_eq!(patch.backends_removed[0], "legacy");
    assert!(patch.backends_added.is_empty());
    assert!(patch.backends_modified.is_empty());
}

#[test]
fn diff_backend_disabled_counts_as_removed() {
    // GIVEN: old has enabled backend, new has same backend but disabled
    let mut old_backends = HashMap::new();
    old_backends.insert("svc".to_string(), http_backend("http://localhost:8003/mcp"));
    let old = config_with_backends(old_backends);

    let mut new_backends = HashMap::new();
    new_backends.insert(
        "svc".to_string(),
        disabled_backend("http://localhost:8003/mcp"),
    );
    let new = config_with_backends(new_backends);
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN: disabling is treated as removal
    assert_eq!(patch.backends_removed.len(), 1);
    assert_eq!(patch.backends_removed[0], "svc");
    assert!(patch.backends_added.is_empty());
}

// -------------------------------------------------------------------------
// compute_diff: modifications
// -------------------------------------------------------------------------

#[test]
fn diff_detects_modified_backend_url() {
    // GIVEN: same name, different URL
    let mut old_backends = HashMap::new();
    old_backends.insert("api".to_string(), http_backend("http://localhost:8080/mcp"));
    let old = config_with_backends(old_backends);

    let mut new_backends = HashMap::new();
    new_backends.insert("api".to_string(), http_backend("http://localhost:8081/mcp"));
    let new = config_with_backends(new_backends);
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert_eq!(patch.backends_modified.len(), 1);
    assert_eq!(patch.backends_modified[0].0, "api");
    assert!(patch.backends_added.is_empty());
    assert!(patch.backends_removed.is_empty());
}

#[test]
fn diff_detects_modified_backend_timeout() {
    // GIVEN: same URL, different timeout
    let mut old_cfg = http_backend("http://localhost:9090/mcp");
    old_cfg.timeout = Duration::from_secs(30);
    let mut new_cfg = http_backend("http://localhost:9090/mcp");
    new_cfg.timeout = Duration::from_secs(60);

    let old = config_with_backends([("svc".to_string(), old_cfg)].into());
    let new = config_with_backends([("svc".to_string(), new_cfg)].into());
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert_eq!(patch.backends_modified.len(), 1);
}

// -------------------------------------------------------------------------
// compute_diff: server changes
// -------------------------------------------------------------------------

#[test]
fn diff_detects_server_port_change() {
    // GIVEN: server port differs
    let old = Config {
        server: ServerConfig {
            port: 39400,
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    let new = Config {
        server: ServerConfig {
            port: 39401,
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert!(patch.server_changed);
}

#[test]
fn diff_detects_public_url_only_change() {
    // GIVEN: only server.public_url differs (host/port unchanged)
    let old = Config::default();
    let new = Config {
        server: ServerConfig {
            public_url: Some("https://mcp.acme.internal".to_string()),
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN: hot-reloadable (endpoint reads live_config), so it is a profile
    // change, not a restart-required server-address change. MIK-6750.
    assert!(patch.profiles_changed, "public_url edit must be detected");
    assert!(
        !patch.server_changed,
        "public_url does not move the listener"
    );
}

#[test]
fn diff_same_server_no_server_change() {
    // GIVEN: identical server configs
    let old = Config::default();
    let new = Config::default();
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert!(!patch.server_changed);
}

// -------------------------------------------------------------------------
// ConfigPatch::is_empty / summary
// -------------------------------------------------------------------------

#[test]
fn patch_is_empty_for_default() {
    let patch = ConfigPatch::default();
    assert!(patch.is_empty());
    assert_eq!(patch.summary(), "no changes");
}

#[test]
fn patch_summary_lists_all_change_types() {
    // GIVEN: a patch with every field populated
    let patch = ConfigPatch {
        backends_added: vec![("x".to_string(), BackendConfig::default())],
        backends_removed: vec!["y".to_string()],
        backends_modified: vec![("z".to_string(), BackendConfig::default())],
        server_changed: true,
        profiles_changed: true,
    };
    let s = patch.summary();
    // THEN: all sections appear in the summary
    assert!(s.contains("added backends"), "missing added: {s}");
    assert!(s.contains("removed backends"), "missing removed: {s}");
    assert!(s.contains("modified backends"), "missing modified: {s}");
    assert!(s.contains("restart required"), "missing server: {s}");
    assert!(s.contains("profiles"), "missing profiles: {s}");
}

#[test]
fn patch_outcome_exposes_restart_required_reason() {
    let patch = ConfigPatch {
        server_changed: true,
        ..ConfigPatch::default()
    };

    let outcome = patch.outcome();

    assert!(outcome.restart_required);
    assert_eq!(outcome.restart_reason, Some("server_address_changed"));
    assert!(outcome.changes.contains("restart required"));
}

#[test]
fn reload_outcome_no_changes_is_explicit() {
    let outcome = ReloadOutcome::no_changes();

    assert_eq!(outcome.changes, "no changes detected");
    assert!(!outcome.restart_required);
    assert_eq!(outcome.restart_reason, None);
}

// -------------------------------------------------------------------------
// LiveConfig
// -------------------------------------------------------------------------

#[test]
fn live_config_get_returns_initial_config() {
    let cfg = Config::default();
    let live = LiveConfig::new(cfg.clone());
    let got = live.get();
    assert_eq!(got.server.port, cfg.server.port);
}

#[test]
fn live_config_set_updates_snapshot() {
    let live = LiveConfig::new(Config::default());
    let mut new_cfg = Config::default();
    new_cfg.server.port = 12345;
    live.set(new_cfg);
    assert_eq!(live.get().server.port, 12345);
}

// -------------------------------------------------------------------------
// diff: multiple simultaneous changes
// -------------------------------------------------------------------------

#[test]
fn diff_handles_mixed_add_remove_modify() {
    // GIVEN: old={a, b}, new={b(modified), c}
    let mut old_backends = HashMap::new();
    old_backends.insert("a".to_string(), http_backend("http://localhost:1001/mcp"));
    old_backends.insert("b".to_string(), http_backend("http://localhost:1002/mcp"));
    let old = config_with_backends(old_backends);

    let mut new_backends = HashMap::new();
    new_backends.insert("b".to_string(), http_backend("http://localhost:1099/mcp")); // modified
    new_backends.insert("c".to_string(), http_backend("http://localhost:1003/mcp")); // added
    let new = config_with_backends(new_backends);

    // WHEN
    let patch = compute_diff(&old, &new);

    // THEN
    assert_eq!(patch.backends_added.len(), 1, "expected c added");
    assert_eq!(patch.backends_added[0].0, "c");

    assert_eq!(patch.backends_removed.len(), 1, "expected a removed");
    assert_eq!(patch.backends_removed[0], "a");

    assert_eq!(patch.backends_modified.len(), 1, "expected b modified");
    assert_eq!(patch.backends_modified[0].0, "b");
}

// -------------------------------------------------------------------------
// expand_tilde
// -------------------------------------------------------------------------

#[test]
fn expand_tilde_leaves_absolute_path_unchanged() {
    // GIVEN: a path that does not start with ~
    let path = super::expand_tilde("/etc/secrets.env");
    // THEN: returned as-is
    assert_eq!(path, std::path::PathBuf::from("/etc/secrets.env"));
}

#[test]
fn expand_tilde_expands_home_prefix() {
    // GIVEN: a tilde-prefixed path
    let path = super::expand_tilde("~/.claude/secrets.env");
    // THEN: ~ is replaced — we just verify it no longer starts with ~
    let path_str = path.to_string_lossy();
    assert!(
        !path_str.starts_with('~'),
        "expected ~ to be expanded, got: {path_str}"
    );
    assert!(
        path_str.ends_with(".claude/secrets.env"),
        "expected suffix preserved, got: {path_str}"
    );
}

// -------------------------------------------------------------------------
// resolve_env_file_paths
// -------------------------------------------------------------------------

#[test]
fn resolve_env_file_paths_expands_tilde_entries() {
    // GIVEN: a mix of absolute and tilde paths
    let raw = vec![
        "/tmp/a.env".to_string(),
        "~/.claude/secrets.env".to_string(),
    ];
    // WHEN
    let resolved = super::resolve_env_file_paths(&raw);
    // THEN: two entries, first unchanged, second has ~ expanded
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved[0], std::path::PathBuf::from("/tmp/a.env"));
    assert!(!resolved[1].to_string_lossy().starts_with('~'));
}

#[test]
fn resolve_env_file_paths_empty_input_returns_empty() {
    // GIVEN: empty slice
    let resolved = super::resolve_env_file_paths(&[]);
    // THEN: empty vec
    assert!(resolved.is_empty());
}

// -------------------------------------------------------------------------
// is_config_event
// -------------------------------------------------------------------------

#[test]
fn is_config_event_matches_modify_on_exact_path() {
    use notify::{EventKind, event::ModifyKind};

    // GIVEN: a Modify event on the watched path
    let config_path = std::path::PathBuf::from("/tmp/config.yaml");
    let event = notify::Event {
        kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
        paths: vec![config_path.clone()],
        attrs: EventAttributes::default(),
    };
    // WHEN / THEN
    assert!(super::is_config_event(&event, &config_path));
}

#[test]
fn is_config_event_does_not_match_different_path() {
    use notify::{EventKind, event::ModifyKind};

    // GIVEN: a Modify event on a different path
    let config_path = std::path::PathBuf::from("/tmp/config.yaml");
    let other_path = std::path::PathBuf::from("/tmp/other.yaml");
    let event = notify::Event {
        kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
        paths: vec![other_path],
        attrs: EventAttributes::default(),
    };
    // WHEN / THEN
    assert!(!super::is_config_event(&event, &config_path));
}

#[test]
fn is_config_event_does_not_match_remove_event() {
    use notify::{EventKind, event::RemoveKind};

    // GIVEN: a Remove event on the exact path
    let config_path = std::path::PathBuf::from("/tmp/config.yaml");
    let event = notify::Event {
        kind: EventKind::Remove(RemoveKind::File),
        paths: vec![config_path.clone()],
        attrs: EventAttributes::default(),
    };
    // WHEN / THEN: Remove is not a trigger (only Create/Modify are)
    assert!(!super::is_config_event(&event, &config_path));
}

// -------------------------------------------------------------------------
// matching_env_file
// -------------------------------------------------------------------------

#[test]
fn matching_env_file_returns_path_when_event_matches_watched_env_file() {
    use notify::{EventKind, event::ModifyKind};

    // GIVEN: an event for a watched env file
    let env_path = std::path::PathBuf::from("/home/user/.claude/secrets.env");
    let event = notify::Event {
        kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
        paths: vec![env_path.clone()],
        attrs: EventAttributes::default(),
    };
    // WHEN
    let result = super::matching_env_file(&event, std::slice::from_ref(&env_path));
    // THEN
    assert_eq!(result, Some(env_path));
}

#[test]
fn matching_env_file_returns_none_when_path_not_in_watch_list() {
    use notify::{EventKind, event::ModifyKind};

    // GIVEN: an event for a file not in the watch list
    let watched = std::path::PathBuf::from("/home/user/.claude/secrets.env");
    let other = std::path::PathBuf::from("/tmp/other.env");
    let event = notify::Event {
        kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
        paths: vec![other],
        attrs: EventAttributes::default(),
    };
    // WHEN / THEN
    assert!(super::matching_env_file(&event, &[watched]).is_none());
}

#[test]
fn matching_env_file_returns_none_for_remove_event() {
    use notify::{EventKind, event::RemoveKind};

    // GIVEN: a Remove event on a watched env file
    let env_path = std::path::PathBuf::from("/home/user/.claude/secrets.env");
    let event = notify::Event {
        kind: EventKind::Remove(RemoveKind::File),
        paths: vec![env_path.clone()],
        attrs: EventAttributes::default(),
    };
    // WHEN / THEN: Remove does not trigger an env-file reload
    assert!(super::matching_env_file(&event, &[env_path]).is_none());
}

#[test]
fn matching_env_file_returns_first_matching_path_among_multiple() {
    use notify::{EventKind, event::ModifyKind};

    // GIVEN: multiple watched env files, event hits the second
    let path_a = std::path::PathBuf::from("/tmp/a.env");
    let path_b = std::path::PathBuf::from("/tmp/b.env");
    let event = notify::Event {
        kind: EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
        paths: vec![path_b.clone()],
        attrs: EventAttributes::default(),
    };
    // WHEN
    let result = super::matching_env_file(&event, &[path_a, path_b.clone()]);
    // THEN: returns the matching path
    assert_eq!(result, Some(path_b));
}

#[test]
fn load_config_patch_rejects_invalid_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    std::fs::write(
        &config_path,
        r#"
backends:
  invalid_backend:
    http_url: "not a url"
"#,
    )
    .unwrap();

    let live_config = std::sync::Arc::new(LiveConfig::new(Config::default()));
    let result = load_config_patch(&config_path, &live_config);

    assert!(matches!(result, Err(msg) if msg.contains("Configuration validation error")));
}

// -------------------------------------------------------------------------
// compute_diff: MetaFields coverage — previously-missing top-level fields
// -------------------------------------------------------------------------

#[test]
fn diff_detects_routing_profiles_change() {
    // GIVEN: old has no routing profiles; new adds one
    use crate::routing_profile::RoutingProfileConfig;

    let old = Config::default();
    let mut new = Config::default();
    new.routing_profiles.insert(
        "limited".to_string(),
        RoutingProfileConfig {
            description: "limited profile".to_string(),
            ..RoutingProfileConfig::default()
        },
    );
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN: profiles_changed is set (routing_profiles is now covered by MetaFields)
    assert!(
        patch.profiles_changed,
        "adding a routing profile should set profiles_changed"
    );
}

#[test]
fn diff_runtime_profile_change_restarts_referencing_backend() {
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

    let patch = compute_diff(&old, &new);
    assert!(patch.profiles_changed);
    assert_eq!(patch.backends_modified.len(), 1);
    assert_eq!(patch.backends_modified[0].0, "docs");
}

#[test]
fn diff_detects_default_routing_profile_change() {
    // GIVEN: default_routing_profile differs
    let old = Config::default();
    let new = Config {
        default_routing_profile: "custom".to_string(),
        ..Config::default()
    };
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert!(
        patch.profiles_changed,
        "changing default_routing_profile should set profiles_changed"
    );
}

#[test]
fn diff_detects_marketplace_change() {
    // GIVEN: marketplace plugin_dir differs
    let old = Config::default();
    let mut new = Config::default();
    new.marketplace.plugin_dir = "/tmp/plugins".to_string();
    // WHEN
    let patch = compute_diff(&old, &new);
    // THEN
    assert!(
        patch.profiles_changed,
        "changing marketplace config should set profiles_changed"
    );
}

#[test]
fn diff_same_routing_profiles_in_different_order_is_not_changed() {
    use crate::routing_profile::RoutingProfileConfig;

    let mut old = Config::default();
    old.routing_profiles.insert(
        "research".to_string(),
        RoutingProfileConfig {
            description: "Research only".to_string(),
            allow_tools: Some(vec!["search_*".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    old.routing_profiles.insert(
        "ops".to_string(),
        RoutingProfileConfig {
            description: "Operations".to_string(),
            allow_backends: Some(vec!["ops_*".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    old.default_routing_profile = "research".to_string();

    let mut new = Config::default();
    new.routing_profiles.insert(
        "ops".to_string(),
        RoutingProfileConfig {
            description: "Operations".to_string(),
            allow_backends: Some(vec!["ops_*".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    new.routing_profiles.insert(
        "research".to_string(),
        RoutingProfileConfig {
            description: "Research only".to_string(),
            allow_tools: Some(vec!["search_*".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    new.default_routing_profile = "research".to_string();

    let patch = compute_diff(&old, &new);

    assert!(
        patch.is_empty(),
        "routing profile key order should not trigger reloads: {}",
        patch.summary()
    );
}

#[test]
fn diff_same_backend_maps_in_different_order_is_not_modified() {
    let mut old_cfg = http_backend("http://localhost:8080/mcp");
    old_cfg.env.insert("ALPHA".to_string(), "1".to_string());
    old_cfg.env.insert("BETA".to_string(), "2".to_string());
    old_cfg
        .headers
        .insert("X-Trace".to_string(), "enabled".to_string());
    old_cfg
        .headers
        .insert("X-Client".to_string(), "gateway".to_string());

    let mut new_cfg = http_backend("http://localhost:8080/mcp");
    new_cfg.env.insert("BETA".to_string(), "2".to_string());
    new_cfg.env.insert("ALPHA".to_string(), "1".to_string());
    new_cfg
        .headers
        .insert("X-Client".to_string(), "gateway".to_string());
    new_cfg
        .headers
        .insert("X-Trace".to_string(), "enabled".to_string());

    let old = config_with_backends([("svc".to_string(), old_cfg)].into());
    let new = config_with_backends([("svc".to_string(), new_cfg)].into());

    let patch = compute_diff(&old, &new);

    assert!(
        patch.is_empty(),
        "backend map key order should not trigger reloads: {}",
        patch.summary()
    );
}

// MIK-6702.CP.RELOAD.2 — a control_plane.role_mapping-only change is detected
// (non-empty patch), so a mapping edit triggers the reload path instead of
// being silently ignored until restart.
#[test]
fn control_plane_role_mapping_change_is_detected() {
    use crate::control_plane::{
        ControlPlaneRole, ControlPlaneRoleMappingConfig, ControlPlaneRoleRule,
    };

    let old = Config::default();
    let mut new = Config::default();
    new.control_plane.role_mapping = ControlPlaneRoleMappingConfig {
        rules: vec![ControlPlaneRoleRule {
            issuer: "https://idp".to_string(),
            group: Some("admins".to_string()),
            email: None,
            domain: None,
            role: ControlPlaneRole::Admin,
        }],
    };

    let patch = compute_diff(&old, &new);
    assert!(
        !patch.is_empty(),
        "a control_plane.role_mapping change must be detected as a reloadable diff"
    );
    assert!(
        patch.profiles_changed,
        "control_plane change should set profiles_changed"
    );
}

// -------------------------------------------------------------------------
// Reload serialization (#397)
// -------------------------------------------------------------------------

/// Two config reloads must not overlap, and the lock has to cover the config
/// read as well as the patch.
///
/// A reload compares the file on disk against the live config, then applies the
/// difference. Registration replaces by name and does not stop what it
/// displaces, so two reloads that both compare against the same live config
/// both decide to add the same backend: the second registration discards the
/// first, and if traffic started that first instance in the gap its child
/// process is orphaned (#397).
///
/// This test drives the stale-comparison case directly. It holds the reload
/// lock, starts two reloads against a config file that adds one backend, then
/// releases. Serialized correctly, the first reload adds the backend and
/// publishes, so the second one compares against the published config and finds
/// nothing to do. If the lock is taken any later than the config read - inside
/// `apply_patch`, say - both reloads decide "backend added" before they queue
/// and both register, which this test sees as a second reload reporting a
/// change instead of reporting none.
#[tokio::test]
async fn concurrent_reloads_do_not_both_add_the_same_backend() {
    // GIVEN: a live config with no backends, and a file on disk that adds one
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    std::fs::write(
        &config_path,
        "backends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();

    let ctx = Arc::new(ReloadContext::new(
        config_path,
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    // WHEN: two reloads start while the reload lock is held, so both are queued
    // before either can read the config.
    //
    // The barrier is what makes that claim checkable. Spawning alone proves
    // nothing: a task that the runtime has not scheduled yet has also not read
    // the config, so releasing the guard before it starts would let this test
    // pass even with the lock in the wrong place. Waiting on a barrier that only
    // opens once all three parties have arrived proves both tasks are running
    // and inside the closure. The sleep that follows covers the remaining few
    // instructions between the barrier and the lock, which is a window no
    // synchronisation primitive can close from outside the function under test.
    let started = Arc::new(tokio::sync::Barrier::new(3));
    let guard = ctx.registry.lock_reload().await;
    let first = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        async move {
            started.wait().await;
            ctx.reload_outcome().await
        }
    });
    let second = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        async move {
            started.wait().await;
            ctx.reload_outcome().await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        ctx.registry.get("svc").is_none(),
        "a reload applied while the reload lock was held"
    );
    drop(guard);

    let first = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("first reload did not finish")
        .expect("first reload task panicked")
        .expect("first reload failed");
    let second = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("second reload did not finish")
        .expect("second reload task panicked")
        .expect("second reload failed");

    // THEN: exactly one of them added the backend; the other saw an up-to-date
    // config and did nothing
    let added = [first.changes.as_str(), second.changes.as_str()]
        .into_iter()
        .filter(|c| c.contains("svc"))
        .count();
    assert_eq!(
        added, 1,
        "both reloads registered the same backend, so one instance was \
         displaced without being stopped (#397); outcomes were {:?} and {:?}",
        first.changes, second.changes
    );
    assert!(
        ctx.registry.get("svc").is_some(),
        "the backend should be registered after the reloads"
    );
}

/// The config write must happen inside the reload lock, not before it.
///
/// This is the assertion that pins the fix. If the write runs first and the
/// lock is taken afterwards, two admin UI edits interleave: both write, then
/// both reload, and each is told its own edit was applied while the file on
/// disk holds only the last writer's bytes. Holding the guard here proves the
/// write is inside the critical section, because a write that were outside it
/// would land on disk while this test still owns the lock.
#[tokio::test]
async fn a_config_write_waits_for_the_reload_lock() {
    // GIVEN: a context whose config file does not exist yet, so the file
    // appearing is unambiguous evidence that the write ran.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    let ctx = Arc::new(ReloadContext::new(
        config_path.clone(),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    // WHEN: a write starts while the reload lock is held
    let started = Arc::new(tokio::sync::Barrier::new(2));
    let guard = ctx.registry.lock_reload().await;
    let writer = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        let path = config_path.clone();
        async move {
            started.wait().await;
            ctx.write_and_reload_outcome(&path, &Config::default())
                .await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // THEN: nothing has been written - the writer is queued behind the lock
    assert!(
        !config_path.exists(),
        "the config was written while the reload lock was held, so the write \
         is outside the critical section and two edits can still interleave"
    );

    // AND: releasing the lock lets it finish
    drop(guard);
    let outcome = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("write did not finish after the lock was released")
        .unwrap();
    assert!(outcome.is_ok(), "write failed: {outcome:?}");
    assert!(config_path.exists(), "config was never written");
}

/// An edit must not erase a change that landed while it was queued. Reading the
/// config outside the lock is what loses one: the queued edit starts from the
/// copy it read before waiting, so its write drops whatever landed in the
/// meantime while still reporting success.
#[tokio::test]
async fn a_queued_edit_does_not_erase_the_edit_it_waited_for() {
    // GIVEN: a config file with no backends in it
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    crate::config_persistence::write_config(&config_path, &Config::default()).unwrap();

    let ctx = Arc::new(ReloadContext::new(
        config_path.clone(),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    // WHEN: an edit adding "beta" is queued behind the reload lock
    let started = Arc::new(tokio::sync::Barrier::new(2));
    let guard = ctx.registry.lock_reload().await;
    let queued_edit = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let started = Arc::clone(&started);
        let path = config_path.clone();
        async move {
            started.wait().await;
            ctx.mutate_and_reload_outcome(&path, |config: &mut Config| {
                config.backends.insert("beta".to_string(), test_backend());
                Ok::<(), ()>(())
            })
            .await
        }
    });
    started.wait().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // AND: the edit that holds the lock adds "alpha" and finishes first
    let mut won_the_lock = Config::default();
    won_the_lock
        .backends
        .insert("alpha".to_string(), test_backend());
    crate::config_persistence::write_config(&config_path, &won_the_lock).unwrap();
    drop(guard);

    let result = tokio::time::timeout(Duration::from_secs(5), queued_edit)
        .await
        .expect("the queued edit never finished")
        .unwrap();
    assert!(result.is_ok(), "the queued edit failed: {:?}", result.err());

    // THEN: the saved config has both, not just the queued edit's own change
    let saved = Config::load(Some(&config_path)).unwrap();
    let mut names: Vec<&String> = saved.backends.keys().collect();
    names.sort();
    assert_eq!(
        names,
        vec!["alpha", "beta"],
        "the queued edit erased the change it was waiting behind"
    );
}

/// A backend config that passes validation, for tests that only care about the
/// name.
#[cfg(test)]
fn test_backend() -> crate::config::BackendConfig {
    crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    }
}

/// Without a live gateway there is nothing to reload, so the write still has
/// to land on disk and report no reload outcome rather than failing.
#[tokio::test]
async fn write_config_and_reload_without_context_persists_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = Config::default();

    write_config_and_reload(&path, &config, None).await.unwrap();

    assert!(path.exists());
    let loaded = Config::load(Some(&path)).unwrap();
    assert_eq!(loaded.backends.len(), config.backends.len());
}

#[tokio::test]
async fn write_config_and_reload_outcome_without_context_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = Config::default();

    let outcome = write_config_and_reload_outcome(&path, &config, None)
        .await
        .unwrap();

    assert!(outcome.is_none());
}

/// `config_persistence` must not reach back into `config_reload`.
///
/// The two modules used to import each other: persistence called the reload
/// context, and the reload context called persistence. A cycle like that has no
/// build order to reason about, so a change to either module can only be
/// reviewed by reading both. The dependency now points one way — reload knows
/// about persistence, never the reverse — and this test is what keeps it that
/// way, because nothing else in the build will complain if someone adds the
/// import back.
#[test]
fn config_persistence_does_not_depend_on_config_reload() {
    let source = include_str!("../config_persistence.rs");

    let offenders: Vec<_> = source
        .lines()
        .filter(|line| line.contains("config_reload"))
        .collect();

    assert!(
        offenders.is_empty(),
        "config_persistence reaches back into config_reload, restoring the cycle: {offenders:?}"
    );
}

/// A config write must not queue behind a stuck reload forever.
///
/// The reload lock is held across a full reload: stop backends, re-register
/// them, republish. A backend that is slow to shut down holds it for as long as
/// it takes. Every admin UI backend edit waits on that same lock with no bound,
/// so the HTTP handler blocks, the request times out somewhere the operator
/// cannot see, and the retry queues behind the first one. Reporting "busy" lets
/// the caller decide, and lets the UI answer 503 instead of hanging.
#[tokio::test]
async fn a_config_write_reports_busy_instead_of_waiting_forever() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = test_reload_context(&config_path);

    let guard = ctx.registry.lock_reload().await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctx.mutate_and_reload_outcome_within(
            &config_path,
            std::time::Duration::from_millis(50),
            |config: &mut Config| -> std::result::Result<(), ()> {
                config
                    .backends
                    .insert("blocked".to_string(), test_backend());
                Ok(())
            },
        ),
    )
    .await
    .expect("the write hung on the reload lock instead of reporting busy");

    drop(guard);

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a write blocked behind a held reload lock did not report busy"
    );
    assert!(
        !config_path.exists(),
        "a write that reported busy still touched the config file"
    );
}

/// The same bound applies to the whole-config write path, not just the
/// read-modify-write one.
#[tokio::test]
async fn a_whole_config_write_reports_busy_instead_of_waiting_forever() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = test_reload_context(&config_path);

    let guard = ctx.registry.lock_reload().await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctx.write_and_reload_outcome_within(
            &config_path,
            std::time::Duration::from_millis(50),
            &Config::default(),
        ),
    )
    .await
    .expect("the write hung on the reload lock instead of reporting busy");

    drop(guard);

    assert!(
        matches!(result, Err(ConfigWriteError::Busy)),
        "a whole-config write blocked behind a held reload lock did not report busy"
    );
}

/// A write that waits and then gets the lock must still succeed. The bound is
/// there to stop unbounded queueing, not to fail edits that arrive during a
/// normal reload.
#[tokio::test]
async fn a_write_that_gets_the_lock_within_its_bound_still_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");
    let ctx = std::sync::Arc::new(test_reload_context(&config_path));

    let guard = ctx.registry.lock_reload().await;

    let writer = tokio::spawn({
        let ctx = std::sync::Arc::clone(&ctx);
        let config_path = config_path.clone();
        async move {
            ctx.mutate_and_reload_outcome_within(
                &config_path,
                std::time::Duration::from_secs(5),
                |config: &mut Config| -> std::result::Result<(), ()> {
                    config
                        .backends
                        .insert("patient".to_string(), test_backend());
                    Ok(())
                },
            )
            .await
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(guard);

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), writer)
        .await
        .expect("the write never completed after the lock was released")
        .expect("the write task panicked");

    assert!(
        matches!(result, Ok(ConfigMutation::Applied((), _))),
        "a write that waited out a normal reload was refused as busy"
    );
}

/// A reload context wired to a scratch config path, with no live backends.
fn test_reload_context(config_path: &std::path::Path) -> ReloadContext {
    ReloadContext::new(
        config_path.to_path_buf(),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

// -------------------------------------------------------------------------
// Posture refusal — a reload must not enter the state startup refuses
//
// The gateway refuses to start when it is reachable by name and its tools are
// invocable without a credential (`network_bind_refusal`). `server.public_url`
// is re-read per request, so adding one to a running gateway reaches that state
// without passing the startup check. These cases pin the refusal that closes it.
//
// The three masking cases are the ones that matter. A refusal judged against the
// FILE passes them by reading fields the reload never applies: the file may say
// authentication is on while the router is still running the startup snapshot.
// They fail against that version and pass against one judged on the config that
// will be in force. See docs/design/unauthenticated-network-posture.md,
// Decision C.
// -------------------------------------------------------------------------

/// A running config that startup would not have refused: loopback, no declared
/// public URL. Every posture case starts here, because the refusal only fires on
/// a reload that would ENTER the refusable state.
fn clean_running() -> Config {
    Config::default()
}

/// The reload context of [`test_reload_context`], with the running config named
/// rather than defaulted, so a case can start from a gateway whose tools are
/// already closed.
fn posture_context(config_path: &std::path::Path, running: Config) -> ReloadContext {
    ReloadContext::new(
        config_path.to_path_buf(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

#[tokio::test]
async fn a_reload_publishing_the_gateway_over_open_tools_is_refused() {
    // GIVEN: a gateway running on loopback with no declared public URL
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL, leaving the tools reachable
    std::fs::write(&path, "server:\n  public_url: \"https://gw.example.com\"\n").unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("a reload that opens the tool surface to the network was applied");

    // THEN: it is refused, under the shared literal every consumer keys on
    assert!(
        err.starts_with(POSTURE_REFUSED_PREFIX),
        "refusal did not carry the shared prefix: {err}"
    );
    // AND: the message carries the remedy, not merely a label
    assert!(
        err.contains("gw.example.com"),
        "refusal did not name the exposure: {err}"
    );
    assert!(
        err.contains("auth.enabled"),
        "refusal did not carry the remedy: {err}"
    );
    // AND: it says what a restart does with this same file
    assert!(
        err.contains("next start"),
        "refusal did not say what a restart does with this file: {err}"
    );
    // AND: it makes NO claim about what remains in force, anywhere in the
    // message — prefix included. `Config::load` has already applied the
    // candidate's env_files to the process and `capability::executor` reads
    // `std::env::var` per call, so any such claim is one the code cannot keep
    // (MIK-7256).
    //
    // Every phrasing that has appeared here, not only the last one. An earlier
    // version of this case listed the two the body had just been corrected of,
    // and so did not notice that the shared PREFIX still said "the running
    // gateway is unchanged" — the same claim, three words shorter, in the one
    // part of the message the test was not reading.
    for claim in [
        "unchanged",
        "in force",
        "still serving",
        "nothing was applied",
        "no changes were made",
    ] {
        assert!(
            !err.to_ascii_lowercase().contains(claim),
            "the refusal claims {claim:?} — what remains in force is what it \
             cannot know: {err}"
        );
    }
    // AND: it says precisely what did not happen — no backend moved, nothing
    // published. Not "nothing was applied", which would be a wider claim than
    // the code can keep: `Config::load` has already applied any `env_files`.
    assert!(
        err.contains("No backend was started or stopped")
            && err.contains("no configuration was published"),
        "refusal did not say what was skipped: {err}"
    );
}

#[tokio::test]
async fn enabling_auth_in_the_same_edit_does_not_mask_the_exposure() {
    // GIVEN: the same running gateway
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL AND enables authentication — the
    // remediation this project recommends everywhere. A reload does not apply
    // `auth`: the router snapshots it at construction, so the request path is
    // still running the old, permissive state while the origin gate has already
    // started admitting the new host.
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx.reload_outcome().await.expect_err(
        "a reload was applied because the FILE enabled auth, while the running \
         gateway's auth is unchanged — the exposure this refusal exists to stop",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn setting_the_override_in_the_same_edit_does_not_mask_it_either() {
    // GIVEN: the same running gateway
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file declares a public URL and sets the escape hatch. Like
    // `auth`, the override is restart-only, so it silences nothing on a running
    // process. A refusal that read the file would let it silence this one.
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  allow_unauthenticated_network_bind: true\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the file's override silenced a refusal it cannot silence until a restart");
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn a_refused_reload_applies_nothing_at_all() {
    // GIVEN: a gateway running on loopback, with no backends
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit adds both a backend and the public URL that refuses
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let _ = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    // THEN: the backend in the same file was never registered — the refusal runs
    // before `apply_patch`, which stops and starts backends
    assert!(
        ctx.registry.get("svc").is_none(),
        "a refused reload registered a backend from the same file"
    );
    // AND: nothing was published, so the origin gate never sees the new host
    assert!(
        ctx.live_config.get().server.public_url.is_none(),
        "a refused reload published its config"
    );
}

#[tokio::test]
async fn a_reload_that_does_not_open_the_tools_still_applies() {
    // GIVEN: a gateway whose RUNNING config already closes the tool surface.
    //
    // Taken from the running config and not from the file on purpose: reading it
    // from the file is the mistake the refusal exists to prevent, so a
    // regression case written that way would pass by making it.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the same public URL is declared, over tools that need a credential
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: it applies, and the backend beside it registers
    ctx.reload_outcome()
        .await
        .expect("a reload that leaves the tools behind a credential was refused");
    assert!(
        ctx.registry.get("svc").is_some(),
        "an applied reload did not register its backend"
    );
    assert_eq!(
        ctx.live_config.get().server.public_url.as_deref(),
        Some("https://gw.example.com")
    );
}

#[tokio::test]
async fn a_published_but_not_running_auth_value_does_not_mask_it_either() {
    // GIVEN: a gateway running with authentication OFF, whose operator has just
    // done what this project advises — turned it on in the file and been told it
    // is restart-required. The value is now PUBLISHED in the live snapshot and
    // is not in force: the router is still running the startup auth state.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "auth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());
    ctx.reload_outcome()
        .await
        .expect("enabling auth with no public_url is not a refusable change");
    assert!(
        ctx.live_config.get().auth.enabled,
        "the first reload did not publish, so the second cannot demonstrate anything"
    );
    assert!(
        !ctx.live_config.running().auth.enabled,
        "the running snapshot moved, which it must never do without a restart"
    );

    // WHEN: they then add the public URL — a second reload, against a published
    // snapshot that disagrees with what is running
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();

    // THEN: still refused. A refusal that overlaid onto the PUBLISHED snapshot
    // would read `auth.enabled = true` here and let it through, which is the
    // round-1 masking hole arriving one reload later.
    let err = ctx.reload_outcome().await.expect_err(
        "the second reload was applied because the published snapshot said auth \
         was on, while the request path is still running without it",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

/// The overlay names the live fields by hand, because `pending_restart_fields`
/// returns names and offers no way to apply them. This is the tripwire that
/// catches a field BECOMING live: it does not check the overlay, it fails when
/// the set it was derived from changes, and sends the reader to the design.
#[test]
fn the_live_field_allow_list_has_not_grown() {
    let mut wanted = Config::default();
    wanted.server.public_url = Some("https://gw.example.com".to_string());
    wanted.control_plane.role_mapping.rules = vec![crate::control_plane::ControlPlaneRoleRule {
        issuer: "https://idp.example.com".to_string(),
        group: Some("admins".to_string()),
        email: None,
        domain: None,
        role: crate::control_plane::ControlPlaneRole::Admin,
    }];

    assert!(
        pending_restart_fields(&Config::default(), &wanted).is_empty(),
        "a field that used to be applied live is now restart-required"
    );

    // And every input the refusal reads is still restart-only. Named one by one
    // rather than as one blob: each is a field the overlay deliberately takes
    // from the RUNNING config, and the overlay is unsound the moment any of them
    // starts applying live.
    for (name, edit) in [
        (
            "auth",
            (|c: &mut Config| c.auth.enabled = true) as fn(&mut Config),
        ),
        ("auth", |c: &mut Config| {
            c.auth.public_paths = vec!["/mcp".to_string()];
        }),
        ("server", |c: &mut Config| {
            c.server.host = "0.0.0.0".to_string();
        }),
        ("server", |c: &mut Config| {
            c.server.allow_unauthenticated_network_bind = true;
        }),
    ] {
        let mut also = wanted.clone();
        edit(&mut also);
        assert!(
            pending_restart_fields(&Config::default(), &also).contains(&name),
            "a field the reload posture overlay reads from the running config is \
             now applied live; the overlay must carry it — see \
             docs/design/unauthenticated-network-posture.md, Decision C"
        );
    }
}

/// The file watcher must log a posture refusal as a refusal, not as the
/// broken-config-file alert a parse failure raises — an operator sent hunting
/// YAML will not revert the `public_url` that is the actual problem.
///
/// Asserted against the string a refused reload really produces, rather than
/// against the constant. That is the whole point: the constant is a PREFIX with
/// the refusal text behind it, so an arm written `e == POSTURE_REFUSED_PREFIX` —
/// the shape the neighbouring `SHUTDOWN_ABORTED_ERROR` arm uses — never matches
/// and falls through to the parse-failure arm. This test fails on that mistake.
#[tokio::test]
async fn the_watcher_recognises_a_posture_refusal_and_not_as_a_broken_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, "server:\n  public_url: \"https://gw.example.com\"\n").unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    assert!(
        is_posture_refusal(&err),
        "the watcher would log this refusal as a broken config file: {err}"
    );
    assert!(
        !is_posture_refusal(SHUTDOWN_ABORTED_ERROR),
        "the shutdown abort is not a posture refusal"
    );
    assert!(
        !is_posture_refusal("failed to parse config file: invalid YAML at line 3"),
        "a parse failure is not a posture refusal"
    );
}

#[tokio::test]
async fn a_reload_is_not_refused_for_a_state_it_did_not_cause() {
    // GIVEN: a gateway already running in the refusable state — wide bind, no
    // credential. Unreachable through `Gateway::run`, which refuses to start
    // there; reachable through `run_stdio`, which has no listener and never runs
    // the check. Keying the refusal on the TRANSITION rather than on the
    // candidate alone is what keeps that gateway able to reload at all.
    let mut running = Config::default();
    running.server.host = "0.0.0.0".to_string();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: it reloads something unrelated
    std::fs::write(
        &path,
        "server:\n  host: \"0.0.0.0\"\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: it applies. The refusal answers "would this reload OPEN the tools",
    // not "are they open" — the second would wedge such a gateway permanently.
    ctx.reload_outcome()
        .await
        .expect("a reload was refused for a state that predates it");
    assert!(ctx.registry.get("svc").is_some());
}

#[tokio::test]
async fn a_blank_public_path_in_force_is_tools_open_and_refuses() {
    // GIVEN: a gateway running on loopback whose public_paths carry a BLANK
    // entry — a stray dash in YAML. Startup allowed it: on loopback with no
    // declared name, reachability is the half that was missing. But blank is a
    // prefix of every path (`ResolvedAuthConfig::is_public_path`), so at request
    // time this gateway's tools need no credential, whatever `auth.enabled`
    // says.
    //
    // Staged in the RUNNING config, not the file, and that is the whole case.
    // In the file it would be harmless here: `auth` is not applied by a reload,
    // so the request path would keep the old, closed paths and the in-force
    // state would be safe. It is being ALREADY IN FORCE that makes it the live
    // half of the forbidden state.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());
    running.auth.public_paths = vec!["/health".to_string(), String::new()];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: the file supplies the other half — a name it is reached by
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n    - \"\"\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: refused. `auth.enabled` is true on both sides, so the overlay saves
    // nothing here — this rests entirely on the refusal counting a blank entry
    // as public, which it did not always do.
    let err = ctx
        .reload_outcome()
        .await
        .expect_err("a blank public path opened every route and the reload was applied");
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
}

#[tokio::test]
async fn a_file_that_a_restart_would_accept_is_not_reported_as_one_to_revert() {
    // GIVEN: a gateway running with authentication OFF
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit declares the public URL and turns authentication on — the
    // fix, written correctly. A reload still cannot apply it, because the auth
    // half needs a restart while the public_url half would take effect at once.
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");

    // THEN: it says a restart applies it — not "revert this". Telling an
    // operator to undo the fix they just wrote correctly is the worse failure,
    // and the deployment guide tells them to do exactly this and restart.
    assert!(
        err.contains("A restart accepts this file"),
        "an operator who wrote the fix correctly was told to revert it: {err}"
    );
    assert!(
        !err.contains("Revert it"),
        "a startup-safe file was reported as one to revert: {err}"
    );
}

#[tokio::test]
async fn tightening_public_paths_in_the_same_edit_does_not_mask_it() {
    // GIVEN: the shape `mcp-gateway init` writes, which is what a default
    // install runs: authentication ON, and `/mcp` public so the MCP client that
    // was already configured keeps working. Tools are therefore invocable
    // without a credential, on purpose, on loopback.
    let mut running = Config::default();
    running.auth.enabled = true;
    running.auth.bearer_token = Some("secret".to_string());
    running.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    // WHEN: one edit publishes the gateway by name AND closes `/mcp` — both
    // halves of the correct fix, written together
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    )
    .unwrap();
    let ctx = posture_context(&path, running);

    // THEN: refused, because the tightening is not in force. This is the case
    // an overlay that took `auth.enabled` from the running config but
    // `public_paths` from the file would let through: both halves must come
    // from the same side, and that side is what is running.
    let err = ctx.reload_outcome().await.expect_err(
        "the file's tightened public_paths masked the exposure, while the request \
         path still has /mcp open",
    );
    assert!(err.starts_with(POSTURE_REFUSED_PREFIX), "{err}");
    // AND: a restart on this file is right, so it must not say revert.
    assert!(
        err.contains("A restart accepts this file"),
        "the correct fix was reported as one to revert: {err}"
    );
}

/// Every refusal reads as a sentence.
///
/// A Rust string literal wrapped across lines WITHOUT a trailing `\` keeps the
/// indentation of the continuation line, so the message reaches an operator
/// with runs of spaces in it. The other cases here assert substrings that
/// happen to fall inside one line, so all of them passed while both branches of
/// the restart advice were mangled. This one reads the whole message.
#[tokio::test]
async fn a_refusal_reads_as_a_sentence_on_both_branches() {
    // Two files, one per branch of the restart advice: the first refuses at the
    // next start too, the second is accepted by one.
    for file in [
        "server:\n  public_url: \"https://gw.example.com\"\n",
        "server:\n  public_url: \"https://gw.example.com\"\nauth:\n  enabled: true\n  bearer_token: \"secret\"\n  public_paths:\n    - /health\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        std::fs::write(&path, file).unwrap();
        let ctx = posture_context(&path, clean_running());

        let err = ctx
            .reload_outcome()
            .await
            .expect_err("the reload was applied");

        assert!(
            !err.contains("  "),
            "the refusal carries a run of spaces, so a literal lost its line \
             continuation: {err}"
        );
        assert!(
            err.trim_end().ends_with('.'),
            "the refusal does not end as a sentence: {err}"
        );
    }
}

#[tokio::test]
async fn the_override_is_reported_as_a_file_a_restart_accepts() {
    // The escape hatch is honoured at STARTUP, so a file that sets it is
    // accepted by a restart even though the reload cannot apply it. Telling
    // that operator to revert would be wrong, and this is the case where the
    // two branches of the advice are easiest to get backwards: the file leaves
    // the tools open on purpose, which reads like the revert case.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        "server:\n  public_url: \"https://gw.example.com\"\n  allow_unauthenticated_network_bind: true\n",
    )
    .unwrap();
    let ctx = posture_context(&path, clean_running());

    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the reload was applied");
    assert!(
        err.contains("A restart accepts this file"),
        "a file the escape hatch makes startup-legal was reported as one to \
         revert: {err}"
    );
}
