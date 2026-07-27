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
