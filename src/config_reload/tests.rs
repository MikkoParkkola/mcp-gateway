use std::collections::HashMap;

use super::*;
use crate::config::{BackendConfig, Config, ServerConfig, TransportConfig};

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
        attrs: Default::default(),
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
        attrs: Default::default(),
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
        attrs: Default::default(),
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
        attrs: Default::default(),
    };
    // WHEN
    let result = super::matching_env_file(&event, &[env_path.clone()]);
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
        attrs: Default::default(),
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
        attrs: Default::default(),
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
        attrs: Default::default(),
    };
    // WHEN
    let result = super::matching_env_file(&event, &[path_a, path_b.clone()]);
    // THEN: returns the matching path
    assert_eq!(result, Some(path_b));
}
