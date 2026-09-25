// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C9 / SECRET.2: a `file:` secret is read once, at startup, so a rotated file
//! is reported as needing a restart, by path and never by value.

use std::sync::Arc;

use super::*;
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

fn start(content: &str) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let token = dir.path().join("token");
    write_owner_only(&token, content).expect("write token");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(
        &config,
        format!(
            "auth:\n  enabled: true\n  bearer_token: 'file:{}'\nsecurity:\n  transparency_log:\n    enabled: true\n    path: '{}'\n",
            token.display(),
            dir.path().join("audit.jsonl").display()
        ),
    )
    .expect("write config");
    (dir, config, token)
}

fn restart_keys(config: &std::path::Path, startup: crate::config::Evaluated) -> Vec<String> {
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);
    let evaluated = load_config_patch(config, &live, &env).expect("reload loads");
    changed_startup_env_keys(&env, &evaluated)
}

#[test]
fn reload_reports_rotated_file() {
    let (_dir, config, token) = start("c9-old-token\n");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    write_owner_only(&token, "c9-new-token\n").expect("rotate");

    let keys = restart_keys(&config, startup);
    assert_eq!(keys, vec![format!("file:{}", token.display())]);
    assert!(
        keys.iter().all(|k| !k.contains("c9-")),
        "a value reached the report: {keys:?}"
    );
}

#[test]
fn reload_unchanged_file_not_reported() {
    let (_dir, config, token) = start("c9-same-token\n");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    // A kubelet `..data` swap rewrites the same bytes: new inode and mtime,
    // same secret. Only a content change needs a restart.
    std::fs::remove_file(&token).expect("remove");
    write_owner_only(&token, "c9-same-token\n").expect("rewrite same bytes");
    assert!(restart_keys(&config, startup).is_empty());
}

/// A Kubernetes `..data` swap can leave the path briefly absent. The reload
/// that sees it is refused (the bearer no longer resolves), and a later one
/// against the restored content reports nothing.
#[test]
fn reload_with_vanished_file_is_refused_and_restore_is_quiet() {
    let (_dir, config, token) = start("c9-kept-token\n");
    let startup = Config::load_evaluated(Some(&config)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(startup.config.clone()));
    let env = LiveEnv::new(startup.overlay, startup.env_paths);
    std::fs::remove_file(&token).expect("remove");
    let refused = load_config_patch(&config, &live, &env)
        .err()
        .expect("a vanished file: secret refuses the reload");
    assert!(refused.contains(&token.display().to_string()), "{refused}");
    write_owner_only(&token, "c9-kept-token\n").expect("restore");
    let evaluated = load_config_patch(&config, &live, &env).expect("restored");
    assert!(changed_startup_env_keys(&env, &evaluated).is_empty());
}
