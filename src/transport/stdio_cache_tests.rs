// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `isolated_package_manager_env`.
//!
//! Split out of `stdio_tests.rs` so it stays under the file-size ceiling
//! `scripts/dev/check-file-size.py` gates. A `#[path]` child, not a
//! sibling module: `use super::*` still resolves to the transport's own
//! items, so nothing had to be widened to move it here.

use super::*;
use std::collections::HashMap;

#[test]
fn distinct_backends_never_share_a_package_cache() {
    let a = isolated_package_manager_env("calendar-justin", "npx -y caldav-mcp", HashMap::new());
    let b = isolated_package_manager_env("calendar-work", "npx -y caldav-mcp", HashMap::new());
    assert_ne!(
        a["npm_config_cache"], b["npm_config_cache"],
        "two backends running the same command must not install into one tree"
    );
}

#[test]
fn one_backend_gets_one_cache_path() {
    let a = isolated_package_manager_env("caldav", "npx -y caldav-mcp", HashMap::new());
    let b = isolated_package_manager_env("caldav", "npx -y caldav-mcp", HashMap::new());
    assert_eq!(a["npm_config_cache"], b["npm_config_cache"]);
}

#[test]
fn an_operator_set_cache_is_left_alone() {
    let mut env = HashMap::new();
    env.insert("npm_config_cache".to_string(), "/custom/cache".to_string());
    let out = isolated_package_manager_env("paperless", "npx -y paperless-mcp", env);
    assert_eq!(out["npm_config_cache"], "/custom/cache");
}

#[test]
fn only_npm_invoking_commands_get_a_cache() {
    for cmd in [
        "npx -y pkg",
        "/usr/local/bin/npx -y pkg",
        "pnpm dlx pkg",
        "npm exec pkg",
    ] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert!(out.contains_key("npm_config_cache"), "{cmd} was missed");
    }
    for cmd in ["uvx meilisearch-mcp", "vikunja-mcp", "sh -c 'x'"] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert!(
            !out.contains_key("npm_config_cache"),
            "{cmd} was given an npm cache it cannot use"
        );
    }
}

#[test]
fn a_name_cannot_escape_the_state_directory() {
    let root = crate::config_persistence::gateway_data_dir()
        .join("pkg-cache")
        .to_string_lossy()
        .into_owned();
    for hostile in ["../evil", "a/b", "..", "", "with space", "/etc/passwd"] {
        let out = isolated_package_manager_env(hostile, "npx -y pkg", HashMap::new());
        let path = &out["npm_config_cache"];
        let component = path
            .strip_prefix(&root)
            .and_then(|rest| rest.strip_prefix('/'))
            .unwrap_or_else(|| panic!("{hostile:?} escaped {root}: {path}"));
        assert!(
            !component.is_empty() && !component.contains('/'),
            "{hostile:?} became a nested path: {path}"
        );
        assert!(
            component
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{hostile:?} left an unsafe character: {path}"
        );
    }
}

#[test]
fn operator_npm_settings_reach_the_backend() {
    let vars = vec![
        ("npm_config_allow_git".into(), "all".into()),
        (
            "npm_config_registry".into(),
            "https://example.invalid".into(),
        ),
        ("PATH".into(), "/usr/bin".into()),
    ];
    let forwarded = forwarded_npm_config(vars);
    assert_eq!(forwarded.len(), 2, "only npm settings are forwarded");
    assert!(
        forwarded
            .iter()
            .any(|(k, v)| k == "npm_config_allow_git" && v == "all")
    );
}

#[test]
fn the_gateways_own_cache_assignment_is_not_overridden() {
    let vars = vec![("npm_config_cache".into(), "/operator/cache".into())];
    assert!(
        forwarded_npm_config(vars).is_empty(),
        "the per-backend cache the gateway assigns must not be replaced by the operator's"
    );
}

#[test]
fn a_cache_shaped_failure_is_recognised() {
    for text in [
        "Failed to get stdout",
        "Error: Cannot find module '/x/_npx/1/node_modules/zod/v3/index.js'",
        "npm error code EALLOWGIT",
        "ERR_MODULE_NOT_FOUND",
    ] {
        let expected = text.contains("Cannot find module")
            || text.contains("EALLOWGIT")
            || text.contains("ERR_MODULE_NOT_FOUND");
        assert_eq!(
            cache_failure(&Error::Transport(text.to_string())),
            expected,
            "misjudged: {text}"
        );
    }
    assert!(
        !cache_failure(&Error::Transport("connection reset by peer".to_string())),
        "an unrelated transport failure must not have its cache thrown away"
    );
}

#[test]
fn clearing_a_cache_removes_it_and_tolerates_a_missing_one() {
    let dir = std::env::temp_dir().join(format!("cache-recovery-{}", std::process::id()));
    let nested = dir.join("_npx/1/node_modules");
    std::fs::create_dir_all(&nested).expect("create temp cache");
    std::fs::write(nested.join("index.js"), "x").expect("seed file");

    assert!(remove_cache_dir(&dir), "an existing cache is removed");
    assert!(!dir.exists(), "the tree is gone");
    assert!(
        remove_cache_dir(&dir),
        "clearing an already-absent cache is success, not failure"
    );
}
