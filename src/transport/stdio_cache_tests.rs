// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `isolated_package_manager_env`, which gives each backend its
//! own npm cache.
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
    for cmd in ["npx -y pkg", "/usr/local/bin/npx -y pkg", "npm exec pkg"] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert!(out.contains_key("npm_config_cache"), "{cmd} was missed");
    }
    for cmd in ["uvx meilisearch-mcp", "vikunja-mcp", "sh -c 'x'"] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert!(
            out.is_empty(),
            "{cmd} was given a cache variable it cannot use"
        );
    }
}

#[test]
fn a_name_cannot_escape_the_state_directory() {
    let root = crate::config_persistence::gateway_data_dir()
        .join("pkg-cache")
        .to_string_lossy()
        .into_owned();
    for hostile in [
        "../evil",
        "a/b",
        "..",
        "",
        "with space",
        "/etc/passwd",
        r"..\evil",
        r"a\b",
        r"C:\evil",
    ] {
        let out = isolated_package_manager_env(hostile, "npx -y pkg", HashMap::new());
        let path = &out["npm_config_cache"];
        let component = path
            .strip_prefix(&root)
            .and_then(|rest| rest.strip_prefix(std::path::MAIN_SEPARATOR))
            .unwrap_or_else(|| panic!("{hostile:?} escaped {root}: {path}"));
        assert!(
            !component.is_empty() && !component.contains(['/', '\\']),
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

// #2258
#[test]
fn names_that_sanitize_alike_get_distinct_cache_dirs() {
    for (a, b) in [
        ("team.alpha", "team_alpha"),
        ("Alpha", "alpha"),
        ("", "unnamed"),
    ] {
        let x = isolated_package_manager_env(a, "npx -y pkg", HashMap::new());
        let y = isolated_package_manager_env(b, "npx -y pkg", HashMap::new());
        assert_ne!(
            x["npm_config_cache"], y["npm_config_cache"],
            "{a:?} vs {b:?}"
        );
    }
}

// #2258
#[test]
fn each_runner_gets_the_variable_it_reads() {
    for (cmd, var) in [
        ("npx -y pkg", "npm_config_cache"),
        ("bunx pkg", "BUN_INSTALL_CACHE_DIR"),
        ("/opt/bin/yarn dlx pkg", "YARN_CACHE_FOLDER"),
    ] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert_eq!(out.len(), 1, "{cmd}: {out:?}");
        assert!(out[var].contains("pkg-cache"), "{cmd} lacked {var}");
    }
    let out = isolated_package_manager_env("thing", "pnpm dlx pkg", HashMap::new());
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(out["pnpm_config_store_dir"].contains("pkg-cache"));
    assert_eq!(out["pnpm_config_store_dir"], out["npm_config_store_dir"]);
    let mut env = HashMap::new();
    env.insert("BUN_INSTALL_CACHE_DIR".to_string(), "/mine".to_string());
    let out = isolated_package_manager_env("thing", "bunx pkg", env);
    assert_eq!(out["BUN_INSTALL_CACHE_DIR"], "/mine");
}

#[test]
fn the_assigned_cache_is_the_one_the_child_receives() {
    // The repair compares the two; a one-byte drift between them would leave
    // every damaged cache in place without an error.
    let env = isolated_package_manager_env("cache-glue", "npx -y some-server", HashMap::new());
    assert_eq!(
        assigned_package_cache_dir("cache-glue", "npx -y some-server", &HashMap::new()),
        Some(std::path::PathBuf::from(&env["npm_config_cache"])),
    );
}

#[test]
fn only_an_npm_cache_the_gateway_set_is_reported_as_assigned() {
    let operator = HashMap::from([("npm_config_cache".to_string(), "/opt/cache".to_string())]);
    assert_eq!(
        assigned_package_cache_dir("b", "npx -y some-server", &operator),
        None,
        "an operator's cache is not the gateway's to clear"
    );
    for command in [
        "bunx some-server",
        "yarn dlx some-server",
        "pnpm dlx some-server",
        "uvx x",
    ] {
        assert_eq!(
            assigned_package_cache_dir("b", command, &HashMap::new()),
            None,
            "the repair covers npm's cache only: {command}"
        );
    }
}

#[test]
fn an_operator_cache_in_either_spelling_is_not_the_gateways() {
    let operator = HashMap::from([("NPM_CONFIG_CACHE".to_string(), "/opt/cache".to_string())]);
    assert_eq!(
        assigned_package_cache_dir("b", "npx -y some-server", &operator),
        None,
        "npm reads its environment case-insensitively, so this names a cache too"
    );
    let env = isolated_package_manager_env("b", "npx -y some-server", operator);
    assert_eq!(
        env.len(),
        1,
        "and the gateway adds no second, lowercase cache beside it: {env:?}"
    );
}

#[test]
fn only_an_absolute_cache_directory_is_repairable() {
    // Relative, it resolves against the gateway's working directory when
    // removed and against the child's `cwd` when used: two different trees.
    assert_eq!(cache::absolute("pkg-cache/b".into()), None);
    let absolute = std::env::temp_dir().join("pkg-cache").join("b");
    assert_eq!(cache::absolute(absolute.clone()), Some(absolute));
}

#[test]
fn a_live_cache_name_never_holds_a_dot() {
    // The startup sweep deletes entries whose name contains ".tombstone-", so a
    // live cache name must never contain a "." whatever the backend is called.
    for name in [
        "a.b",
        "team.alpha",
        "..",
        "x.tombstone-1-0",
        "émoji.🙂",
        "plain",
    ] {
        let env = isolated_package_manager_env(name, "npx -y some-server", HashMap::new());
        let leaf = std::path::Path::new(&env["npm_config_cache"])
            .file_name()
            .expect("a cache directory has a name")
            .to_string_lossy()
            .into_owned();
        assert!(!leaf.contains('.'), "{name:?} became {leaf:?}");
    }
}
