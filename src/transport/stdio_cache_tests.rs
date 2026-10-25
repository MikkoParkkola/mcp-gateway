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

/// A quoted program is the one the launch spawns, so it gets the same cache
/// as the unquoted spelling; a whitespace split read `"/opt/node` and skipped
/// isolation (MIK-8831.REL.4).
#[test]
fn a_quoted_runner_gets_the_cache_its_unquoted_spelling_gets() {
    for (quoted, plain, var) in [
        (
            r#""/opt/node js/bin/npx" -y pkg"#,
            "npx -y pkg",
            "npm_config_cache",
        ),
        (r#""npx" -y pkg"#, "npx -y pkg", "npm_config_cache"),
        (
            r#""/opt/bun dir/bunx" pkg"#,
            "bunx pkg",
            "BUN_INSTALL_CACHE_DIR",
        ),
        (
            r#""/opt/node js/bin/npm" exec pkg"#,
            "npm exec pkg",
            "npm_config_cache",
        ),
        (
            r#""/opt/node js/bin/pnpm" dlx pkg"#,
            "pnpm dlx pkg",
            "pnpm_config_store_dir",
        ),
        (
            r#""/opt/node js/bin/pnpm" dlx pkg"#,
            "pnpm dlx pkg",
            "npm_config_store_dir",
        ),
        (
            r#""/opt/node js/bin/yarn" dlx pkg"#,
            "yarn dlx pkg",
            "YARN_CACHE_FOLDER",
        ),
        (
            r#""/opt/node js/bin/yarn" dlx pkg"#,
            "yarn dlx pkg",
            "YARN_ENABLE_GLOBAL_CACHE",
        ),
        // Windows: either separator, and a `.cmd` or `.exe` launcher.
        (
            r#""C:\Program Files\nodejs\npx.cmd" -y pkg"#,
            "npx -y pkg",
            "npm_config_cache",
        ),
        (
            r#""C:\Program Files\nodejs\npx.CMD" -y pkg"#,
            "npx -y pkg",
            "npm_config_cache",
        ),
        (
            r#""C:\bun\bunx.exe" pkg"#,
            "bunx pkg",
            "BUN_INSTALL_CACHE_DIR",
        ),
    ] {
        let want = isolated_package_manager_env("thing", plain, HashMap::new());
        let got = isolated_package_manager_env("thing", quoted, HashMap::new());
        assert_eq!(got.get(var), want.get(var), "{quoted} was missed");
        assert!(got.contains_key(var), "{plain} itself got no {var}");
        assert_eq!(
            assigned_package_cache_dir("thing", quoted, &HashMap::new()),
            assigned_package_cache_dir("thing", plain, &HashMap::new()),
            "{quoted}: the repair records what the plain spelling records"
        );
    }
}

/// One start reads one assignment: the cache handed to the child is the one
/// the repair records (MIK-8831.REL.5).
#[test]
fn the_child_env_and_the_recorded_cache_come_from_one_assignment() {
    let (env, recorded) =
        crate::transport::isolated_env_and_assigned_cache("thing", "npx -y pkg", HashMap::new());
    assert_eq!(
        recorded
            .as_deref()
            .map(|dir| dir.to_string_lossy().into_owned()),
        env.get("npm_config_cache").cloned()
    );
    let (env, recorded) =
        crate::transport::isolated_env_and_assigned_cache("thing", "bunx pkg", HashMap::new());
    assert!(env.contains_key("BUN_INSTALL_CACHE_DIR"));
    assert_eq!(recorded, None, "only npm's cache is the repair's");
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
    // Yarn also gets Berry's global cache turned off, or Berry ignores the
    // folder (MIK-8147 D3b).
    for (cmd, var, count) in [
        ("npx -y pkg", "npm_config_cache", 1),
        ("bunx pkg", "BUN_INSTALL_CACHE_DIR", 2),
        ("/opt/bin/yarn dlx pkg", "YARN_CACHE_FOLDER", 2),
    ] {
        let out = isolated_package_manager_env("thing", cmd, HashMap::new());
        assert_eq!(out.len(), count, "{cmd}: {out:?}");
        assert!(out[var].contains("pkg-cache"), "{cmd} lacked {var}");
    }
    let out = isolated_package_manager_env("thing", "pnpm dlx pkg", HashMap::new());
    assert_eq!(out.len(), 4, "{out:?}");
    assert!(out["pnpm_config_store_dir"].contains("pkg-cache"));
    // `pnpm dlx` installs under `<cache-dir>/dlx`, not the store (MIK-8831.REL.6).
    for var in [
        "npm_config_store_dir",
        "pnpm_config_cache_dir",
        "npm_config_cache_dir",
    ] {
        assert_eq!(out["pnpm_config_store_dir"], out[var], "{var}");
    }
    // bunx installs the executable under the platform temp dir, which Bun
    // reads from `TMPDIR` first (MIK-8831.REL.6).
    let out = isolated_package_manager_env("thing", "bunx pkg", HashMap::new());
    assert_eq!(out["TMPDIR"], out["BUN_INSTALL_CACHE_DIR"]);
    let mut env = HashMap::new();
    env.insert("BUN_INSTALL_CACHE_DIR".to_string(), "/mine".to_string());
    let out = isolated_package_manager_env("thing", "bunx pkg", env);
    assert_eq!(out["BUN_INSTALL_CACHE_DIR"], "/mine");
    assert!(
        !out.contains_key("TMPDIR"),
        "an operator who chose one of bunx's dirs gets no other filled in: {out:?}"
    );
}

/// An operator who sets one of a runner's cache or store variables keeps
/// their choice: the gateway fills in none of that runner's others, or a
/// second variable could override or split what they asked for
/// (MIK-8831.REL.6).
#[test]
fn an_operator_value_for_one_runner_variable_leaves_all_of_them_alone() {
    for (command, key, vars) in [
        (
            "pnpm dlx pkg",
            "npm_config_store_dir",
            &[
                "pnpm_config_store_dir",
                "pnpm_config_cache_dir",
                "npm_config_cache_dir",
            ][..],
        ),
        (
            "pnpm dlx pkg",
            "pnpm_config_cache_dir",
            &[
                "pnpm_config_store_dir",
                "npm_config_store_dir",
                "npm_config_cache_dir",
            ][..],
        ),
        ("bunx pkg", "TMPDIR", &["BUN_INSTALL_CACHE_DIR"][..]),
        // Bun falls back from `TMPDIR` to `TMP` and `TEMP`: either is the
        // operator choosing the temp dir, which an injected `TMPDIR` would
        // override.
        ("bunx pkg", "TMP", &["BUN_INSTALL_CACHE_DIR", "TMPDIR"][..]),
        ("bunx pkg", "TEMP", &["BUN_INSTALL_CACHE_DIR", "TMPDIR"][..]),
    ] {
        let operator = HashMap::from([(key.to_owned(), "/operator/dir".to_owned())]);
        let out = isolated_package_manager_env("thing", command, operator);
        for var in vars {
            assert!(
                !out.contains_key(*var),
                "{command} with {key}: the gateway filled in {var}: {out:?}"
            );
        }
        assert_eq!(out[key], "/operator/dir");
    }
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
    assert_eq!(cache::usable("pkg-cache/b".into()), None);
    let absolute = std::env::temp_dir().join("pkg-cache").join("b");
    assert_eq!(
        cache::usable(absolute.clone()).as_deref(),
        absolute.to_str()
    );
    // npm expands `${VAR}` in a config value: such a path names another tree.
    assert_eq!(cache::usable(absolute.join("${HOME}")), None);
    // `..` is text to npm and a symlink walk to the filesystem.
    assert_eq!(cache::usable(absolute.join("..").join("b")), None);
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
