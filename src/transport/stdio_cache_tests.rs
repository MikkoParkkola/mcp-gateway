// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the two package-manager environment helpers a stdio child is
//! built from: `isolated_package_manager_env`, which gives each backend its own
//! npm cache, and `forwarded_npm_config`, the allowlist of the operator's npm
//! settings that reach every backend.
//!
//! Split out of `stdio_tests.rs` so it stays under the file-size ceiling
//! `scripts/dev/check-file-size.py` gates. A `#[path]` child, not a
//! sibling module: `use super::*` still resolves to the transport's own
//! items, so nothing had to be widened to move it here.

use super::env::forwarded_npm_config;
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

fn env_pairs(pairs: &[(&str, &str)]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    pairs
        .iter()
        .map(|(key, value)| {
            (
                std::ffi::OsString::from(*key),
                std::ffi::OsString::from(*value),
            )
        })
        .collect()
}

#[test]
fn nothing_in_forwards_nothing_out() {
    assert!(
        forwarded_npm_config(
            Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
            &HashMap::new()
        )
        .is_empty()
    );
    assert!(
        forwarded_npm_config(
            std::iter::empty::<(std::ffi::OsString, std::ffi::OsString)>(),
            &HashMap::new()
        )
        .is_empty(),
        "a source with no variables must not invent any"
    );
}

#[test]
fn only_the_settings_on_the_allowlist_are_forwarded() {
    // The match is on the folded key: npm reads its environment
    // case-insensitively, and `NPM_CONFIG_ALLOW_GIT` is the spelling npm's own
    // documentation uses. Everything off the list stays behind, whether it is a
    // credential, the cache the gateway assigns, or simply unknown.
    const CASES: [(&str, bool); 21] = [
        ("npm_config_allow_git", true),
        ("npm_config_prefer_offline", true),
        ("npm_config_cafile", true),
        ("npm_config_strict_ssl", true),
        ("npm_config_loglevel", true),
        ("NPM_CONFIG_ALLOW_GIT", true),
        ("NPM_CONFIG_PREFER_OFFLINE", true),
        ("npm_config_cache", false),
        ("NPM_CONFIG_CACHE", false),
        ("npm_config_registry", false),
        ("npm_config_https_proxy", false),
        ("npm_config_userconfig", false),
        ("npm_config__auth", false),
        ("npm_config_//registry.npmjs.org/:_authToken", false),
        ("NPM_CONFIG_//REGISTRY.NPMJS.ORG/:_AUTHTOKEN", false),
        ("npm_config__password", false),
        ("npm_config_key", false),
        ("npm_config_certfile", false),
        ("npm_config_keyfile", false),
        ("npm_config", false),
        ("npm_configfoo", false),
    ];
    for (key, expected) in CASES {
        let forwarded =
            forwarded_npm_config(env_pairs(&[(key, "operator-value")]), &HashMap::new());
        if expected {
            assert_eq!(
                forwarded,
                env_pairs(&[(key, "operator-value")]),
                "{key:?} is on the allowlist and must reach the child with its value"
            );
        } else {
            assert!(
                forwarded.is_empty(),
                "{key:?} is not a setting the gateway passes on: it is the cache the gateway                  assigns, a credential, or something no backend asked for"
            );
        }
    }
}

#[test]
fn a_setting_off_the_allowlist_never_reaches_a_child() {
    // The shapes a deny list would have to anticipate, one case each: the
    // maintainer's list of what a substring rule let through.
    const CREDENTIAL_SHAPES: [&str; 7] = [
        "npm_config__password",
        "npm_config_key",
        "npm_config_certfile",
        "npm_config_keyfile",
        "npm_config_userconfig",
        "npm_config_https_proxy",
        "npm_config_registry",
    ];
    let forwarded = forwarded_npm_config(
        env_pairs(&CREDENTIAL_SHAPES.map(|key| (key, "secret-value"))),
        &HashMap::new(),
    );
    assert!(
        forwarded.is_empty(),
        "an allowlist forwards nothing it does not name: {forwarded:?}"
    );
}

#[test]
fn the_operators_cache_setting_yields_to_the_gateways_own() {
    let forwarded = forwarded_npm_config(
        env_pairs(&[
            ("npm_config_allow_git", "all"),
            ("npm_config_cache", "/root/.npm"),
            ("npm_config_registry", "https://user:pass@registry.invalid"),
            ("npm_config_prefer_offline", "true"),
            ("PATH", "/usr/bin"),
        ]),
        &HashMap::new(),
    );
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_allow_git", "all"),
            ("npm_config_prefer_offline", "true"),
        ]),
        "the cache directory is the gateway's to assign per backend: forwarding the operator's \
         would put every backend on one shared tree and tear it"
    );
}

#[test]
fn forwarded_pairs_keep_their_bytes_exactly() {
    let input = env_pairs(&[
        ("npm_config_cafile", "/etc/ssl/ca cert.pem"),
        (
            "npm_config_loglevel",
            "http://collector.invalid:4318/v1/traces?service=mcp-gateway&a=1=2",
        ),
        ("npm_config_strict_ssl", "  true  "),
        ("npm_config_offline", ""),
        ("npm_config_prefer_offline", "café ☕"),
    ]);
    assert_eq!(
        forwarded_npm_config(input.clone(), &HashMap::new()),
        input,
        "a forwarded pair is the operator's own key and value: no trimming, no case folding, \
         no re-encoding"
    );
}

#[test]
fn repeated_keys_survive_in_the_order_they_arrived() {
    let forwarded = forwarded_npm_config(
        env_pairs(&[
            ("npm_config_cafile", "/etc/ssl/first.pem"),
            ("PATH", "/usr/bin"),
            ("npm_config_cafile", "/etc/ssl/second.pem"),
            ("npm_config_cafile", "/etc/ssl/third.pem"),
        ]),
        &HashMap::new(),
    );
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_cafile", "/etc/ssl/first.pem"),
            ("npm_config_cafile", "/etc/ssl/second.pem"),
            ("npm_config_cafile", "/etc/ssl/third.pem"),
        ]),
        "the filter drops nothing and reorders nothing: the last pair is still the one that wins \
         when the child environment is built"
    );
}

#[cfg(unix)]
#[test]
fn a_key_that_is_not_utf8_is_dropped_rather_than_mangled() {
    use std::os::unix::ffi::OsStringExt;

    let mut hostile = b"npm_config_".to_vec();
    hostile.push(0xff);
    let forwarded = forwarded_npm_config(
        vec![
            (std::ffi::OsString::from_vec(hostile), "value".into()),
            (
                std::ffi::OsString::from("npm_config_allow_git"),
                "all".into(),
            ),
        ],
        &HashMap::new(),
    );
    assert_eq!(
        forwarded,
        env_pairs(&[("npm_config_allow_git", "all")]),
        "a key that is not UTF-8 has no name the filter can read, so it must be dropped: \
         lossily decoding it would forward an `npm_config_` key under a mangled name"
    );
}

#[cfg(unix)]
#[test]
fn a_value_that_is_not_utf8_is_forwarded_unchanged() {
    use std::os::unix::ffi::OsStringExt;

    let value = std::ffi::OsString::from_vec(b"/root/npm/cafile/\xff\xfe.pem".to_vec());
    let forwarded = forwarded_npm_config(
        vec![(std::ffi::OsString::from("npm_config_cafile"), value.clone())],
        &HashMap::new(),
    );
    assert_eq!(
        forwarded,
        vec![(std::ffi::OsString::from("npm_config_cafile"), value)],
        "only the key is read, so a non-UTF-8 value passes through byte for byte"
    );
}

/// The case the fold has to cover: the operator exports the lowercase
/// `npm_config_strict_ssl=false` and the backend configures
/// `NPM_CONFIG_STRICT_SSL=true`. The child receives one value, the backend's.
#[test]
fn a_backends_own_setting_survives_the_operators_spelling() {
    let backend = HashMap::from([("NPM_CONFIG_STRICT_SSL".to_string(), "true".to_string())]);
    let forwarded = forwarded_npm_config(
        env_pairs(&[
            ("npm_config_strict_ssl", "false"),
            ("npm_config_cafile", "/etc/ssl/corp-ca.pem"),
        ]),
        &backend,
    );
    assert_eq!(
        forwarded,
        env_pairs(&[("npm_config_cafile", "/etc/ssl/corp-ca.pem")]),
        "the backend names strict_ssl, so the operator's is not forwarded at all: the child \
         sees one value for the setting and it is the backend's"
    );
}

#[test]
fn a_backend_can_match_the_operator_spelling_for_spelling() {
    // Every mixed pairing folds the same way, so any of them suppresses.
    for configured in [
        "npm_config_strict_ssl",
        "NPM_CONFIG_STRICT_SSL",
        "Npm_Config_Strict_Ssl",
        "npm_CONFIG_strict_SSL",
    ] {
        let forwarded = forwarded_npm_config(
            env_pairs(&[("npm_config_strict_ssl", "false")]),
            &HashMap::from([(configured.to_string(), "true".to_string())]),
        );
        assert!(
            forwarded.is_empty(),
            "a backend spelling of {configured:?} names the same setting npm reads, so nothing \
             may be forwarded beside it: {forwarded:?}"
        );
    }
}

#[test]
fn a_backend_naming_an_unforwarded_setting_changes_nothing() {
    // Suppression is limited to settings the gateway would otherwise forward.
    let backend = HashMap::from([
        ("npm_config_cache".to_string(), "/custom/cache".to_string()),
        (
            "npm_config_registry".to_string(),
            "https://registry.invalid".to_string(),
        ),
        (
            "NPM_CONFIG_USERCONFIG".to_string(),
            "/root/.npmrc".to_string(),
        ),
    ]);
    let forwarded = forwarded_npm_config(
        env_pairs(&[
            ("npm_config_strict_ssl", "false"),
            ("npm_config_cafile", "/etc/ssl/corp-ca.pem"),
        ]),
        &backend,
    );
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_strict_ssl", "false"),
            ("npm_config_cafile", "/etc/ssl/corp-ca.pem"),
        ]),
        "settings the gateway does not forward cannot suppress the ones it does"
    );
}

#[test]
fn one_backend_setting_suppresses_only_its_own_setting() {
    let backend = HashMap::from([("npm_config_prefer_offline".to_string(), "true".to_string())]);
    let forwarded = forwarded_npm_config(
        env_pairs(&[
            ("npm_config_prefer_offline", "false"),
            ("npm_config_loglevel", "warn"),
            ("NPM_CONFIG_OFFLINE", "false"),
        ]),
        &backend,
    );
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_loglevel", "warn"),
            ("NPM_CONFIG_OFFLINE", "false"),
        ]),
        "the suppression is per setting: prefer_offline is the backend's, the other two are the \
         operator's"
    );
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
