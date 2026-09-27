// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the per-backend package-cache helpers:
//! `isolated_package_manager_env`, and the three decisions the cache-recovery
//! path in `StdioTransport::start` rests on -- `forwarded_npm_config`,
//! `cache_failure`, and `remove_cache_dir`.
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
        forwarded_npm_config(Vec::<(std::ffi::OsString, std::ffi::OsString)>::new()).is_empty()
    );
    assert!(
        forwarded_npm_config(std::iter::empty::<(std::ffi::OsString, std::ffi::OsString)>())
            .is_empty(),
        "a source with no variables must not invent any"
    );
}

#[test]
fn only_keys_carrying_the_npm_config_prefix_are_forwarded() {
    // npm reads its environment case-insensitively, so the match is made on the
    // folded key: the uppercase spelling is the one npm's own documentation
    // uses. Credentials are the exception — a backend names its own.
    const CASES: [(&str, bool); 17] = [
        ("npm_config_allow_git", true),
        ("npm_config_registry", true),
        ("npm_config_prefer_offline", true),
        ("npm_config_", true),
        ("npm_config_cache_dir", true),
        ("NPM_CONFIG_ALLOW_GIT", true),
        ("NPM_CONFIG_REGISTRY", true),
        ("npm_config_cache", false),
        ("NPM_CONFIG_CACHE", false),
        ("npm_config__auth", false),
        ("npm_config_//registry.npmjs.org/:_authToken", false),
        ("NPM_CONFIG_//REGISTRY.NPMJS.ORG/:_AUTHTOKEN", false),
        ("npm_config_//registry.npmjs.org/:_password", false),
        ("npm_config", false),
        ("npm_configfoo", false),
        ("x_npm_config_foo", false),
        ("npm_config.cache", false),
    ];
    for (key, expected) in CASES {
        let forwarded = forwarded_npm_config(env_pairs(&[(key, "operator-value")]));
        if expected {
            assert_eq!(
                forwarded,
                env_pairs(&[(key, "operator-value")]),
                "{key:?} is an npm setting and must reach the child with its value"
            );
        } else {
            assert!(
                forwarded.is_empty(),
                "{key:?} is either not an `npm_config_` key, the cache the gateway assigns, or a \
                 credential the config did not name"
            );
        }
    }
}

#[test]
fn the_operators_cache_setting_yields_to_the_gateways_own() {
    let forwarded = forwarded_npm_config(env_pairs(&[
        ("npm_config_allow_git", "all"),
        ("npm_config_cache", "/root/.npm"),
        ("npm_config_registry", "https://registry.invalid"),
        ("npm_config_prefer_offline", "true"),
        ("PATH", "/usr/bin"),
    ]));
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_allow_git", "all"),
            ("npm_config_registry", "https://registry.invalid"),
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
            "npm_config_otel_endpoint",
            "http://collector.invalid:4318/v1/traces?service=mcp-gateway&a=1=2",
        ),
        ("npm_config_userconfig", "  /root/.npmrc  "),
        ("npm_config_", ""),
        ("npm_config_fund", "café ☕"),
    ]);
    assert_eq!(
        forwarded_npm_config(input.clone()),
        input,
        "a forwarded pair is the operator's own key and value: no trimming, no case folding, \
         no re-encoding"
    );
}

#[test]
fn repeated_keys_survive_in_the_order_they_arrived() {
    let forwarded = forwarded_npm_config(env_pairs(&[
        ("npm_config_registry", "https://first.invalid"),
        ("PATH", "/usr/bin"),
        ("npm_config_registry", "https://second.invalid"),
        ("npm_config_registry", "https://third.invalid"),
    ]));
    assert_eq!(
        forwarded,
        env_pairs(&[
            ("npm_config_registry", "https://first.invalid"),
            ("npm_config_registry", "https://second.invalid"),
            ("npm_config_registry", "https://third.invalid"),
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
    let forwarded = forwarded_npm_config(vec![
        (std::ffi::OsString::from_vec(hostile), "value".into()),
        (
            std::ffi::OsString::from("npm_config_allow_git"),
            "all".into(),
        ),
    ]);
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
    let forwarded = forwarded_npm_config(vec![(
        std::ffi::OsString::from("npm_config_cafile"),
        value.clone(),
    )]);
    assert_eq!(
        forwarded,
        vec![(std::ffi::OsString::from("npm_config_cafile"), value)],
        "only the key is read, so a non-UTF-8 value passes through byte for byte"
    );
}
