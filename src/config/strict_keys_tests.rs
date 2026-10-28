// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `strict_keys.rs`: the refused, retired and annotation key tables.

use std::collections::BTreeSet;
use std::time::Duration;

use super::{
    A2A_BACKEND_KEYS, KNOWN_BACKEND_KEYS, REMOVED_KEYS, RETIRED_KEYS, is_annotation,
    missing_feature_for, removed_reason, retired_warning,
};

/// COLLUDE.1 §13.1 B4: a build without `firewall` names the feature for
/// the firewall block and anything under it; a build with it names none.
#[test]
fn a_firewall_key_names_the_missing_feature() {
    let without = |f: &str| f != "firewall";
    for key in ["security.firewall", "security.firewall.collusion"] {
        let leaf = key.rsplit('.').next().unwrap_or(key);
        assert_eq!(
            missing_feature_for(key, leaf, without),
            Some("firewall"),
            "{key}"
        );
        assert_eq!(missing_feature_for(key, leaf, |_| true), None, "{key}");
    }
    assert_eq!(
        missing_feature_for("security.firewalls", "firewalls", without),
        None
    );
}

/// MIK-8044 (T5b): a build without `cost-governance` still names the
/// feature for the block, `currency` included: the feature is the first
/// fix, and the removed-key refusal follows once it is on.
#[test]
fn a_cost_governance_key_names_the_missing_feature() {
    assert_eq!(
        missing_feature_for("cost_governance", "cost_governance", |_| false),
        Some("cost-governance")
    );
}

use crate::config::{BackendConfig, OAuthConfig, TransportConfig};
use crate::identity_propagation::IdentityPropagationConfig;
use crate::secret_injection::CredentialRule;

/// Drift guard for the hand list: every key a `BackendConfig` serializes,
/// across every transport variant, is on the list, and every list entry is
/// a key some variant serializes.
#[test]
fn known_backend_keys_match_struct() {
    let identity: IdentityPropagationConfig =
        crate::yaml::from_str("{strategy: token_exchange, audience: a, session_mode: stateless}")
            .expect("identity propagation sample parses");
    let transports = vec![
        TransportConfig::Stdio {
            command: "c".into(),
            cwd: Some("d".into()),
            protocol_version: Some("v".into()),
        },
        TransportConfig::Http {
            http_url: "h".into(),
            streamable_http: Some(true),
            protocol_version: Some("v".into()),
        },
        TransportConfig::WebSocket {
            ws_url: "w".into(),
            protocol_version: Some("v".into()),
        },
    ];
    // Shadowed, not `mut`: without `a2a` nothing is pushed.
    #[cfg(feature = "a2a")]
    let transports = {
        let mut all = transports;
        all.push(TransportConfig::A2a {
            a2a_url: "u".into(),
            a2a_agent_card_path: Some("p".into()),
        });
        all
    };
    let oauth: OAuthConfig = crate::yaml::from_str("{}").expect("oauth sample parses");
    let rule: CredentialRule = crate::yaml::from_str("{name: n, value: v, inject_key: k}")
        .expect("credential rule sample parses");
    let one = || std::iter::once(("k".to_owned(), "v".to_owned())).collect();
    let mut serialized = BTreeSet::new();
    for transport in transports {
        // Exhaustive on purpose, every optional field set: a new field is
        // a compile error here, and a field that skips serializing when
        // unset still shows up in `serialized`.
        let backend = BackendConfig {
            description: "d".into(),
            enabled: true,
            transport,
            stop_when_idle_for: Some(Duration::from_secs(1)),
            max_frame_bytes: Some(1 << 20),
            // timing: fixture
            timeout: Duration::from_secs(1),
            env: one(),
            headers: one(),
            oauth: Some(oauth.clone()),
            secrets: vec![rule.clone()],
            passthrough: true,
            input_schema_enforcement: crate::config::InputSchemaEnforcement::Standard,
            allow_flagged_tools: [("t".to_string(), "0".repeat(64))].into(),
            allowed_tools: Some(vec!["t".into()]),
            allow_cleartext_credentials: true,
            runtime_profile: Some("p".into()),
            identity_propagation: Some(identity.clone()),
            account: Some("a".into()),
            signature_chain: crate::config::ChainMode::Require,
            chain_origins: vec!["o".into()],
            chain_signer: Some("s".into()),
        };
        let value = crate::yaml::to_value(&backend).expect("backend serializes");
        let fields = value.as_mapping().expect("backend is a mapping");
        serialized.extend(fields.keys().filter_map(|k| k.as_str().map(str::to_owned)));
    }
    let mut listed: BTreeSet<String> = KNOWN_BACKEND_KEYS.iter().map(|k| (*k).to_owned()).collect();
    if cfg!(feature = "a2a") {
        listed.extend(A2A_BACKEND_KEYS.iter().map(|k| (*k).to_owned()));
    }
    // `url` never reaches the struct: the loader resolves it first.
    listed.remove("url");
    assert_eq!(
        serialized, listed,
        "KNOWN_BACKEND_KEYS drifted from BackendConfig"
    );
}

/// #2360: an annotation can never shadow a real key. Covers every backend
/// key and every key the default `Config` serializes, at any depth; a
/// section that is absent by default is not covered here.
#[test]
fn annotation_prefixes_name_no_real_key() {
    fn walk(value: &crate::yaml::Value, path: &str) {
        if let Some(map) = value.as_mapping() {
            for (key, child) in map {
                let key = key.as_str().unwrap_or_default();
                assert!(
                    !is_annotation(key),
                    "real key `{path}.{key}` looks like an annotation"
                );
                walk(child, &format!("{path}.{key}"));
            }
        }
    }
    for key in KNOWN_BACKEND_KEYS.iter().chain(A2A_BACKEND_KEYS) {
        assert!(!is_annotation(key), "backend key `{key}`");
    }
    let config = crate::yaml::to_value(crate::config::Config::default()).expect("serializes");
    walk(&config, "");
}

/// UPGRADING quotes the `request_timeout` refusal verbatim (MIK-8044).
#[test]
fn upgrading_quotes_the_request_timeout_refusal() {
    let (_, why) = REMOVED_KEYS
        .iter()
        .find(|(path, _)| *path == ["server", "request_timeout"])
        .expect("request_timeout is removed");
    let quote = removed_reason("server.request_timeout", why);
    assert!(
        include_str!("../../docs/UPGRADING-4.0.md").contains(&quote),
        "UPGRADING must quote: {quote}"
    );
}

/// #2360: a retired key warns once, an annotation logs at DEBUG once, and a
/// reload of the same file stays quiet. A refused file still warns first.
#[test]
fn ignored_keys_are_logged_once_even_beside_a_refusal() {
    use crate::test_log_capture::{count, records};
    let dir = tempfile::tempdir().expect("tempdir");
    let ok = dir.path().join("ok.yaml");
    let bad = dir.path().join("bad.yaml");
    let write = crate::gateway::test_helpers::write_owner_only;
    write(
        &ok,
        "meta_mcp:\n  cache_tools: false\nbackends:\n  x:\n    command: y\n    _note: n\n",
    )
    .expect("write ok");
    write(
        &bad,
        "meta_mcp:\n  cache_tools: false\nbackends:\n  x:\n    command: y\n    idel: 1\n",
    )
    .expect("write bad");
    let logs = records(|| {
        crate::config::Config::load(Some(&ok)).expect("loads");
        crate::config::Config::load(Some(&ok)).expect("reloads");
        crate::config::Config::load(Some(&bad)).expect_err("typo refuses");
    });
    let retired = "`meta_mcp.cache_tools` is ignored since 4.0";
    assert_eq!(count(&logs, "WARN", retired), 2, "once per file: {logs:?}");
    assert_eq!(
        count(&logs, "DEBUG", "`backends.x._note` is an annotation"),
        1
    );
}

/// D6 F14: a misspelt rotation key fails the load and names the key, so
/// the defaults never run while the operator believes otherwise.
#[test]
fn strict_keys_reject_unknown_rotation_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        "security:\n  transparency_log:\n    rotation:\n      max_segment_byte: 1\n",
    )
    .expect("write config");
    let err = crate::config::Config::load(Some(&path))
        .expect_err("a misspelt rotation key must fail the load")
        .to_string();
    assert!(err.contains("max_segment_byte"), "{err}");
}

/// The `plugin` command is removed in 4.0: a config that still carries its
/// `marketplace` block is refused with the reason, and warns nothing.
#[test]
fn removed_marketplace_block_is_refused_not_warned() {
    use crate::test_log_capture::{count, records};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        "marketplace:\n  marketplace_url: https://plugins.example\n  plugin_dir: /tmp/p\n",
    )
    .expect("write config");
    let mut refusal = String::new();
    let logs = records(|| {
        refusal = crate::config::Config::load(Some(&path))
            .expect_err("refused")
            .to_string();
    });
    assert!(
        refusal.contains("`marketplace` was removed in 4.0")
            && refusal.contains("mcp-gateway upgrade"),
        "{refusal}"
    );
    assert_eq!(count(&logs, "WARN", "`marketplace`"), 0, "{logs:?}");
}

/// MIK-8064: `meta_mcp.cache_tools` was read by nothing; a config that
/// still sets it loads, and says once that the key does nothing.
#[test]
fn retired_cache_tools_loads_and_warns_once() {
    use crate::test_log_capture::{count, records};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "meta_mcp:\n  cache_tools: false\n")
        .expect("write config");
    let logs = records(|| {
        crate::config::Config::load(Some(&path)).expect("loads");
        crate::config::Config::load(Some(&path)).expect("reloads");
    });
    let retired = "`meta_mcp.cache_tools` is ignored since 4.0";
    assert_eq!(count(&logs, "WARN", retired), 1, "{logs:?}");
}

/// MIK-8064: UPGRADING quotes the `cache_tools` warning verbatim.
#[test]
fn upgrading_quotes_the_cache_tools_warning() {
    let why = RETIRED_KEYS
        .iter()
        .find(|(path, _)| *path == ["meta_mcp", "cache_tools"])
        .map(|(_, why)| *why);
    let quote = why.map(|why| retired_warning("meta_mcp.cache_tools", why));
    assert!(
        quote
            .as_deref()
            .is_some_and(|quote| include_str!("../../docs/UPGRADING-4.0.md").contains(quote)),
        "UPGRADING must quote the cache_tools warning: {quote:?}"
    );
}

/// UPGRADING quotes the `marketplace` refusal verbatim (MIK-8044).
#[test]
fn upgrading_quotes_the_marketplace_refusal() {
    let (_, why) = REMOVED_KEYS
        .iter()
        .find(|(path, _)| *path == ["marketplace"])
        .expect("marketplace is removed");
    let quote = removed_reason("marketplace", why);
    assert!(
        include_str!("../../docs/UPGRADING-4.0.md").contains(&quote),
        "UPGRADING must quote: {quote}"
    );
}
