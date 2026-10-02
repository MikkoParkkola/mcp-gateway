// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a stdio child's environment holds. Moved out of `stdio_tests.rs`
//! with the code it tests, to keep that file under the file-size ceiling.

use std::collections::HashMap;
use std::ffi::OsString;

use super::forwarded_npm_config;

#[cfg(unix)] // Unix-only: the scenario builds a real transport.
use crate::transport::{StdioTransport, Transport};

#[cfg(unix)] // Unix-only child environment scenario: shared by the two env-isolation tests below.
const CHILD_SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_CHILD_ENV_SCENARIO";
#[cfg(unix)] // Unix-only child environment scenario: shared by the two env-isolation tests below.
const PARENT_SECRET_ENV: &str = "MCP_GATEWAY_TEST_PARENT_SECRET";
#[cfg(unix)] // Unix-only child environment scenario: shared by the two env-isolation tests below.
const EXPLICIT_BACKEND_ENV: &str = "MCP_GATEWAY_TEST_EXPLICIT_BACKEND";

#[test]
#[cfg(unix)] // Unix-only child environment scenario: the backend is an sh script probing its stripped environment.
fn backend_subprocess_receives_only_safe_and_explicit_environment() {
    let current_test_binary = std::env::current_exe().expect("resolve current test binary");
    let scenario_name =
        "transport::stdio::child_env::tests::stdio_child_environment_isolation_scenario";
    let output = std::process::Command::new(current_test_binary)
        .args(["--exact", scenario_name, "--nocapture"])
        .env(CHILD_SCENARIO_ENV, "1")
        .env(
            PARENT_SECRET_ENV,
            "dummy-parent-secret-must-not-reach-backend",
        )
        // The operator's npm settings in both spellings npm reads, a credential
        // no backend's config names, and a setting the backend overrides.
        .env("npm_config_allow_git", "all")
        .env("NPM_CONFIG_PREFER_OFFLINE", "1")
        .env("npm_config__auth", "must-not-reach-a-backend")
        .env("npm_config_strict_ssl", "false")
        .output()
        .expect("run isolated child-environment scenario");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(scenario_name),
        "nested test filter did not execute the environment scenario; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        output.status.success(),
        "stdio child environment scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test]
#[cfg(unix)] // Unix-only child environment scenario: the backend is an sh script probing its stripped environment.
async fn stdio_child_environment_isolation_scenario() {
    if std::env::var_os(CHILD_SCENARIO_ENV).is_none() {
        return;
    }
    assert!(
        std::env::var_os(PARENT_SECRET_ENV).is_some(),
        "nested scenario must start with the parent-only sentinel present"
    );

    let workspace = tempfile::tempdir().expect("create stdio child workspace");
    let server = workspace.path().join("server.sh");
    std::fs::write(
        &server,
        r#"while IFS= read -r request; do
case "$request" in
    *'"method":"initialize"'*)
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}'
        ;;
    *'"method":"env/check"'*)
        parent_secret_present=false
        explicit_backend_present=false
        path_present=false
        home_present=false
        tmpdir_present=false
        cwd_preserved=false
        npm_setting_present=false
        npm_upper_setting_present=false
        npm_credential_present=false
        npm_operator_override_present=false
        [ "${MCP_GATEWAY_TEST_PARENT_SECRET+x}" = x ] && parent_secret_present=true
        [ "${MCP_GATEWAY_TEST_EXPLICIT_BACKEND:-}" = configured-value ] && explicit_backend_present=true
        [ -n "${PATH:-}" ] && path_present=true
        [ -n "${HOME:-}" ] && home_present=true
        [ -n "${TMPDIR:-}" ] && tmpdir_present=true
        [ -f server.sh ] && cwd_preserved=true
        [ "${npm_config_allow_git:-}" = all ] && npm_setting_present=true
        [ "${NPM_CONFIG_PREFER_OFFLINE:-}" = 1 ] && npm_upper_setting_present=true
        [ "${npm_config__auth+x}" = x ] && npm_credential_present=true
        [ "${npm_config_strict_ssl+x}" = x ] && npm_operator_override_present=true
        printf '{"jsonrpc":"2.0","id":2,"result":{"parent_secret_present":%s,"explicit_backend_present":%s,"path_present":%s,"home_present":%s,"tmpdir_present":%s,"cwd_preserved":%s,"npm_setting_present":%s,"npm_upper_setting_present":%s,"npm_credential_present":%s,"npm_operator_override_present":%s}}\n' \
            "$parent_secret_present" "$explicit_backend_present" "$path_present" \
            "$home_present" "$tmpdir_present" "$cwd_preserved" \
            "$npm_setting_present" "$npm_upper_setting_present" "$npm_credential_present" \
            "$npm_operator_override_present"
        ;;
esac
done
"#,
    )
    .expect("write stdio child server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::from([
            (
                EXPLICIT_BACKEND_ENV.to_string(),
                "configured-value".to_string(),
            ),
            // The backend's own spelling of a setting the operator also sets.
            ("NPM_CONFIG_STRICT_SSL".to_string(), "true".to_string()),
        ]),
        Some(workspace.path().to_string_lossy().into_owned()),
        std::time::Duration::from_secs(5),
        None,
    );

    transport.start().await.expect("start stdio child server");
    let response = transport
        .request("env/check", None)
        .await
        .expect("request child environment report");
    transport.close().await.expect("close stdio child server");

    let report = response.result.expect("environment report result");
    assert_eq!(report["parent_secret_present"], false);
    assert_eq!(report["explicit_backend_present"], true);
    assert_eq!(report["path_present"], true);
    assert_eq!(report["home_present"], true);
    assert_eq!(report["tmpdir_present"], true);
    assert_eq!(report["cwd_preserved"], true);
    assert_eq!(
        report["npm_setting_present"], true,
        "a setting that decides whether a git-sourced dependency can install at all must reach \
         the package manager the backend shells out to"
    );
    assert_eq!(
        report["npm_upper_setting_present"], true,
        "npm reads its environment case-insensitively, so the uppercase spelling is a setting too"
    );
    assert_eq!(
        report["npm_credential_present"], false,
        "a credential the config does not name for this backend must not be inherited"
    );
    assert_eq!(
        report["npm_operator_override_present"], false,
        "the backend sets strict_ssl in its own spelling, so the operator's lowercase key must not \
         also reach the child: npm keeps the last one it reads, and that would be the operator's"
    );
}

// The npm settings allowlist: the unit tests below are from #1760 by
// @terafin, carried onto this branch.

fn env_pairs(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(key, value)| (OsString::from(*key), OsString::from(*value)))
        .collect()
}

/// The filter with no backend configuration on top.
fn forwarded<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    forwarded_npm_config(vars, &HashMap::new())
}

#[test]
fn nothing_in_forwards_nothing_out() {
    assert!(
        forwarded(std::iter::empty::<(OsString, OsString)>()).is_empty(),
        "a source with no variables must not invent any"
    );
}

#[test]
fn only_the_settings_on_the_allowlist_are_forwarded() {
    // The match is on the folded key: npm reads its environment
    // case-insensitively, and `NPM_CONFIG_ALLOW_GIT` is the spelling npm's own
    // documentation uses. Everything off the list stays behind, whether it is a
    // credential, the cache the gateway assigns, or simply unknown.
    const CASES: [(&str, bool); 22] = [
        ("npm_config_allow_git", true),
        ("npm_config_prefer_offline", true),
        ("npm_config_offline", true),
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
        let out = forwarded(env_pairs(&[(key, "operator-value")]));
        if expected {
            assert_eq!(
                out,
                env_pairs(&[(key, "operator-value")]),
                "{key:?} is on the allowlist and must reach the child with its value"
            );
        } else {
            assert!(
                out.is_empty(),
                "{key:?} is not a setting the gateway passes on: it is the cache the gateway \
                 assigns, a credential, or something no backend asked for"
            );
        }
    }
}

#[test]
fn the_operators_cache_setting_yields_to_the_gateways_own() {
    let out = forwarded(env_pairs(&[
        ("npm_config_allow_git", "all"),
        ("npm_config_cache", "/root/.npm"),
        ("npm_config_registry", "https://user:pass@registry.invalid"),
        ("npm_config_prefer_offline", "true"),
        ("PATH", "/usr/bin"),
    ]));
    assert_eq!(
        out,
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
        forwarded(input.clone()),
        input,
        "a forwarded pair is the operator's own key and value: no trimming, no case folding, \
         no re-encoding"
    );
}

#[test]
fn repeated_keys_survive_in_the_order_they_arrived() {
    let out = forwarded(env_pairs(&[
        ("npm_config_cafile", "/etc/ssl/first.pem"),
        ("PATH", "/usr/bin"),
        ("npm_config_cafile", "/etc/ssl/second.pem"),
    ]));
    assert_eq!(
        out,
        env_pairs(&[
            ("npm_config_cafile", "/etc/ssl/first.pem"),
            ("npm_config_cafile", "/etc/ssl/second.pem"),
        ]),
        "the filter drops nothing and reorders nothing: the last pair still wins when the child \
         environment is built"
    );
}

#[test]
fn a_backends_own_setting_wins_in_any_spelling() {
    // Both keys would otherwise reach the child, and on unix the environment
    // is passed sorted, so the operator's lowercase key is read last and wins.
    let operator = env_pairs(&[
        ("npm_config_strict_ssl", "false"),
        ("NPM_CONFIG_CAFILE", "/etc/ssl/operator.pem"),
        ("npm_config_loglevel", "warn"),
    ]);
    let backend = HashMap::from([
        ("NPM_CONFIG_STRICT_SSL".to_string(), "true".to_string()),
        (
            "npm_config_cafile".to_string(),
            "/etc/ssl/backend.pem".to_string(),
        ),
    ]);
    assert_eq!(
        forwarded_npm_config(operator, &backend),
        env_pairs(&[("npm_config_loglevel", "warn")]),
        "a setting the backend names, in any spelling, is the backend's; the operator's value \
         reaches only the backends that leave it unset"
    );
}

#[cfg(unix)]
#[test]
fn a_key_that_is_not_utf8_is_dropped_rather_than_mangled() {
    use std::os::unix::ffi::OsStringExt;

    let mut hostile = b"npm_config_".to_vec();
    hostile.push(0xff);
    let out = forwarded(vec![
        (OsString::from_vec(hostile), "value".into()),
        (OsString::from("npm_config_allow_git"), "all".into()),
    ]);
    assert_eq!(
        out,
        env_pairs(&[("npm_config_allow_git", "all")]),
        "a key that is not UTF-8 has no name the filter can read, so it must be dropped"
    );
}

#[cfg(unix)]
#[test]
fn a_value_that_is_not_utf8_is_forwarded_unchanged() {
    use std::os::unix::ffi::OsStringExt;

    let value = OsString::from_vec(b"/root/npm/cafile/\xff\xfe.pem".to_vec());
    let out = forwarded(vec![(OsString::from("npm_config_cafile"), value.clone())]);
    assert_eq!(
        out,
        vec![(OsString::from("npm_config_cafile"), value)],
        "only the key is read, so a non-UTF-8 value passes through byte for byte"
    );
}
