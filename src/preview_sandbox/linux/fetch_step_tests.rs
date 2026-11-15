// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the helper's npm fetch step (R-env).

use super::npm_env;

/// Kills "a variable is added, dropped or changed": the npm environment is
/// exactly this list, the credential and relay port substituted.
#[test]
fn the_npm_environment_is_exactly_the_designed_list() {
    let mut got = npm_env("c0ffee", 41_234, "/usr/lib/node/bin:/usr/lib/npm/bin");
    got.sort();
    let proxy = "http://x:c0ffee@127.0.0.1:41234";
    let ca = "/etc/mcp-gateway-preview/ca.pem";
    let empty = "/etc/mcp-gateway-preview/empty.npmrc";
    let mut want: Vec<(String, String)> = [
        ("PATH", "/usr/lib/node/bin:/usr/lib/npm/bin"),
        ("HOME", "/preview-home"),
        ("TMPDIR", "/preview-home"),
        ("HTTPS_PROXY", proxy),
        ("HTTP_PROXY", proxy),
        ("npm_config_https_proxy", proxy),
        ("npm_config_proxy", proxy),
        ("NO_PROXY", ""),
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_registry", "https://registry.npmjs.org/"),
        ("npm_config_git", "/nonexistent/git"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
        ("npm_config_cafile", ca),
        ("npm_config_strict_ssl", "true"),
        ("npm_config_userconfig", empty),
        ("npm_config_globalconfig", empty),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    want.sort();
    assert_eq!(got, want);
}
