// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a stdio child's environment holds. Moved out of `stdio_tests.rs`
//! with the code it tests, to keep that file under the file-size ceiling.

#[cfg(unix)] // Unix-only: the scenario builds a real transport.
use std::collections::HashMap;

#[cfg(unix)] // Unix-only: the scenario builds a real transport.
use crate::transport::StdioTransport;

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
        [ "${MCP_GATEWAY_TEST_PARENT_SECRET+x}" = x ] && parent_secret_present=true
        [ "${MCP_GATEWAY_TEST_EXPLICIT_BACKEND:-}" = configured-value ] && explicit_backend_present=true
        [ -n "${PATH:-}" ] && path_present=true
        [ -n "${HOME:-}" ] && home_present=true
        [ -n "${TMPDIR:-}" ] && tmpdir_present=true
        [ -f server.sh ] && cwd_preserved=true
        printf '{"jsonrpc":"2.0","id":2,"result":{"parent_secret_present":%s,"explicit_backend_present":%s,"path_present":%s,"home_present":%s,"tmpdir_present":%s,"cwd_preserved":%s}}\n' \
            "$parent_secret_present" "$explicit_backend_present" "$path_present" \
            "$home_present" "$tmpdir_present" "$cwd_preserved"
        ;;
esac
done
"#,
    )
    .expect("write stdio child server");

    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::from([(
            EXPLICIT_BACKEND_ENV.to_string(),
            "configured-value".to_string(),
        )]),
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
}
