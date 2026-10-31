// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R1a: the radar's own scan finds what the environment names and reads no
//! client config file: those come from the shared discovery cache. Runs in a
//! child process, whose home and environment the row sets.

use super::AutoDiscovery;

const CASE: &str = "MCP_GW_TEST_NON_CLIENT_CASE";
/// The find a client config file in the child's home names.
const FILE_FIND: &str = "r1a-file-find";
/// The find an environment variable in the child names.
const ENV_FIND: &str = "r1a-env-find";

#[test]
fn the_radars_own_scan_finds_the_environment_and_no_client_file() {
    let home = tempfile::tempdir().expect("tempdir");
    let dir = home.path().join(".config/mcp");
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("servers.json"),
        format!(r#"{{"mcpServers": {{"{FILE_FIND}": {{"command": "npx"}}}}}}"#),
    )
    .expect("write");
    let out = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args([
            "--exact",
            "discovery::non_client_tests::child",
            "--ignored",
            "--nocapture",
        ])
        .env(CASE, "1")
        .env("MCP_GATEWAY_TEST_HOME_DIR", home.path())
        .env(
            "MCP_SERVER_R1A_ENV_FIND_URL",
            "https://env.example.internal/mcp",
        )
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    // Printed only after the child's assertions, so a child that ran no case
    // cannot read as a pass.
    assert!(stdout.contains("non-client child ok"), "{stdout}\n{stderr}");
}

#[test]
#[ignore = "run by the row above, in a child with its own home and environment"]
fn child() {
    if std::env::var(CASE).is_err() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let names = |found: Vec<super::DiscoveredServer>| -> Vec<String> {
        found.into_iter().map(|server| server.name).collect()
    };
    let discovery = AutoDiscovery::new();
    let all = names(runtime.block_on(discovery.discover_all()).expect("scan"));
    assert!(
        all.iter().any(|n| n == FILE_FIND) && all.iter().any(|n| n == ENV_FIND),
        "premise: the full scan sees both fixtures: {all:?}"
    );
    let own = names(
        runtime
            .block_on(discovery.discover_non_client())
            .expect("scan"),
    );
    assert!(
        own.iter().any(|n| n == ENV_FIND),
        "the environment find is missing: {own:?}"
    );
    assert!(
        !own.iter().any(|n| n == FILE_FIND),
        "the radar read a client config file itself: {own:?}"
    );
    println!("non-client child ok");
}
