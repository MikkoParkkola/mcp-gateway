// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7217.STDIO.1: the stdio `server/discover` answer advertises 2026-07-28
//! when the modern protocol is on, asserted by exact version lists.
//!
//! Test plan: `docs/design/2026-09-30-sub4-stdio-owner-test-plan.md` (I5);
//! design D7 in `docs/design/2026-09-30-sub4-stdio-owner.md`. Driven through
//! `Gateway::run_stdio_on` over in-memory pipes, so the rows compile before and
//! after the fix.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::gateway::Gateway;

/// `supportedVersions` from a stdio gateway whose config sets
/// `server.modern_protocol` to `modern`.
async fn discovered_versions(modern: bool) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    config.server.modern_protocol = modern;
    config.tasks.store_dir = dir.path().join("tasks").display().to_string();
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let discover = json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}});
    stdin
        .write_all(format!("{discover}\n").as_bytes())
        .await
        .expect("write");
    let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("discover answered in time")
        .expect("read")
        .expect("a line");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(40), served)
        .await
        .expect("EOF returns")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    let answer: Value = serde_json::from_str(&line).expect("one frame");
    answer["result"]["supportedVersions"]
        .as_array()
        .unwrap_or_else(|| panic!("supportedVersions is a list: {answer}"))
        .iter()
        .map(|version| version.as_str().expect("a version string").to_owned())
        .collect()
}

fn listed(versions: &[&str]) -> Vec<String> {
    versions
        .iter()
        .map(|version| (*version).to_owned())
        .collect()
}

/// S1: modern on. The list is exactly the legacy revisions, then 2026-07-28.
#[tokio::test]
async fn stdio_discover_advertises_2026_when_modern_is_on() {
    let mut expected = listed(crate::protocol::SUPPORTED_VERSIONS);
    expected.extend(listed(crate::protocol::meta::MODERN_VERSIONS));
    assert_eq!(discovered_versions(true).await, expected);
}

/// S2: modern off. The list is exactly the legacy revisions.
#[tokio::test]
async fn stdio_discover_hides_2026_when_modern_is_off() {
    assert_eq!(
        discovered_versions(false).await,
        listed(crate::protocol::SUPPORTED_VERSIONS)
    );
}
