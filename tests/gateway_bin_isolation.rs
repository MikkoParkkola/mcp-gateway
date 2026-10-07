// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7637: a gateway started through `gateway_bin` with nothing inherited (the
//! case of every spawner that used to call `env_clear`) still resolves its home
//! to the fixture: the default task store it opens at startup is created there.
//! Before the helper, a spawner that cleared the environment and forgot one
//! isolation variable left the child to find the developer's real home.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Stdio;
use std::time::{Duration, Instant};

#[test]
fn a_cleared_environment_still_opens_the_store_under_the_fixture_home() {
    let fixture = tempfile::tempdir().expect("a fixture home");
    let store = fixture.path().join(".mcp-gateway").join("tasks");
    let mut child = gateway_bin::command(fixture.path(), gateway_bin::Inherit::Nothing)
        .args(["serve", "--stdio"])
        .current_dir(fixture.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the gateway starts");

    // Bounded only as a hang guard: the store appears as the child starts.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !store.is_dir() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("the gateway exited ({status}) before opening its store");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let opened = store.is_dir();

    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("child status").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    assert!(
        opened,
        "the default task store was not created under the fixture home {}",
        fixture.path().display()
    );
}
