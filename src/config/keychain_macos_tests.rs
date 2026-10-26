// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The macOS keychain against a temporary keychain each test creates, because
//! a runner's login keychain may be locked, and with prompts off that fails
//! for reasons that are not the code's.
//!
//! macOS adds a created keychain to the user's search list and the framework
//! has no safe call to remove it, so a dangling entry for a deleted temporary
//! directory can remain; macOS skips a search-list path that no longer exists.

use std::time::{Duration, Instant};

use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};

use super::keychain::{KeychainError, KeychainRead};
use super::keychain_macos::MacKeychain;

const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

/// An unlocked temporary keychain holding `entries` under the gateway's
/// account. The directory must outlive the keychain.
fn temporary_keychain(entries: &[(&str, &[u8])]) -> (tempfile::TempDir, SecKeychain) {
    let dir = tempfile::tempdir().expect("tempdir");
    let keychain = CreateOptions::new()
        .password("temporary")
        .create(dir.path().join("gateway-test.keychain"))
        .expect("create a temporary keychain");
    for (name, bytes) in entries {
        keychain
            .add_generic_password(name, "mcp-gateway", bytes)
            .expect("add an entry");
    }
    (dir, keychain)
}

fn backend(keychain: &SecKeychain, bound: Duration, delay: Duration) -> MacKeychain {
    MacKeychain::with_keychains(vec![keychain.clone()], bound, delay)
}

#[test]
fn an_entry_reads_back_byte_exact() {
    let (_dir, keychain) = temporary_keychain(&[("gw-exact", b" a\n")]);
    let read = backend(&keychain, Duration::from_secs(2), Duration::ZERO)
        .read("gw-exact")
        .expect("read");
    assert_eq!(read.as_bytes(), b" a\n");
}

#[test]
fn a_missing_name_is_missing() {
    let (_dir, keychain) = temporary_keychain(&[("gw-present", b"x")]);
    let err = backend(&keychain, Duration::from_secs(2), Duration::ZERO)
        .read("gw-absent")
        .expect_err("absent");
    assert_eq!(err, KeychainError::Missing);
}

/// Set in the child that [`guard_child`] runs in.
const GUARD_CHILD: &str = "MCP_GW_TEST_KEYCHAIN_GUARD_CHILD";

/// The prompt flag is process-wide, so it is checked in a fresh process where
/// no other test can have set it: on before any backend, off after two
/// backends and an overlay are built and dropped.
#[test]
#[ignore = "run by prompts_stay_off_after_every_backend_is_dropped, in a child"]
fn guard_child() {
    if std::env::var_os(GUARD_CHILD).is_none() {
        return;
    }
    let allowed = || SecKeychain::user_interaction_allowed().expect("read the prompt flag");
    assert!(allowed(), "a fresh process already had prompts off");
    let (_dir, keychain) = temporary_keychain(&[]);
    drop(backend(&keychain, Duration::from_secs(2), Duration::ZERO));
    drop(MacKeychain::search_list());
    drop(super::EnvOverlay::none());
    assert!(!allowed(), "keychain prompts came back on");
    // Printed only after both checks, so a child that ran nothing fails.
    println!("keychain guard child ok");
}

#[test]
fn prompts_stay_off_after_every_backend_is_dropped() {
    let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "config::keychain_macos_tests::guard_child",
            "--ignored",
            "--nocapture",
        ])
        .env(GUARD_CHILD, "1")
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("keychain guard child ok"),
        "the child ran no check:\n{stdout}\n{stderr}"
    );
}

#[test]
fn a_late_answer_times_out_and_leaks_nothing() {
    let (_dir, keychain) = temporary_keychain(&[("gw-late", SENTINEL)]);
    let started = Instant::now();
    let err = backend(
        &keychain,
        Duration::from_millis(100),
        Duration::from_secs(30),
    )
    .read("gw-late")
    .expect_err("late");
    assert_eq!(err, KeychainError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "waited for the late answer"
    );
    let shown = format!("{err:?} {}", err.reason());
    assert!(
        !shown
            .as_bytes()
            .windows(SENTINEL.len())
            .any(|w| w == SENTINEL)
    );
}

#[test]
fn a_read_value_does_not_show_in_debug() {
    let (_dir, keychain) = temporary_keychain(&[("gw-shown", SENTINEL)]);
    let read = backend(&keychain, Duration::from_secs(2), Duration::ZERO)
        .read("gw-shown")
        .expect("read");
    assert_eq!(read.as_bytes(), SENTINEL);
    assert!(!format!("{read:?}").contains("kc-sentinel-7f3a"));
}

/// B18: the writer's create, exists, collision and delete in a temporary
/// keychain, read back through the production reader.
#[test]
fn b18_the_writer_round_trips_and_refuses_a_taken_name() {
    use crate::secret_store::{SecretStore, StoreError};
    let (_dir, keychain) = temporary_keychain(&[]);
    let store = backend(&keychain, Duration::from_secs(2), Duration::ZERO);
    store.probe().expect("an unlocked keychain probes clean");
    let name = "mcp-gateway.b18.1.00ff";
    assert_eq!(store.exists(name), Ok(false));
    assert_eq!(store.create(name, b" a\n"), Ok(format!("keychain:{name}")));
    assert_eq!(store.exists(name), Ok(true));
    assert_eq!(store.read(name).expect("read back").as_bytes(), b" a\n");
    assert_eq!(store.create(name, b"other"), Err(StoreError::Exists));
    assert_eq!(store.read(name).expect("kept").as_bytes(), b" a\n");
    store.delete(name).expect("delete");
    assert_eq!(store.exists(name), Ok(false));
    assert_eq!(store.delete(name), Ok(()), "already gone is gone");
}

/// The macOS limit: 65,535 bytes round trip exactly through the reader.
#[test]
fn b18_the_largest_value_round_trips_byte_exact() {
    use crate::secret_store::SecretStore;
    let (_dir, keychain) = temporary_keychain(&[]);
    let store = backend(&keychain, Duration::from_secs(5), Duration::ZERO);
    assert_eq!(store.limit(), 65_535);
    let value: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz"
        .iter()
        .copied()
        .cycle()
        .take(65_535)
        .collect();
    let name = "mcp-gateway.b18-large.1.00ff";
    store.create(name, &value).expect("create");
    assert_eq!(
        store.read(name).expect("read back").as_bytes(),
        value.as_slice()
    );
    store.delete(name).expect("delete");
}
