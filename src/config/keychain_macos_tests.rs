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

#[test]
fn prompts_stay_off_after_every_backend_is_dropped() {
    let (_dir, keychain) = temporary_keychain(&[]);
    drop(backend(&keychain, Duration::from_secs(2), Duration::ZERO));
    drop(MacKeychain::search_list());
    assert!(
        !SecKeychain::user_interaction_allowed().expect("read the prompt flag"),
        "keychain prompts came back on"
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
