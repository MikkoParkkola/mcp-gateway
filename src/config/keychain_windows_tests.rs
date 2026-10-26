// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows keychain backend over real Credential Manager entries.

use std::time::{Duration, Instant};

use super::keychain::{KeychainError, KeychainRead};
use super::keychain_windows::WindowsKeychain;
use crate::win_cred;

const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

fn fresh(tag: &str) -> String {
    format!("mcp-gateway-test.backend-{tag}.{}", std::process::id())
}

#[test]
fn an_entry_reads_back_and_a_missing_one_is_missing() {
    let name = fresh("read");
    win_cred::create(&name, SENTINEL).expect("create");
    let read = WindowsKeychain::new().read(&name);
    win_cred::delete(&name).expect("delete");
    let read = read.expect("read");
    assert_eq!(read.as_bytes(), SENTINEL);
    assert!(!format!("{read:?}").contains("kc-sentinel-7f3a"));
    assert_eq!(
        WindowsKeychain::new().read(&name).expect_err("deleted"),
        KeychainError::Missing
    );
}

#[test]
fn a_late_answer_times_out_and_leaks_nothing() {
    let name = fresh("late");
    win_cred::create(&name, SENTINEL).expect("create");
    let started = Instant::now();
    let err = WindowsKeychain::with_timing(Duration::from_millis(100), Duration::from_secs(30))
        .read(&name)
        .expect_err("late");
    win_cred::delete(&name).expect("delete");
    assert_eq!(err, KeychainError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "waited for the late answer"
    );
    assert!(!format!("{err:?} {}", err.reason()).contains("kc-sentinel-7f3a"));
}
