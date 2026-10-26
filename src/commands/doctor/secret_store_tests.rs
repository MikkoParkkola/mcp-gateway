// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `secret-store` doctor row's status for each report shape.

use mcp_gateway::SecretStoreReport;

use super::super::CheckStatus;
use super::row;

fn report(
    chosen: Option<&'static str>,
    fell_back: bool,
    unused: Option<usize>,
) -> SecretStoreReport {
    SecretStoreReport {
        setting: "auto",
        chosen,
        reason: "auto: the keychain probe failed: no session bus".to_owned(),
        fell_back,
        unused,
        unused_error: None,
    }
}

#[test]
fn an_auto_fallback_to_files_is_a_warning_never_ok() {
    let row = row(&report(Some("files"), true, Some(0)));
    assert_eq!(row.status, CheckStatus::Warn);
    assert!(row.detail.contains("store=files"), "{}", row.detail);
    assert!(row.detail.contains("no session bus"), "{}", row.detail);
}

#[test]
fn a_keychain_that_refuses_saves_fails_and_a_clean_store_passes() {
    assert_eq!(row(&report(None, false, Some(0))).status, CheckStatus::Fail);
    let clean = row(&report(Some("keychain"), false, Some(0)));
    assert_eq!(clean.status, CheckStatus::Pass);
    assert!(clean.detail.contains("unused=0"), "{}", clean.detail);
}

#[test]
fn unused_entries_warn_with_their_count() {
    let row = row(&report(Some("keychain"), false, Some(2)));
    assert_eq!(row.status, CheckStatus::Warn);
    assert!(row.detail.contains("unused=2"), "{}", row.detail);
}

#[test]
fn a_count_that_could_not_be_taken_warns() {
    let mut failed = report(Some("keychain"), false, None);
    failed.unused_error = Some("another save held the vault lock".to_owned());
    let row = row(&failed);
    assert_eq!(row.status, CheckStatus::Warn);
    assert!(row.detail.contains("held the vault lock"), "{}", row.detail);
}
