// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Credential Manager round trips on the Windows shard (ADR-028 §2a). Each
//! test owns its names and deletes them.

use crate::win_cred::{self, CredError};

/// A name no other test or run uses.
fn fresh(tag: &str) -> String {
    format!("mcp-gateway-test.{tag}.{}", std::process::id())
}

#[test]
fn a_created_credential_reads_back_byte_exact_and_deletes() {
    let name = fresh("exact");
    win_cred::create(&name, b" a\n").expect("create");
    let read = win_cred::read(&name).expect("read");
    assert_eq!(read.as_bytes(), b" a\n");
    win_cred::delete(&name).expect("delete");
    assert_eq!(
        win_cred::read(&name).expect_err("gone"),
        CredError::NotFound
    );
}

#[test]
fn creating_an_existing_name_is_refused_and_keeps_the_bytes() {
    let name = fresh("exists");
    win_cred::create(&name, b"first").expect("create");
    assert_eq!(win_cred::create(&name, b"second"), Err(CredError::Exists));
    assert_eq!(win_cred::read(&name).expect("read").as_bytes(), b"first");
    win_cred::delete(&name).expect("delete");
}

#[test]
fn a_missing_name_is_not_found() {
    assert_eq!(
        win_cred::read(&fresh("absent")).expect_err("absent"),
        CredError::NotFound
    );
}

#[test]
fn a_name_with_a_nul_is_refused() {
    assert_eq!(win_cred::read("a\0b").expect_err("nul"), CredError::BadName);
    assert_eq!(win_cred::create("a\0b", b"x"), Err(CredError::BadName));
}
