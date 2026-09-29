// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1718: generated TLS files are owner-only from creation on Windows, even in
//! a directory that grants Everyone full control.
#![cfg(windows)]

use super::cert_manager::{CaParams, CertGenerator};
use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir};

#[test]
fn write_to_dir_creates_key_and_cert_owner_only_in_an_open_directory() {
    let row = "1718-W3";
    let dir = everyone_full_dir(row);
    let out = dir.path().join("tls");
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();

    CertGenerator::write_to_dir(&ca, &out, "x").unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only(row, &out.join("x.key"), false);
    assert_owner_only(row, &out.join("x.crt"), false);
}

#[test]
fn write_to_dir_over_an_open_existing_cert_replaces_it_owner_only() {
    let row = "1718-W3b";
    let dir = everyone_full_dir(row);
    let out = dir.path().to_path_buf();
    std::fs::write(out.join("x.crt"), "stale").unwrap();
    std::fs::write(out.join("x.key"), "stale").unwrap();
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "Test CA",
        validity_days: 365,
    })
    .unwrap();

    CertGenerator::write_to_dir(&ca, &out, "x").unwrap();

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only(row, &out.join("x.key"), false);
    assert_owner_only(row, &out.join("x.crt"), false);
}
