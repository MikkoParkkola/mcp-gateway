// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 K11: a filesystem without hard links fails startup closed.

use super::*;

// K11: when the no-replace link is unsupported, publishing fails naming the
// error, writes no key file and leaves no temp behind; the caller names the path.
#[test]
fn k11_a_filesystem_without_hard_links_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_file = dir.path().join("record-principal.key");
    let err = publish_new_key(&key_file, |_, _| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hard links unsupported",
        ))
    })
    .expect_err("an unsupported link must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(!key_file.exists(), "no fallback write");
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("dir").count(),
        0,
        "the temp is removed"
    );
}
