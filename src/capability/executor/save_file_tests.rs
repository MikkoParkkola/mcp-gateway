// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn spec(max: u64) -> SaveFileSpec {
    SaveFileSpec {
        data: "data".into(),
        encoding: SaveEncoding::Base64url,
        filename: "{filename}".into(),
        max_bytes: max,
    }
}

fn roots(dir: &std::path::Path, quota: u64) -> FileRoots {
    FileRoots {
        downloads: Some(dir.to_path_buf()),
        downloads_quota_bytes: quota,
        ..FileRoots::default()
    }
}

#[test]
fn hostile_names_are_refused() {
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a\0b",
        "c:evil",
        "x.",
        "x ",
        "con",
        "CON.txt",
        "com1.log",
        "LPT\u{b9}",
        "Aux.tar.gz",
    ] {
        assert!(validate_filename(bad).is_err(), "{bad:?}");
    }
    assert!(validate_filename(&"a".repeat(256)).is_err());
    for ok in ["report.pdf", "console.txt", "com10.txt", ".bashrc"] {
        assert!(validate_filename(ok).is_ok(), "{ok}");
    }
}

#[tokio::test]
async fn saves_decodes_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let r = roots(dir.path(), 1 << 20);
    // "hello" in base64url without padding.
    let resp = json!({"data": "aGVsbG8"});
    let p = json!({"filename": "a.txt"});
    let first = save(&spec(100), &resp, &p, &r).await.unwrap();
    assert_eq!(first["size"], 5);
    assert_eq!(first["filename"], "a.txt");
    let second = save(&spec(100), &resp, &p, &r).await.unwrap();
    assert_eq!(second["filename"], "a_1.txt");
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"hello");
    assert!(first.get("data").is_none());
}

#[tokio::test]
async fn refuses_unset_root_oversize_and_quota() {
    let p = json!({"filename": "a.txt"});
    let resp = json!({"data": "aGVsbG8"});
    let none = FileRoots::default();
    let e = save(&spec(100), &resp, &p, &none).await.unwrap_err();
    assert!(e.to_string().contains("capabilities.files.downloads"));

    let dir = tempfile::tempdir().unwrap();
    let r = roots(dir.path(), 1 << 20);
    assert!(save(&spec(4), &resp, &p, &r).await.is_err());
    let tiny = roots(dir.path(), 3);
    assert!(save(&spec(100), &resp, &p, &tiny).await.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn does_not_follow_a_planted_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("victim");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join("a.txt")).unwrap();
    let r = roots(dir.path(), 1 << 20);
    let out = save(
        &spec(100),
        &json!({"data": "aGVsbG8"}),
        &json!({"filename": "a.txt"}),
        &r,
    )
    .await
    .unwrap();
    assert_eq!(out["filename"], "a_1.txt");
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
}

#[test]
fn a_value_that_looks_like_a_slot_is_not_expanded_again() {
    let params = json!({"a": "{b}", "b": "boom"});
    assert_eq!(render_filename("{a}.txt", &params), "{b}.txt");
    assert_eq!(render_filename("x{missing}y", &params), "x{missing}y");
}
