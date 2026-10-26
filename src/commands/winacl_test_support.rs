// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows owner-only fixtures for the binary's callers, which cannot reach the
//! library's test helpers: a folder that hands Everyone full access to its
//! children, an owner-only file in it, and the file's access list read back as
//! SDDL through `icacls /save`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run(row: &str, cmd: &mut Command) -> Vec<u8> {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("WT-FIXTURE {row}: {cmd:?}: {e}"));
    assert!(out.status.success(), "WT-FIXTURE {row}: {cmd:?}: {out:?}");
    out.stdout
}

/// The current user's SID, from `whoami /user` (CSV: name, SID).
pub(super) fn user_sid(row: &str) -> String {
    let out = run(
        row,
        Command::new("whoami").args(["/user", "/fo", "csv", "/nh"]),
    );
    let text = String::from_utf8_lossy(&out);
    text.trim()
        .rsplit(',')
        .next()
        .map(|s| s.trim_matches('"').to_owned())
        .filter(|s| s.starts_with("S-1-"))
        .unwrap_or_else(|| panic!("WT-FIXTURE {row}: no SID in {text}"))
}

/// A folder granting Everyone full access to its children, and in it a file
/// `name` holding `old`, made owner-only for the current user.
pub(super) fn owner_only_file(row: &str, name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    run(
        row,
        Command::new("icacls")
            .arg(dir.path())
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"]),
    );
    let path = dir.path().join(name);
    std::fs::write(&path, b"old").unwrap();
    let grant = format!("*{}:F", user_sid(row));
    run(
        row,
        Command::new("icacls")
            .arg(&path)
            .args(["/inheritance:r", "/grant:r", &grant]),
    );
    assert_owner_only(row, &path);
    (dir, path)
}

/// The DACL part of `path`'s descriptor, from `icacls <path> /save`.
fn dacl(row: &str, path: &Path) -> String {
    // A path no handle holds open: icacls creates the file itself.
    let out = tempfile::tempdir().unwrap();
    let saved = out.path().join("acl.txt");
    run(
        row,
        Command::new("icacls").arg(path).arg("/save").arg(&saved),
    );
    let bytes = std::fs::read(&saved).unwrap();
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&wide);
    let at = text
        .find("D:")
        .unwrap_or_else(|| panic!("WT-FIXTURE {row}: no DACL in {text}"));
    let rest = &text[at + 2..];
    rest[..rest.find("S:").unwrap_or(rest.len())]
        .trim_end()
        .to_owned()
}

/// `path` is protected and carries exactly the user's full-access entry.
pub(super) fn assert_owner_only(row: &str, path: &Path) {
    let dacl = dacl(row, path);
    let user = user_sid(row);
    let aces = &dacl[dacl.find('(').unwrap_or(dacl.len())..];
    assert!(
        dacl.starts_with('P') && aces == format!("(A;;FA;;;{user})"),
        "WT-ASSERT {row}: {} is not owner-only: D:{dacl}",
        path.display()
    );
}
