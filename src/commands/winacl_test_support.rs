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
    // A setup that did not take is a fixture failure, never a red row.
    if let Err(dacl) = owner_only(row, &path) {
        panic!("WT-FIXTURE {row}: planting owner-only left D:{dacl}");
    }
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
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
///
/// `icacls /save` writes a well-known account as its SDDL alias rather than
/// its SID (a runner signed in as the built-in Administrator reads back as
/// `LA`), so the user is matched by SID or by that alias.
pub(super) fn assert_owner_only(row: &str, path: &Path) {
    if let Err(dacl) = owner_only(row, path) {
        panic!(
            "WT-ASSERT {row}: {} is not owner-only: D:{dacl}",
            path.display()
        );
    }
}

/// `Err(dacl)` unless `path` is protected and carries exactly the user's
/// full-access entry.
fn owner_only(row: &str, path: &Path) -> Result<(), String> {
    let dacl = dacl(row, path);
    let user = user_sid(row);
    let alias = if user.ends_with("-500") {
        Some("LA")
    } else if user.ends_with("-501") {
        Some("LG")
    } else {
        None
    };
    let aces = &dacl[dacl.find('(').unwrap_or(dacl.len())..];
    let is_user_only = aces == format!("(A;;FA;;;{user})")
        || alias.is_some_and(|a| aces == format!("(A;;FA;;;{a})"));
    if dacl.starts_with('P') && is_user_only {
        Ok(())
    } else {
        Err(dacl)
    }
}
