// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability writer: the cases code review found (pin shapes, the
//! no-follow read, the patch).

use super::super::{Base, Change, PinUpdate, Refused, commit, commit_observed};
#[cfg(unix)]
use super::set_mode;
use super::{TEXT, described, dir_with, edit, pinned, sha, soon};
use crate::capability::compute_capability_hash;

// ── Code review r1 ────────────────────────────────────────────────────

#[tokio::test]
async fn pin_rewrite_keeps_quotes_and_comment() {
    let base = format!(
        "sha256: \"{}\"  # pinned by ops\n{TEXT}",
        compute_capability_hash(TEXT)
    );
    let (dir, file) = dir_with(&base);
    let sent = base.replace("description: Original", "description: Edited");

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&base)),
            Change::Write(sent.clone()),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    let on_disk = std::fs::read_to_string(&file).unwrap();
    let edited = described(TEXT, "Edited");
    assert_eq!(
        on_disk.lines().next().unwrap(),
        format!(
            "sha256: \"{}\"  # pinned by ops",
            compute_capability_hash(&edited)
        ),
        "only the value changes"
    );
    let cap = crate::capability::parser::parse_capability_text(&on_disk, &file).unwrap();
    assert_eq!(
        cap.providers.integrity,
        crate::capability::Integrity::Verified
    );
}

#[tokio::test]
async fn quoted_pin_key_is_refused_not_bypassed() {
    // The loader reads a quoted key as the pin; no `sha256:` line carries it.
    let base = format!("\"sha256\": {}\n{TEXT}", compute_capability_hash(TEXT));
    let (dir, file) = dir_with(&base);
    let sent = base.replace("description: Original", "description: Edited");

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&base)),
            Change::Write(sent),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(
        matches!(
            result,
            Err(Refused::PinMismatch { .. } | Refused::PinAmbiguous { .. })
        ),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), base);
}

#[cfg(unix)]
#[tokio::test]
async fn a_private_file_removed_before_the_rename_is_written_private() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, file) = dir_with(TEXT);
    set_mode(&file, 0o600);

    let result = commit_observed(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
        |target| std::fs::remove_file(target).unwrap(),
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the umask must not widen a file read as private"
    );
}

#[test]
fn patch_marks_a_missing_final_newline_and_keeps_terminators() {
    let patch = super::super::unified_diff("a\r\nb", "a\r\nc");
    assert!(patch.contains(" a\r\n"), "{patch:?}");
    assert!(
        patch.contains("-b\n\\ No newline at end of file\n"),
        "{patch:?}"
    );
    assert!(
        patch.contains("+c\n\\ No newline at end of file\n"),
        "{patch:?}"
    );
}

#[test]
fn patch_of_two_large_unrelated_files_stays_bounded() {
    let from: String = (0..3000).map(|i| format!("a{i}\n")).collect();
    let to: String = (0..3000).map(|i| format!("b{i}\n")).collect();
    let patch = super::super::unified_diff(&from, &to);
    assert_eq!(
        patch.lines().filter(|l| l.starts_with('-')).count(),
        3001,
        "--- header plus 3000"
    );
    assert_eq!(
        patch.lines().filter(|l| l.starts_with('+')).count(),
        3001,
        "+++ header plus 3000"
    );
}

// ── T10, catalogue half: what a reload serves ─────────────────────────

/// A write that fails at the rename leaves the catalogue as it was after the
/// next reload (the one the watcher triggers); a commit changes it.
#[cfg(unix)]
#[tokio::test]
async fn catalogue_unchanged_after_a_failed_write_and_changed_after_a_commit() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};
    let (dir, _file) = dir_with(TEXT);
    let root = dir.path().to_path_buf();
    let backend = CapabilityBackend::new("caps", std::sync::Arc::new(CapabilityExecutor::new()));
    backend.register_directories(&[root.to_string_lossy().into_owned()]);
    backend.reload().await.expect("the directory loads");
    let description = |b: &CapabilityBackend| b.get("kept").map(|c| c.description);
    assert_eq!(description(&backend).as_deref(), Some("Original"));

    let failed = commit_observed(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
        |_| set_mode(&root, 0o555),
    )
    .await;
    set_mode(&root, 0o755);
    assert!(
        matches!(failed, Err(Refused::Unwritable { .. })),
        "{failed:?}"
    );
    backend.reload().await.expect("the directory still loads");
    assert_eq!(
        backend.list(),
        vec!["kept".to_string()],
        "no scratch is served"
    );
    assert_eq!(description(&backend).as_deref(), Some("Original"));

    commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(described(TEXT, "Edited")),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await
    .expect("the save commits");
    backend.reload().await.expect("the directory loads");
    assert_eq!(description(&backend).as_deref(), Some("Edited"));
}

// ── Code review r2 ────────────────────────────────────────────────────

#[tokio::test]
async fn a_schema_broken_pinned_file_is_still_judged_by_its_pin() {
    // A pin over the original text, then the bytes changed AND the schema
    // broken: a save that repairs the schema must not re-pin unseen bytes.
    let tampered = pinned(TEXT).replace("fulcrum: \"1.0\"", "fulcrum: [1]");
    let tampered = tampered.replace("description: Original", "description: Tampered");
    let (dir, file) = dir_with(&tampered);
    assert!(
        crate::capability::parse_capability(&tampered).is_err(),
        "the schema is broken"
    );
    let repaired = tampered.replace("fulcrum: [1]", "fulcrum: \"1.0\"");

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(&tampered)),
            Change::Write(repaired),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(
        matches!(result, Err(Refused::PinMismatch { .. })),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), tampered);
}

#[tokio::test]
async fn a_hash_inside_a_plain_pin_value_is_part_of_the_value() {
    // YAML ends a plain scalar at " #", not at "#": the whole token "abc#x"
    // is the value, and the splice replaces all of it.
    let (dir, file) = dir_with(TEXT);
    let sent = format!("sha256: abc#x\n{}", described(TEXT, "Edited"));

    let result = commit(
        edit(
            dir.path(),
            Base::Bytes(sha(TEXT)),
            Change::Write(sent),
            PinUpdate::InPlace,
        ),
        None,
        soon(),
    )
    .await;

    assert!(result.is_ok(), "{result:?}");
    let on_disk = std::fs::read_to_string(&file).unwrap();
    assert!(
        !on_disk.contains("#x"),
        "no part of the old value survives: {on_disk:?}"
    );
    let cap = crate::capability::parser::parse_capability_text(&on_disk, &file).unwrap();
    assert_eq!(
        cap.providers.integrity,
        crate::capability::Integrity::Verified
    );
}

/// Every current `sha256` other than a verified 64-hex match: an edit-save
/// is `PinMismatch` and the bytes stay (lead ruling: one total rule).
fn unverifiable_pins() -> Vec<String> {
    let good = compute_capability_hash(TEXT);
    vec![
        "sha256: 0\n".into(),
        "sha256: true\n".into(),
        "sha256: ~\n".into(),
        "sha256: [x]\n".into(),
        "sha256: {a: 1}\n".into(),
        "sha256: abc\n".into(),
        format!("sha256: {}\n", "g".repeat(64)),
        format!("sha256: {good}\nsha256: {good}\n"),
        format!("\"sha256\": {good}\n\"sha256\": {good}\n"),
    ]
}

#[tokio::test]
async fn every_unverifiable_pin_is_a_mismatch() {
    for pin in unverifiable_pins() {
        let base = format!("{pin}{TEXT}");
        let (dir, file) = dir_with(&base);
        let sent = base.replace("description: Original", "description: Edited");

        let result = commit(
            edit(
                dir.path(),
                Base::Bytes(sha(&base)),
                Change::Write(sent.clone()),
                PinUpdate::InPlace,
            ),
            None,
            soon(),
        )
        .await;

        assert!(
            matches!(result, Err(Refused::PinMismatch { .. })),
            "{pin:?}: {result:?}"
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), base, "{pin:?}");
        assert!(
            matches!(
                super::super::preview(&sent, Some(&base)),
                Err(Refused::PinMismatch { .. })
            ),
            "validate refuses it too: {pin:?}"
        );
    }
}

#[test]
fn an_empty_side_starts_at_line_zero() {
    let created = super::super::unified_diff("", "a\n");
    assert!(created.contains("@@ -0,0 +1,1 @@"), "{created:?}");
    let deleted = super::super::unified_diff("a\n", "");
    assert!(deleted.contains("@@ -1,1 +0,0 @@"), "{deleted:?}");
}

#[test]
fn a_large_middle_falls_back_to_a_full_replace() {
    // Half the lines are shared, so an LCS would keep them as context; the
    // fallback keeps none. Past the cell budget, no context line remains
    // after the shared first line.
    let from: String = (0..3000).map(|i| format!("x{i}\n")).collect();
    let to: String = (0..3000)
        .map(|i| {
            if i % 2 == 0 {
                format!("x{i}\n")
            } else {
                format!("y{i}\n")
            }
        })
        .collect();
    let patch = super::super::unified_diff(&from, &to);
    let context = patch.lines().filter(|l| l.starts_with(' ')).count();
    assert_eq!(context, 1, "only the shared prefix line is context");
}
