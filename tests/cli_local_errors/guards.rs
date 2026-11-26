// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Guards for the second half of the local-errors work: verdict exits keep their code and their text. These rows
//! are committed before any file they guard is converted, so the text they pin is today's.

use super::{run, strings, text, write};

/// A capability with no outcome verb in its name or description, so the validator reports a failure.
const VERDICT_CAPABILITY: &str = "name: zz\ndescription: Zz\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://gw.test\n      path: /x\n";

/// V3: validate on a file it cannot parse keeps its verdict code 2 and its text.
#[test]
fn validate_unparseable_keeps_its_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("bad.yaml");
    write(&file, "x: [\n");
    let out = run(&strings(&["validate", &text(&file)]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "\nSummary: 0 passed, 0 warnings, 0 failures\n"
    );
    let want = format!("Parse error in {}: ", text(&file));
    assert!(stderr.starts_with(&want), "stderr: {stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "stderr: {stderr:?}");
}

/// V4: validate on a capability with a finding keeps its verdict code 1 and its report.
#[test]
fn validate_finding_keeps_its_verdict() {
    let scratch = tempfile::tempdir().expect("scratch");
    let file = scratch.path().join("zz.yaml");
    write(&file, VERDICT_CAPABILITY);
    let out = run(&strings(&["validate", &text(&file)]));
    let stdout = String::from_utf8_lossy(&out.stdout).replace(&text(&file), "{file}");
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout:?}");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
    // Digest pin (copy guard blocks the literal; guard row 63): the structure below is readable, and the sha256 of
    // the complete report, with the scratch path written as {file}, keeps the pin byte-exact. The digest was
    // computed on Spark from the unconverted head; on a mismatch the whole report is printed.
    assert!(stdout.starts_with("\n--- {file} ---\n"), "stdout: {stdout}");
    for (marker, code) in [
        ("FAIL", "AX-001"),
        ("PASS", "AX-002"),
        ("FAIL", "AX-003"),
        ("PASS", "AX-004"),
        ("WARN", "AX-005"),
        ("PASS", "AX-006"),
        ("FAIL", "AX-007"),
        ("PASS", "AX-008"),
        ("PASS", "AX-009"),
        ("PASS", "AX-010"),
    ] {
        let line = format!("  [{marker}] [{code}] zz - ");
        assert!(
            stdout.lines().any(|l| l.starts_with(&line)),
            "{code} is not {marker}: {stdout}"
        );
    }
    assert!(
        stdout.ends_with("\nSummary: 6 passed, 1 warnings, 3 failures\n"),
        "stdout: {stdout}"
    );
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(stdout.as_bytes()));
    assert_eq!(
        digest, "d8f5083ae522eef3d6acaf49885122a71136370b2d9d392b97d5c38bbf34cd13",
        "stdout: {stdout}"
    );
}
