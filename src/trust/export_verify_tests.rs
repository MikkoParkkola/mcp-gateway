// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `audit verify --export` command's exit status, against a JWK file.

use std::process::ExitCode;

use super::{export_verdict, run_verify_export};
use crate::trust::provenance_public::{ACTIVITY_EXPORT_DOMAIN, ProvenancePublicSigner};

fn signed_export(s: &ProvenancePublicSigner) -> Vec<u8> {
    use sha2::Digest as _;
    let rows = b"{\"id\":\"1-0123456789abcdef\"}\n".to_vec();
    let mut manifest = serde_json::json!({
        "kind": "manifest", "rows": 1, "filters": {}, "integrity_failed": 0,
        "truncated": "none", "sha256": hex::encode(sha2::Sha256::digest(&rows)),
        "kid": s.kid(),
    });
    let signed = serde_json_canonicalizer::to_vec(&manifest).unwrap();
    manifest["public_signature"] = s.sign_bytes(ACTIVITY_EXPORT_DOMAIN, &signed).into();
    let mut out = rows;
    out.extend_from_slice(format!("{manifest}\n").as_bytes());
    out
}

fn code(c: ExitCode) -> String {
    format!("{c:?}")
}

#[test]
fn exits_zero_on_a_valid_export_and_non_zero_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let s = ProvenancePublicSigner::from_seed_for_test([3u8; 32], "cli-test-1");
    let jwk = dir.path().join("key.jwk");
    std::fs::write(&jwk, s.public_jwk().to_string()).unwrap();
    let file = dir.path().join("export.ndjson");
    let good = signed_export(&s);
    std::fs::write(&file, &good).unwrap();
    assert_eq!(
        code(run_verify_export(
            &file,
            Some(&jwk),
            None,
            crate::cli::output::Render::Text
        )),
        code(ExitCode::SUCCESS)
    );
    // The `provenance public-key` output, as printed, works as the key file.
    let printed = dir.path().join("printed.json");
    std::fs::write(
        &printed,
        serde_json::json!({"jwk": s.public_jwk(), "thumbprint": s.jwk_thumbprint()}).to_string(),
    )
    .unwrap();
    assert_eq!(
        code(run_verify_export(
            &file,
            Some(&printed),
            None,
            crate::cli::output::Render::Text
        )),
        code(ExitCode::SUCCESS)
    );
    std::fs::write(&file, &good[..good.len() - 3]).unwrap();
    assert_eq!(
        code(run_verify_export(
            &file,
            Some(&jwk),
            None,
            crate::cli::output::Render::Text
        )),
        code(ExitCode::FAILURE)
    );
}

#[test]
fn a_repeated_manifest_member_and_an_oversized_file_are_refused() {
    use super::{ExportRefusal, read_bounded, verify_export};
    let s = ProvenancePublicSigner::from_seed_for_test([3u8; 32], "cli-test-1");
    let trust =
        crate::trust::provenance_public::TrustSet::from_json(&s.public_jwk().to_string()).unwrap();
    let good = signed_export(&s);
    let text = String::from_utf8(good).unwrap();
    // The same key twice: one value could verify while another is read.
    let (rows, manifest) = text.trim_end().rsplit_once('\n').unwrap();
    let doubled = format!("{rows}\n{{\"rows\":9,{}\n", &manifest[1..]);
    assert_ne!(doubled, text);
    assert_eq!(
        verify_export(doubled.as_bytes(), &trust),
        Err(ExportRefusal::DuplicateMember)
    );

    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big");
    std::fs::write(&big, vec![b'x'; 11]).unwrap();
    assert_eq!(read_bounded(&big, 10), Err("too_large".to_string()));
    assert_eq!(read_bounded(&big, 11).unwrap().len(), 11);
}

/// One verdict document: exactly one line ending in one newline, parsed.
fn one_document(stdout: &str) -> serde_json::Value {
    let line = stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no single trailing newline: {stdout:?}"));
    assert!(!line.contains('\n'), "more than one line: {stdout:?}");
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line:?}"))
}

/// V2 (MIK-9764.JSONF.1, design D6): every export verdict, valid or not, is one document under `--json` with the exit
/// the text form has; the text form of the same fixtures is pinned; a trust set that does not load is no verdict.
#[test]
fn export_verdicts_print_one_document_and_keep_their_text() {
    use crate::cli::output::{Printed, Render};
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let s = ProvenancePublicSigner::from_seed_for_test([3u8; 32], "cli-test-1");
    let jwk = dir.path().join("key.jwk");
    std::fs::write(&jwk, s.public_jwk().to_string()).unwrap();
    let file = dir.path().join("export.ndjson");
    let good = signed_export(&s);
    std::fs::write(&file, &good).unwrap();

    assert_eq!(
        export_verdict(&file, Some(&jwk), None, Render::Text),
        Printed {
            stdout: "VALID export: 1 rows, truncated=none, integrity_failed=0, key cli-test-1\nEach row's own sig \
                     authenticates its original log entry and needs the gateway's secret; this check covers the \
                     bundle as exported.\n"
                .to_owned(),
            stderr: String::new(),
            exit: 0,
        }
    );
    let valid = export_verdict(&file, Some(&jwk), None, Render::Json);
    assert_eq!((valid.exit, valid.stderr.as_str()), (0, ""));
    assert_eq!(
        one_document(&valid.stdout),
        json!({"schema_version": 1, "valid": true, "reason": null, "rows": 1, "truncated": "none",
               "integrity_failed": 0, "kid": "cli-test-1"})
    );

    // A refusal and a read failure: the reason is the text after `INVALID `, written out here (A8), the four report
    // fields null.
    let truncated = dir.path().join("truncated.ndjson");
    std::fs::write(&truncated, &good[..good.len() - 3]).unwrap();
    let missing = dir.path().join("missing.ndjson");
    for (input, pinned) in [(&truncated, "torn"), (&missing, "unreadable_input")] {
        let text = export_verdict(input, Some(&jwk), None, Render::Text);
        let reason = text
            .stdout
            .strip_prefix("INVALID ")
            .and_then(|r| r.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("not an INVALID line: {:?}", text.stdout))
            .to_owned();
        assert_eq!(reason, pinned);
        assert_eq!((text.exit, text.stderr.as_str()), (1, ""));
        let json = export_verdict(input, Some(&jwk), None, Render::Json);
        assert_eq!((json.exit, json.stderr.as_str()), (1, ""));
        assert_eq!(
            one_document(&json.stdout),
            json!({"schema_version": 1, "valid": false, "reason": reason, "rows": null, "truncated": null,
                   "integrity_failed": null, "kid": null})
        );
    }

    // No key file: not a verdict, stderr only, the same in both forms.
    let no_key = dir.path().join("no-key.jwk");
    let text = export_verdict(&file, Some(&no_key), None, Render::Text);
    assert!(
        text.stdout.is_empty() && !text.stderr.is_empty() && text.exit == 1,
        "{text:?}"
    );
    assert_eq!(
        export_verdict(&file, Some(&no_key), None, Render::Json),
        text
    );
}
