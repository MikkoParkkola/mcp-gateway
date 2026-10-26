// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `audit verify --export` command's exit status, against a JWK file.

use std::process::ExitCode;

use super::run_verify_export;
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
        code(run_verify_export(&file, Some(&jwk), None)),
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
        code(run_verify_export(&file, Some(&printed), None)),
        code(ExitCode::SUCCESS)
    );
    std::fs::write(&file, &good[..good.len() - 3]).unwrap();
    assert_eq!(
        code(run_verify_export(&file, Some(&jwk), None)),
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
