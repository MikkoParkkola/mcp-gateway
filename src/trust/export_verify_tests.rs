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
    std::fs::write(&file, &good[..good.len() - 3]).unwrap();
    assert_eq!(
        code(run_verify_export(&file, Some(&jwk), None)),
        code(ExitCode::FAILURE)
    );
}
