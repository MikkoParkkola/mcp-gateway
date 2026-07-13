// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Integration coverage for the `provenance-eval` binary (MIK-6908, rung 3).
//!
//! RUNG3.3: the binary reproduces a known unsupported-claim rate on a
//! committed fixture whose ground truth (the signed receipts) and whose
//! labels (the claims) come from independent sources — this test asserts the
//! exact counts and rate, not just "it ran".

use std::io::Write as _;
use std::process::Command;

use mcp_gateway::attestation::{ATTESTATION_KEY_ID_ENV, ATTESTATION_SIGNING_KEY_ENV};

/// HMAC key the committed fixture (`tests/fixtures/provenance-corpus.jsonl`)
/// was signed with. Must match [`regenerate_fixture`]'s `FIXTURE_KEY`.
const FIXTURE_KEY: &str = "provenance-eval-fixture-key";

/// Path to the committed fixture, relative to the crate root (`CARGO_MANIFEST_DIR`).
const FIXTURE_PATH: &str = "tests/fixtures/provenance-corpus.jsonl";

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_provenance-eval"))
}

/// RUNG3.3 — running the binary against the committed fixture with the
/// fixture's signing key exits 0 and prints the exact known report: 3
/// supported, 2 unsupported, 1 abstained, 1 rejected, 1 mis-joined, over a
/// total of 7 scored cases (the 8th record is the mis-join, excluded before
/// scoring), for an unsupported rate of 2/5 = 0.4000.
#[test]
fn binary_reproduces_known_rate_on_committed_fixture() {
    let output = binary()
        .arg(FIXTURE_PATH)
        .env(ATTESTATION_SIGNING_KEY_ENV, FIXTURE_KEY)
        .env(ATTESTATION_KEY_ID_ENV, "gateway")
        .output()
        .expect("failed to run provenance-eval binary");

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("total:        7"), "stdout was:\n{stdout}");
    assert!(stdout.contains("supported:    3"), "stdout was:\n{stdout}");
    assert!(stdout.contains("unsupported:  2"), "stdout was:\n{stdout}");
    assert!(stdout.contains("abstained:    1"), "stdout was:\n{stdout}");
    assert!(stdout.contains("rejected:     1"), "stdout was:\n{stdout}");
    assert!(stdout.contains("mis-joined:   1"), "stdout was:\n{stdout}");
    assert!(
        stdout.contains("unsupported rate: 0.4000 (adjudicated 5 of 7 cases)"),
        "stdout was:\n{stdout}"
    );
}

/// A malformed corpus line must be a hard failure — non-zero exit, no
/// silent skip — because a scorer that silently drops unparseable input
/// could silently drop exactly the cases that would move the metric.
#[test]
fn binary_exits_nonzero_on_malformed_line() {
    let mut file = tempfile::NamedTempFile::new().expect("create temp corpus file");
    writeln!(file, "{{\"call_id\": \"gw-1\", not valid json").expect("write malformed line");
    file.flush().expect("flush temp corpus file");

    let output = binary()
        .arg(file.path())
        .env(ATTESTATION_SIGNING_KEY_ENV, FIXTURE_KEY)
        .output()
        .expect("failed to run provenance-eval binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit on malformed input, got success\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(":1:"),
        "expected the line-1 error to be reported, stderr was:\n{stderr}"
    );
}

/// An unset (or empty) signing key must be a hard, reported failure — never
/// a silent fall-through to an empty HMAC key, which would let a corpus
/// signed with the empty key verify as "trusted" (cross-family review
/// finding, HIGH: signature-verification bypass). `env_remove` guarantees
/// the key is actually absent regardless of the ambient shell environment.
#[test]
fn binary_exits_nonzero_when_signing_key_unset() {
    let output = binary()
        .arg(FIXTURE_PATH)
        .env_remove(ATTESTATION_SIGNING_KEY_ENV)
        .output()
        .expect("failed to run provenance-eval binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit when {ATTESTATION_SIGNING_KEY_ENV} is unset, got success\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(ATTESTATION_SIGNING_KEY_ENV),
        "expected stderr to mention the missing {ATTESTATION_SIGNING_KEY_ENV}, stderr was:\n{stderr}"
    );
}

/// An empty (but set) signing key must be refused identically to an unset
/// one — `env("...", "")` still resolves to an empty HMAC key.
#[test]
fn binary_exits_nonzero_when_signing_key_empty() {
    let output = binary()
        .arg(FIXTURE_PATH)
        .env(ATTESTATION_SIGNING_KEY_ENV, "")
        .output()
        .expect("failed to run provenance-eval binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit for empty {ATTESTATION_SIGNING_KEY_ENV}, got success\nstdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(ATTESTATION_SIGNING_KEY_ENV),
        "expected stderr to mention the missing {ATTESTATION_SIGNING_KEY_ENV}, stderr was:\n{stderr}"
    );
}

/// A missing corpus file is also a hard, reported failure (not a panic).
#[test]
fn binary_exits_nonzero_on_missing_file() {
    let output = binary()
        .arg("tests/fixtures/does-not-exist.jsonl")
        .env(ATTESTATION_SIGNING_KEY_ENV, FIXTURE_KEY)
        .output()
        .expect("failed to run provenance-eval binary");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to open"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regenerates `tests/fixtures/provenance-corpus.jsonl` deterministically
/// from the real signer — never hand-forge a receipt signature. `#[ignore]`d
/// because it is a generator, not a check; run it explicitly with
/// `cargo test --test provenance_eval_binary -- --ignored regenerate_fixture --nocapture`
/// and redirect the single JSONL line block it prints between the markers to
/// the fixture path if the corpus ever needs to change.
///
/// Mixed corpus, 8 records:
/// 1. `Succeeded`, observed success                          -> supported
/// 2. `AuthoritativeEmpty`, observed empty on success        -> supported
/// 3. `FoundRows{5}`, observed 5                              -> supported
/// 4. `FoundRows{12}`, observed 3 (inflated claim)            -> unsupported
/// 5. `AuthoritativeEmpty` on a FAILED call (silent failure) -> unsupported
/// 6. `FoundRows{2}`, backend exposes no count                -> abstained
/// 7. `Succeeded`, receipt tampered post-signing             -> rejected
/// 8. `Succeeded`, `call_id` mismatched with its receipt     -> mis-joined
#[test]
#[ignore = "fixture generator, not a check — run explicitly to regenerate the fixture"]
fn regenerate_fixture() {
    use mcp_gateway::attestation::BnautAttestationSigner;
    use mcp_gateway::trust::provenance_eval::{Claim, CorpusRecord};
    use mcp_gateway::trust::{CacheOutcome, RuntimeProvenanceReceipt};

    let signer = BnautAttestationSigner::new(FIXTURE_KEY.as_bytes().to_vec(), "gateway");

    let receipt = |call_id: &str, backend_ok: bool, row_count: Option<u64>| {
        let mut r = RuntimeProvenanceReceipt::observed(
            "demo-backend",
            "search",
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            backend_ok,
        )
        .with_call_id(call_id);
        if let Some(n) = row_count {
            r = r.with_row_count(n);
        }
        r
    };

    let records = vec![
        CorpusRecord {
            call_id: "gw-fixture-001".to_string(),
            claim: Claim::Succeeded,
            receipt: receipt("gw-fixture-001", true, None).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-002".to_string(),
            claim: Claim::AuthoritativeEmpty,
            receipt: receipt("gw-fixture-002", true, Some(0)).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-003".to_string(),
            claim: Claim::FoundRows { count: 5 },
            receipt: receipt("gw-fixture-003", true, Some(5)).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-004".to_string(),
            claim: Claim::FoundRows { count: 12 },
            receipt: receipt("gw-fixture-004", true, Some(3)).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-005".to_string(),
            claim: Claim::AuthoritativeEmpty,
            receipt: receipt("gw-fixture-005", false, None).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-006".to_string(),
            claim: Claim::FoundRows { count: 2 },
            receipt: receipt("gw-fixture-006", true, None).sign(&signer),
        },
        CorpusRecord {
            call_id: "gw-fixture-007".to_string(),
            claim: Claim::Succeeded,
            receipt: {
                let mut tampered = receipt("gw-fixture-007", true, None).sign(&signer);
                // Tamper AFTER signing so the HMAC no longer matches — a real
                // signature, just no longer over the content it's attached to.
                tampered.receipt.backend_ok = false;
                tampered
            },
        },
        CorpusRecord {
            call_id: "gw-fixture-008".to_string(),
            claim: Claim::Succeeded,
            // Correctly signed, but the receipt's own call_id disagrees with
            // the record's call_id: a mis-join.
            receipt: receipt("gw-fixture-008-mismatch", true, None).sign(&signer),
        },
    ];

    println!("----- BEGIN provenance-corpus.jsonl -----");
    for record in &records {
        println!(
            "{}",
            serde_json::to_string(record).expect("serialize record")
        );
    }
    println!("----- END provenance-corpus.jsonl -----");
}
