// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every test that opens a transparency log in a temporary directory hands
//! the log that directory (`keep_test_dir`; the shared fixture
//! `grant_audit_fixture::logger` does so itself), so a late append from a worker
//! the test left running lands before the directory goes. A source scan, as
//! the task store's: file-level, a backstop for review.

/// Test files that still open a log without keeping its directory, each to
/// be converted. A listed file that keeps, or no longer opens a log, fails
/// the scan until its row is removed. A new row is added only for a test
/// file the release line brought in while this sweep is open; any other new
/// unkept file fails the scan.
const PENDING: &[&str] = &[
    "src/cli/main_audit_secret_tests.rs",
    "src/commands/audit_race_tests.rs",
    "src/config_reload/override_audit_tests.rs",
    "src/config_reload/replace_audit_tests.rs",
    "src/control_plane/export_clock_tests.rs",
    "src/control_plane/export_reader_tests.rs",
    "src/control_plane/export_signed_entry_tests.rs",
    "src/control_plane/export_tests.rs",
    "src/control_plane/grant_change_store_tests.rs",
    "src/control_plane/store_rotation_tests.rs",
    "src/control_plane/store_tests.rs",
    "src/events/services_audit_tests.rs",
    "src/events/subscribe_order_tests.rs",
    "src/gateway/meta_mcp/account_direct_bridge_fence_tests.rs",
    "src/gateway/meta_mcp/audit_record_tests.rs",
    "src/gateway/meta_mcp/audit_record_tests/canary.rs",
    "src/gateway/meta_mcp/audit_record_tests/chain_replay.rs",
    "src/gateway/meta_mcp/audit_record_tests/decision_kinds.rs",
    "src/gateway/meta_mcp/audit_record_tests/tenants.rs",
    "src/gateway/meta_mcp/callback_admin_denial_tests.rs",
    "src/gateway/meta_mcp/invoke/audit_settlement_tests.rs",
    "src/gateway/meta_mcp/invoke/ci_rewrite_gate_tests.rs",
    "src/gateway/meta_mcp/invoke/identity_propagation_enforcement_tests.rs",
    "src/gateway/meta_mcp/invoke/identity_propagation_enforcement_tests/resolution.rs",
    "src/gateway/meta_mcp/invoke/not_found_race_tests.rs",
    "src/gateway/meta_mcp/invoke/stored_proof_tests.rs",
    "src/gateway/meta_mcp/response_delivery_tests.rs",
    "src/gateway/meta_mcp/response_security/delivery_record_tests.rs",
    "src/gateway/meta_mcp/signing_delivery_tests.rs",
    "src/gateway/outbound/caller_key_record_tests.rs",
    "src/gateway/outbound/coverage_tests.rs",
    "src/gateway/outbound/stdio_tests.rs",
    "src/gateway/record_principal_scan_tests.rs",
    "src/gateway/streaming_tests.rs",
    "src/gateway/task_service/execution/upstream/recovered_rewrite_record_tests.rs",
    "src/gateway/ui/activity/export_tests.rs",
    "src/gateway/ui/activity/list_tests.rs",
    "src/gateway/ui/activity/reader_tests.rs",
    "src/gateway/ui/activity/receipt_tests.rs",
    "src/gateway/ui/activity/seek_tests.rs",
    "src/gateway/ui/backends/signin_fixture.rs",
    "src/gateway/ui/decisions_tests.rs",
    "src/gateway/ui/discovery_adopt_route_tests.rs",
    "src/gateway/ui/keys_tests.rs",
    "src/identity_propagation/audit_fail_closed_tests.rs",
    "src/security/audit_tests.rs",
    "src/security/tenant_read_corpus_tests.rs",
];

/// The log module's own unit tests are exempt: they write synchronously and
/// drop the log before its directory, and their one late write (a released
/// bounded write) is drained by `release_and_drain`.
const EXEMPT_PREFIX: &str = "src/security/transparency_log";

fn is_test(rel: &str) -> bool {
    (rel.contains("/tests/")
        || rel.contains("_tests")
        || rel.ends_with("tests.rs")
        || rel.contains("_fixture"))
        && std::path::Path::new(rel)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
}

/// Whether `text` opens a log and never keeps a directory for one.
/// A file opens a log without keeping its dir: it neither hands the log its
/// dir (`keep_test_dir`) nor opens it in a registered one (a `kept_tempdir(`
/// or `kept_tempdir_in(` call), nor uses only `TempLog`s for its temp dirs.
fn unkept(text: &str) -> bool {
    text.contains("TransparencyLogger::open")
        && !text.contains("keep_test_dir")
        && !text.contains("kept_tempdir(")
        && !text.contains("kept_tempdir_in(")
        && !temp_log_only(text)
}

/// A real `TempLog` construction keeps its dir, but cannot vouch for a plain
/// constructor elsewhere in the file. Keep evidence excludes prose; plain
/// constructor evidence deliberately includes it, making the scan stricter.
fn temp_log_only(text: &str) -> bool {
    crate::test_source_text::sanitize(text).contains("TempLog::new(")
        && ![
            "tempdir(",
            "tempdir_in(",
            "TempDir::new",
            "TempDir::with_",
            "NamedTempFile",
            "tempfile(",
            "tempfile_in(",
            "temp_dir(",
        ]
        .iter()
        .any(|constructor| {
            text.match_indices(*constructor).any(|(at, _)| {
                text[..at]
                    .bytes()
                    .next_back()
                    .is_none_or(|c| c.is_ascii() && !c.is_ascii_alphanumeric() && c != b'_')
            })
        })
}

fn test_sources(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            test_sources(&path, root, out);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        if is_test(&rel) && !rel.starts_with(EXEMPT_PREFIX) {
            out.push((rel, std::fs::read_to_string(&path).expect("read source")));
        }
    }
}

#[test]
fn every_test_log_in_a_temp_dir_keeps_it_or_is_pending() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    test_sources(&root.join("src"), root, &mut sources);
    let pending: std::collections::BTreeSet<&str> = PENDING.iter().copied().collect();
    let unkept_files: Vec<&str> = sources
        .iter()
        .filter(|(rel, text)| !pending.contains(rel.as_str()) && unkept(text))
        .map(|(rel, _)| rel.as_str())
        .collect();
    assert!(
        unkept_files.is_empty(),
        "test files open a transparency log without keep_test_dir (hand the log its \
         directory): {unkept_files:?}"
    );
    let stale: Vec<&&str> = pending
        .iter()
        .filter(|path| {
            !sources
                .iter()
                .any(|(rel, text)| rel == *path && unkept(text))
        })
        .collect();
    assert!(
        stale.is_empty(),
        "PENDING rows with nothing left to keep: {stale:?}"
    );
}

#[test]
fn the_scan_tells_a_kept_log_from_an_unkept_one() {
    assert!(unkept("let log = TransparencyLogger::open(cfg).unwrap();"));
    assert!(!unkept(
        "let log = TransparencyLogger::open(cfg).unwrap();\nlog.keep_test_dir(dir);"
    ));
    // R14: a dir from `kept_tempdir()` is kept by the open.
    assert!(!unkept(
        "let dir = kept_tempdir();\nlet log = TransparencyLogger::open(cfg).unwrap();"
    ));
    assert!(!unkept(
        "let dir = kept_tempdir_in(parent);\nlet log = TransparencyLogger::open(cfg).unwrap();"
    ));
    // R15: TempLog alone keeps the directory a log opens in.
    assert!(!unkept(
        "let file = TempLog::new();\nlet log = TransparencyLogger::open(cfg).unwrap();"
    ));
    // R16: a TempLog cannot vouch for another, plain temporary directory.
    for constructor in [
        "tempfile::tempdir()",
        "tempdir_in(parent)",
        "tempfile::TempDir::new()",
        "tempfile::NamedTempFile::new()",
        "tempfile::Builder::new().tempdir()",
        "tempfile::TempDir::with_prefix(\"x\")",
        "tempfile::TempDir::with_suffix_in(\"x\", parent)",
        "tempfile::Builder::new().tempfile()",
        "tempfile::Builder::new().tempfile_in(parent)",
        "tempfile::tempfile()",
        "std::env::temp_dir()",
    ] {
        assert!(unkept(&format!(
            "let file = TempLog::new();\nlet dir = {constructor};\n\
             let log = TransparencyLogger::open(cfg).unwrap();"
        )));
    }
    // R17: a comment or literal is not evidence that a TempLog was built.
    for prose in [
        "// TempLog::new()\n",
        "/* TempLog::new() */",
        "let prose = \"TempLog::new()\";",
        "let prose = r#\"TempLog::new()\"#;",
    ] {
        assert!(unkept(&format!(
            "{prose}\nlet log = TransparencyLogger::open(cfg).unwrap();"
        )));
    }
    // R18: string contents cannot hide a plain constructor between them.
    assert!(unkept(
        "let file = TempLog::new();\nlet start = \"/*\";\n\
         let dir = tempfile::tempdir();\nlet end = \"*/\";\n\
         let log = TransparencyLogger::open(cfg).unwrap();"
    ));
    // R19: only whole constructor names count as plain temp directories.
    for constructor in [
        "other_tempdir()",
        "other_tempdir_in(parent)",
        "OtherTempDir::new()",
        "OtherNamedTempFile::new()",
        "FooBuilder::new()",
        "other_temp_dir()",
        "other_tempfile()",
        "other_tempfile_in(parent)",
        "OtherTempDir::with_prefix(x)",
    ] {
        assert!(!unkept(&format!(
            "let file = TempLog::new();\nlet other = {constructor};\n\
             let log = TransparencyLogger::open(cfg).unwrap();"
        )));
    }
    // R20: plain constructor evidence is retained even in prose.
    assert!(unkept(
        "let file = TempLog::new();\n// tempfile::tempdir()\n\
         let log = TransparencyLogger::open(cfg).unwrap();"
    ));
}
