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
    "src/gateway/meta_mcp/account_rest_fixture.rs",
    "src/gateway/meta_mcp/audit_record_tests.rs",
    "src/gateway/meta_mcp/audit_record_tests/canary.rs",
    "src/gateway/meta_mcp/audit_record_tests/chain_replay.rs",
    "src/gateway/meta_mcp/audit_record_tests/decision_kinds.rs",
    "src/gateway/meta_mcp/audit_record_tests/tenants.rs",
    "src/gateway/meta_mcp/cache_read_only_slot_tests.rs",
    "src/gateway/meta_mcp/callback_admin_denial_tests.rs",
    "src/gateway/meta_mcp/caller_forward_identity_tests.rs",
    "src/gateway/meta_mcp/catalogue_per_caller_tests.rs",
    "src/gateway/meta_mcp/catalogue_stateless_oauth_guard_tests.rs",
    "src/gateway/meta_mcp/chain_resume_binding_tests.rs",
    "src/gateway/meta_mcp/grant_slot_wrap_tests.rs",
    "src/gateway/meta_mcp/invoke/audit_settlement_tests.rs",
    "src/gateway/meta_mcp/invoke/ci_rewrite_gate_tests.rs",
    "src/gateway/meta_mcp/invoke/identity_propagation_enforcement_tests.rs",
    "src/gateway/meta_mcp/invoke/identity_propagation_enforcement_tests/resolution.rs",
    "src/gateway/meta_mcp/invoke/not_found_race_tests.rs",
    "src/gateway/meta_mcp/invoke/stored_proof_tests.rs",
    "src/gateway/meta_mcp/response_delivery_tests.rs",
    "src/gateway/meta_mcp/response_security/delivery_record_tests.rs",
    "src/gateway/meta_mcp/signing_delivery_tests.rs",
    "src/gateway/meta_mcp/slot_verdict_fixture.rs",
    "src/gateway/meta_mcp/trace_correlation_tests.rs",
    "src/gateway/meta_mcp/upstream_401_direct_tests.rs",
    "src/gateway/outbound/caller_key_record_tests.rs",
    "src/gateway/outbound/coverage_tests.rs",
    "src/gateway/outbound/stdio_tests.rs",
    "src/gateway/proxy_session_tests.rs",
    "src/gateway/record_principal_scan_tests.rs",
    "src/gateway/router/backend_handlers/direct_audit_subject_tests.rs",
    "src/gateway/router/backend_handlers/tests.rs",
    "src/gateway/router/capability_edit_audit_tests.rs",
    "src/gateway/router/collusion_direct_tests/meta.rs",
    "src/gateway/router/collusion_direct_tests/verdict.rs",
    "src/gateway/router/direct_anonymous_continuation_tests.rs",
    "src/gateway/router/direct_guards_fixture_quota.rs",
    "src/gateway/router/direct_lent_arms_tests.rs",
    "src/gateway/router/direct_list_scope_tests.rs",
    "src/gateway/router/direct_notification_credential_tests.rs",
    "src/gateway/router/direct_notification_refusal_tests.rs",
    "src/gateway/router/direct_notification_slot_tests.rs",
    "src/gateway/router/direct_notification_wire_tests.rs",
    "src/gateway/router/direct_sole_operator_tests.rs",
    "src/gateway/router/e5_dashboard_session_tests.rs",
    "src/gateway/router/handlers/tasks/frame_subject_tests.rs",
    "src/gateway/router/lend_refusal_tests.rs",
    "src/gateway/router/meta_refusal_audit_tests.rs",
    "src/gateway/router/oracle_capability_tests.rs",
    "src/gateway/router/overview_tests.rs",
    "src/gateway/router/r2_identity_keys_tests.rs",
    "src/gateway/router/slot_verdict_g2_managed_http_tests.rs",
    "src/gateway/router/sso_admin_tests/admin_action.rs",
    "src/gateway/router/tests/meta_state_fixtures.rs",
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
    "src/identity_propagation/account_strategies_tests.rs",
    "src/identity_propagation/audit_fail_closed_tests.rs",
    "src/main_audit_secret_tests.rs",
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
/// or `kept_tempdir_in(` call; a mention in prose does not count).
fn unkept(text: &str) -> bool {
    text.contains("TransparencyLogger::open")
        && !text.contains("keep_test_dir")
        && !text.contains("kept_tempdir(")
        && !text.contains("kept_tempdir_in(")
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
}
