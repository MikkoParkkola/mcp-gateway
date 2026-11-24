// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! G1: the literal list of wrapped tests, and the scan that holds every
//! `require_private_home!()` call to it.

/// G1's literal list: every test that calls `require_private_home!()`, as
/// (binary, fn), from the per-test probe (51 tests) plus the
/// probe fn, and the two CA rows the release line added later, which start a
/// preview through the same `fetching()` path as the probed
/// `r1_a_fetching_preview_runs_its_target_after_the_handshake`, and one webui
/// row the bare probe rerun found once each test ran alone (its lookup runs on
/// a tokio worker thread, which the first probe could not name). It may only
/// grow: a test that newly resolves the home joins it.
const WRAPPED: &[(&str, &str)] = &[
    (
        "audit_verify_pairing_cli",
        "a_pairing_failure_prints_its_own_headline_with_the_token_escaped",
    ),
    (
        "audit_verify_pairing_cli",
        "an_expired_intent_note_prints_as_info_with_the_token_escaped",
    ),
    (
        "audit_verify_pairing_cli",
        "warnings_and_unverified_warnings_print_no_payload_value_and_escape_the_token",
    ),
    (
        "capability_egress_env_proxy",
        "an_environment_proxy_carries_no_capability_import_or_discovery_traffic",
    ),
    (
        "capability_egress_proxy_opt_in",
        "capabilities_egress_proxy_is_the_only_proxy_route",
    ),
    (
        "cli_json_forms_verify",
        "audit_verify_errors_before_a_verdict_print_no_document",
    ),
    (
        "cli_json_forms_verify",
        "audit_verify_failed_verdicts_print_their_document_with_exit_1",
    ),
    (
        "cli_json_forms_verify",
        "audit_verify_passing_logs_print_their_verdict",
    ),
    (
        "cli_json_forms_verify",
        "audit_verify_warnings_and_notes_are_in_the_document",
    ),
    (
        "control_plane_file_modes",
        "control_plane_missing_file_is_empty",
    ),
    (
        "control_plane_file_modes",
        "control_plane_readable_collection_loads",
    ),
    (
        "control_plane_file_modes",
        "control_plane_world_writable_refused",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_archive_accepts_a_copy_without_hwm",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_checks_the_log_against_an_anchor",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_escapes_a_predecessor_id_in_its_warning",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_escapes_bidi_and_zero_width_characters",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_escapes_log_text_in_its_failure_line",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_prints_a_verified_predecessor_warning_on_a_passing_log",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_prints_its_warnings_when_the_chain_fails",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_reads_sealed_segments_when_the_active_file_is_gone",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_spans_segments_as_a_process",
    ),
    (
        "d6_audit_verify_cli",
        "audit_verify_tells_literal_escape_text_from_a_real_bidi_character",
    ),
    ("discovery_tests", "test_auto_discovery_initialization"),
    ("discovery_tests", "test_deduplication"),
    ("discovery_tests", "test_discover_claude_desktop_config"),
    ("discovery_tests", "test_discover_mcp_config_dir"),
    ("discovery_tests", "test_discover_vscode_config"),
    (
        "mik_7215_control3b_acs",
        "ac_control_3b_client_params_meta_trace_id_is_the_correlation_key",
    ),
    (
        "mik_7215_control3b_acs",
        "control_params_meta_without_traceparent_yields_no_otel_key",
    ),
    (
        "preview_sandbox_inherited_fd",
        "an_inherited_descriptor_makes_the_preview_refuse",
    ),
    (
        "preview_sandbox_linux",
        "a_dropped_preview_kills_its_namespace",
    ),
    (
        "preview_sandbox_linux",
        "a_gateway_path_covers_an_interpreter_bind_back",
    ),
    (
        "preview_sandbox_linux",
        "a_preview_dropped_after_its_runtime_still_ends",
    ),
    (
        "preview_sandbox_linux",
        "a_program_beside_a_secret_binds_as_its_file_alone",
    ),
    ("preview_sandbox_linux", "a_runtime_file_is_readable"),
    (
        "preview_sandbox_linux",
        "a_setsid_descendant_is_gone_after_teardown",
    ),
    (
        "preview_sandbox_linux",
        "a_symlinked_gateway_path_is_masked_where_it_really_is",
    ),
    (
        "preview_sandbox_linux",
        "a_symlinked_program_runs_under_its_requested_name",
    ),
    (
        "preview_sandbox_linux_fetch",
        "ca_files_are_read_only_from_the_run_child",
    ),
    (
        "preview_sandbox_linux",
        "canaries_outside_the_binds_are_unreadable",
    ),
    (
        "preview_sandbox_linux_fetch",
        "f2_t1_the_unshares_only_child_is_the_helper",
    ),
    (
        "preview_sandbox_linux_fetch",
        "f2_t2_the_run_child_holds_no_control_connection",
    ),
    ("preview_sandbox_linux", "masked_system_paths_are_empty"),
    (
        "preview_sandbox_linux_fetch",
        "r1_a_fetching_preview_runs_its_target_after_the_handshake",
    ),
    (
        "preview_sandbox_linux_fetch",
        "r6b_a_dropped_start_leaves_no_sandbox_running",
    ),
    (
        "preview_sandbox_linux_fetch",
        "r6b_a_helper_that_never_connects_is_refused",
    ),
    (
        "preview_sandbox_linux_fetch",
        "the_ca_snapshot_sits_under_tmp_on_this_host",
    ),
    (
        "preview_sandbox_linux",
        "the_filter_refuses_keyrings_and_ptrace",
    ),
    ("preview_sandbox_linux", "the_filter_refuses_vsock"),
    (
        "preview_sandbox_linux",
        "the_helper_cannot_be_read_from_inside",
    ),
    ("preview_sandbox_linux", "the_home_is_bounded"),
    ("preview_sandbox_linux", "the_host_root_is_unreachable"),
    (
        "preview_sandbox_linux",
        "the_run_phase_cannot_connect_anywhere",
    ),
    (
        "preview_sandbox_linux",
        "the_run_phase_starts_in_its_own_home",
    ),
    ("preview_sandbox_linux", "tmp_is_bounded"),
    (
        "webui_management_tests",
        "api4_5_and_api4_1_status_rows_keep_every_old_key_and_add_the_state",
    ),
    (
        "webui_management_tests",
        "a_selection_change_is_on_its_audit_record",
    ),
    (
        "webui_management_tests",
        "a_credential_edited_in_the_panel_is_stored_not_written",
    ),
    ("private_home_rule", "private_home_probe"),
];

/// G1: every listed fn starts with `require_private_home!();`, and no other fn
/// calls it. Deleting a wrapper, or wrapping an unlisted fn, fails this row.
#[test]
fn g1_every_listed_test_starts_with_the_rule() {
    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut found = std::collections::BTreeSet::new();
    let mut late = Vec::new();
    let mut sources = Vec::new();
    crate::test_source_files::rust_files(&tests_dir, &mut sources);
    for path in sources {
        if path.ends_with("common/private_home.rs") {
            continue;
        }
        let rel = path.strip_prefix(&tests_dir).expect("under tests/");
        let binary = rel
            .components()
            .next()
            .map(|c| {
                c.as_os_str()
                    .to_string_lossy()
                    .trim_end_matches(".rs")
                    .to_string()
            })
            .expect("a binary");
        let text = std::fs::read_to_string(&path).expect("readable");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !is_rule_statement(line) {
                continue;
            }
            // The rule is the first statement: only items (`use`, `const`,
            // `static`) may sit between the fn's opening brace and it.
            let opener = lines[..i]
                .iter()
                .rposition(|l| {
                    let t = l.trim();
                    !t.is_empty()
                        && !t.starts_with("use ")
                        && !t.starts_with("const ")
                        && !t.starts_with("static ")
                })
                .expect("a line before");
            let sig = lines[..=opener]
                .iter()
                .rposition(|l| l.contains("fn "))
                .expect("an enclosing fn");
            let name = lines[sig]
                .split("fn ")
                .nth(1)
                .and_then(|rest| rest.split(['(', '<']).next())
                .expect("a fn name")
                .trim()
                .to_string();
            if !lines[opener].trim_end().ends_with('{') {
                late.push(format!("{binary}::{name}"));
            }
            found.insert((binary.clone(), name));
        }
    }
    let expected: std::collections::BTreeSet<(String, String)> = WRAPPED
        .iter()
        .map(|(b, n)| ((*b).to_string(), (*n).to_string()))
        .collect();
    assert!(
        late.is_empty(),
        "the rule is not the first statement in {late:?}"
    );
    assert_eq!(found, expected, "the wrapped tests differ from the list");
}

/// The whole trimmed line is the rule call, under any path to the macro
/// (`crate::require_private_home!();` too). Code before the call on the same
/// line, another macro whose name ends the same way, or a comment, is not.
fn is_rule_statement(line: &str) -> bool {
    static RULE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*require_private_home!\(\);$")
            .expect("a valid pattern")
    });
    RULE.is_match(line.trim())
}

/// G1's matcher, both sides: what it takes and what it refuses.
#[test]
fn g1_matches_only_the_whole_rule_statement() {
    for taken in [
        "require_private_home!();",
        "    require_private_home!();  ",
        "crate::require_private_home!();",
        "a::b_1::require_private_home!();",
    ] {
        assert!(is_rule_statement(taken), "should take {taken:?}");
    }
    for refused in [
        "my_require_private_home!();",
        "foo(); require_private_home!();",
        "let _ = 1; crate::require_private_home!();",
        "// require_private_home!();",
        "require_private_home!()",
        "::require_private_home!();",
        "1a::require_private_home!();",
    ] {
        assert!(!is_rule_statement(refused), "should refuse {refused:?}");
    }
}
