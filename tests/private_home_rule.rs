// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private-home rule (`require_private_home!()`): which envs it refuses,
//! which it accepts, and the child protocol and env helpers its rows rely on.
//! Every row here runs its case in a child of this binary, so the parent's own
//! env never decides the outcome.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;

use private_home::{
    Expect, canonical, fresh_private_dir, literal_env_command, refuse, run_row_child,
};
use std::path::Path;
use std::process::Command;

/// The rule's only caller outside the wrapped tests: run as a child by every
/// R row, with that row's env.
#[test]
#[ignore = "run by the R rows as a child, with their env"]
fn private_home_probe() {
    require_private_home!();
}

/// The fix line every refusal ends with.
const FIX: &str = "MCP_GATEWAY_TEST_HOME_DIR=$(mktemp -d)";

/// Run the probe in a child built from `command` and expect `expect`.
fn probe(command: Command, expect: &Expect, keep: Vec<tempfile::TempDir>) {
    let _kept = run_row_child(command, "private_home_probe", true, expect, keep);
}

/// The literal env with the override set to `home`.
fn with_override(home: &Path) -> Command {
    let mut command = literal_env_command();
    command.env("MCP_GATEWAY_TEST_HOME_DIR", home);
    command
}

/// R0a: a private override with the config and data variables unset is accepted.
#[test]
fn r0a_a_private_override_alone_is_accepted() {
    let home = fresh_private_dir();
    probe(with_override(home.path()), &Expect::Pass, vec![home]);
}

/// R0b: the harness shape, both variables exactly under the override and not
/// created yet, is accepted.
#[test]
fn r0b_the_harness_shape_is_accepted() {
    let home = fresh_private_dir();
    let mut command = with_override(home.path());
    command
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("MCP_GATEWAY_CONFIG_DIR", home.path().join(".mcp-gateway"));
    probe(command, &Expect::Pass, vec![home]);
}

/// The fix line when a config or data variable broke the rule.
const FIX_ENV: &str = "env -u XDG_CONFIG_HOME -u MCP_GATEWAY_CONFIG_DIR";

/// R1: no override at all.
#[test]
fn r1_an_unset_override_is_refused() {
    probe(
        literal_env_command(),
        &refuse(&[
            "(check 2)",
            "MCP_GATEWAY_TEST_HOME_DIR is unset or empty",
            FIX,
        ]),
        Vec::new(),
    );
}

/// R2: an empty override.
#[test]
fn r2_an_empty_override_is_refused() {
    let mut command = literal_env_command();
    command.env("MCP_GATEWAY_TEST_HOME_DIR", "");
    probe(
        command,
        &refuse(&[
            "(check 2)",
            "MCP_GATEWAY_TEST_HOME_DIR is unset or empty",
            FIX,
        ]),
        Vec::new(),
    );
}

/// R3: an override naming nothing. Its own message, before any canonicalisation.
#[test]
fn r3_a_nonexistent_override_is_refused() {
    let parent = fresh_private_dir();
    let command = with_override(&parent.path().join("absent"));
    probe(
        command,
        &refuse(&["(check 3)", "names no existing directory", FIX]),
        vec![parent],
    );
}

/// R10: an override naming a regular file.
#[test]
fn r10_an_override_naming_a_file_is_refused() {
    let parent = fresh_private_dir();
    let file = parent.path().join("file");
    std::fs::write(&file, b"").expect("a regular file");
    probe(
        with_override(&file),
        &refuse(&["(check 3)", "names no existing directory", FIX]),
        vec![parent],
    );
}

/// R4: the real home itself. Read-only: the rule refuses before any lookup.
#[test]
fn r4_the_real_home_is_refused() {
    let home = private_home::real_home_raw().expect("this host has a home");
    probe(
        with_override(&home),
        &refuse(&["(check 4)", "is the real home", FIX]),
        Vec::new(),
    );
}

/// R5: a symlink to the real home, the same home by another name.
#[cfg(unix)]
#[test]
fn r5_a_symlink_to_the_real_home_is_refused() {
    let home = private_home::real_home().expect("this host has a home");
    let dir = fresh_private_dir();
    let link = dir.path().join("home-link");
    std::os::unix::fs::symlink(&home, &link).expect("a symlink");
    probe(
        with_override(&link),
        &refuse(&["(check 4)", "is the real home", FIX]),
        vec![dir],
    );
}

/// R6: a release build refuses a valid env (the release library ignores the
/// override). Runs only in a release build; no CI job builds integration tests
/// in release.
#[cfg(not(debug_assertions))]
#[test]
fn r6_a_release_build_is_refused() {
    let home = fresh_private_dir();
    probe(
        with_override(home.path()),
        &refuse(&["(check 1)", "these tests need a debug build"]),
        vec![home],
    );
}

/// A private override plus one config or data variable set to `value`,
/// expected refused by `check` with `text`.
fn refuse_var(
    var: &str,
    value: impl FnOnce(&Path, &Path) -> std::path::PathBuf,
    check: &str,
    text: &str,
) {
    let home = fresh_private_dir();
    let other = fresh_private_dir();
    let mut command = with_override(home.path());
    command.env(var, value(home.path(), other.path()));
    probe(command, &refuse(&[check, text, FIX_ENV]), vec![home, other]);
}

const XDG_TEXT: &str = "XDG_CONFIG_HOME must be unset or <override>/.config";
const DATA_TEXT: &str = "MCP_GATEWAY_CONFIG_DIR must be unset or <override>/.mcp-gateway";

/// R7a: the right name under the wrong parent.
#[test]
fn r7a_xdg_under_another_dir_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, other| other.join(".config"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R7b: the right parent with the wrong name.
#[test]
fn r7b_xdg_with_another_name_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |home, _| home.join("other"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R8a: the right name under the wrong parent.
#[test]
fn r8a_data_dir_under_another_dir_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, other| other.join(".mcp-gateway"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R8b: the right parent with the wrong name.
#[test]
fn r8b_data_dir_with_another_name_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |home, _| home.join("other"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R11: an empty XDG_CONFIG_HOME, which the library would take as the working dir.
#[test]
fn r11_an_empty_xdg_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, _| std::path::PathBuf::new(),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R12: an empty MCP_GATEWAY_CONFIG_DIR, likewise.
#[test]
fn r12_an_empty_data_dir_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, _| std::path::PathBuf::new(),
        "(check 6)",
        DATA_TEXT,
    );
}

/// R13a: XDG_CONFIG_HOME under a parent that cannot be resolved.
#[test]
fn r13a_xdg_under_a_missing_parent_is_refused() {
    refuse_var(
        "XDG_CONFIG_HOME",
        |_, other| other.join("absent").join(".config"),
        "(check 5)",
        XDG_TEXT,
    );
}

/// R13b: MCP_GATEWAY_CONFIG_DIR under a parent that cannot be resolved.
#[test]
fn r13b_data_dir_under_a_missing_parent_is_refused() {
    refuse_var(
        "MCP_GATEWAY_CONFIG_DIR",
        |_, other| other.join("absent").join(".mcp-gateway"),
        "(check 6)",
        DATA_TEXT,
    );
}

/// A private override whose `leaf` is a link (made by `link`) to a decoy dir
/// outside it, expected refused by check 7.
fn refuse_leaf(leaf: &str, link: impl FnOnce(&Path, &Path)) {
    let home = fresh_private_dir();
    let decoy = fresh_private_dir();
    let at = home.path().join(leaf);
    assert!(!at.exists(), "premise: the leaf is absent before the link");
    assert!(
        decoy.path().is_absolute() && decoy.path().is_dir(),
        "premise: the decoy is an existing absolute dir"
    );
    link(decoy.path(), &at);
    assert_eq!(
        canonical(&at),
        canonical(decoy.path()),
        "premise: the leaf resolves to the decoy"
    );
    let text = format!("{leaf} resolves outside the override");
    probe(
        with_override(home.path()),
        &refuse(&["(check 7)", &text, FIX_ENV]),
        vec![home, decoy],
    );
}

/// R14: `<override>/.config` is a symlink out of the override.
#[cfg(unix)]
#[test]
fn r14_a_config_leaf_symlink_out_is_refused() {
    refuse_leaf(".config", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink")
    });
}

/// R15: `<override>/.mcp-gateway` is a symlink out of the override.
#[cfg(unix)]
#[test]
fn r15_a_data_leaf_symlink_out_is_refused() {
    refuse_leaf(".mcp-gateway", |decoy, at| {
        std::os::unix::fs::symlink(decoy, at).expect("a symlink")
    });
}

/// A directory junction at `at` to `decoy`; `mklink /J` needs no admin rights.
#[cfg(windows)]
fn junction(decoy: &Path, at: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(at)
        .arg(decoy)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("cmd runs");
    assert!(status.success(), "mklink /J made the junction");
}

/// R14w: `<override>\.config` is a junction out of the override. Required on Windows.
#[cfg(windows)]
#[test]
fn r14w_a_config_leaf_junction_out_is_refused() {
    refuse_leaf(".config", junction);
}

/// R15w: `<override>\.mcp-gateway` is a junction out of the override. Required on Windows.
#[cfg(windows)]
#[test]
fn r15w_a_data_leaf_junction_out_is_refused() {
    refuse_leaf(".mcp-gateway", junction);
}

/// R9 (Windows): the real profile spelt three other ways is still the real home.
#[cfg(windows)]
mod r9_windows_aliases {
    use super::{FIX, probe, refuse, with_override};
    use std::path::PathBuf;

    fn refused(alias: &std::path::Path) {
        probe(
            with_override(alias),
            &refuse(&["(check 4)", "is the real home", FIX]),
            Vec::new(),
        );
    }

    /// The verbatim form (`\\?\C:\...`), which canonicalisation itself returns.
    #[test]
    fn r9a_the_verbatim_form_is_refused() {
        refused(&crate::private_home::real_home().expect("a home"));
    }

    /// A case variant: Windows paths are case-insensitive.
    #[test]
    fn r9b_a_case_variant_is_refused() {
        let raw = crate::private_home::real_home_raw().expect("a home");
        refused(&PathBuf::from(raw.to_string_lossy().to_uppercase()));
    }

    /// The 8.3 short form, read from cmd. Skipped, saying why, when the volume
    /// has 8.3 names off (the short form equals the long one).
    #[test]
    fn r9c_the_short_form_is_refused() {
        let raw = crate::private_home::real_home_raw().expect("a home");
        let out = std::process::Command::new("cmd")
            .args([
                "/c",
                &format!("for %I in (\"{}\") do @echo %~sI", raw.display()),
            ])
            .output()
            .expect("cmd runs");
        let short = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if short.eq_ignore_ascii_case(&raw.to_string_lossy()) {
            println!("skipped: 8.3 names are off on this volume ({short})");
            return;
        }
        refused(&PathBuf::from(short));
    }
}

/// The env a built command carries: every explicit set as `Some`, every
/// removal as `None`.
fn explicit_env(command: &Command) -> std::collections::BTreeMap<String, Option<String>> {
    command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

/// The literal env T2 and T7 run in: a planted inherited `MCP_GATEWAY_*` pair
/// to be removed, nothing else of the gateway's.
fn golden_child() -> Command {
    let mut command = literal_env_command();
    command
        .env("MCP_GATEWAY_FOO", "x")
        .env("MCP_GATEWAY_CONFIG_DIR", "y");
    command
}

/// What every isolated command removes and passes through, given the child's env.
fn removals_and_switch(expected: &mut std::collections::BTreeMap<String, Option<String>>) {
    expected.insert("MCP_GATEWAY_FOO".into(), None);
    expected.insert("MCP_GATEWAY_CONFIG_DIR".into(), None);
    if let Ok(mutant) = std::env::var("MCP_GATEWAY_MUTANT") {
        expected.insert("MCP_GATEWAY_MUTANT".into(), Some(mutant));
    }
}

fn s(path: &Path) -> Option<String> {
    Some(path.to_string_lossy().into_owned())
}

/// T2: isolated_with_env_home puts the override at A and every platform-home
/// variable at B, removes inherited gateway variables, and sets nothing else.
#[test]
fn t2_isolated_with_env_home_maps_two_homes() {
    if private_home::is_row_child("t2_isolated_with_env_home_maps_two_homes") {
        let a = Path::new("/never-created/a");
        let b = Path::new("/never-created/b");
        let built = gateway_bin::isolated_with_env_home(
            Command::new("never-run"),
            a,
            b,
            gateway_bin::Inherit::Environment,
        );
        let mut expected = std::collections::BTreeMap::from([
            ("HOME".to_string(), s(b)),
            ("USERPROFILE".to_string(), s(b)),
            ("APPDATA".to_string(), s(&b.join("AppData").join("Roaming"))),
            (
                "LOCALAPPDATA".to_string(),
                s(&b.join("AppData").join("Local")),
            ),
            ("MCP_GATEWAY_TEST_HOME_DIR".to_string(), s(a)),
            (
                "MCP_GATEWAY_SECRETS__STORE".to_string(),
                Some("files".to_string()),
            ),
            ("XDG_CONFIG_HOME".to_string(), s(&a.join(".config"))),
            (
                "XDG_DATA_HOME".to_string(),
                s(&a.join(".local").join("share")),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                s(&a.join(".local").join("state")),
            ),
        ]);
        removals_and_switch(&mut expected);
        assert_eq!(explicit_env(&built), expected);
        return;
    }
    let _ = run_row_child(
        golden_child(),
        "t2_isolated_with_env_home_maps_two_homes",
        false,
        &Expect::Pass,
        Vec::new(),
    );
}

/// T7: the existing command() and command_with_env_home() keep today's env.
#[test]
fn t7_existing_gateway_bin_envs_are_unchanged() {
    if private_home::is_row_child("t7_existing_gateway_bin_envs_are_unchanged") {
        let home = Path::new("/never-created/home");
        let env_home = Path::new("/never-created/env-home");
        let mut expected = std::collections::BTreeMap::from([
            ("HOME".to_string(), s(home)),
            ("USERPROFILE".to_string(), s(home)),
            (
                "APPDATA".to_string(),
                s(&home.join("AppData").join("Roaming")),
            ),
            (
                "LOCALAPPDATA".to_string(),
                s(&home.join("AppData").join("Local")),
            ),
            ("MCP_GATEWAY_TEST_HOME_DIR".to_string(), s(home)),
            (
                "MCP_GATEWAY_SECRETS__STORE".to_string(),
                Some("files".to_string()),
            ),
            ("XDG_CONFIG_HOME".to_string(), s(&home.join(".config"))),
            (
                "XDG_DATA_HOME".to_string(),
                s(&home.join(".local").join("share")),
            ),
            (
                "XDG_STATE_HOME".to_string(),
                s(&home.join(".local").join("state")),
            ),
        ]);
        removals_and_switch(&mut expected);
        let plain = gateway_bin::command(home, gateway_bin::Inherit::Environment);
        assert_eq!(explicit_env(&plain), expected, "command()");
        expected.insert("HOME".into(), s(env_home));
        expected.insert("USERPROFILE".into(), s(env_home));
        let split =
            gateway_bin::command_with_env_home(home, env_home, gateway_bin::Inherit::Environment);
        assert_eq!(explicit_env(&split), expected, "command_with_env_home()");
        return;
    }
    let _ = run_row_child(
        golden_child(),
        "t7_existing_gateway_bin_envs_are_unchanged",
        false,
        &Expect::Pass,
        Vec::new(),
    );
}

/// The mutant switch reaches a grandchild that only its grandparent was given.
#[test]
fn the_mutant_switch_reaches_a_grandchild() {
    const ME: &str = "the_mutant_switch_reaches_a_grandchild";
    if private_home::is_row_child(ME) {
        // The child: spawn the grandchild without supplying the switch.
        let seen = std::env::var("MCP_GATEWAY_MUTANT").expect("the child has the switch");
        let mut command = literal_env_command();
        command.env("MCP_GW_EXPECT_MUTANT", &seen);
        let _ = run_row_child(
            command,
            "mutant_switch_grandchild",
            true,
            &Expect::Pass,
            Vec::new(),
        );
        return;
    }
    let mut command = literal_env_command();
    if std::env::var_os("MCP_GATEWAY_MUTANT").is_none() {
        command.env("MCP_GATEWAY_MUTANT", "pass-through-probe");
    }
    let _ = run_row_child(command, ME, false, &Expect::Pass, Vec::new());
}

/// The grandchild of the row above: it sees exactly the switch its parent had.
#[test]
#[ignore = "run by the_mutant_switch_reaches_a_grandchild as a grandchild"]
fn mutant_switch_grandchild() {
    let expected = std::env::var("MCP_GW_EXPECT_MUTANT").expect("the expected switch");
    assert_eq!(std::env::var("MCP_GATEWAY_MUTANT").ok(), Some(expected));
}

/// G1's literal list: every test that calls `require_private_home!()`, as
/// (binary, fn), from the per-test probe (51 tests) plus the
/// probe fn. It may only grow: a test that newly resolves the home joins it.
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
        "preview_sandbox_linux",
        "canaries_outside_the_binds_are_unreadable",
    ),
    (
        "preview_sandbox_linux",
        "f2_t1_the_unshares_only_child_is_the_helper",
    ),
    (
        "preview_sandbox_linux",
        "f2_t2_the_run_child_holds_no_control_connection",
    ),
    ("preview_sandbox_linux", "masked_system_paths_are_empty"),
    (
        "preview_sandbox_linux",
        "r1_a_fetching_preview_runs_its_target_after_the_handshake",
    ),
    (
        "preview_sandbox_linux",
        "r6b_a_dropped_start_leaves_no_sandbox_running",
    ),
    (
        "preview_sandbox_linux",
        "r6b_a_helper_that_never_connects_is_refused",
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
    ("private_home_rule", "private_home_probe"),
];

/// G1: every listed fn starts with `require_private_home!();`, and no other fn
/// calls it. Deleting a wrapper, or wrapping an unlisted fn, fails this row.
#[test]
fn g1_every_listed_test_starts_with_the_rule() {
    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut found = std::collections::BTreeSet::new();
    let mut late = Vec::new();
    for path in rust_files(&tests_dir) {
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
            if line.trim() != "require_private_home!();" {
                continue;
            }
            let opener = lines[..i]
                .iter()
                .rposition(|l| !l.trim().is_empty())
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

fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("readable dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
