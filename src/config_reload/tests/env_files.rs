// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env-file reload tests: home resolution and the startup-only restart report.

use super::env_support::*;
use super::*;

// -------------------------------------------------------------------------
// MIK-7256 — env files on a failed load (§P2 failing tests)
//
// Rows from `docs/design/mik-7256-test-plan.md`, against the design in
// `docs/design/mik-7256-env-files-on-a-failed-load.md`. The design's types do
//
// Seam naming: the design requires that expansion reach its home "through an
// injected resolver rather than calling `dirs::home_dir()` inline"
// (design:314-315) without naming it. These tests name it
// `config::HomeResolver`, `fn home_dir(&self, so_far: &EnvOverlay) ->
// Option<PathBuf>`. `so_far` is load-bearing: startup applies each file before
// expanding the next, so a resolver blind to the overlay under construction
// cannot reproduce production's sequential semantics — the property 19c pins.
// -------------------------------------------------------------------------

/// ENVFILE.19c — two `~/...` entries where the FIRST sets `HOME` to a second
/// temp dir.
///
/// The ORDERING of the assertions is the test. Agreement between consumers is
/// not enough on its own: an implementation that resolves the whole list up
/// front before applying anything makes all three consumers agree — on the
/// wrong second path — and passes an agreement-only check while silently
/// changing which file a restart reads. Asserting each path's home FIRST pins
/// startup's sequential semantics; asserting reuse SECOND pins the single
/// resolution.
#[tokio::test]
async fn envfile_19c_startup_resolves_each_entry_under_the_home_in_force_then_the_reload_reuses_them()
 {
    // GIVEN: two homes; the file in the first ASSIGNS `HOME` to the second
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();
    env_file(
        home_a.path(),
        "one.env",
        &format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19C_ONE=from-one\n",
            home_b.path().display()
        ),
    );
    let two = env_file(
        home_b.path(),
        "two.env",
        "MCP_GW_TEST_ENVFILE19C_TWO=from-two\n",
    );

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = config_naming_env_files(cfg_dir.path(), &["~/one.env", "~/two.env"]);

    // WHEN: startup runs, resolving through a recording home based at the
    // first temp home, so that `~/one.env` names the file written above.
    let home = RecordingHome::based_at(home_a.path());
    let startup = startup_through(&cfg, &home);
    let recorded = home.recorded();

    // THEN, FIRST: each entry was resolved under the home reported at the moment
    // that entry was applied — the expected values computed the same way
    // production does, at the same point in the sequence.
    assert_eq!(
        recorded.len(),
        2,
        "one home resolution per `~` entry, in sequence"
    );
    let expected = vec![recorded[0].join("one.env"), recorded[1].join("two.env")];
    assert_eq!(
        startup.env_paths.as_paths(),
        expected.as_slice(),
        "each entry must be resolved under the home in force when it was applied"
    );

    // The discriminating half. Named limitation, not a hidden one: the oracle is
    // "the home in force when that entry was applied", because `dirs::home_dir()`
    // consults `HOME` only where the platform says so. On Windows it reads a
    // known folder and ignores `HOME` entirely, so file one cannot move entry two
    // and the two expected paths coincide — there the row keeps the reuse and
    // reload assertion and loses its power to separate sequential from
    // up-front resolution, because there the two ARE the same computation.
    #[cfg(unix)]
    {
        assert_eq!(
            recorded[0],
            home_a.path(),
            "entry one resolves under the home in force before any file applied"
        );
        assert_eq!(
            recorded[1],
            home_b.path(),
            "entry two resolves under the home file one assigned — an \
             implementation that resolves the whole list up front lands here on \
             home_a and reads a file nothing watches"
        );
        assert_eq!(expected[1], two, "entry two is the file under the new home");
    }
    #[cfg(not(unix))]
    let _ = two;

    // THEN, SECOND: the reload opens those same two paths, and cannot resolve
    // again — the resolver refuses every call from here on.
    home.finish_startup();
    let ctx = reload_context_with_env(&cfg, &startup);
    ctx.reload_outcome().await.unwrap();
    assert_eq!(
        ctx.env_paths().as_paths(),
        expected.as_slice(),
        "a reload must open the paths startup recorded"
    );
}

/// ENVFILE.19e — a `~/...` entry, and a reload whose env files set `HOME` to a
/// different directory.
///
/// The only case that separates REPORTING the self-relocation from
/// RE-RESOLVING it. It can fail two ways: an implementation that reports
/// nothing leaves a running gateway silently disagreeing with its own restart,
/// and one that reports by resolving the entry a second time reintroduces
/// exactly the rule this design deleted. The injected resolver makes the second
/// failure mode UNREACHABLE rather than merely unobserved — asserting the
/// recorded path is still opened leaves an implementation free to resolve a
/// second time for the sole purpose of deciding the warning, agree with itself,
/// and pass.
#[tokio::test]
async fn envfile_19e_a_reload_assigning_home_reports_restart_required_without_resolving_again() {
    // GIVEN: a home with a `~/...` env file, running
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();
    let recorded_path = env_file(
        home_a.path(),
        "rot.env",
        "MCP_GW_TEST_ENVFILE19E_KEY=startup-value\n",
    );

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = config_naming_env_files(cfg_dir.path(), &["~/rot.env"]);

    let home = RecordingHome::based_at(home_a.path());
    let startup = startup_through(&cfg, &home);
    assert_eq!(
        startup.env_paths.as_paths(),
        std::slice::from_ref(&recorded_path)
    );

    // WHEN: the env file is rewritten to assign `HOME` elsewhere, and reloaded
    home.finish_startup();
    write_owner_only(
        &recorded_path,
        format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19E_KEY=rotated-value\n",
            home_b.path().display()
        ),
    )
    .unwrap();

    let ctx = reload_context_with_env(&cfg, &startup);
    let outcome = ctx.reload_outcome().await.unwrap();

    // THEN: the outcome is restart-required and NAMES `HOME`
    assert!(
        outcome.restart_required,
        "a `HOME` assignment against a `~` entry moves where a restart would \
         read: outcome was {outcome:?}"
    );
    assert!(
        outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
        "the report must name HOME; got {:?}",
        outcome.pending_restart_fields
    );

    // AND: the overlay still reads the path startup recorded. The resolver
    // refuses every call from `finish_startup` on, so a second resolution is
    // impossible rather than merely unobserved — this assertion holds because
    // the fixture enforces the design's one-resolution rule, not because an
    // outcome happened to agree with itself.
    assert_eq!(
        ctx.env_paths().as_paths(),
        &[recorded_path],
        "the running gateway keeps the path it recorded at startup"
    );
    assert_eq!(
        ctx.live_env()
            .get()
            .resolve("MCP_GW_TEST_ENVFILE19E_KEY")
            .as_deref(),
        Some("rotated-value"),
        "the rotation still applies to the file the gateway actually reads"
    );
}

/// ENVFILE.19f — the two halves of the conjunction, held apart.
///
/// 19e is satisfied by an implementation that treats ANY `HOME` assignment as
/// restart-required, which would tell operators to restart for a change that
/// moves nothing they read. The rule is the CONJUNCTION — a `HOME` ASSIGNMENT
/// and an entry whose spelling depends on it — and only a negative can hold the
/// two halves apart.
///
/// The second case is stated as NO assignment rather than an assignment of the
/// same value on purpose: the design triggers the notice on assignment, not on
/// value, because the value a restart would resolve against is not knowable
/// from the reload. A row phrased "HOME does not change" would read as licence
/// to suppress the notice for a same-value assignment, which is the one place
/// that rule must not bend.
#[tokio::test]
async fn envfile_19f_neither_half_of_the_conjunction_alone_is_restart_required_on_home() {
    // CASE 1: a `HOME` assignment, and NO `~/...` entry anywhere in `env_files`
    {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let path = env_file(dir.path(), "plain.env", "MCP_GW_TEST_ENVFILE19F_A=one\n");
        let cfg = config_naming_env_files(dir.path(), &[&path.to_string_lossy()]);

        let home = RecordingHome::new();
        let startup = startup_through(&cfg, &home);
        home.finish_startup();

        write_owner_only(
            &path,
            format!(
                "HOME='{}'\nMCP_GW_TEST_ENVFILE19F_A=two\n",
                elsewhere.path().display()
            ),
        )
        .unwrap();

        let outcome = reload_context_with_env(&cfg, &startup)
            .reload_outcome()
            .await
            .unwrap();

        // Asserted on the field list rather than on `restart_required`: another
        // tracked section may legitimately set the boolean, and a test that
        // failed on it would be failing for the wrong reason.
        assert!(
            !outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
            "no `~` entry depends on HOME, so its assignment moves nothing; got {:?}",
            outcome.pending_restart_fields
        );
    }

    // CASE 2: a `~/...` entry, and NO `HOME` assignment at all
    {
        let home_dir = tempfile::tempdir().unwrap();
        let recorded_path = env_file(home_dir.path(), "rot.env", "MCP_GW_TEST_ENVFILE19F_B=one\n");
        let cfg_dir = tempfile::tempdir().unwrap();
        let cfg = config_naming_env_files(cfg_dir.path(), &["~/rot.env"]);

        let home = RecordingHome::new();
        let startup = startup_through(&cfg, &home);
        home.finish_startup();

        write_owner_only(&recorded_path, "MCP_GW_TEST_ENVFILE19F_B=two\n").unwrap();

        let outcome = reload_context_with_env(&cfg, &startup)
            .reload_outcome()
            .await
            .unwrap();

        assert!(
            !outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
            "nothing assigned HOME, so nothing moved; got {:?}",
            outcome.pending_restart_fields
        );
    }
}

/// ENVFILE.19g — a `~/...` entry, and a reload that re-states the SAME `HOME`.
///
/// The accepted cost of the conservative rule, and the reason it is written
/// down as a test rather than left to be rediscovered. Re-stating the same
/// value moves nothing, and the notice fires anyway, because the only thing
/// that could tell this case apart from 19i — where the same final value hides
/// a genuine relocation — is knowing which home each entry was expanded
/// against, and a reload does not re-expand them. Early beats absent: an
/// operator who restarts for nothing loses a restart, one who is not told
/// silently reads a file the running process never opened.
#[tokio::test]
async fn envfile_19g_a_reload_restating_the_same_home_reports_restart_required() {
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();

    // GIVEN: a `~/...` entry whose file assigns `HOME` elsewhere
    let recorded_path = env_file(
        home_a.path(),
        "rot.env",
        &format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19G_KEY=startup-value\n",
            home_b.path().display()
        ),
    );
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = config_naming_env_files(cfg_dir.path(), &["~/rot.env"]);

    let home = RecordingHome::based_at(home_a.path());
    let startup = startup_through(&cfg, &home);

    // WHEN: the file is rewritten with the SAME `HOME` and a rotated value
    home.finish_startup();
    write_owner_only(
        &recorded_path,
        format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19G_KEY=rotated-value\n",
            home_b.path().display()
        ),
    )
    .unwrap();

    let ctx = reload_context_with_env(&cfg, &startup);
    let outcome = ctx.reload_outcome().await.unwrap();

    // THEN: the notice fires, though nothing moved — the rule cannot tell this
    // apart from 19i without re-expanding, and it errs early
    assert!(
        outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
        "the conservative rule reports on any `HOME` assignment beside a `~` \
         entry; got {:?}",
        outcome.pending_restart_fields
    );
}

/// ENVFILE.19h — a `~/...` entry, and a reload that REMOVES the `HOME`
/// assignment startup had.
///
/// The half a rule keyed on ASSIGNMENT alone cannot see: the deleted line
/// leaves no assignment to notice, and `HOME` falls back to the process
/// environment. For the sole entry here nothing relocates — `~/rot.env` was
/// expanded before its own `HOME` line applied — but the same deletion ahead of
/// a later `~` entry does relocate it, and the value comparison is what catches
/// both. Kept as the value branch's own test, alongside 19i for the assignment
/// branch.
#[tokio::test]
async fn envfile_19h_a_reload_removing_the_home_assignment_reports_restart_required() {
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();

    // GIVEN: a `~/...` entry whose file assigns `HOME` elsewhere
    let recorded_path = env_file(
        home_a.path(),
        "rot.env",
        &format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19H_KEY=startup-value\n",
            home_b.path().display()
        ),
    );
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = config_naming_env_files(cfg_dir.path(), &["~/rot.env"]);

    let home = RecordingHome::based_at(home_a.path());
    let startup = startup_through(&cfg, &home);
    assert_eq!(
        startup.overlay.resolve("HOME").as_deref(),
        Some(home_b.path().to_str().unwrap()),
        "fixture: startup must have taken its `HOME` from the env file"
    );

    // WHEN: the `HOME` line is deleted and the file reloaded
    home.finish_startup();
    write_owner_only(&recorded_path, "MCP_GW_TEST_ENVFILE19H_KEY=rotated-value\n").unwrap();

    let ctx = reload_context_with_env(&cfg, &startup);
    let outcome = ctx.reload_outcome().await.unwrap();

    // THEN: the restart is reported, and it names `HOME`
    assert!(
        outcome.restart_required,
        "the value left standing changed, which the rule reports whether or not \
         this particular entry moved: outcome was {outcome:?}"
    );
    assert!(
        outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
        "the report must name HOME; got {:?}",
        outcome.pending_restart_fields
    );
}

/// ENVFILE.19i — `HOME` moved BEFORE a later `~/...` entry, with the final
/// value restored by the file that entry names.
///
/// The case a comparison of final `HOME` values cannot see. The first env file
/// moves `HOME` somewhere new, so a restart expands the second entry against a
/// different directory and reads a file this process never opened; the file it
/// did open then sets `HOME` back, so startup and reload agree on the final
/// value and a rule comparing only that value stays silent. `~` is expanded
/// against the home in force AT THAT POINT (`Config::evaluate`), not the home
/// left standing at the end, so the end value is not what decides.
#[tokio::test]
async fn envfile_19i_home_moved_before_a_later_tilde_entry_reports_restart_required() {
    let home_a = tempfile::tempdir().unwrap();
    let home_b = tempfile::tempdir().unwrap();
    let home_c = tempfile::tempdir().unwrap();
    let cfg_dir = tempfile::tempdir().unwrap();

    // GIVEN: a plain entry that sets `HOME`, then a `~/...` entry whose own
    // file restores it
    let mover = env_file(
        cfg_dir.path(),
        "mover.env",
        &format!("HOME='{}'\n", home_b.path().display()),
    );
    env_file(
        home_b.path(),
        "late.env",
        &format!(
            "HOME='{}'\nMCP_GW_TEST_ENVFILE19I_KEY=startup-value\n",
            home_b.path().display()
        ),
    );
    let cfg = config_naming_env_files(cfg_dir.path(), &[mover.to_str().unwrap(), "~/late.env"]);

    let home = RecordingHome::based_at(home_a.path());
    let startup = startup_through(&cfg, &home);
    assert_eq!(
        startup.env_paths.as_paths().last().unwrap(),
        &home_b.path().join("late.env"),
        "fixture: the tilde entry must have expanded against the home the \
         FIRST file assigned"
    );

    // WHEN: the first file moves `HOME` somewhere else, leaving the final
    // value untouched — the second file still assigns it back
    home.finish_startup();
    write_owner_only(&mover, format!("HOME='{}'\n", home_c.path().display())).unwrap();

    let ctx = reload_context_with_env(&cfg, &startup);
    let outcome = ctx.reload_outcome().await.unwrap();

    assert_eq!(
        startup.overlay.resolve("HOME").as_deref(),
        Some(home_b.path().to_str().unwrap()),
        "fixture: `late.env` assigns the same `HOME` on both runs, so the FINAL \
         values agree and this test exercises the case a final-value comparison \
         misses"
    );

    // THEN: the restart is reported, and it names `HOME`
    assert!(
        outcome.restart_required,
        "a restart would expand `~/late.env` against {} and read a file this \
         process never opened: outcome was {outcome:?}",
        home_c.path().display()
    );
    assert!(
        outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
        "the report must name HOME; got {:?}",
        outcome.pending_restart_fields
    );
}

/// ENVFILE.19j — the 19i move DELETED, with startup's restored value equal to
/// the process environment's. The case that survives checking the reload overlay alone. Startup moved
/// `HOME` before a later `~` entry and a file after it restored the process
/// home; the reload deletes both lines. Nothing on the reload side assigns
/// `HOME`, and the value it leaves standing is the process home (the same one
/// startup ended on), so both an assignment check over the reload overlay and a
/// comparison of final values are silent. A restart would expand the entry
/// against the process home instead of the moved one. Only startup's OWN
/// assignment records that the expansion base was ever moved. Unix only: no process HOME on Windows.
// Unix-only: moves and restores HOME; Windows resolves the home directory from USERPROFILE.
#[cfg(unix)]
#[tokio::test]
async fn envfile_19j_deleting_the_move_still_reports_when_the_restored_value_is_the_process_home() {
    let process_home = std::env::var("HOME").expect("the process must have a HOME");
    let home_b = tempfile::tempdir().unwrap();
    let cfg_dir = tempfile::tempdir().unwrap();

    // GIVEN: a first file that moves `HOME`, and a `~/...` entry whose file
    // puts it back exactly where the process environment has it
    let mover = env_file(
        cfg_dir.path(),
        "mover.env",
        &format!("HOME='{}'\n", home_b.path().display()),
    );
    let late = env_file(
        home_b.path(),
        "late.env",
        &format!("HOME='{process_home}'\nMCP_GW_TEST_ENVFILE19J_KEY=startup-value\n"),
    );
    let cfg = config_naming_env_files(cfg_dir.path(), &[mover.to_str().unwrap(), "~/late.env"]);

    let home = RecordingHome::based_at(home_b.path());
    let startup = startup_through(&cfg, &home);
    assert_eq!(
        startup.env_paths.as_paths().last().unwrap(),
        &home_b.path().join("late.env"),
        "fixture: the tilde entry must have expanded against the MOVED home"
    );
    assert_eq!(
        startup.overlay.resolve("HOME").as_deref(),
        Some(process_home.as_str()),
        "fixture: startup must end on the process home, or the value \
         comparison would catch this on its own"
    );

    // WHEN: both `HOME` lines are deleted
    home.finish_startup();
    write_owner_only(&mover, "MCP_GW_TEST_ENVFILE19J_KEY=rotated-value\n").unwrap();
    write_owner_only(&late, "MCP_GW_TEST_ENVFILE19J_OTHER=x\n").unwrap();

    let ctx = reload_context_with_env(&cfg, &startup);
    let outcome = ctx.reload_outcome().await.unwrap();

    // THEN: the report still names HOME
    assert!(
        outcome.pending_restart_fields.iter().any(|f| *f == "HOME"),
        "a restart would expand `~/late.env` against {process_home} instead of \
         {}, reading a file this process never opened; got {:?}",
        home_b.path().display(),
        outcome.pending_restart_fields
    );
}

/// ENVFILE.6b — a key that genuinely cannot be applied to a running process.
///
/// Retargeted: `MCP_GATEWAY_PORT` is applied live by `EffectiveEnv`, so the warn
/// this row once asserted described a lag the design removed. What survives the
/// removal is the half that still binds — #439's no-values rule must not be
/// reintroduced by this change's own reporting.
#[tokio::test]
async fn envfile_6b_the_restart_report_names_the_key_and_carries_neither_value() {
    const KEY: &str = "MCP_GW_TEST_ENVFILE6B_TOKEN";
    const OLD: &str = "s3cr3t-6b-old-4a91f2";
    const NEW: &str = "s3cr3t-6b-new-7c30bd";

    // GIVEN: a bearer token supplied by an env file. `ResolvedAuthConfig` is
    // built once at startup and nothing rebuilds it, so this key cannot be
    // applied to the running process.
    let dir = tempfile::tempdir().unwrap();
    let env_path = env_file(dir.path(), "auth.env", &format!("{KEY}={OLD}\n"));
    let cfg = dir.path().join("gateway.yaml");
    write_owner_only(
        &cfg,
        format!(
            "env_files:\n  - '{}'\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: \"env:{KEY}\"\n",
            env_path.display()
        ),
    )
    .unwrap();

    let home = RecordingHome::new();
    let startup = startup_through(&cfg, &home);
    home.finish_startup();

    // WHEN: the env file rotates the value and the reload is accepted
    write_owner_only(&env_path, format!("{KEY}={NEW}\n")).unwrap();
    let outcome = reload_context_with_env(&cfg, &startup)
        .reload_outcome()
        .await
        .unwrap();

    // THEN: the report names the key
    assert!(
        outcome.restart_required,
        "a startup-only holder cannot take the new value: {outcome:?}"
    );
    let report = format!("{} {:?}", outcome.changes, outcome.pending_restart_fields);
    assert!(
        report.contains(KEY),
        "the report must name the key that needs a restart; got {report}"
    );

    // AND: neither the old nor the new value appears anywhere in it
    assert!(
        !report.contains(OLD),
        "the report leaked the OLD value; got {report}"
    );
    assert!(
        !report.contains(NEW),
        "the report leaked the NEW value; got {report}"
    );
    let serialized = serde_json::to_string(&outcome).unwrap();
    assert!(
        !serialized.contains(OLD) && !serialized.contains(NEW),
        "the serialized outcome leaked a value; got {serialized}"
    );
}

/// MIK-8014.PERF.6 — the input scanner parses its free-text key list once per
/// published overlay. Its cache is correct only because every reload publishes
/// a new overlay through `publish_overlay` and none is mutated in place, so
/// this row drives the production reload, not `LiveEnv::set`: an exemption a
/// reload revokes must reach the very next scan.
#[tokio::test]
async fn perf6_a_reload_that_revokes_a_skip_key_reaches_the_next_scan() {
    use crate::security::firewall::input_scanner::InputScanner;

    let home = tempfile::tempdir().unwrap();
    let path = env_file(
        home.path(),
        "firewall.env",
        "MCP_GATEWAY_FIREWALL_SKIP_KEYS=release_notes\n",
    );
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg = config_naming_env_files(cfg_dir.path(), &[path.to_str().unwrap()]);
    let startup = startup_through(&cfg, &RecordingHome::based_at(home.path()));
    let ctx = reload_context_with_env(&cfg, &startup);
    let scanner = InputScanner::with_env(Arc::clone(ctx.live_env()));
    let args = serde_json::Map::from_iter([(
        "release_notes".to_string(),
        serde_json::Value::String("run `id`".into()),
    )]);
    assert!(scanner.scan_args(&args).is_empty(), "exempt at startup");
    assert!(
        scanner.scan_args(&args).is_empty(),
        "still exempt, from the held list"
    );

    write_owner_only(&path, "MCP_GATEWAY_FIREWALL_SKIP_KEYS=changelog\n").unwrap();
    ctx.reload_outcome().await.unwrap();

    assert!(
        !scanner.scan_args(&args).is_empty(),
        "the reload revoked the exemption; the next scan must flag the command"
    );
}
