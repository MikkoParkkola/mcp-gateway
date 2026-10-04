// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::prerelease_tests::stamp_4_0_0;
use super::*;
use tempfile::TempDir;

// ── stamp read/write ──────────────────────────────────────────────────────

#[test]
fn stamp_missing_read_returns_none() {
    // GIVEN: a temp dir with no stamp file
    let dir = TempDir::new().unwrap();
    let path = stamp_path(dir.path());
    // WHEN: reading the missing stamp
    let result = read_stamp(&path).unwrap();
    // THEN: None is returned
    assert!(result.is_none());
}

#[test]
fn stamp_write_then_read_round_trips_version() {
    // GIVEN: a temp dir
    let dir = TempDir::new().unwrap();
    let path = stamp_path(dir.path());
    // WHEN: version is written
    write_stamp(&path, "2.9.1").unwrap();
    // THEN: reading it back returns the same string
    assert_eq!(read_stamp(&path).unwrap().as_deref(), Some("2.9.1"));
}

#[test]
fn stamp_write_trims_on_read() {
    // GIVEN: a stamp file with trailing newline
    let dir = TempDir::new().unwrap();
    let path = stamp_path(dir.path());
    std::fs::write(&path, "2.9.1\n").unwrap();
    // WHEN: read back
    let v = read_stamp(&path).unwrap().unwrap();
    // THEN: whitespace is trimmed
    assert_eq!(v, "2.9.1");
}

// ── check_upgrade ─────────────────────────────────────────────────────────

#[test]
fn check_upgrade_fresh_install_writes_stamp() {
    // GIVEN: a data dir with no stamp file
    let dir = TempDir::new().unwrap();
    // WHEN: check_upgrade is called
    check_upgrade(dir.path()).unwrap();
    // THEN: the stamp now contains the current version
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

#[test]
fn check_upgrade_same_version_is_noop() {
    // GIVEN: a stamp at the current version
    let dir = TempDir::new().unwrap();
    let current = env!("CARGO_PKG_VERSION");
    write_stamp(&stamp_path(dir.path()), current).unwrap();
    // WHEN: check_upgrade is called (noop: stamp == current binary version)
    check_upgrade(dir.path()).unwrap();
    // THEN: stamp content is unchanged — check_upgrade must not re-write the stamp
    // when installed == current; we verify by reading back and comparing the value.
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(v, current);
    // Note: mtime comparison is platform-specific, so we only check content above.
}

#[test]
fn check_upgrade_older_stamp_updates_to_current() {
    // GIVEN: a stamp at a very old version
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), "0.1.0").unwrap();
    // WHEN: check_upgrade is called
    check_upgrade(dir.path()).unwrap();
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(
        v,
        env!("CARGO_PKG_VERSION"),
        "the stamp keeps the prerelease"
    );
}

#[test]
fn check_upgrade_downgrade_does_not_touch_stamp() {
    // GIVEN: a stamp at a future version (simulates downgrade)
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), "99.0.0").unwrap();
    // WHEN: check_upgrade is called
    check_upgrade(dir.path()).unwrap();
    // THEN: stamp is left at 99.0.0 (downgrade protection)
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(v, "99.0.0");
}

// ── run_upgrade_command ───────────────────────────────────────────────────

#[test]
fn upgrade_command_fresh_install_returns_success() {
    // GIVEN: an empty data dir
    let dir = TempDir::new().unwrap();
    // WHEN: upgrade command runs
    let code = run_upgrade_command(false, true, Some(dir.path()));
    // THEN: exits successfully and writes stamp
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(stamp_path(dir.path()).exists());
}

#[test]
fn upgrade_command_dry_run_does_not_write_stamp() {
    // GIVEN: an empty data dir and dry-run mode
    let dir = TempDir::new().unwrap();
    // WHEN: upgrade command runs in dry-run mode
    let code = run_upgrade_command(true, true, Some(dir.path()));
    // THEN: exits successfully but stamp is NOT written (fresh install dry-run)
    assert_eq!(code, ExitCode::SUCCESS);
    // Dry-run on fresh install: stamp is not created
    assert!(!stamp_path(dir.path()).exists());
}

#[test]
fn upgrade_command_same_version_is_noop() {
    // GIVEN: stamp at current version
    let dir = TempDir::new().unwrap();
    let current = env!("CARGO_PKG_VERSION");
    write_stamp(&stamp_path(dir.path()), current).unwrap();
    // WHEN: upgrade command runs
    let code = run_upgrade_command(false, true, Some(dir.path()));
    // THEN: success, stamp unchanged
    assert_eq!(code, ExitCode::SUCCESS);
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(v, current);
}

#[test]
fn upgrade_command_old_stamp_updates_to_current() {
    // GIVEN: stamp at 0.1.0
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), "0.1.0").unwrap();
    // WHEN: upgrade runs (quiet so no stdout noise in test)
    let code = run_upgrade_command(false, true, Some(dir.path()));
    assert_eq!(code, ExitCode::SUCCESS);
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(
        v,
        env!("CARGO_PKG_VERSION"),
        "the stamp keeps the prerelease"
    );
}

#[test]
fn upgrade_command_downgrade_returns_success_stamp_unchanged() {
    // GIVEN: stamp at 99.0.0
    let dir = TempDir::new().unwrap();
    write_stamp(&stamp_path(dir.path()), "99.0.0").unwrap();
    // WHEN: upgrade runs
    let code = run_upgrade_command(false, true, Some(dir.path()));
    // THEN: success, stamp untouched
    assert_eq!(code, ExitCode::SUCCESS);
    let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(v, "99.0.0");
}

// ── backup_config ─────────────────────────────────────────────────────────

#[test]
fn backup_config_missing_returns_none() {
    // GIVEN: a dir with no gateway.yaml
    let dir = TempDir::new().unwrap();
    // WHEN: backup is attempted
    let result = backup_config(dir.path(), "1.0.0").unwrap();
    // THEN: None (nothing to back up)
    assert!(result.is_none());
}

#[test]
fn backup_config_creates_versioned_bak_file() {
    // GIVEN: a dir with gateway.yaml
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    std::fs::write(&yaml, "server:\n  port: 39400\n").unwrap();
    // WHEN: backup is called
    let bak = backup_config(dir.path(), "1.2.3").unwrap().unwrap();
    // THEN: backup file exists with correct name
    assert_eq!(bak.file_name().unwrap(), "gateway.yaml.bak.1.2.3");
    assert!(bak.exists());
}

#[test]
fn backup_config_preserves_content() {
    // GIVEN: a gateway.yaml with known content
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    std::fs::write(&yaml, "content: preserved\n").unwrap();
    // WHEN: backup is made
    let bak = backup_config(dir.path(), "2.0.0").unwrap().unwrap();
    // THEN: backup has the same content
    let content = std::fs::read_to_string(bak).unwrap();
    assert_eq!(content, "content: preserved\n");
}

// ── applicable_migrations ─────────────────────────────────────────────────

#[test]
fn migrations_registry_registers_each_ceiling_once() {
    // GIVEN: the MIGRATIONS registry
    // WHEN/THEN: one entry per release that needs a migration, in order.
    // A ceiling registered twice would run its notice twice on one upgrade.
    assert_eq!(MIGRATIONS.len(), 2);
    assert_eq!(MIGRATIONS[0].applies_below, "3.0.0");
    assert_eq!(MIGRATIONS[1].applies_below, "4.0.0");
}

#[test]
fn pre_3_0_0_stamp_has_every_migration_applicable() {
    // GIVEN: an install stamped below 3.0.0
    let dir = TempDir::new().unwrap();
    let ctx = UpgradeContext {
        data_dir: dir.path(),
        old_ver: SemVer::parse("1.0.0").unwrap(),
        new_ver: SemVer::parse("2.10.0").unwrap(),
        dry_run: false,
        quiet: true,
    };
    // WHEN: applicable migrations are collected
    // THEN: both notices apply — the install predates each ceiling
    assert_eq!(ctx.applicable_migrations().len(), 2);
}

#[test]
fn stamp_at_3_0_0_leaves_only_the_4_0_0_notice_applicable() {
    // GIVEN: an install already stamped at 3.0.0 (the migration's own ceiling)
    let dir = TempDir::new().unwrap();
    let ctx = UpgradeContext {
        data_dir: dir.path(),
        old_ver: SemVer::parse("3.0.0").unwrap(),
        new_ver: SemVer::parse("3.0.0").unwrap(),
        dry_run: false,
        quiet: true,
    };
    // WHEN: applicable migrations are collected
    // THEN: the 3.0.0 notice is done with — `applies_below` is a strict upper
    // bound (idempotency guard) — and only the 4.0.0 notice remains
    let applicable = ctx.applicable_migrations();
    assert_eq!(applicable.len(), 1);
    assert_eq!(applicable[0].applies_below, "4.0.0");
}

// ── what's new ───────────────────────────────────────────────────────────

#[test]
fn whats_new_registry_has_entries_for_current_version() {
    // GIVEN: the WHATS_NEW registry
    // WHEN: we look for entries at 2.10.0
    let v2100 = SemVer::parse("2.10.0").unwrap();
    let has_entries = WHATS_NEW
        .iter()
        .any(|w| SemVer::parse(w.version).as_ref() == Some(&v2100));
    // THEN: at least one entry exists
    assert!(has_entries, "WHATS_NEW should have entries for v2.10.0");
}

#[test]
fn whats_new_items_shown_when_upgrading_past_version() {
    // GIVEN: upgrading from 2.9.1 to 2.10.0
    let from = SemVer::parse("2.9.1").unwrap();
    let to = SemVer::parse("2.10.0").unwrap();
    // WHEN: collecting what's-new items
    let items: Vec<&str> = WHATS_NEW
        .iter()
        .filter(|w| SemVer::parse(w.version).is_some_and(|v| v > from && v <= to))
        .flat_map(|w| w.items.iter().copied())
        .collect();
    // THEN: items are not empty (v2.10.0 entries should match)
    assert!(
        !items.is_empty(),
        "Should have what's-new items for 2.9.1 -> 2.10.0"
    );
}

#[test]
fn whats_new_items_not_shown_for_same_version() {
    // GIVEN: no version change (already at 2.10.0)
    let from = SemVer::parse("2.10.0").unwrap();
    let to = SemVer::parse("2.10.0").unwrap();
    // WHEN: collecting what's-new items
    let items: Vec<&str> = WHATS_NEW
        .iter()
        .filter(|w| SemVer::parse(w.version).is_some_and(|v| v > from && v <= to))
        .flat_map(|w| w.items.iter().copied())
        .collect();
    // THEN: no items (version > from is false when from == to)
    assert!(items.is_empty());
}

// ── backup during migration ──────────────────────────────────────────────

#[test]
fn backup_called_when_migrations_apply() {
    // GIVEN: a data dir with gateway.yaml and an UpgradeContext that has a
    // migration (we simulate by directly calling backup_config, since the
    // static MIGRATIONS slice cannot be mutated in tests)
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    let config_content = "server:\n  port: 39400\n  host: 0.0.0.0\n";
    std::fs::write(&yaml, config_content).unwrap();

    // WHEN: backup_config is called as the migration engine would
    let bak = backup_config(dir.path(), "2.8.0").unwrap();

    // THEN: backup file exists and preserves content
    let bak_path = bak.expect("backup should be created when gateway.yaml exists");
    assert_eq!(bak_path.file_name().unwrap(), "gateway.yaml.bak.2.8.0");
    let backed_up = std::fs::read_to_string(&bak_path).unwrap();
    assert_eq!(backed_up, config_content);
    // Original is untouched
    let original = std::fs::read_to_string(&yaml).unwrap();
    assert_eq!(original, config_content);
}

#[test]
fn no_backup_when_zero_migrations() {
    // GIVEN: a data dir with gateway.yaml stamped above every registered
    // `applies_below` ceiling, so no migration matches.
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    std::fs::write(&yaml, "server:\n  port: 39400\n").unwrap();
    write_stamp(&stamp_path(dir.path()), "4.0.0").unwrap();

    // WHEN: upgrade runs (stamp already satisfies every registered migration)
    let ctx = UpgradeContext {
        data_dir: dir.path(),
        old_ver: SemVer::parse("4.0.0").unwrap(),
        new_ver: SemVer::parse("4.0.1").unwrap(),
        dry_run: false,
        quiet: true,
    };
    let n = ctx.run().unwrap();

    // THEN: no migrations applied, no backup file created
    assert_eq!(n, 0);
    let bak = dir.path().join("gateway.yaml.bak.4.0.0");
    assert!(
        !bak.exists(),
        "backup should NOT be created when 0 migrations apply"
    );
}

// ── 3.0.0 multi-user posture notice migration ────────────────────────────

#[test]
fn posture_auth_disabled_when_auth_section_absent() {
    // GIVEN: a config with no `auth` section at all
    let yaml: serde_yaml::Value = serde_yaml::from_str("server:\n  port: 39400\n").unwrap();
    // WHEN/THEN: treated as auth-disabled (default `auth.enabled` is false)
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::AuthDisabled
    );
}

#[test]
fn posture_auth_disabled_when_enabled_false() {
    // GIVEN: auth explicitly disabled
    let yaml: serde_yaml::Value = serde_yaml::from_str("auth:\n  enabled: false\n").unwrap();
    // WHEN/THEN
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::AuthDisabled
    );
}

#[test]
fn posture_undeclared_when_auth_enabled_without_single_user_or_shared_account() {
    // GIVEN: auth enabled, no single_user flag, no backend shared_account
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n",
    )
    .unwrap();
    // WHEN/THEN: this is exactly the silent-behavior-change case
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::Undeclared
    );
}

#[test]
fn posture_already_declared_when_single_user_true() {
    // GIVEN: auth enabled and single_user explicitly declared
    let yaml: serde_yaml::Value =
        serde_yaml::from_str("auth:\n  enabled: true\n  single_user: true\n").unwrap();
    // WHEN/THEN
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::AlreadyDeclared
    );
}

#[test]
fn posture_already_declared_when_backend_shared_account_true() {
    // GIVEN: auth enabled, single_user unset, but one backend opts in to shared_account
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n      shared_account: true\n",
    )
    .unwrap();
    // WHEN/THEN
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::AlreadyDeclared
    );
}

#[test]
fn posture_undeclared_ignores_shared_account_false() {
    // GIVEN: a backend that explicitly sets shared_account: false (still fail-closed)
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      shared_account: false\n",
    )
    .unwrap();
    // WHEN/THEN: an explicit `false` must not be mistaken for an opt-in
    assert_eq!(
        detect_multi_user_posture(&yaml),
        MultiUserPosture::Undeclared
    );
}

#[test]
fn migration_apply_is_a_noop_when_config_file_missing() {
    // GIVEN: a data dir with no gateway.yaml at all
    let dir = TempDir::new().unwrap();
    // WHEN: the migration runs
    let result = migrate_3_0_0_multi_user_notice(dir.path());
    // THEN: it succeeds without creating any file
    assert!(result.is_ok());
    assert!(!dir.path().join("gateway.yaml").exists());
}

#[test]
fn migration_apply_is_a_noop_on_unparseable_yaml() {
    // GIVEN: a gateway.yaml that is not valid YAML
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    std::fs::write(&yaml, "not: [valid: yaml").unwrap();
    // WHEN: the migration runs
    let result = migrate_3_0_0_multi_user_notice(dir.path());
    // THEN: it succeeds (never fails the upgrade over a notice) and leaves
    // the unparseable file untouched.
    assert!(result.is_ok());
    assert_eq!(std::fs::read_to_string(&yaml).unwrap(), "not: [valid: yaml");
}

#[test]
fn migration_apply_never_mutates_the_config_file() {
    // GIVEN: a config that would trigger the "undeclared" notice branch
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    let original = "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n";
    std::fs::write(&yaml, original).unwrap();

    // WHEN: the migration runs (potentially twice, simulating a re-run)
    migrate_3_0_0_multi_user_notice(dir.path()).unwrap();
    migrate_3_0_0_multi_user_notice(dir.path()).unwrap();

    // THEN: the file is byte-for-byte unchanged — no `single_user` or
    // `shared_account` was injected, no security posture was altered.
    assert_eq!(std::fs::read_to_string(&yaml).unwrap(), original);
}

#[test]
fn migration_apply_is_idempotent_via_check_upgrade_version_stamp() {
    // GIVEN: a v2.x install with an auth-enabled, undeclared-posture config
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    let original = "auth:\n  enabled: true\n";
    std::fs::write(&yaml, original).unwrap();
    write_stamp(&stamp_path(dir.path()), "2.10.0").unwrap();

    // WHEN: check_upgrade runs once — the migration applies and the stamp
    // advances to the current binary version
    check_upgrade(dir.path()).unwrap();
    let stamp_after_first = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    // GH475.MIG.2: exactly 4.0.0 plus this build's own prerelease, so a
    // version bump still reds the 4.0.0 behaviour this case pins.
    assert_eq!(stamp_after_first, stamp_4_0_0());
    let content_after_first = std::fs::read_to_string(&yaml).unwrap();
    assert_eq!(content_after_first, original);

    // AND WHEN: check_upgrade runs again (simulating the next process start)
    check_upgrade(dir.path()).unwrap();

    // THEN: the stamp and config are unchanged — the migration did not
    // re-run because `installed == current` short-circuits to the no-op
    // branch (idempotency guaranteed by the version stamp, not by the
    // migration's own logic).
    let stamp_after_second = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
    assert_eq!(stamp_after_second, stamp_4_0_0());
    let content_after_second = std::fs::read_to_string(&yaml).unwrap();
    assert_eq!(content_after_second, original);
}

/// GH475.MIG.1 / GH475.MIG.2 — upgrading from 3.9.0 advances the stamp and
/// leaves the operator's config byte-identical, and the second start is a
/// no-op. The stamp is the only file the upgrade may write.
#[test]
fn migration_4_0_0_advances_the_stamp_without_touching_the_config() {
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    let original = "auth:\n  enabled: true\n  single_user: true\n";
    std::fs::write(&yaml, original).unwrap();
    write_stamp(&stamp_path(dir.path()), "3.9.0").unwrap();

    check_upgrade(dir.path()).unwrap();
    // GH475.MIG.2: pinned to the literal 4.0.0, not env!("CARGO_PKG_VERSION")
    // — that macro tracks whatever version this crate happens to be next.
    // Only the prerelease (`-beta.1`) comes from the manifest; see
    // `prerelease_tests::stamp_4_0_0`.
    assert_eq!(
        read_stamp(&stamp_path(dir.path())).unwrap().unwrap(),
        stamp_4_0_0()
    );
    assert_eq!(std::fs::read_to_string(&yaml).unwrap(), original);

    check_upgrade(dir.path()).unwrap();
    assert_eq!(
        read_stamp(&stamp_path(dir.path())).unwrap().unwrap(),
        stamp_4_0_0()
    );
    assert_eq!(
        std::fs::read_to_string(&yaml).unwrap(),
        original,
        "the second start must change nothing at all"
    );
}

/// GH475.MIG.3 — the comparison direction is pinned. `applicable_migrations`
/// selects a migration when `old_ver < applies_below`; every other case in
/// this file starts at or below 4.0.0, so an inverted comparison
/// (`old_ver > applies_below`) would stay green under all of them. This
/// starts strictly above 4.0.0 and asserts the 4.0.0 notice does not
/// re-fire.
#[test]
fn upgrade_from_above_4_0_0_does_not_refire_the_notice() {
    let ctx = UpgradeContext {
        data_dir: Path::new("/nonexistent"),
        old_ver: SemVer::parse("4.0.1").unwrap(),
        new_ver: SemVer::parse("4.0.1").unwrap(),
        dry_run: true,
        quiet: true,
    };
    assert!(
        ctx.applicable_migrations().is_empty(),
        "no migration should apply when already installed above 4.0.0"
    );
}

#[test]
fn notice_only_upgrade_leaves_no_config_backup() {
    // GIVEN: a pre-3.0.0 install with a gateway.yaml present
    let dir = TempDir::new().unwrap();
    let yaml = dir.path().join("gateway.yaml");
    std::fs::write(&yaml, "auth:\n  enabled: true\n  single_user: true\n").unwrap();
    write_stamp(&stamp_path(dir.path()), "2.10.0").unwrap();

    // WHEN: check_upgrade runs, and every applicable migration is a notice
    check_upgrade(dir.path()).unwrap();

    // THEN: nothing was copied, because nothing was changed. A backup file
    // for an upgrade that only advanced the version stamp is an unexplained
    // artefact the operator has to reason about.
    let bak = dir.path().join("gateway.yaml.bak.2.10.0");
    assert!(
        !bak.exists(),
        "a notice-only upgrade must not write a config backup"
    );
    assert!(
        MIGRATIONS.iter().all(|m| m.notice),
        "this test is only meaningful while every registered migration is a notice"
    );
}

/// GH475.MIG.4 — every command a notice tells an operator to run must exist.
///
/// The 4.0.0 notice shipped `mcp-gateway auth login <backend>` for a binary
/// that has no `auth` subcommand, so the one item requiring operator action
/// gave an instruction that exits 2. Asserting the notice *names its four
/// items* did not catch it, because the text was present and wrong.
///
/// Checked against clap's own subcommand list rather than a hand-kept
/// spelling, so a renamed or removed subcommand fails here instead of in an
/// operator's terminal.
#[test]
fn every_command_a_notice_prints_is_a_real_subcommand() {
    use clap::CommandFactory;

    let cli = mcp_gateway::cli::Cli::command();
    let known: Vec<&str> = cli.get_subcommands().map(clap::Command::get_name).collect();

    for item in NOTICE_4_0_0_ITEMS {
        for (offset, _) in item.match_indices("mcp-gateway ") {
            let rest = &item[offset + "mcp-gateway ".len()..];
            let sub = rest
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .next()
                .unwrap_or("");
            assert!(
                !sub.is_empty() && known.contains(&sub),
                "the notice tells the operator to run `mcp-gateway {sub}`, \
which is not one of the binary's subcommands: {known:?}"
            );
        }
    }
}
