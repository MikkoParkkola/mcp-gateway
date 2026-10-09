// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add` and `remove` keep the comments in gateway.yaml, through the shipped
//! binary.
//!
//! Both re-serialised the whole config, which dropped every comment,
//! including the security warning `init` writes next to `bearer_token`.

use std::path::Path;

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

fn gateway(home: &Path, args: &[&str]) {
    let output = gateway_bin::command(home, gateway_bin::Inherit::Environment)
        .args(args)
        .current_dir(home)
        .output()
        .expect("run mcp-gateway");
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn comments(yaml: &str) -> Vec<&str> {
    yaml.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('#'))
        .collect()
}

#[test]
fn add_keeps_the_comments_init_wrote() {
    for init_args in [&["init"][..], &["init", "--profile", "minimal"][..]] {
        let home = tempfile::tempdir().expect("home");
        let path = home.path().join("gateway.yaml");
        gateway(home.path(), init_args);
        let before = std::fs::read_to_string(&path).expect("init wrote gateway.yaml");
        assert!(before.contains("Do not commit it."), "init's warning moved");

        gateway(
            home.path(),
            &["add", "--url", "https://mcp.example.test/mcp", "remote"],
        );
        gateway(home.path(), &["add", "--command", "echo hi", "local"]);

        let after = std::fs::read_to_string(&path).expect("gateway.yaml");
        for comment in comments(&before) {
            assert!(
                after.contains(comment),
                "{init_args:?}: `add` dropped {comment:?}:\n{after}"
            );
        }
        let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
        assert!(
            config.backends.contains_key("remote") && config.backends.contains_key("local"),
            "{init_args:?}: both backends must be added:\n{after}"
        );

        gateway(home.path(), &["remove", "remote"]);
        let removed = std::fs::read_to_string(&path).expect("gateway.yaml");
        for comment in comments(&before) {
            assert!(
                removed.contains(comment),
                "{init_args:?}: `remove` dropped {comment:?}:\n{removed}"
            );
        }
        let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
        assert!(
            !config.backends.contains_key("remote") && config.backends.contains_key("local"),
            "{init_args:?}: `remove` must take out only its backend:\n{removed}"
        );
    }
}

/// `remove` alone, on a hand-written config: the row that bites the old
/// re-serialising `remove` without depending on `add`.
#[test]
fn remove_keeps_hand_written_comments() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    let yaml = "# operator notes: keep this file under review\n\
                server:\n  port: 39400  # fixed for the firewall rule\n\
                \n# backends we run\nbackends:\n  # the one that stays\n  keep:\n    command: \"echo keep\"\n  \
                drop:\n    command: \"echo drop\"\n";
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write");

    gateway(home.path(), &["remove", "drop"]);

    let after = std::fs::read_to_string(&path).expect("gateway.yaml");
    for comment in comments(yaml) {
        assert!(
            after.contains(comment),
            "`remove` dropped {comment:?}:\n{after}"
        );
    }
    assert!(
        after.contains("# fixed for the firewall rule"),
        "trailing comment lost:\n{after}"
    );
    let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
    assert!(config.backends.contains_key("keep") && !config.backends.contains_key("drop"));
}

#[test]
fn a_file_another_writer_broke_is_refused_not_replaced() {
    use mcp_gateway::config::BackendConfig;
    use mcp_gateway::config_persistence::load_existing_or_default;
    use mcp_gateway::gateway::test_helpers::write_config_fixture;

    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "backends: {}\n").expect("write");
    let before = load_existing_or_default(&path).expect("load");
    let mut config = before.clone();
    let backend: BackendConfig = serde_yaml::from_str("command: echo\n").expect("backend");
    config.backends.insert("new".into(), backend);
    // Another writer adds a key the loader refuses after `add` loaded the file.
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends: {}\nnot_a_gateway_key: 1\n",
    )
    .expect("write");

    // Replacing it would erase that writer's change with `add`'s older copy.
    let error = write_config_fixture(&path, &config).expect_err("refused");
    assert!(error.starts_with("Failed to load"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "backends: {}\nnot_a_gateway_key: 1\n"
    );
}

#[test]
fn an_invalid_config_is_refused_and_left_unwritten() {
    use mcp_gateway::config::BackendConfig;
    use mcp_gateway::config_persistence::load_existing_or_default;
    use mcp_gateway::gateway::test_helpers::write_config_fixture;

    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "# mine\nbackends: {}\n")
        .expect("write");
    let before = load_existing_or_default(&path).expect("load");
    let mut config = before.clone();
    let backend: BackendConfig =
        serde_yaml::from_str("command: echo\nruntime_profile: nosuch\n").expect("backend");
    config.backends.insert("new".into(), backend);

    assert!(write_config_fixture(&path, &config).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "# mine\nbackends: {}\n"
    );
}

/// The web UI and admin write through `backend_ops::write_config`.
fn ui_write(path: &Path, change: impl FnOnce(&mut mcp_gateway::config::Config)) -> String {
    use mcp_gateway::gateway::test_helpers::write_config_fixture;
    use mcp_gateway::gateway::ui::backend_ops::load_config_or_default;
    let mut config = load_config_or_default(path);
    change(&mut config);
    write_config_fixture(path, &config).expect("write config");
    std::fs::read_to_string(path).expect("read")
}

fn echo_backend() -> mcp_gateway::config::BackendConfig {
    serde_yaml::from_str("command: echo\n").expect("backend")
}

const NOTED: &str = "# kept by hand\nbackends:\n  # why old exists\n  old:\n    command: x\n";

#[test]
fn a_single_backend_add_and_remove_through_the_ui_writer_keep_comments() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, NOTED).expect("write");

    let added = ui_write(&path, |c| {
        c.backends.insert("new".into(), echo_backend());
    });
    assert!(
        added.contains("# kept by hand") && added.contains("# why old exists"),
        "{added}"
    );
    assert!(added.contains("new:"), "{added}");

    let removed = ui_write(&path, |c| {
        c.backends.remove("new");
    });
    assert!(
        removed.contains("# kept by hand") && removed.contains("# why old exists"),
        "{removed}"
    );
    assert!(!removed.contains("new:"), "{removed}");
}

#[test]
fn a_change_outside_backends_takes_the_full_rewrite() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, NOTED).expect("write");
    let written = ui_write(&path, |c| c.server.port += 1);
    assert!(
        !written.contains("# kept by hand"),
        "only a backends change is spliced:\n{written}"
    );
    mcp_gateway::config::Config::load_literal(Some(&path)).expect("the rewrite loads");
}

/// MIK-8017: several backends at once are spliced in turn and written once
/// on the CLI path (the web UI writes one backend change at a time).
#[test]
fn several_backends_at_once_keep_comments() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, NOTED).expect("write");
    let mut config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
    config.backends.insert("one".into(), echo_backend());
    config.backends.insert("two".into(), echo_backend());
    let kept = mcp_gateway::config_persistence::edit_config(
        &path,
        mcp_gateway::config_persistence::CommentLoss::Refuse,
        |c| {
            *c = config.clone();
            Ok(())
        },
    )
    .map(drop);
    assert_eq!(kept, Ok(()));
    let written = std::fs::read_to_string(&path).expect("read");
    assert!(written.contains("# kept by hand"), "{written}");
    let config = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
    let mut names: Vec<_> = config.backends.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["old", "one", "two"], "{written}");
}

/// A stale config (another writer added `c` after it was loaded) differs by
/// a removal plus an addition: it is refused, never spliced over `c`.
#[test]
fn a_stale_multi_change_is_refused_not_spliced() {
    use mcp_gateway::config_persistence::edit_config;
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, NOTED).expect("write");
    let mut stale = mcp_gateway::config::Config::load_literal(Some(&path)).expect("loads");
    stale.backends.insert("b".into(), echo_backend());
    let current = format!("{NOTED}  c:\n    command: c\n");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, &current).expect("write");
    let refusal = edit_config(
        &path,
        mcp_gateway::config_persistence::CommentLoss::Refuse,
        |c| {
            *c = stale.clone();
            Ok(())
        },
    )
    .map(drop)
    .expect_err("refused");
    assert!(
        refusal.starts_with("Not saved") && refusal.contains("--force"),
        "{refusal}"
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), current);
}

/// The binary in `home`, isolated as the setup and discovery tests run it:
/// no inherited environment, and a PATH with no host programs to scan.
fn run(home: &Path, args: &[&str]) -> std::process::Output {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    command
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", home.join("no-system-programs"))
        .current_dir(home)
        .stdin(std::process::Stdio::null())
        .args(args);
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    command.output().expect("run mcp-gateway")
}

/// `MIK-CLI-COMMENTS.WARN.1`: a CLI write that would drop comments writes
/// nothing, exits non-zero, and names the commented lines and `--force`.
/// `line 1` is what rules out a clap usage error passing for a refusal.
fn refused(home: &Path, path: &Path, before: &str, args: &[&str]) {
    let output = run(home, args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{args:?} succeeded:\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(path).expect("read"),
        before,
        "{args:?} wrote the file"
    );
    assert!(
        stderr.contains("line 1") && stderr.contains("--force"),
        "{args:?} must name the commented line and --force:\n{stderr}"
    );
    assert!(
        !stderr.contains("# top") && !stderr.contains("# keep me"),
        "{args:?} echoed comment text:\n{stderr}"
    );
}

/// A write that succeeded, and the config it left. With `--force` it must
/// still name the commented line it drops (`MIK-CLI-COMMENTS.FORCE.1`). The
/// flag does not exist on the base, so those rows go red there on clap's
/// usage error, not on an assertion.
fn wrote(home: &Path, path: &Path, args: &[&str]) -> mcp_gateway::config::Config {
    let output = run(home, args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?} failed:\n{stderr}");
    if args.contains(&"--force") {
        assert!(
            stderr.contains("line 1"),
            "{args:?} must name the dropped line:\n{stderr}"
        );
    }
    mcp_gateway::config::Config::load_literal(Some(path)).expect("the rewrite loads")
}

/// A flow-style file the splice cannot edit, with a comment on line 1.
const FLOW: &str = "# top\nbackends: {a: {command: x}, b: {command: y}}\n";

fn flow_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, FLOW).expect("write");
    (home, path)
}

#[test]
fn cli_add_that_would_drop_comments_is_refused() {
    let (home, path) = flow_home();
    let p = path.to_str().unwrap();
    refused(
        home.path(),
        &path,
        FLOW,
        &["add", "--command", "echo hi", "--config", p, "local"],
    );
}

#[test]
fn cli_add_with_force_rewrites() {
    let (home, path) = flow_home();
    let p = path.to_str().unwrap();
    let args = [
        "add",
        "--force",
        "--command",
        "echo hi",
        "--config",
        p,
        "local",
    ];
    let config = wrote(home.path(), &path, &args);
    assert!(config.backends.contains_key("a") && config.backends.contains_key("local"));
}

#[test]
fn cli_remove_that_would_drop_comments_is_refused() {
    let (home, path) = flow_home();
    let p = path.to_str().unwrap();
    refused(home.path(), &path, FLOW, &["remove", "--config", p, "a"]);
}

#[test]
fn cli_remove_with_force_rewrites() {
    let (home, path) = flow_home();
    let p = path.to_str().unwrap();
    let config = wrote(
        home.path(),
        &path,
        &["remove", "--force", "--config", p, "a"],
    );
    assert!(!config.backends.contains_key("a") && config.backends.contains_key("b"));
}

/// A block-style file with a comment on line 1.
const NOTED_BLOCK: &str = "# keep me\nbackends:\n  old:\n    command: x\n";

/// Two Claude Code servers for setup and discovery to import, and
/// `gateway.yaml` holding `yaml` (none when `None`).
fn two_client_servers(yaml: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempfile::tempdir().expect("home");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.path().join(".claude.json"),
        serde_json::to_vec(&serde_json::json!({"mcpServers": {
            "one": {"command": "echo", "args": ["one"]},
            "two": {"command": "echo", "args": ["two"]},
        }}))
        .unwrap(),
    )
    .expect("seed client");
    let path = home.path().join("gateway.yaml");
    if let Some(yaml) = yaml {
        mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write");
    }
    (home, path)
}

#[test]
fn setup_import_keeps_comments() {
    let (home, path) = two_client_servers(Some(NOTED_BLOCK));
    let p = path.to_str().unwrap();
    let config = wrote(
        home.path(),
        &path,
        &["setup", "wizard", "--yes", "--output", p],
    );
    for name in ["old", "one", "two"] {
        assert!(config.backends.contains_key(name), "{name} missing");
    }
    let after = std::fs::read_to_string(&path).expect("read");
    assert!(after.contains("# keep me"), "{after}");
}

/// A first run: setup bootstraps the config `init` writes, with its
/// credential warning, then imports both servers into it.
#[test]
fn setup_on_a_fresh_home_keeps_the_init_warning() {
    let (home, path) = two_client_servers(None);
    let p = path.to_str().unwrap();
    let config = wrote(
        home.path(),
        &path,
        &["setup", "wizard", "--yes", "--output", p],
    );
    assert!(config.backends.contains_key("one") && config.backends.contains_key("two"));
    let after = std::fs::read_to_string(&path).expect("read");
    assert!(after.contains("Do not commit it."), "{after}");
}

#[test]
fn setup_import_that_would_drop_comments_is_refused() {
    let (home, path) = two_client_servers(Some(FLOW));
    let p = path.to_str().unwrap();
    refused(
        home.path(),
        &path,
        FLOW,
        &["setup", "wizard", "--yes", "--output", p],
    );
}

#[test]
fn setup_import_with_force_rewrites() {
    let (home, path) = two_client_servers(Some(FLOW));
    let p = path.to_str().unwrap();
    let args = ["setup", "wizard", "--yes", "--force", "--output", p];
    let config = wrote(home.path(), &path, &args);
    for name in ["a", "b", "one", "two"] {
        assert!(config.backends.contains_key(name), "{name} missing");
    }
}

#[test]
fn discover_write_keeps_comments() {
    let (home, path) = two_client_servers(Some(NOTED_BLOCK));
    let p = path.to_str().unwrap();
    let args = ["cap", "discover", "--write-config", "--config-path", p];
    let config = wrote(home.path(), &path, &args);
    assert!(config.backends.contains_key("one") && config.backends.contains_key("two"));
    let after = std::fs::read_to_string(&path).expect("read");
    assert!(after.contains("# keep me"), "{after}");
}

/// Discovery replaces a same-named backend: that edit, beside an addition,
/// is spliced with the file's comments kept, not refused.
#[test]
fn discover_write_that_replaces_a_backend_keeps_comments() {
    let (home, path) = two_client_servers(Some("# keep me\nbackends:\n  one:\n    command: x\n"));
    let p = path.to_str().unwrap();
    let args = ["cap", "discover", "--write-config", "--config-path", p];
    let config = wrote(home.path(), &path, &args);
    assert!(config.backends.contains_key("one") && config.backends.contains_key("two"));
    let after = std::fs::read_to_string(&path).expect("read");
    assert!(
        after.contains("# keep me") && !after.contains("command: x"),
        "{after}"
    );
}

#[test]
fn discover_write_that_would_drop_comments_is_refused() {
    let (home, path) = two_client_servers(Some(FLOW));
    let p = path.to_str().unwrap();
    refused(
        home.path(),
        &path,
        FLOW,
        &["cap", "discover", "--write-config", "--config-path", p],
    );
}

#[test]
fn discover_write_with_force_rewrites() {
    let (home, path) = two_client_servers(Some(FLOW));
    let p = path.to_str().unwrap();
    let args = [
        "cap",
        "discover",
        "--write-config",
        "--force",
        "--config-path",
        p,
    ];
    let config = wrote(home.path(), &path, &args);
    for name in ["a", "b", "one", "two"] {
        assert!(config.backends.contains_key(name), "{name} missing");
    }
}

/// `cap discover --shadow --write-config` adopts unregistered servers into
/// the compared config through the same writer.
#[test]
fn shadow_adopt_that_would_drop_comments_is_refused() {
    let (home, path) = two_client_servers(Some(FLOW));
    let p = path.to_str().unwrap();
    refused(
        home.path(),
        &path,
        FLOW,
        &[
            "cap",
            "discover",
            "--shadow",
            "--write-config",
            "--gateway-config",
            p,
        ],
    );
}

/// `MIK-CLI-COMMENTS.SILENT.1`: `remove` keeps every comment outside the
/// entry and names, by line, the ones that went with it.
#[test]
fn remove_names_the_comments_that_went_with_the_entry() {
    let home = tempfile::tempdir().expect("home");
    let path = home.path().join("gateway.yaml");
    let yaml = "# top\nbackends:\n  keep:\n    command: x\n  drop:\n    command: y  # why\n";
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("write");
    let p = path.to_str().unwrap();
    let output = run(home.path(), &["remove", "--config", p, "drop"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("line 6"),
        "the dropped line is named:\n{stderr}"
    );
    assert!(
        !stderr.contains("# why"),
        "comment text is never printed:\n{stderr}"
    );
    let after = std::fs::read_to_string(&path).expect("read");
    assert!(
        after.contains("# top") && !after.contains("drop:"),
        "{after}"
    );
}
