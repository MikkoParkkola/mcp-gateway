// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH462 regression-first checks for real config loaders, mutations and CLI writes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, LiveEnv, TransportConfig};
use mcp_gateway::config_persistence::{load_existing_or_default, write_config};
use mcp_gateway::config_reload::{
    ConfigMutation, ConfigWriteError, LiveConfig, ReloadContext, mutate_config_and_reload,
};

const MALFORMED: &str =
    "# preserve this operator edit\nbackends:\n  sentinel:\n    command: \"unfinished\n";
const SEMANTIC: &str =
    "# preserve this invalid name\nbackends:\n  bad/name:\n    command: echo sentinel\n";
const SECRET: &str = "gh462-distinctive-resolved-secret-keep-out-of-yaml";

fn baseline() -> Config {
    let mut config = Config::default();
    config.server.port = 39462;
    config.backends.insert(
        "sentinel".into(),
        BackendConfig {
            description: "original operator backend".into(),
            enabled: false,
            transport: TransportConfig::Stdio {
                command: "echo sentinel".into(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    config
}

fn context(path: &Path, config: Config) -> ReloadContext {
    let registry = Arc::new(BackendRegistry::new());
    for (name, backend) in &config.backends {
        assert!(registry.register(Arc::new(Backend::new(
            name,
            backend.clone(),
            &config.failsafe,
            Duration::from_secs(60),
        ))));
    }
    ReloadContext::new(
        path.to_owned(),
        Arc::new(LiveConfig::new(config.clone())),
        registry,
        config.failsafe,
        Duration::from_secs(60),
    )
}

async fn refused_mutation(path: &Path, with_context: bool) {
    let ctx = context(path, baseline());
    let before = ctx.live_config.get();
    let sentinel = ctx.registry.get("sentinel").expect("fixture registry");
    let mut calls = 0;
    let outcome = mutate_config_and_reload(path, with_context.then_some(&ctx), |config| {
        calls += 1;
        config.server.port = 39463;
        Ok::<_, ()>(())
    })
    .await;

    assert_eq!(calls, 0, "GH462: failed load executed the mutation closure");
    assert!(matches!(outcome, Err(ConfigWriteError::Failed(_))));
    if with_context {
        assert!(Arc::ptr_eq(&before, &ctx.live_config.get()));
        assert_eq!(ctx.registry.all().len(), 1);
        assert!(Arc::ptr_eq(
            &sentinel,
            &ctx.registry.get("sentinel").expect("original backend lost")
        ));
    }
}

fn assert_invalid_fixture(path: &Path, original: &str) {
    let error = Config::load_literal(Some(path)).unwrap_err();
    if original == SEMANTIC {
        assert!(matches!(error, mcp_gateway::Error::ConfigValidation(_)));
    } else {
        assert!(matches!(error, mcp_gateway::Error::Config(_)));
    }
}

// GH462.CONFIG.1 / GH462.CONFIG.2: independent cases retain every red result.
macro_rules! invalid_mutation_case {
    ($name:ident, $original:expr, $with_context:expr) => {
        #[tokio::test]
        async fn $name() {
            let original = $original;
            let home = tempfile::tempdir().unwrap();
            let path = home.path().join("gateway.yaml");
            std::fs::write(&path, original).unwrap();
            assert_invalid_fixture(&path, original);
            let before = tree_snapshot(home.path());
            refused_mutation(&path, $with_context).await;
            assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
            assert_eq!(tree_snapshot(home.path()), before);
        }
    };
}

invalid_mutation_case!(gh462_malformed_without_context, MALFORMED, false);
invalid_mutation_case!(gh462_malformed_with_context, MALFORMED, true);
invalid_mutation_case!(gh462_semantic_without_context, SEMANTIC, false);
invalid_mutation_case!(gh462_semantic_with_context, SEMANTIC, true);

// GH462.CONFIG.5: same entry paths as negative cases; missing really means missing.
macro_rules! valid_mutation_case {
    ($name:ident, $with_context:expr, $existing:expr) => {
        #[tokio::test]
        async fn $name() {
            let with_context = $with_context;
            let existing = $existing;
            let home = tempfile::tempdir().unwrap();
            let path = home.path().join("gateway.yaml");
            let config = if existing {
                baseline()
            } else {
                Config::default()
            };
            if existing {
                write_config(&path, &config).unwrap();
            }
            let ctx = context(&path, config);
            let mut calls = 0;
            let result = mutate_config_and_reload(&path, with_context.then_some(&ctx), |c| {
                calls += 1;
                c.server.port = 39463;
                Ok::<_, ()>("applied")
            })
            .await;
            assert!(matches!(result, Ok(ConfigMutation::Applied("applied", _))));
            assert_eq!(calls, 1);
            let saved = Config::load_literal(Some(&path)).unwrap();
            assert_eq!(saved.server.port, 39463);
            assert_eq!(saved.backends.contains_key("sentinel"), existing);
            if existing {
                assert_eq!(
                    saved.backends["sentinel"].description,
                    "original operator backend"
                );
            }
            if with_context {
                assert_eq!(ctx.live_config.get().server.port, 39463);
            }
        }
    };
}

valid_mutation_case!(gh462_missing_without_context, false, false);
valid_mutation_case!(gh462_missing_with_context, true, false);
valid_mutation_case!(gh462_valid_without_context, false, true);
valid_mutation_case!(gh462_valid_with_context, true, true);

// GH462.CONFIG.5: a deliberate refusal remains distinct from a failed load.
#[tokio::test]
async fn gh462_rejected_mutation_leaves_valid_config_exactly_unchanged() {
    for with_context in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("gateway.yaml");
        let config = baseline();
        write_config(&path, &config).unwrap();
        let before = tree_snapshot(home.path());
        let ctx = context(&path, config);
        let live = ctx.live_config.get();
        let result = mutate_config_and_reload(&path, with_context.then_some(&ctx), |c| {
            c.backends.clear();
            Err::<(), _>("deliberate refusal")
        })
        .await;
        assert!(matches!(
            result,
            Ok(ConfigMutation::Rejected("deliberate refusal"))
        ));
        assert_eq!(tree_snapshot(home.path()), before);
        if with_context {
            assert!(Arc::ptr_eq(&live, &ctx.live_config.get()));
        }
    }
}

fn reference_config(home: &Path) -> Config {
    let env_file = home.join("credentials.env");
    std::fs::write(&env_file, format!("GH462_REFERENCE_TOKEN={SECRET}\n")).unwrap();
    let mut config = baseline();
    config.env_files = vec![env_file.display().to_string()];
    config.auth.enabled = true;
    config.auth.bearer_token = Some("env:GH462_REFERENCE_TOKEN".into());
    config
        .backends
        .get_mut("sentinel")
        .unwrap()
        .env
        .insert("REFERENCED".into(), "${GH462_REFERENCE_TOKEN}".into());
    config
}

fn assert_references(path: &Path) {
    let saved = std::fs::read_to_string(path).unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&saved).unwrap();
    assert_eq!(
        parsed["auth"]["bearer_token"].as_str(),
        Some("env:GH462_REFERENCE_TOKEN")
    );
    assert_eq!(
        parsed["backends"]["sentinel"]["env"]["REFERENCED"].as_str(),
        Some("${GH462_REFERENCE_TOKEN}")
    );
    assert!(!saved.contains(SECRET));
}

// GH462.CONFIG.6: real literal loader/writer, resolved live config as control.
#[tokio::test]
async fn gh462_successful_mutations_preserve_literal_secret_references() {
    // Give this admin test its own deployment environment without mutating the
    // shared test process (set_var is unsafe in Rust 2024).
    const CHILD: &str = "GH462_ADMIN_ENV_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "gh462_successful_mutations_preserve_literal_secret_references",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("MCP_GATEWAY_SERVER__PORT", "39464")
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated admin test timed out")
        .expect("launch isolated admin test");
        assert!(
            output.status.success(),
            "isolated admin test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("GH462_ADMIN_OVERRIDE_CHECKS_COMPLETE"),
            "isolated child did not finish both production mutation paths"
        );
        return;
    }
    assert_eq!(std::env::var(CHILD).unwrap(), "1");
    assert_eq!(std::env::var("MCP_GATEWAY_SERVER__PORT").unwrap(), "39464");

    for with_context in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("gateway.yaml");
        write_config(&path, &reference_config(home.path())).unwrap();
        let resolved = Config::load_evaluated(Some(&path)).unwrap();
        assert_eq!(resolved.config.auth.bearer_token.as_deref(), Some(SECRET));
        assert_eq!(
            resolved.config.server.port, 39464,
            "override fixture is inactive"
        );
        let ctx = context(&path, resolved.config)
            .with_env(Arc::new(LiveEnv::new(resolved.overlay, resolved.env_paths)));
        let result = mutate_config_and_reload(&path, with_context.then_some(&ctx), |c| {
            c.backends.get_mut("sentinel").unwrap().description = "gh462 admin edit".into();
            Ok::<_, ()>(())
        })
        .await;
        assert!(matches!(result, Ok(ConfigMutation::Applied((), _))));
        assert_references(&path);
        let saved = Config::load_literal(Some(&path)).unwrap();
        assert_eq!(
            saved.server.port, 39462,
            "admin persisted an environment override"
        );
        assert_eq!(saved.backends["sentinel"].description, "gh462 admin edit");
    }
    println!("GH462_ADMIN_OVERRIDE_CHECKS_COMPLETE");
}

// GH462.CONFIG.3 / GH462.CONFIG.5: pin the shared helper independently of callers.
#[test]
fn gh462_shared_loader_distinguishes_missing_valid_and_invalid_files() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("gateway.yaml");
    assert!(load_existing_or_default(&path).unwrap().backends.is_empty());
    assert!(!path.exists(), "a loader must not create the missing file");
    write_config(&path, &baseline()).unwrap();
    assert_eq!(load_existing_or_default(&path).unwrap().server.port, 39462);
    for original in [MALFORMED, SEMANTIC] {
        std::fs::write(&path, original).unwrap();
        assert_invalid_fixture(&path, original);
        let before = tree_snapshot(home.path());
        assert!(load_existing_or_default(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        assert_eq!(tree_snapshot(home.path()), before);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct EntrySnapshot {
    contents: Vec<u8>,
    #[cfg(unix)]
    identity: (u64, u64),
}

/// Includes Unix device/inode identity: equal bytes alone cannot prove no replacement.
fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, EntrySnapshot> {
    fn visit(root: &Path, dir: &Path, entries: &mut BTreeMap<PathBuf, EntrySnapshot>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            let value = if kind.is_symlink() {
                format!("symlink:{}", std::fs::read_link(&path).unwrap().display()).into_bytes()
            } else if kind.is_dir() {
                visit(root, &path, entries);
                b"directory".to_vec()
            } else {
                std::fs::read(&path).unwrap()
            };
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                (metadata.dev(), metadata.ino())
            };
            entries.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                EntrySnapshot {
                    contents: value,
                    #[cfg(unix)]
                    identity,
                },
            );
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[cfg(unix)]
mod unix_io {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[derive(Clone, Copy, Debug)]
    pub(super) enum Failure {
        Unreadable,
        DeniedParent,
        Dangling,
    }

    pub(super) struct RestorePermissions(PathBuf, std::fs::Permissions);

    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            std::fs::set_permissions(&self.0, self.1.clone()).unwrap();
        }
    }

    pub(super) fn prepare(home: &Path, failure: Failure) -> PathBuf {
        let parent = home.join("config");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("gateway.yaml");
        if matches!(failure, Failure::Dangling) {
            symlink(parent.join("missing-target.yaml"), &path).unwrap();
        } else {
            write_config(&path, &baseline()).unwrap();
            assert!(Config::load_literal(Some(&path)).is_ok());
        }
        path
    }

    pub(super) fn deny(path: &Path, failure: Failure) -> Option<RestorePermissions> {
        let target = match failure {
            Failure::Unreadable => path,
            Failure::DeniedParent => path.parent().unwrap(),
            Failure::Dangling => {
                assert!(std::fs::symlink_metadata(path).unwrap().is_symlink());
                assert_eq!(
                    std::fs::File::open(path).unwrap_err().kind(),
                    std::io::ErrorKind::NotFound
                );
                return None;
            }
        };
        let restore = RestorePermissions(
            target.to_owned(),
            std::fs::metadata(target).unwrap().permissions(),
        );
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o0)).unwrap();
        // An elevated runner must not silently skip an ineffective fixture.
        assert_eq!(
            std::fs::File::open(path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        if matches!(failure, Failure::DeniedParent) {
            assert_eq!(
                std::fs::symlink_metadata(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        Some(restore)
    }

    // GH462.CONFIG.3: helper matrix, independent of admin/setup error mapping.
    macro_rules! loader_io_case {
        ($name:ident, $failure:expr) => {
            #[test]
            fn $name() {
                let failure = $failure;
                let home = tempfile::tempdir().unwrap();
                let path = prepare(home.path(), failure);
                let before = tree_snapshot(home.path());
                let guard = deny(&path, failure);
                let result = load_existing_or_default(&path);
                drop(guard);
                assert!(result.is_err(), "{failure:?} was mistaken for absence");
                assert_eq!(tree_snapshot(home.path()), before);
            }
        };
    }

    loader_io_case!(gh462_loader_unreadable, Failure::Unreadable);
    loader_io_case!(gh462_loader_denied_parent, Failure::DeniedParent);
    loader_io_case!(gh462_loader_dangling, Failure::Dangling);

    // GH462.CONFIG.3: six failure/path pairs; context helper asserts live invariants.
    macro_rules! mutation_io_case {
        ($name:ident, $failure:expr, $with_context:expr) => {
            #[tokio::test]
            async fn $name() {
                let failure = $failure;
                let home = tempfile::tempdir().unwrap();
                let path = prepare(home.path(), failure);
                let before = tree_snapshot(home.path());
                let guard = deny(&path, failure);
                refused_mutation(&path, $with_context).await;
                drop(guard);
                assert_eq!(tree_snapshot(home.path()), before);
            }
        };
    }

    mutation_io_case!(gh462_unreadable_without_context, Failure::Unreadable, false);
    mutation_io_case!(gh462_unreadable_with_context, Failure::Unreadable, true);
    mutation_io_case!(
        gh462_denied_parent_without_context,
        Failure::DeniedParent,
        false
    );
    mutation_io_case!(
        gh462_denied_parent_with_context,
        Failure::DeniedParent,
        true
    );
    mutation_io_case!(gh462_dangling_without_context, Failure::Dangling, false);
    mutation_io_case!(gh462_dangling_with_context, Failure::Dangling, true);
}

#[cfg(feature = "webui")]
mod cli {
    use super::*;
    use std::process::Stdio;
    use tokio::process::Command;

    const IMPORTED: &str = "gh462-fixture-import";

    fn seed_client(home: &Path) {
        std::fs::write(
            home.join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "operatorSetting": "preserve client sentinel",
                "mcpServers": {(IMPORTED): {"command": "echo", "args": ["gh462 fixture"]}}
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::create_dir(home.join(".cursor")).unwrap();
        std::fs::write(
            home.join(".cursor/mcp.json"),
            b"{\"mcpServers\":{},\"sentinel\":true}\n",
        )
        .unwrap();
    }

    async fn run(
        home: &Path,
        path: &Path,
        setup: bool,
        configure_client: bool,
    ) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .env_clear()
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("APPDATA", home.join("AppData/Roaming"))
            // Process discovery invokes ps/wmic by name. An isolated child PATH
            // removes host-process input while retaining real client discovery.
            .env("PATH", home.join("no-system-programs"))
            .env("GH462_REFERENCE_TOKEN", SECRET)
            .env("MCP_GATEWAY_SERVER__PORT", "39464")
            .current_dir(home)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if setup {
            command
                .args(["setup", "wizard", "--yes", "--output"])
                .arg(path);
            if configure_client {
                command.arg("--configure-client");
            }
        } else {
            command
                .args([
                    "add",
                    IMPORTED,
                    "--command",
                    "echo gh462 fixture",
                    "--config",
                ])
                .arg(path);
        }
        tokio::time::timeout(Duration::from_secs(30), command.output())
            .await
            .expect("GH462 CLI timed out")
            .expect("launch gateway binary")
    }

    fn assert_refused(output: &std::process::Output, path: &Path, setup: bool) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "invalid config accepted: {stdout}\n{stderr}"
        );
        assert!(
            stderr.contains(path.to_string_lossy().as_ref()),
            "not a selected-config error: {stderr}"
        );
        assert!(
            !stderr.contains("unexpected argument"),
            "clap failure is not config rejection"
        );
        assert!(
            !stderr.contains("Failed to write"),
            "a write-stage error does not prove the failed load stopped the edit: {stderr}"
        );
        assert!(!stdout.contains("Imported ") && !stdout.contains("Added '"));
        if setup {
            assert!(
                stdout.contains("MCP Gateway Setup"),
                "setup entry point was not reached"
            );
            assert!(
                !stdout.contains("Scanning AI client"),
                "invalid config reached discovery"
            );
        }
    }

    // GH462.CONFIG.1 / .2 / .4: cover plain setup and optional client export.
    macro_rules! invalid_cli_case {
        ($name:ident, $original:expr, $setup:expr, $configure_client:expr) => {
            #[tokio::test]
            async fn $name() {
                let original = $original;
                let home = tempfile::tempdir().unwrap();
                seed_client(home.path());
                let path = home.path().join("gateway.yaml");
                std::fs::write(&path, original).unwrap();
                assert_invalid_fixture(&path, original);
                let before = tree_snapshot(home.path());
                let output = run(home.path(), &path, $setup, $configure_client).await;
                assert_refused(&output, &path, $setup);
                assert_eq!(
                    tree_snapshot(home.path()),
                    before,
                    "gateway/client paths changed"
                );
            }
        };
    }

    invalid_cli_case!(gh462_add_malformed, MALFORMED, false, false);
    invalid_cli_case!(gh462_add_semantic, SEMANTIC, false, false);
    #[cfg(feature = "config-export")]
    invalid_cli_case!(gh462_setup_malformed, MALFORMED, true, true);
    #[cfg(feature = "config-export")]
    invalid_cli_case!(gh462_setup_semantic, SEMANTIC, true, true);
    invalid_cli_case!(gh462_setup_malformed_without_client, MALFORMED, true, false);
    invalid_cli_case!(gh462_setup_semantic_without_client, SEMANTIC, true, false);

    // GH462.CONFIG.4: reject before any discovery outcome, including no clients.
    async fn invalid_empty_discovery(configure_client: bool) {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("gateway.yaml");
        std::fs::write(&path, MALFORMED).unwrap();
        let before = tree_snapshot(home.path());
        let output = run(home.path(), &path, true, configure_client).await;
        assert_refused(&output, &path, true);
        assert_eq!(tree_snapshot(home.path()), before);
    }

    #[cfg(feature = "config-export")]
    #[tokio::test]
    async fn gh462_setup_refuses_invalid_config_before_empty_discovery() {
        invalid_empty_discovery(true).await;
    }

    #[tokio::test]
    async fn gh462_setup_empty_discovery_without_client() {
        invalid_empty_discovery(false).await;
    }

    #[tokio::test]
    async fn gh462_valid_config_control_reaches_empty_discovery() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("gateway.yaml");
        write_config(&path, &baseline()).unwrap();
        let before = tree_snapshot(home.path());
        let output = run(home.path(), &path, true, false).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("No MCP servers found in any AI client config."));
        assert!(!stdout.contains("Importing all"));
        assert_eq!(tree_snapshot(home.path()), before);
    }

    // GH462.CONFIG.3: actual CLI I/O behavior, preserving even a dangling entry.
    #[cfg(unix)]
    macro_rules! cli_io_case {
        ($name:ident, $failure:ident, $setup:expr, $configure_client:expr) => {
            #[tokio::test]
            async fn $name() {
                use super::unix_io::{Failure, deny, prepare};
                let failure = Failure::$failure;
                let home = tempfile::tempdir().unwrap();
                seed_client(home.path());
                let path = prepare(home.path(), failure);
                let before = tree_snapshot(home.path());
                let guard = deny(&path, failure);
                let output = run(home.path(), &path, $setup, $configure_client).await;
                drop(guard);
                assert_refused(&output, &path, $setup);
                assert_eq!(tree_snapshot(home.path()), before);
            }
        };
    }

    #[cfg(unix)]
    cli_io_case!(gh462_add_unreadable, Unreadable, false, false);
    #[cfg(unix)]
    cli_io_case!(gh462_add_denied_parent, DeniedParent, false, false);
    #[cfg(unix)]
    cli_io_case!(gh462_add_dangling, Dangling, false, false);
    #[cfg(all(unix, feature = "config-export"))]
    cli_io_case!(gh462_setup_unreadable, Unreadable, true, true);
    #[cfg(all(unix, feature = "config-export"))]
    cli_io_case!(gh462_setup_denied_parent, DeniedParent, true, true);
    #[cfg(all(unix, feature = "config-export"))]
    cli_io_case!(gh462_setup_dangling, Dangling, true, true);
    #[cfg(unix)]
    cli_io_case!(
        gh462_setup_unreadable_without_client,
        Unreadable,
        true,
        false
    );
    #[cfg(unix)]
    cli_io_case!(
        gh462_setup_denied_parent_without_client,
        DeniedParent,
        true,
        false
    );
    #[cfg(unix)]
    cli_io_case!(gh462_setup_dangling_without_client, Dangling, true, false);

    // GH462.CONFIG.4 / .5: positive control proves client-writing fixture is live.
    macro_rules! valid_cli_case {
        ($name:ident, $setup:expr, $existing:expr) => {
            #[tokio::test]
            async fn $name() {
                let setup = $setup;
                let existing = $existing;
                let home = tempfile::tempdir().unwrap();
                seed_client(home.path());
                let path = home.path().join("gateway.yaml");
                if existing {
                    write_config(&path, &baseline()).unwrap();
                }
                let client_before = std::fs::read(home.path().join(".claude.json")).unwrap();
                let output = run(home.path(), &path, setup, true).await;
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let saved = Config::load_literal(Some(&path)).unwrap();
                assert!(
                    saved.backends.contains_key(IMPORTED),
                    "fixture backend was not discovered/imported"
                );
                if existing {
                    assert_eq!(
                        saved.server.port, 39462,
                        "environment override was persisted"
                    );
                    assert_eq!(
                        saved.backends["sentinel"].description,
                        "original operator backend"
                    );
                }
                if setup {
                    let client_after = std::fs::read(home.path().join(".claude.json")).unwrap();
                    assert_ne!(
                        client_before, client_after,
                        "control did not exercise client writing"
                    );
                    let client: serde_json::Value = serde_json::from_slice(&client_after).unwrap();
                    assert!(client["mcpServers"]["gateway"]["url"].is_string());
                    assert_eq!(client["operatorSetting"], "preserve client sentinel");
                    if !existing {
                        assert!(
                            home.path()
                                .join("capabilities/knowledge/weather_current.yaml")
                                .exists()
                        );
                        assert!(
                            home.path()
                                .join("capabilities/knowledge/public_holidays.yaml")
                                .exists()
                        );
                    }
                } else {
                    assert_eq!(
                        std::fs::read(home.path().join(".claude.json")).unwrap(),
                        client_before
                    );
                }
            }
        };
    }

    valid_cli_case!(gh462_add_missing, false, false);
    valid_cli_case!(gh462_add_valid, false, true);
    #[cfg(feature = "config-export")]
    valid_cli_case!(gh462_setup_missing, true, false);
    #[cfg(feature = "config-export")]
    valid_cli_case!(gh462_setup_valid, true, true);

    // GH462.CONFIG.6: binary isolation enables non-vacuous secret/override checks.
    macro_rules! reference_cli_case {
        ($name:ident, $setup:expr) => {
            #[tokio::test]
            async fn $name() {
                let home = tempfile::tempdir().unwrap();
                seed_client(home.path());
                let path = home.path().join("gateway.yaml");
                write_config(&path, &reference_config(home.path())).unwrap();
                assert_eq!(
                    Config::load(Some(&path))
                        .unwrap()
                        .auth
                        .bearer_token
                        .as_deref(),
                    Some(SECRET)
                );
                let output = run(home.path(), &path, $setup, false).await;
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_references(&path);
                let saved = Config::load_literal(Some(&path)).unwrap();
                assert_eq!(
                    saved.server.port, 39462,
                    "environment override was persisted"
                );
                assert!(saved.backends.contains_key(IMPORTED));
            }
        };
    }

    reference_cli_case!(gh462_add_references, false);
    reference_cli_case!(gh462_setup_references, true);
}
