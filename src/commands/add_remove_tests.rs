// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for `add`: the env inputs, the store step and the refusals.

use super::*;
use mcp_gateway::config::{Config, TransportConfig};
use mcp_gateway::gateway::ui::backend_ops::{BackendUpdate, update_backend};
use tempfile::TempDir;

fn temp_config() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    (dir, path)
}

/// Runs `cli` on its own thread while a gateway mutation holds the config
/// lock and adds backend `x` to `a`: the overlap checked for each CLI
/// writer. Returns what `cli` returned and the backends left after.
async fn overlap_with_gateway_add<T: Send + 'static>(
    cli: impl FnOnce(std::path::PathBuf) -> T + Send + 'static,
) -> (T, Vec<String>) {
    let (_dir, path) = temp_config();
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  a:\n    command: a\n",
    )
    .expect("write");
    let at = path.clone();
    let mutated = mcp_gateway::config_reload::mutate_config_and_reload(&path, None, |config| {
        let queued = mcp_gateway::gateway::test_helpers::when_waiting_for_config_lock(&at);
        let writer = at.clone();
        let cli = std::thread::spawn(move || cli(writer));
        assert!(
            queued
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "the CLI writer never waited for the config lock"
        );
        let x = crate::yaml::from_str("command: x\n").expect("backend");
        config.backends.insert("x".into(), x);
        Ok::<_, String>(cli)
    })
    .await;
    let Ok(mcp_gateway::config_reload::ConfigMutation::Applied(cli, _)) = mutated else {
        panic!("mutation not applied");
    };
    let out = cli.join().expect("cli thread");
    let config = Config::load_literal(Some(&path)).expect("loads");
    let mut names: Vec<_> = config.backends.keys().cloned().collect();
    names.sort_unstable();
    (out, names)
}

/// Overlap, add: `add` overlapping a gateway's locked
/// mutation keeps the mutation's backend and adds its own.
#[tokio::test]
async fn add_racing_a_gateway_mutation_keeps_both_backends() {
    let (code, names) = overlap_with_gateway_add(|path| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(run_add_command(
                "y",
                Some("y"),
                None,
                None,
                AddValues::default(),
                &path,
                CommentLoss::Refuse,
            ))
    })
    .await;
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(names, ["a", "x", "y"]);
}

/// Overlap, discover: `cap discover --write-config` overlapping a
/// gateway's locked mutation keeps the mutation's backend and adds the
/// discovered one.
#[tokio::test]
async fn discover_write_racing_a_gateway_mutation_keeps_both() {
    let (written, names) = overlap_with_gateway_add(|path| {
        let server = mcp_gateway::discovery::DiscoveredServer::new(
            "found".to_string(),
            "found description".to_string(),
            mcp_gateway::discovery::DiscoverySource::ClaudeDesktop,
            TransportConfig::Stdio {
                command: "found".to_string(),
                cwd: None,
                protocol_version: None,
            },
            mcp_gateway::discovery::ServerMetadata::default(),
        );
        crate::cli::entry::write_discovered_to_config(&[server], Some(&path), CommentLoss::Refuse)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
    assert_eq!(written, Ok(()));
    assert_eq!(names, ["a", "found", "x"]);
}

/// Overlap, remove: `remove` overlapping a gateway's locked mutation loads the
/// file under the same lock it writes with, so the backend the mutation
/// added survives the removal.
#[tokio::test]
async fn remove_racing_a_gateway_mutation_keeps_its_add() {
    let (_dir, path) = temp_config();
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  a:\n    command: a\n  b:\n    command: b\n",
    )
    .expect("write");
    let at = path.clone();
    let mutated = mcp_gateway::config_reload::mutate_config_and_reload(&path, None, |config| {
        let queued = mcp_gateway::gateway::test_helpers::when_waiting_for_config_lock(&at);
        let remove = at.clone();
        let cli = std::thread::spawn(move || run_remove_command("b", &remove, CommentLoss::Refuse));
        assert!(
            queued
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "remove never waited for the config lock"
        );
        let x = crate::yaml::from_str("command: x\n").expect("backend");
        config.backends.insert("x".into(), x);
        Ok::<_, String>(cli)
    })
    .await;
    let Ok(mcp_gateway::config_reload::ConfigMutation::Applied(cli, _)) = mutated else {
        panic!("mutation not applied");
    };
    assert_eq!(cli.join().expect("cli thread"), ExitCode::SUCCESS);
    let config = Config::load_literal(Some(&path)).expect("loads");
    let mut names: Vec<_> = config.backends.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["a", "x"]);
}

// ── add round-trip ────────────────────────────────────────────────────────

#[tokio::test]
async fn add_then_remove_round_trip() {
    // GIVEN: a temp config file
    let (_dir, path) = temp_config();

    // WHEN: adding a backend by registry name
    let code = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "add should succeed");

    // THEN: it appears in the config
    let config = Config::load(Some(&path)).unwrap();
    assert!(
        config.backends.contains_key("tavily"),
        "tavily must be present"
    );

    // WHEN: removing it
    let code = run_remove_command("tavily", &path, CommentLoss::Refuse);
    assert_eq!(code, ExitCode::SUCCESS, "remove should succeed");

    // THEN: it is gone
    let config = Config::load(Some(&path)).unwrap();
    assert!(
        !config.backends.contains_key("tavily"),
        "tavily must be gone"
    );
}

/// CLIADD.1/.4 (A1): a credential-named `-e` literal goes to the secret
/// store; gateway.yaml holds only its reference. The files store is
/// pinned so no test reaches an OS keychain.
#[tokio::test]
async fn add_custom_command_backend() {
    // GIVEN: a temp config whose secrets go to owner-only files
    let (_dir, path) = temp_config();
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "secrets:\n  store: files\n")
        .expect("write");

    // WHEN: adding with an explicit --command, the value from --env-file
    let env_file = path.with_file_name("env.json");
    std::fs::write(&env_file, br#"{"API_KEY":"secret123"}"#).expect("env file");
    let code = run_add_command(
        "my-server",
        Some("node /home/user/my-server.js"),
        None,
        Some("My custom server"),
        AddValues {
            env_vars: &[],
            env_file: Some(&env_file),
            keep_as_text: &[],
        },
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS);

    // THEN: the backend has correct fields, as written (a load would
    // resolve the reference back to the value)
    let config = Config::load_literal(Some(&path)).unwrap();
    let backend = config.backends.get("my-server").unwrap();
    assert_eq!(backend.description, "My custom server");
    let written = backend.env.get("API_KEY").expect("API_KEY");
    assert!(written.starts_with("file:"), "{written}");
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(!text.contains("secret123"), "{text}");
    // A files-store reference names the owner-only file holding the value.
    let stored = std::fs::read_to_string(written.trim_start_matches("file:")).expect("entry");
    assert_eq!(stored.trim_end(), "secret123");
}

/// CLIADD.2 (A4): `--keep-as-text API_KEY` writes that value as typed
/// and stores nothing; a misspelt field is refused and nothing is written.
#[tokio::test]
async fn keep_as_text_writes_the_value_as_typed() {
    let (_dir, path) = temp_config();
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, "secrets:\n  store: files\n")
        .expect("write");
    let env_file = path.with_file_name("env.json");
    std::fs::write(&env_file, br#"{"API_KEY":"secret123"}"#).expect("env file");
    for (keep, code) in [
        ("API_KEYY", ExitCode::FAILURE),
        ("API_KEY", ExitCode::SUCCESS),
    ] {
        let got = run_add_command(
            "my-server",
            Some("node server.js"),
            None,
            None,
            AddValues {
                env_vars: &[],
                env_file: Some(&env_file),
                keep_as_text: &[keep.to_string()],
            },
            &path,
            CommentLoss::Refuse,
        )
        .await;
        assert_eq!(got, code, "{keep}");
    }
    let config = Config::load(Some(&path)).expect("loads");
    assert_eq!(config.backends["my-server"].env["API_KEY"], "secret123");
    assert!(
        !path.with_file_name("secrets").exists(),
        "nothing was stored"
    );
}

#[tokio::test]
async fn add_duplicate_returns_failure() {
    // GIVEN: a config that already has "tavily"
    let (_dir, path) = temp_config();
    let setup = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(setup, ExitCode::SUCCESS, "the setup add succeeds");

    // WHEN: adding again
    let code = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;

    // THEN: failure
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn remove_nonexistent_backend_returns_failure() {
    let (_dir, path) = temp_config();
    let code = run_remove_command("does-not-exist", &path, CommentLoss::Refuse);
    assert_eq!(code, ExitCode::FAILURE);
}

#[tokio::test]
async fn add_http_url_backend() {
    // GIVEN: a temp config
    let (_dir, path) = temp_config();

    // WHEN: adding an HTTP backend
    let code = run_add_command(
        "context7",
        None,
        Some("https://mcp.context7.com/mcp"),
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS);

    // THEN: transport is Http
    let config = Config::load(Some(&path)).unwrap();
    let backend = config.backends.get("context7").unwrap();
    match &backend.transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "https://mcp.context7.com/mcp");
        }
        other => panic!("expected Http transport, got {other:?}"),
    }
}

// ── get command ───────────────────────────────────────────────────────────

#[tokio::test]
async fn get_existing_backend_returns_success() {
    let (_dir, path) = temp_config();
    let setup = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(setup, ExitCode::SUCCESS, "the setup add succeeds");
    let code = run_get_command("tavily", &path);
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn get_missing_backend_returns_failure() {
    let (_dir, path) = temp_config();
    let code = run_get_command("ghost", &path);
    assert_eq!(code, ExitCode::FAILURE);
}

// ── list command ──────────────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_success_when_empty() {
    let (_dir, path) = temp_config();
    let code = run_list_command(false, &path);
    assert_eq!(code, ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_json_returns_success_with_backends() {
    let (_dir, path) = temp_config();
    let setup = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(setup, ExitCode::SUCCESS, "the setup add succeeds");
    let code = run_list_command(true, &path);
    assert_eq!(code, ExitCode::SUCCESS);
}

// ── run_update_backend ────────────────────────────────────────────────────

/// `update_backend` through the CLI's comment-keeping writer. Test-only:
/// no CLI verb updates a backend, and the web UI's PATCH goes through the
/// async reload API, never this blocking writer.
fn run_update_backend(name: &str, update: BackendUpdate, config: &Path) -> Result<(), String> {
    super::super::config_write::write(config, CommentLoss::Refuse, |gateway_config| {
        update_backend(gateway_config, name, update)
    })
}

#[tokio::test]
async fn update_existing_backend_succeeds() {
    let (_dir, path) = temp_config();
    let setup = run_add_command(
        "tavily",
        None,
        None,
        None,
        AddValues::default(),
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(setup, ExitCode::SUCCESS, "the setup add succeeds");

    let result = run_update_backend(
        "tavily",
        BackendUpdate {
            description: Some("updated desc".to_string()),
            ..Default::default()
        },
        &path,
    );
    assert!(result.is_ok());

    let config = Config::load(Some(&path)).unwrap();
    assert_eq!(config.backends["tavily"].description, "updated desc");
}

/// Comments kept or refused: an update that cannot keep the comments
/// is refused and leaves the file as it was.
#[test]
fn update_that_would_drop_comments_is_refused() {
    let (_dir, path) = temp_config();
    let flow = "# keep\nbackends: {a: {command: x}}\n";
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, flow).unwrap();
    let update = BackendUpdate {
        description: Some("new".into()),
        ..BackendUpdate::default()
    };
    let error = run_update_backend("a", update, &path).unwrap_err();
    assert!(error.contains("line 1"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), flow);
}

#[test]
fn update_missing_backend_returns_error() {
    let (_dir, path) = temp_config();
    let result = run_update_backend("ghost", BackendUpdate::default(), &path);
    assert!(result.is_err());
}

// GH462.CONFIG.5: these guarded writers must never persist an empty fallback.
fn assert_guarded_writers_preserve_invalid_config(original: &str) {
    let (_dir, path) = temp_config();
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, original).unwrap();
    let error = Config::load_literal(Some(&path)).unwrap_err();
    if original.contains("bad/name") {
        assert!(matches!(error, mcp_gateway::Error::ConfigValidation(_)));
    } else {
        assert!(matches!(error, mcp_gateway::Error::Config(_)));
    }
    // Unix-only: compares (dev, ino) file identity, which Windows metadata does not expose.
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path).unwrap();
        (metadata.dev(), metadata.ino())
    };

    assert_eq!(
        run_remove_command("original", &path, CommentLoss::Refuse),
        ExitCode::FAILURE
    );
    assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
    // Unix-only: compares (dev, ino) file identity, which Windows metadata does not expose.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
    }

    let result = run_update_backend(
        "original",
        BackendUpdate {
            description: Some("gh462 edit must not persist".into()),
            ..BackendUpdate::default()
        },
        &path,
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
    // Unix-only: compares (dev, ino) file identity, which Windows metadata does not expose.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
    }
}

#[test]
fn gh462_remove_and_update_preserve_malformed_config() {
    assert_guarded_writers_preserve_invalid_config(
        "backends:\n  original:\n    command: \"unterminated\n",
    );
}

#[test]
fn gh462_remove_and_update_preserve_semantic_invalid_config() {
    assert_guarded_writers_preserve_invalid_config(
        "backends:\n  bad/name:\n    command: echo original\n",
    );
}

/// A real CLI edit after a crashed byte write: `remove` meets a pending
/// replace journal over an unparseable candidate and refuses, leaving the
/// file, the journal and the staged original as they were. The CLI holds
/// no audit sink, so it does not recover; a gateway reload does, and
/// records it when the gateway keeps an audit log. The refusal checks only
/// that a journal exists; the on-disk format is pinned by the startup
/// recovery row in `serve_load_tests`.
#[test]
fn remove_refuses_a_crashed_byte_write_and_leaves_it_pending() {
    use sha2::Digest as _;
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("gateway.yaml");
    let original = "# operator's note\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    std::fs::write(&config, "backends: [not: yaml\n").unwrap();
    let target = std::fs::canonicalize(&config).unwrap();
    let staged = target.with_file_name(".gateway.yaml.replace-original");
    // Owner-only, as the writer stages it: recovery reads both files
    // through the config guard.
    mcp_gateway::gateway::test_helpers::write_owner_only(&staged, original).unwrap();
    let journal = target.with_file_name(".gateway.yaml.replace-journal");
    let revision = hex::encode(sha2::Sha256::digest(original.as_bytes()));
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &journal,
        serde_json::json!({
            "version": 1,
            "state": "staged",
            "target": target,
            "original": staged,
            "original_revision": revision,
        })
        .to_string(),
    )
    .unwrap();

    let code = run_remove_command("b", &config, CommentLoss::Refuse);

    assert_eq!(code, ExitCode::FAILURE, "the refusal fails the command");

    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "backends: [not: yaml\n",
        "nothing was written"
    );
    assert!(journal.exists(), "the journal is still pending");
    assert_eq!(
        std::fs::read_to_string(&staged).unwrap(),
        original,
        "the staged original is kept for the audited recovery"
    );
}

/// E2 (D-CLI): `-e NAME` takes NAME's value from the environment; a name
/// the environment lacks is refused, naming it.
#[test]
fn e2_a_name_takes_its_value_from_the_environment() {
    let lookup = |name: &str| (name == "MY_TOKEN").then(|| "tok-0123456789abcdef".to_string());
    let got = env_inputs(&["MY_TOKEN".to_string()], None, lookup).expect("found");
    assert_eq!(
        got.get("MY_TOKEN").map(String::as_str),
        Some("tok-0123456789abcdef")
    );
    let missing = env_inputs(&["NOT_SET".to_string()], None, lookup).expect_err("refused");
    assert!(missing.contains("NOT_SET"), "{missing}");
}

/// E1u (D-CLI): a `-e` value with `=` is refused without its value ever
/// appearing in the message.
#[test]
fn e1u_a_value_on_the_command_line_is_refused() {
    let error = env_inputs(&["MY_TOKEN=zz-canary-value-0123".to_string()], None, |_| {
        None
    })
    .expect_err("refused");
    assert!(error.contains("MY_TOKEN"), "{error}");
    assert!(!error.contains("zz-canary"), "{error}");
}

/// E4 (D-CLI): `--env-file` must be a JSON object of names to strings
/// within the bound; each other shape is refused, never naming a value.
#[test]
fn e4_an_env_file_that_is_not_a_bounded_object_is_refused() {
    let file = br#"{"MY_TOKEN":"tok-0123456789abcdef","LOG_LEVEL":"debug"}"#;
    let got = env_inputs(&[], Some(file), |_| None).expect("read");
    assert_eq!(got.len(), 2);
    // Over the bound but valid JSON, so the bound itself must refuse it.
    let big = format!(r#"{{"MY_TOKEN":"{}"}}"#, "a".repeat(ENV_FILE_MAX_BYTES)).into_bytes();
    for (bytes, what) in [
        (br#"{"MY_TOKEN": 12345678}"#.as_slice(), "non-string value"),
        (b"[1]".as_slice(), "not an object"),
        (b"not json".as_slice(), "not JSON"),
        (big.as_slice(), "over the bound"),
    ] {
        let error = env_inputs(&[], Some(bytes), |_| None).expect_err(what);
        assert!(!error.contains("12345678"), "{what}: {error}");
    }
}

/// E5 (D-CLI): a name given by both sources, or twice, is refused.
#[test]
fn e5_a_name_given_twice_is_refused() {
    let lookup = |_: &str| Some("tok-0123456789abcdef".to_string());
    let file = br#"{"MY_TOKEN":"tok-fedcba9876543210"}"#;
    let both = env_inputs(&["MY_TOKEN".to_string()], Some(file), lookup).expect_err("both");
    assert!(both.contains("MY_TOKEN"), "{both}");
    let twice = env_inputs(
        &["MY_TOKEN".to_string(), "MY_TOKEN".to_string()],
        None,
        lookup,
    )
    .expect_err("twice");
    assert!(twice.contains("MY_TOKEN"), "{twice}");
}

/// E1 (D-CLI, NEW.CLIUX.6 canary): `-e` with a value joined by `=` is a
/// usage error (exit 2) before any side effect: no config is created and
/// the value is written nowhere.
#[tokio::test]
async fn e1_a_value_on_the_command_line_is_refused_before_any_write() {
    let (dir, path) = temp_config();
    let code = run_add_command(
        "my-server",
        Some("node server.js"),
        None,
        None,
        AddValues {
            env_vars: &["MY_TOKEN=zz-canary-value-0123".to_string()],
            env_file: None,
            keep_as_text: &[],
        },
        &path,
        CommentLoss::Refuse,
    )
    .await;
    assert_eq!(code, ExitCode::from(2));
    assert!(!path.exists(), "a config was created");
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

/// E5b (D-CLI r1, gpt): a name repeated inside one env file is refused,
/// not silently replaced by its last value.
#[test]
fn e5b_a_name_repeated_in_the_env_file_is_refused() {
    let file = br#"{"MY_TOKEN":"tok-0123456789abcdef","MY_TOKEN":"tok-fedcba9876543210"}"#;
    let error = env_inputs(&[], Some(file), |_| None).expect_err("refused");
    assert!(error.contains("MY_TOKEN"), "{error}");
    assert!(!error.contains("tok-"), "{error}");
}

/// E4c (D-CLI r1, both seats): the env file is read at most one byte past
/// the bound, so an oversized file is refused without buffering it whole.
#[test]
fn e4c_an_oversized_env_file_is_read_only_past_the_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("env.json");
    std::fs::write(&path, vec![b' '; ENV_FILE_MAX_BYTES * 4]).expect("big file");
    let bytes = read_env_file(&path).expect("read");
    assert_eq!(bytes.len(), ENV_FILE_MAX_BYTES + 1);
    assert!(env_inputs(&[], Some(&bytes), |_| None).is_err());
}

/// C1, C2 (D-CLI r2): a credential in `--url` or in the command is a
/// usage error (exit 2) before any write; no config is created.
#[tokio::test]
async fn c1_a_credential_in_the_url_or_command_exits_2() {
    for (cmd, url) in [
        (None, Some("https://h.example/mcp?api_key=zz-canary-0123")),
        (Some("npx tool --token zz-canary-0123"), None),
    ] {
        let (dir, path) = temp_config();
        let code = run_add_command(
            "srv",
            cmd,
            url,
            None,
            AddValues::default(),
            &path,
            CommentLoss::Refuse,
        )
        .await;
        assert_eq!(code, ExitCode::from(2), "{cmd:?} {url:?}");
        assert!(!path.exists(), "a config was created");
        assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
    }
}
