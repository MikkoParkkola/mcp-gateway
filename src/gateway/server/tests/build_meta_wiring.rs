// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The optional sections `build_meta_mcp` wires into the running meta-MCP.
//!
//! `build_meta_mcp` is a Critical row (MIK-8144): each security section it
//! reads must reach the meta-MCP the serve modes use, and a section it cannot
//! honour must not stop the gateway when the operator asked for a best-effort
//! feature. Each test turns one section on and reads the field it sets.
//!
//! An INFO subscriber is installed so the startup log lines are formatted;
//! without one their field expressions are never evaluated.
//!
//! Every test pins its environment with an overlay, so a key in the developer's
//! own environment cannot decide it.

use std::path::{Path, PathBuf};

use base64::Engine as _;

use super::*;

fn info_logging() -> tracing::subscriber::DefaultGuard {
    // The crate's one keeper for cached callsite interest (MIK-8254): without
    // it a test that logged first with no subscriber can leave a callsite
    // cached as off, and this scoped subscriber would never see it.
    crate::test_log_capture::keep_interest_open();
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::sink)
            .finish(),
    )
}

/// The environment every test here builds against: the attestation keys
/// `build_meta_mcp` reads are assigned empty. An overlay falls through to the
/// process environment for any key it does not assign
/// (`EnvOverlay::resolve`), so an empty overlay would still let a key in the
/// developer's own environment decide the build; assigning them closes that.
fn pinned_env() -> Arc<crate::config::LiveEnv> {
    use crate::attestation::{
        ATTESTATION_AUDIENCE_ENV, ATTESTATION_KEY_ID_ENV, ATTESTATION_MODE_ENV,
        ATTESTATION_SIGNING_KEY_ENV,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join(".env");
    let mut body = String::new();
    for key in [
        ATTESTATION_MODE_ENV,
        ATTESTATION_SIGNING_KEY_ENV,
        ATTESTATION_KEY_ID_ENV,
        ATTESTATION_AUDIENCE_ENV,
    ] {
        body.push_str(key);
        body.push_str("=\n");
    }
    crate::gateway::test_helpers::write_owner_only(&env_file, body).expect("env file");
    // The overlay is read here, so the file may go when `dir` drops. A file
    // that fails to load must fail the test, not fall back to the process
    // environment the pin exists to exclude.
    let overlay = crate::config::EnvOverlay::from_paths_checked(&[env_file]).expect("pinned env");
    for key in [
        ATTESTATION_MODE_ENV,
        ATTESTATION_SIGNING_KEY_ENV,
        ATTESTATION_KEY_ID_ENV,
        ATTESTATION_AUDIENCE_ENV,
    ] {
        assert!(overlay.assigns(key), "the pinned env must assign {key}");
    }
    Arc::new(crate::config::LiveEnv::new(
        Arc::new(overlay),
        crate::config::ResolvedEnvFiles::default(),
    ))
}

async fn built(config: Config) -> Arc<MetaMcp> {
    let gateway = Gateway::new(config)
        .await
        .expect("gateway")
        .with_env(pinned_env());
    gateway
        .build_meta_mcp()
        .await
        .expect("build_meta_mcp")
        .meta_mcp
}

/// Claim capture opens its sink (creating the parent directory) and hands it
/// to the meta-MCP, so derived claims are written for offline scoring.
#[tokio::test]
async fn claim_capture_opens_its_sink_and_reaches_the_meta_mcp() {
    let _log = info_logging();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("claims").join("capture.jsonl");
    let mut config = Config::default();
    config.security.claim_capture.enabled = true;
    config.security.claim_capture.path = path.display().to_string();

    let meta = built(config).await;

    assert!(
        meta.claim_capture.is_some(),
        "an enabled claim capture must be installed on the running meta-MCP"
    );
    assert!(
        path.exists(),
        "the capture sink must be created at the configured path"
    );
}

/// A capture path that cannot be opened leaves capture off and still boots:
/// capture is an offline-scoring aid, not a control, so it must not take the
/// gateway down.
#[tokio::test]
async fn an_unopenable_claim_capture_path_boots_without_capture() {
    let _log = info_logging();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    config.security.claim_capture.enabled = true;
    // A directory, not a file: opening it for append fails.
    config.security.claim_capture.path = dir.path().display().to_string();

    let meta = built(config).await;

    assert!(
        meta.claim_capture.is_none(),
        "a sink that failed to open must not be installed"
    );
}

/// Response inspection in action mode blocks HIGH/CRITICAL findings; in
/// observe mode it only logs; `enabled: false` turns it off, action mode
/// included. The mode the operator chose is the one installed.
#[tokio::test]
async fn response_inspection_installs_the_configured_mode() {
    use crate::security::response_inspect::ResponseInspectionMode as Mode;
    let _log = info_logging();
    for (enabled, action_mode, want) in [
        (true, true, Mode::Action),
        (true, false, Mode::Observe),
        (false, false, Mode::Off),
        (false, true, Mode::Off),
    ] {
        let mut config = Config::default();
        config.security.response_inspection.enabled = enabled;
        config.security.response_inspection.action_mode = action_mode;
        assert_eq!(
            built(config).await.response_inspection,
            want,
            "enabled: {enabled}, action_mode: {action_mode}"
        );
    }
    assert_eq!(
        built(Config::default()).await.response_inspection,
        Mode::Observe,
        "the default is unchanged"
    );
}

/// The response contract gate is installed with the operator's config,
/// including observe mode.
#[tokio::test]
async fn the_response_contract_reaches_the_meta_mcp_in_observe_mode() {
    let _log = info_logging();
    let mut config = Config::default();
    config.security.response_contract.enabled = true;
    config.security.response_contract.action_mode = false;

    let meta = built(config).await;

    let contract = meta
        .response_contract
        .as_ref()
        .expect("an enabled response contract must be installed");
    assert!(
        !contract.action_mode,
        "the installed contract keeps observe mode"
    );
}

/// A cache with no entry limit is still a cache: `max_entries: 0` means
/// unbounded, not off.
#[tokio::test]
async fn an_unbounded_response_cache_is_installed() {
    let _log = info_logging();
    let mut config = Config::default();
    config.cache.max_entries = 0;

    assert!(
        built(config).await.cache.is_some(),
        "an enabled cache with no entry limit must be installed"
    );
}

/// A configured signature chain gives the meta-MCP its chain identity, so
/// responses can carry the gateway's link.
#[tokio::test]
async fn a_configured_signature_chain_installs_the_chain_signer() {
    let _log = info_logging();
    let seed = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let mut config = Config::default();
    config.security.signature_chain = Some(
        serde_json::from_value(json!({ "signing_key": seed, "key_id": "gw-wiring" }))
            .expect("signature chain section"),
    );

    assert!(
        built(config).await.chain_signer.is_some(),
        "a configured signature chain must install the chain signer"
    );
}

/// Provenance stamping with an empty signing key fails closed: no signer is
/// installed, because an empty-key HMAC would let anyone forge a receipt.
#[tokio::test]
async fn provenance_stamping_without_a_key_installs_no_signer() {
    let _log = info_logging();
    let mut config = Config::default();
    config.security.provenance_stamping = true;

    let meta = built(config).await;

    assert!(
        meta.provenance_signer.is_none(),
        "stamping with an empty key must leave the signer uninstalled"
    );
}

/// A configured local grants file is loaded into the running meta-MCP.
#[tokio::test]
async fn configured_identity_grants_reach_the_meta_mcp() {
    let _log = info_logging();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("identity-grants.json");
    let body = serde_json::to_string_pretty(&super::boot::test_grant_file()).expect("grants");
    crate::gateway::test_helpers::write_owner_only(&path, body).expect("grants file");
    let mut config = Config::default();
    config.security.identity_grants.enabled = true;
    config.security.identity_grants.path = path.display().to_string();

    let meta = built(config).await;

    assert_eq!(
        meta.identity_grants.read().len(),
        1,
        "the configured grant must be loaded"
    );
}

/// MIK-8783.AUTO.1 (T2.2): `cache.enabled` is retired. A config that still
/// says `false` gets the response cache anyway; what it stores stays gated by
/// the read-only annotations.
#[tokio::test]
async fn a_retired_cache_off_switch_still_installs_the_cache() {
    let _log = info_logging();
    let config: Config = serde_json::from_value(json!({ "cache": { "enabled": false } }))
        .expect("a config with the retired key still parses");
    assert!(
        built(config).await.cache.is_some(),
        "the response cache is always built"
    );
}

/// the gateway's events opener must reject an unowned directory
/// before its opening sweep or any worker can touch the store.
#[tokio::test]
#[should_panic(expected = "kept_tempdir")]
async fn registered_gateway_events_opener_refuses_a_plain_tempdir() {
    let dir = tempfile::tempdir().expect("an unregistered directory");
    let path = dir.path().join("events");
    let data = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.events.enabled = true;
    config.events.store_dir = path.display().to_string();
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway constructor")
        .with_env(pinned_env())
        .with_data_dir(data.path().to_path_buf());
    let built = gateway.build_meta_mcp().await.expect("gateway meta layer");
    let webhooks = Arc::new(parking_lot::RwLock::new(
        crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
    ));
    let live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    let counters = Arc::new(crate::counters::CounterStore::new(0));
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::super::events_wiring::install(
            &config,
            &built.meta_mcp,
            &gateway.backends,
            &webhooks,
            &live,
            crate::events::LiveCredentials::default(),
            &counters,
        )
        .expect("events wiring");
    }));
    if let Err(panic) = refused {
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains(&path.display().to_string()),
            "missing store path"
        );
        assert!(message.contains("kept_tempdir"), "missing ownership hint");
        assert!(!path.exists(), "refusal must precede store creation");
        std::panic::resume_unwind(panic);
    }
    // Returning normally makes should_panic fail when the exemption survives.
}

// ── R4 (HOME.4): the private data dir, seen from a child ────────────

/// Set in the child [`r4_child`] runs in.
const R4_CASE: &str = "MCP_GW_TEST_R4_CASE";
/// The directory the child's home and data dir must lie under before it builds.
const R4_ROOT: &str = "MCP_GW_TEST_R4_ROOT";
/// Set to plant a malformed ranker file in the child's own data dir first.
const R4_PLANT: &str = "MCP_GW_TEST_R4_PLANT";
const RANKER_WARNING: &str = "Failed to load search ranker usage data";
const MALFORMED: &[u8] = b"{not json";

/// Runs [`r4_child`] with `platform_home` as HOME and USERPROFILE, every test-home
/// variable removed (unless `override_home` is given), and `tmp` as its temp
/// dir. Fails if the child refused to build outside `root`.
fn r4(
    platform_home: &Path,
    tmp: &Path,
    root: &Path,
    override_home: Option<&Path>,
    plant: bool,
) -> std::collections::BTreeMap<String, String> {
    let mut cmd = crate::test_home::test_binary();
    cmd.args([
        "--exact",
        "gateway::server::tests::build_meta_wiring::r4_child",
        "--ignored",
        "--nocapture",
    ])
    .env_remove("MCP_GATEWAY_TEST_HOME_DIR")
    .env_remove("XDG_CONFIG_HOME")
    .env_remove("MCP_GATEWAY_CONFIG_DIR")
    .env("HOME", platform_home)
    .env("USERPROFILE", platform_home)
    .env(R4_CASE, "1")
    .env(R4_ROOT, root);
    for key in ["TMPDIR", "TMP", "TEMP"] {
        cmd.env(key, tmp);
    }
    if let Some(home) = override_home {
        cmd.env("MCP_GATEWAY_TEST_HOME_DIR", home);
    }
    if plant {
        cmd.env(R4_PLANT, "1");
    }
    let out = cmd.output().expect("spawn the r4 child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("REFUSED"),
        "the child resolved outside its root and refused to build:\n{stdout}\n{stderr}"
    );
    assert!(out.status.success(), "r4 child failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("r4 child ok"),
        "r4 child ran no case:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("PROBE "))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// Every regular file under `root`, relative to it, sorted.
#[cfg(unix)]
fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("entry").path();
            let kind = std::fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                found.push(path.strip_prefix(root).expect("under root").to_path_buf());
            }
        }
    }
    found.sort();
    found
}

#[cfg(unix)]
fn plant_in(home: &Path) -> PathBuf {
    let planted = home.join(".mcp-gateway").join("usage.json");
    std::fs::create_dir_all(planted.parent().expect("parent")).expect("data dir");
    std::fs::write(&planted, MALFORMED).expect("plant");
    planted
}

/// R4.1: a malformed ranker file in the platform home's data dir is never read
/// or touched. The child builds under its private fallback, and the platform
/// home holds exactly the planted file afterwards.
#[cfg(unix)]
#[test]
fn r4_build_meta_never_reads_the_platform_homes_data_dir() {
    let platform = tempfile::tempdir().expect("platform home");
    let tmp = tempfile::tempdir().expect("tmp");
    let planted = plant_in(platform.path());
    let seen = r4(platform.path(), tmp.path(), tmp.path(), None, false);
    assert_eq!(seen["WARNED"], "false", "the planted file was read");
    assert!(
        PathBuf::from(&seen["DATA"]).starts_with(tmp.path()),
        "{seen:?}"
    );
    assert_eq!(
        files_under(platform.path()),
        vec![PathBuf::from(".mcp-gateway").join("usage.json")]
    );
    assert_eq!(std::fs::read(&planted).expect("read back"), MALFORMED);
}

/// R4.2, the control: pointed at the same home through the override, the child
/// does read the planted file. Without it, a broken log capture would let R4.1
/// pass on a child that reads everything.
#[cfg(unix)]
#[test]
fn r4_control_the_same_plant_is_read_through_the_override() {
    let platform = tempfile::tempdir().expect("platform home");
    let tmp = tempfile::tempdir().expect("tmp");
    plant_in(platform.path());
    let seen = r4(
        platform.path(),
        tmp.path(),
        platform.path(),
        Some(platform.path()),
        false,
    );
    assert_eq!(
        seen["WARNED"], "true",
        "the planted file was not read: {seen:?}"
    );
}

/// R4.3 (Windows, path evidence only: the platform lookup ignores HOME and
/// USERPROFILE, so nothing is planted): the child builds under its fallback.
#[cfg(windows)]
#[test]
fn r4_build_meta_resolves_under_the_fallback_on_windows() {
    let platform = tempfile::tempdir().expect("platform home");
    let tmp = tempfile::tempdir().expect("tmp");
    let seen = r4(platform.path(), tmp.path(), tmp.path(), None, false);
    assert!(
        PathBuf::from(&seen["DATA"]).starts_with(tmp.path()),
        "{seen:?}"
    );
}

/// R4.4: the private data dir is the one read. A malformed ranker file the
/// child plants there is reported.
#[test]
fn r4_build_meta_reads_the_private_data_dir() {
    let platform = tempfile::tempdir().expect("platform home");
    let tmp = tempfile::tempdir().expect("tmp");
    let seen = r4(platform.path(), tmp.path(), tmp.path(), None, true);
    assert_eq!(
        seen["WARNED"], "true",
        "the private data dir was not read: {seen:?}"
    );
}

#[test]
#[ignore = "run by the r4 rows, in a child whose home each row sets"]
fn r4_child() {
    if std::env::var_os(R4_CASE).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os(R4_ROOT).expect("root"));
    let home = crate::home_dir::home_dir().expect("a home");
    let data = crate::config_persistence::gateway_data_dir();
    // Refuse before anything is built, so a red or mutant run never writes
    // outside the parent's directories, a real Windows home included.
    if !home.starts_with(&root) || !data.starts_with(&root) {
        println!(
            "REFUSED home={} data={} root={}",
            home.display(),
            data.display(),
            root.display()
        );
        std::process::exit(3);
    }
    if std::env::var_os(R4_PLANT).is_some() {
        std::fs::create_dir_all(&data).expect("data dir");
        std::fs::write(data.join("usage.json"), MALFORMED).expect("plant");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (_meta, warnings) =
        crate::test_log_capture::capture_warnings(|| runtime.block_on(built(Config::default())));
    println!("PROBE DATA={}", data.display());
    println!("PROBE WARNED={}", warnings.contains(RANKER_WARNING));
    println!("r4 child ok");
}
