// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: stdio startup installs the catalogue pieces its config enables,
//! and refuses to start a session it cannot serve.

use std::sync::Arc;

use super::super::Gateway;
use super::super::warmstart::{WarmStartMode, WarmerGuard};
use crate::config::{Config, LiveEnv};
use crate::gateway::meta_mcp::MetaMcp;

/// Stdio startup's catalogue step for `config`, on the gateway and Meta-MCP
/// the stdio loop builds: its outcome, and the Meta-MCP it installed into.
async fn startup(config: Config) -> (crate::Result<()>, Arc<MetaMcp>) {
    let gateway = Gateway::new(config)
        .await
        .expect("VOID: the gateway builds");
    startup_on(gateway).await
}

/// [`startup`] on an already-built gateway.
async fn startup_on(gateway: Gateway) -> (crate::Result<()>, Arc<MetaMcp>) {
    let built = gateway
        .build_meta_mcp()
        .await
        .expect("VOID: the Meta-MCP builds");
    let warmer = WarmerGuard::new(&gateway.backends, WarmStartMode::Stdio, None);
    let outcome = gateway
        .install_stdio_startup_catalogue(&built.meta_mcp, None, &warmer)
        .await;
    (outcome, built.meta_mcp)
}

/// A stdio session serves the playbooks its config names: each directory is
/// loaded into the engine the session runs `gateway_run_playbook` against, and
/// a missing directory is skipped, not fatal.
/// Mutant: the loaded engine never installed (or a directory skipped): the
/// named playbook is not served by the session.
#[tokio::test(flavor = "current_thread")]
async fn stdio_startup_serves_the_configured_playbooks() {
    let dir = tempfile::tempdir().expect("VOID: a temp dir");
    std::fs::write(
        dir.path().join("good.yaml"),
        "playbook: '1.0'\nname: good\ndescription: d\nsteps:\n  - {name: ask, tool: ask, server: srv, arguments: {}}\n",
    )
    .expect("VOID: write the playbook");
    let mut config = Config::default();
    config.playbooks.enabled = true;
    config.playbooks.directories = vec![
        dir.path().join("absent").display().to_string(),
        dir.path().display().to_string(),
    ];
    let (outcome, meta) = startup(config).await;
    outcome.expect("stdio startup with playbooks succeeds");
    let (servers, _digest) = meta
        .playbook_step_servers("good")
        .expect("the configured playbook is served on stdio");
    assert_eq!(servers, vec!["srv".to_string()]);
}

/// A stdio session whose config binds an enabled backend to a managed account
/// refuses to start when no account custody was started, as HTTP does: it
/// never serves that backend as though it were a shared one.
/// Mutant: the install error ignored on stdio: startup succeeds.
#[tokio::test(flavor = "current_thread")]
async fn stdio_startup_refuses_a_managed_binding_with_no_custody() {
    // The accounts key resolves through an env file, as a deployment's does,
    // so the gateway builds and only the stdio install can refuse.
    let dir = tempfile::tempdir().expect("VOID: a temp dir");
    let env_path = dir.path().join("accounts.env");
    crate::gateway::test_helpers::write_owner_only(
        &env_path,
        "STDIO_STARTUP_KEY=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n",
    )
    .expect("VOID: write the env file");
    let yaml = format!(
        "env_files:\n  - {}\n\
         backends:\n  mail:\n    http_url: https://backend.fixture.test/mcp\n    enabled: true\n    \
         account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  deployment: single_process\n  \
         instance_id: unit\n  store_dir: {}\n  authority_dir: {}\n  \
         current_key_id: primary\n  keys:\n    primary: env:STDIO_STARTUP_KEY\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: fixture-client\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      \
         scopes: [read]\n      send_resource_parameter: true\n",
        env_path.display(),
        dir.path().join("store").display(),
        dir.path().join("authority").display(),
    );
    let config_path = dir.path().join("config.yaml");
    crate::gateway::test_helpers::write_owner_only(&config_path, yaml)
        .expect("VOID: write the config");
    let evaluated = Config::load_evaluated(Some(&config_path)).expect("VOID: the config evaluates");
    let env = Arc::new(LiveEnv::new(evaluated.overlay, evaluated.env_paths));
    let gateway = Gateway::new_with_env(evaluated.config, env, Some(config_path.clone()))
        .await
        .expect("VOID: the gateway builds with no custody started");
    let (outcome, _meta) = startup_on(gateway).await;
    let error = outcome.expect_err("stdio must refuse a managed binding with no custody");
    let text = error.to_string();
    assert!(
        text.contains("no account custody was started") && text.contains("'mail'"),
        "{text}"
    );
}

/// The startup error for a failed account signing key: a configuration error
/// naming the stdio account signing key and carrying the random source's own
/// message, so an operator sees why stdio refused to start.
/// Mutant: another variant, or the source's message dropped.
#[test]
fn a_failed_signing_key_is_a_named_config_error() {
    let error = super::key_error("the system random source is unavailable".to_string());
    match error {
        crate::Error::Config(message) => assert_eq!(
            message,
            "stdio account signing key generation failed: the system random source is unavailable"
        ),
        other => panic!("a failed signing key must be a Config error: {other:?}"),
    }
}
