// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway` through a real start: the process start, the version
//! change the counter restore recorded, and the refused-at-start snapshot are
//! all taken by `Gateway::run`, not seeded by a fixture.

use std::time::Duration;

use super::super::Gateway;
use crate::config::{AuthConfig, Config};
use crate::counters::persist::CounterFile;

const TOKEN: &str = "gateway-status-start-token";

fn config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config.auth = AuthConfig {
        enabled: true,
        bearer_token: Some(TOKEN.to_string()),
        ..AuthConfig::default()
    };
    config
}

/// A `counters.json` saved by `version`, as an earlier run would have left it.
fn seed_counters(dir: &std::path::Path, version: &str) {
    let now = crate::clock::unix_secs().expect("a readable clock");
    let restored = CounterFile::restore(dir.join("counters.json"), now, version, &chrono::Utc);
    restored.file.save(&restored.store, version, now);
    assert!(dir.join("counters.json").exists(), "premise: file saved");
}

/// Start a gateway on `dir`, read the route once, shut it down.
async fn read_route(dir: &std::path::Path) -> serde_json::Value {
    Box::pin(read_route_with(config(dir), dir)).await
}

/// [`read_route`] for a gateway started from `config`.
async fn read_route_with(config: Config, dir: &std::path::Path) -> serde_json::Value {
    let mut gateway = Gateway::new(config)
        .await
        .expect("gateway builds")
        .with_data_dir(dir.to_path_buf());
    let bound = gateway.bound_port_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("binds within a minute")
        .expect("reports its port");
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/ui/api/gateway"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), 200);
    let body = response.json().await.expect("JSON");
    trigger.send(()).expect("run holds the trigger");
    let ended = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("run returns")
        .expect("no panic");
    assert!(ended.is_ok(), "{ended:?}");
    body
}

#[tokio::test]
async fn a_started_gateway_reports_its_own_start_and_an_empty_refused_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = Box::pin(read_route(dir.path())).await;
    assert!(body["started_at"].is_string(), "{body}");
    assert!(body["uptime_secs"].is_u64(), "{body}");
    assert_eq!(body["refused_at_start"], serde_json::json!([]), "{body}");
    assert!(body["upgrade"].is_null(), "{body}");
}

#[tokio::test]
async fn a_restore_from_another_version_is_reported_as_the_upgrade() {
    let dir = tempfile::tempdir().expect("tempdir");
    seed_counters(dir.path(), "3.5.1");
    let body = Box::pin(read_route(dir.path())).await;
    assert_eq!(body["upgrade"]["from"], "3.5.1", "{body}");
    assert_eq!(body["upgrade"]["to"], env!("CARGO_PKG_VERSION"), "{body}");
}

/// A stdio backend whose runtime profile mounts `/etc`: configuration accepts
/// the profile, and the runtime policy denies the plan when it is made, before
/// anything serves.
fn config_with_denied_backend(dir: &std::path::Path) -> Config {
    let mut config = config(dir);
    config.runtime.profiles.insert(
        "etc-mount".to_string(),
        crate::config::RuntimeProfileConfig {
            provider: Some(crate::runtime::RuntimeProviderKind::Docker),
            image: Some("example/mcp-server:1".to_string()),
            mounts: vec![crate::runtime::RuntimeMount {
                source: "/etc".to_string(),
                target: "/host-etc".to_string(),
                mode: crate::runtime::RuntimeMountMode::ReadOnly,
            }],
            ..crate::config::RuntimeProfileConfig::default()
        },
    );
    config.backends.insert(
        "sandboxed".to_string(),
        crate::config::BackendConfig {
            transport: crate::config::TransportConfig::Stdio {
                command: "definitely-not-a-real-mcp-server".to_string(),
                cwd: None,
                protocol_version: None,
            },
            runtime_profile: Some("etc-mount".to_string()),
            ..crate::config::BackendConfig::default()
        },
    );
    config
}

#[tokio::test]
async fn a_backend_the_runtime_policy_denies_is_in_refused_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = Box::pin(read_route_with(
        config_with_denied_backend(dir.path()),
        dir.path(),
    ))
    .await;
    let refused = body["refused_at_start"].as_array().expect("a list");
    assert_eq!(refused.len(), 1, "{body}");
    assert_eq!(refused[0]["kind"], "startup", "{body}");
    assert_eq!(refused[0]["backend"], "sandboxed", "{body}");
}
