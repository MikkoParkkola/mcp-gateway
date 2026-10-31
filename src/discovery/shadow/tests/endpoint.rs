// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R7: the radar shows no URL path and no full config path, for a find from a
//! client config, an environment variable or a running process. A token
//! planted in a URL path and a username planted in a config path appear
//! nowhere in the serialized report, its id included.

use super::*;

/// A token as it would sit in a URL path.
const TOKEN: &str = "tkn9f3e1c7a2b";
/// A username as it would sit in a home-directory path.
const USER: &str = "zquser7716";

fn url_find(source: DiscoverySource, pid: Option<u32>) -> DiscoveredServer {
    let mut server = http_server(
        "remote-docs",
        "Remote docs",
        &format!("https://mcp.remote.internal/{TOKEN}/mcp?k=v"),
        source,
        pid,
        None,
    );
    server.metadata.config_path = Some(PathBuf::from(format!(
        "/home/{USER}/.config/client/mcp.json"
    )));
    server
}

fn assert_no_canary(source: DiscoverySource, pid: Option<u32>) {
    let report = report(&[url_find(source.clone(), pid)], &[]);
    let json = serde_json::to_string(&report).expect("serializes");
    assert!(
        !json.contains(TOKEN),
        "{source:?}: a URL path reached the radar: {json}"
    );
    assert!(
        !json.contains(USER),
        "{source:?}: a full config path reached the radar: {json}"
    );
}

#[test]
fn a_client_config_find_shows_no_url_path_or_config_path() {
    assert_no_canary(DiscoverySource::McpConfig, None);
}

#[test]
fn an_environment_find_shows_no_url_path() {
    assert_no_canary(DiscoverySource::Environment, None);
}

#[test]
fn a_process_find_shows_no_url_path() {
    assert_no_canary(DiscoverySource::RunningProcess, Some(4242));
}

/// The endpoint the radar shows is the URL's origin.
#[test]
fn the_endpoint_is_the_origin() {
    let report = report(&[url_find(DiscoverySource::McpConfig, None)], &[]);
    assert_eq!(
        report.assets[0].transport.endpoint.as_deref(),
        Some("https://mcp.remote.internal"),
    );
}

/// The id does not change between two reports of the same find.
#[test]
fn a_url_find_keeps_its_id_across_reports() {
    let first = report(&[url_find(DiscoverySource::McpConfig, None)], &[]);
    let second = report(&[url_find(DiscoverySource::McpConfig, None)], &[]);
    assert_eq!(first.assets[0].id, second.assets[0].id);
}
