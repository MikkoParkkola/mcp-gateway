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

fn keyed(
    discovered: &[DiscoveredServer],
    key: &crate::gateway::record_principal::RecordPrincipalKey,
) -> ShadowScanReport {
    ShadowScanReport::from_discovered_keyed(
        discovered,
        &HashSet::new(),
        Some(Path::new("gateway.yaml")),
        key,
    )
}

fn other_key() -> crate::gateway::record_principal::RecordPrincipalKey {
    crate::gateway::record_principal::RecordPrincipalKey::from_text(
        "another-test-record-key-not-a-secret-fedcba9876543210",
    )
    .expect("long enough")
}

fn at_url(url: &str) -> DiscoveredServer {
    http_server(
        "remote-docs",
        "Remote docs",
        url,
        DiscoverySource::McpConfig,
        None,
        None,
    )
}

/// A URL find's id is keyed: another record key gives another id.
#[test]
fn a_url_finds_id_is_keyed_by_the_record_key() {
    let key = crate::gateway::record_principal::test_record_key();
    let find = [url_find(DiscoverySource::McpConfig, None)];
    assert_ne!(
        keyed(&find, &key).assets[0].id,
        keyed(&find, &other_key()).assets[0].id,
        "the id does not depend on the key"
    );
}

/// Under one key, finds differing only in URL path keep distinct ids; finds
/// differing only in credentials, query or fragment share one.
#[test]
fn ids_tell_paths_apart_but_not_credentials_query_or_fragment() {
    let key = crate::gateway::record_principal::test_record_key();
    let id = |url: &str| keyed(&[at_url(url)], &key).assets[0].id.clone();
    let base = id("https://mcp.remote.internal/a/mcp");
    assert_ne!(base, id("https://mcp.remote.internal/b/mcp"), "paths");
    assert_eq!(
        base,
        id("https://u:p@mcp.remote.internal/a/mcp"),
        "credentials"
    );
    assert_eq!(base, id("https://mcp.remote.internal/a/mcp?x=1"), "query");
    assert_eq!(base, id("https://mcp.remote.internal/a/mcp#f"), "fragment");
}

/// One name from a client config, the environment and a process is one
/// asset: the client config's.
#[test]
fn one_name_from_three_sources_is_one_client_asset() {
    let key = crate::gateway::record_principal::test_record_key();
    let finds = [
        url_find(DiscoverySource::McpConfig, None),
        url_find(DiscoverySource::Environment, None),
        url_find(DiscoverySource::RunningProcess, Some(4242)),
    ];
    let report = keyed(&finds, &key);
    assert_eq!(report.assets.len(), 1, "{:?}", report.assets);
    assert_eq!(report.assets[0].source, DiscoverySource::McpConfig);
    assert_eq!(report.summary.unmanaged_total, 1);
}

/// The classification is pinned as values: a risk only a command keyword
/// gives, and an auth exposure only an `Authorization` header key gives.
#[test]
fn a_command_keyword_and_an_auth_header_key_classify_as_before() {
    let key = crate::gateway::record_principal::test_record_key();
    let files = stdio_server(
        "files",
        "Files",
        "npx -y @modelcontextprotocol/server-filesystem /data",
        DiscoverySource::McpConfig,
        Some("/tmp/mcp.json"),
        None,
        None,
    );
    let mut authed = at_url("https://mcp.remote.internal/mcp");
    authed.headers = [("Authorization".to_string(), "Bearer zqsecret".to_string())]
        .into_iter()
        .collect();
    let report = keyed(&[files, authed], &key);
    let by_name = |name: &str| {
        report
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .expect("listed")
    };
    assert_eq!(by_name("files").data_risk, ShadowDataRisk::HighPrivilege);
    assert_eq!(
        by_name("remote-docs").auth_exposure,
        ShadowAuthExposure::HttpAuthHeader
    );
}
