// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one name-precedence rule: a client config's find wins, then the
//! environment's, then a process's, whatever order the scans returned them
//! in, and within one kind the first found wins.

use super::{DiscoveredServer, DiscoverySource, ServerMetadata, unique_by_name};
use crate::config::TransportConfig;

fn server(name: &str, source: DiscoverySource, url: &str) -> DiscoveredServer {
    DiscoveredServer::new(
        name.to_string(),
        String::new(),
        source,
        TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ServerMetadata::default(),
    )
}

fn kept(servers: Vec<DiscoveredServer>) -> Vec<(String, DiscoverySource, String)> {
    unique_by_name(servers)
        .into_iter()
        .map(|server| {
            let url = match &server.transport {
                TransportConfig::Http { http_url, .. } => http_url.clone(),
                _ => String::new(),
            };
            (server.name, server.source, url)
        })
        .collect()
}

#[test]
fn a_client_find_wins_whatever_order_the_scans_returned() {
    let found = kept(vec![
        server("docs", DiscoverySource::Environment, "https://env"),
        server("docs", DiscoverySource::RunningProcess, "https://process"),
        server("docs", DiscoverySource::Cursor, "https://client"),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2, "https://client", "{found:?}");
}

#[test]
fn the_environment_wins_over_a_process_and_the_first_find_of_a_kind_wins() {
    let found = kept(vec![
        server("api", DiscoverySource::RunningProcess, "https://process"),
        server("api", DiscoverySource::Environment, "https://env-first"),
        server("api", DiscoverySource::Environment, "https://env-second"),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2, "https://env-first", "{found:?}");
}
