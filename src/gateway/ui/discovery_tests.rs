// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The discovery route's answer: one read of gateway.yaml judges every find,
//! a missing file serves the list as not adoptable, and an unreadable or
//! unparseable one is a 503.

use std::sync::Arc;
use std::time::Instant;

use futures::future::BoxFuture;

use super::*;
use crate::config::TransportConfig;
use crate::discovery::config_scanner::client_scan::{ClientScan, Fingerprint};
use crate::discovery::listing::ScanSource;
use crate::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use crate::gateway::test_helpers::write_owner_only;

struct Fixed(Vec<DiscoveredServer>);

impl ScanSource for Fixed {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&[])
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        let scan = ClientScan {
            finds: self.0.clone(),
            fingerprint: self.fingerprint(),
            unreadable: vec![(DiscoverySource::VsCode, "settings.json".to_string())],
        };
        Box::pin(async move { scan })
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn find(name: &str) -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        name.to_string(),
        String::new(),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: "npx".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    );
    server.entry_digest = format!("digest-{name}");
    server
}

async fn listing(names: &[&str]) -> Arc<Listing> {
    let cache = DiscoveryCache::new(Arc::new(Fixed(names.iter().map(|n| find(n)).collect())));
    cache.listing().await.expect("listing").0
}

const GATEWAY: &str = "backends:\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

fn gateway_file(dir: &std::path::Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, text).expect("write");
    path
}

fn server<'a>(body: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    body["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == name)
        .expect("listed")
}

#[test]
fn the_config_file_is_read_once_and_judged_by_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(read_gateway(None), Ok(Gateway::None)));
    assert!(matches!(
        read_gateway(Some(&dir.path().join("absent.yaml"))),
        Ok(Gateway::None)
    ));
    // A directory exists but does not read as a file.
    assert_eq!(
        read_gateway(Some(dir.path())).err(),
        Some("gateway.yaml could not be loaded")
    );
    let broken = gateway_file(dir.path(), "backends: [\n");
    assert_eq!(
        read_gateway(Some(&broken)).err(),
        Some("gateway.yaml could not be loaded")
    );

    let path = gateway_file(dir.path(), GATEWAY);
    let Ok(Gateway::File { revision, .. }) = read_gateway(Some(&path)) else {
        panic!("a readable config");
    };
    assert_eq!(revision, FileRevision::of(GATEWAY.as_bytes()));
}

#[tokio::test]
async fn each_find_is_judged_against_the_config_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gateway = read_gateway(Some(&gateway_file(dir.path(), GATEWAY))).expect("reads");
    let Gateway::File { config, .. } = &gateway else {
        panic!("a config");
    };
    let capabilities = config.capabilities.name.clone();
    let listing = listing(&["a", "b", capabilities.as_str(), "x/y"]).await;

    let body = body(&gateway, &listing, false);

    let a = server(&body, "a");
    assert_eq!(
        (a["adoptable"].clone(), a["managed"].clone()),
        (json!(true), json!(false))
    );
    let b = server(&body, "b");
    assert_eq!(
        (b["adoptable"].clone(), b["managed"].clone()),
        (json!(false), json!(true))
    );
    assert_eq!(
        server(&body, &capabilities)["refusals"],
        json!([{"reason": "capabilities_name", "field": "name"}])
    );
    assert_eq!(
        server(&body, "x/y")["refusals"],
        json!([{"reason": "invalid_name", "field": "name"}])
    );
    let radar: Vec<&str> = body["radar"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(
        !radar.contains(&"b"),
        "a backend is not on the radar: {radar:?}"
    );
    assert_eq!(
        body["unreadable_files"],
        json!([{"source": "VsCode", "file": "settings.json"}])
    );
    assert_eq!(
        body["revision"],
        json!(FileRevision::of(GATEWAY.as_bytes()).as_str())
    );
}

#[tokio::test]
async fn a_cached_listing_follows_a_config_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listing = listing(&["a"]).await;
    let path = gateway_file(dir.path(), GATEWAY);
    let before = body(&read_gateway(Some(&path)).expect("reads"), &listing, false);
    assert_eq!(server(&before, "a")["managed"], json!(false));

    write_owner_only(
        &path,
        format!("{GATEWAY}  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n"),
    )
    .expect("add a");
    let after = body(&read_gateway(Some(&path)).expect("reads"), &listing, false);
    assert_eq!(server(&after, "a")["managed"], json!(true));
    assert_eq!(after["radar"]["findings"], json!([]));
    assert_ne!(before["revision"], after["revision"]);
}

#[tokio::test]
async fn without_a_config_file_nothing_is_adoptable() {
    let listing = listing(&["a"]).await;
    let body = body(&Gateway::None, &listing, false);
    assert_eq!(body["revision"], json!(null));
    assert_eq!(server(&body, "a")["adoptable"], json!(false));
    assert_eq!(
        server(&body, "a")["refusals"],
        json!([{"reason": "no_config_file", "field": "name"}])
    );
}

/// R5: the decision set's adopt rule is the route's own: a configured name
/// (an adopted backend is written disabled), the capabilities name, an
/// invalid name, no config file, or a scan-level refusal is no decision.
#[tokio::test]
async fn the_adopt_rule_is_the_routes_own() {
    const DISABLED: &str =
        "backends:\n  adopted:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    enabled: false\n";
    let dir = tempfile::tempdir().expect("tempdir");
    let gateway = read_gateway(Some(&gateway_file(dir.path(), DISABLED))).expect("reads");
    let Gateway::File { config, .. } = &gateway else {
        panic!("a config");
    };
    let capabilities = config.capabilities.name.clone();
    let mut refused = find("needs-secret");
    refused.uncarried = vec!["env.TOKEN".to_string()];
    let cache = DiscoveryCache::new(Arc::new(Fixed(vec![
        find("fresh"),
        find("adopted"),
        find(&capabilities),
        find("x/y"),
        refused,
    ])));
    let (listing, _) = cache.listing().await.expect("listing");
    let eligible = |name: &str, gateway: &Gateway| {
        let find = listing
            .finds
            .iter()
            .find(|f| f.name == name)
            .expect("listed");
        adopt_eligible(find, gateway)
    };
    assert!(
        eligible("fresh", &gateway),
        "an unmanaged find is a decision"
    );
    for name in ["adopted", capabilities.as_str(), "x/y", "needs-secret"] {
        assert!(!eligible(name, &gateway), "{name} is no decision");
    }
    assert!(
        !eligible("fresh", &Gateway::None),
        "without a config file nothing is a decision"
    );
}
