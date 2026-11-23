// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Servers the config holds switched off, as the status stream carries them:
//! a reload that switches one off keeps it listed, and the off rows keep one
//! order however the config's map walks them, so no frame is sent for nothing.

use serde_json::Value;

use super::*;
use crate::config::{BackendConfig, Config, TransportConfig};

const URL: &str = "http://127.0.0.1:9/mcp";

fn switched_off() -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: URL.to_owned(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        enabled: false,
        ..BackendConfig::default()
    }
}

fn row<'a>(body: &'a Value, name: &str) -> Option<&'a Value> {
    body["servers"]
        .as_array()?
        .iter()
        .find(|row| row["name"] == name)
}

fn breakers(body: &Value) -> u64 {
    ["closed", "open", "half_open"]
        .iter()
        .map(|word| body["circuit_breakers"][word].as_u64().unwrap_or(0))
        .sum()
}

/// The names of the off rows, in the order the body lists them.
fn off_rows(body: &Value) -> Vec<String> {
    body["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["state"] == "off")
        .filter_map(|row| row["name"].as_str().map(str::to_owned))
        .collect()
}

/// The switched-off names in the order `config`'s map walks them.
fn walk_order(config: &Config) -> Vec<String> {
    config
        .backends
        .iter()
        .filter(|(_, server)| !server.enabled)
        .map(|(name, _)| name.clone())
        .collect()
}

#[tokio::test]
async fn a_server_a_reload_switches_off_stays_in_the_next_status_frame() {
    let (state, _dir) = fixture().await;
    for name in ["alpha", "beta"] {
        assert!(
            state.backends.register(http_backend_at(name, URL)),
            "{name}"
        );
    }
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = admin.until("status").await.json();
    assert_eq!(breakers(&first), 2, "premise: both run: {first}");
    // Both effects of the reload, with no await between them, so no tick
    // sees one without the other: the config holds `beta` switched off, and
    // the registry no longer holds it.
    state.live_config.edit(|c| {
        c.backends.insert("beta".to_owned(), switched_off());
    });
    assert!(
        state.backends.remove("beta"),
        "premise: beta was registered"
    );
    let next = admin.until("status").await.json();
    assert!(
        row(&next, "beta").is_some_and(|beta| beta["state"] == "off"),
        "the switched-off server is listed off: {next}"
    );
    assert_eq!(breakers(&next), 1, "only alpha has a breaker: {next}");
}

#[tokio::test]
async fn off_rows_keep_name_order_so_a_new_map_order_sends_no_frame() {
    let (state, _dir) = fixture().await;
    let names = ["off-a", "off-b"];
    state.live_config.edit(|c| {
        for name in names {
            c.backends.insert(name.to_owned(), switched_off());
        }
    });
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = admin.until("status").await.json();
    assert_eq!(off_rows(&first), names, "listed in name order: {first}");
    let r0 = admin.until("reload").await.json()["generation"].as_u64();

    // A config the same in all but its map's walk order: a clone keeps the
    // order, a rebuilt map draws a new one, so rebuild until it differs.
    let before = walk_order(&state.live_config.get());
    let mut after = before.clone();
    state.live_config.edit(|c| {
        for _ in 0..64 {
            c.backends = std::mem::take(&mut c.backends).into_iter().collect();
            after = walk_order(c);
            if after != before {
                break;
            }
        }
    });
    assert_ne!(after, before, "premise: the map walks them the other way");

    // A changed body is sent before the reload frame of the same tick.
    let mut status_frames = 0;
    loop {
        let frame = admin.next().await.expect("the stream is still open");
        if frame.event == "status" {
            status_frames += 1;
        }
        if frame.event == "reload" && frame.json()["generation"].as_u64() > r0 {
            break;
        }
    }
    assert_eq!(status_frames, 0, "the same servers in the same order");
}
