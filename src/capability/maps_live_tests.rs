// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map tools against the real providers (L rows). `#[ignore]`: they run only
//! in the opt-in `maps-live-smoke` workflow, one exact test per cargo
//! invocation with the host's interval between runs on one host, never on a
//! developer machine or in the default suites.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::capability::parser::parse_capability_text;
use crate::capability::{CapabilityBackend, CapabilityExecutor};

const OSM: &str = "© OpenStreetMap contributors";
const OPEN_METEO: &str = "Data by Open-Meteo.com (CC BY 4.0)";

/// One call of the shipped tool `rel` through a production executor: the
/// result's `structuredContent`.
async fn live(rel: &str, args: Value) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("capabilities")
        .join(rel);
    let text = std::fs::read_to_string(&path).expect("shipped YAML");
    let capability = parse_capability_text(&text, &path).expect("the shipped file loads");
    let name = capability.name.clone();
    let backend = CapabilityBackend::new("maps-live", Arc::new(CapabilityExecutor::new()));
    backend.register_capability(capability).expect("registered");
    let result = backend
        .call_tool(&name, args)
        .await
        .unwrap_or_else(|e| panic!("{rel}: a live answer: {e}"));
    serde_json::to_value(result).expect("json")["structuredContent"].clone()
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_geocode() {
    let out = live(
        "maps/geocode.yaml",
        json!({ "name": "Helsinki", "count": 1 }),
    )
    .await;
    assert_eq!(out["results"][0]["country_code"], "FI", "{out}");
    assert_eq!(out["attribution"], OPEN_METEO);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_weather() {
    let out = live(
        "knowledge/weather.yaml",
        json!({ "latitude": 60.1699, "longitude": 24.9384 }),
    )
    .await;
    assert!(out["current"]["temperature_2m"].is_number(), "{out}");
    assert_eq!(out["attribution"], OPEN_METEO);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_geocode_then_weather() {
    let found = live("maps/geocode.yaml", json!({ "name": "Turku", "count": 1 })).await;
    let place = &found["results"][0];
    let out = live(
        "knowledge/weather.yaml",
        json!({ "latitude": place["latitude"], "longitude": place["longitude"] }),
    )
    .await;
    let lat = out["latitude"].as_f64().expect("latitude");
    assert!(
        (lat - place["latitude"].as_f64().expect("lat")).abs() < 0.1,
        "{out}"
    );
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_nominatim_search() {
    let out = live(
        "maps/nominatim_search.yaml",
        json!({ "q": "Helsinki Cathedral", "limit": 1 }),
    )
    .await;
    assert!(out["results"][0]["display_name"].is_string(), "{out}");
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_nominatim_reverse() {
    let out = live(
        "maps/nominatim_reverse.yaml",
        json!({ "latitude": 60.1699, "longitude": 24.9384 }),
    )
    .await;
    assert!(
        out["display_name"]
            .as_str()
            .is_some_and(|n| n.contains("Helsin")),
        "{out}"
    );
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_photon() {
    let out = live(
        "maps/photon_search.yaml",
        json!({ "q": "Helsinki Cathedral", "limit": 1 }),
    )
    .await;
    assert_eq!(out["type"], "FeatureCollection", "{out}");
    assert!(
        out["features"].as_array().is_some_and(|f| !f.is_empty()),
        "{out}"
    );
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_overpass() {
    let out = live(
        "maps/overpass_nearby.yaml",
        json!({ "latitude": 60.1699, "longitude": 24.9384, "category": "cafe", "radius": 500, "limit": 5 }),
    )
    .await;
    assert!(
        out["elements"].as_array().is_some_and(|e| !e.is_empty()),
        "cafes near Helsinki centre: {out}"
    );
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
#[ignore = "live provider; opt-in maps-live-smoke workflow only"]
async fn maps_live_osrm() {
    let out = live(
        "maps/osrm_route.yaml",
        json!({ "from_latitude": 60.1699, "from_longitude": 24.9384, "to_latitude": 60.4518, "to_longitude": 22.2666 }),
    )
    .await;
    assert_eq!(out["code"], "Ok", "{out}");
    assert_eq!(out["attribution"], OSM);
}
