// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map-tool calls refused before any request, a child of `maps_tools_tests`
//! using its helpers: a missing required input (T-req), a value outside an
//! enum (T-enum) and the weather bounds on both sides (W2). The parent holds
//! the calls that reach the provider and the shipped catalogue.

use super::*;

// ── T-req, T-enum, W2: refused before any request; bounds both sides ──

/// Call `rel` with `args` on a fresh host: whether it was refused, and the
/// requests the stub saw.
async fn attempt(rel: &str, host: &str, fixture: &str, args: Value) -> (bool, usize) {
    let stub = Stub::start(recorded(fixture)).await;
    let capability = shipped(rel, host, &stub);
    let name = capability.name.clone();
    // Input validation answers with an error result, not an `Err`
    // (backend.rs: "Validate arguments against the YAML schema").
    let refused = match backend(capability).call_tool(&name, args).await {
        Err(_) => true,
        Ok(result) => result.is_error,
    };
    (refused, stub.count())
}

fn with(base: &Value, key: &str, value: Value) -> Value {
    let mut args = base.clone();
    args[key] = value;
    args
}

fn without(base: &Value, key: &str) -> Value {
    let mut args = base.clone();
    args.as_object_mut().expect("object").remove(key);
    args
}

/// One broken field per case: every required input missing, then null; each
/// bound one step outside (refused, no request) and at its edge (one request).
async fn bounds(
    rel: &str,
    fixture: &str,
    base: Value,
    required: &[&str],
    edges: &[(&str, Value, Value, Value, Value)],
) {
    let mut n = 0;
    let mut host = |tag: &str| {
        n += 1;
        format!("treq-{}-{tag}-{n}.test", fixture.replace('_', "-"))
    };
    for key in required {
        for (case, args) in [
            ("missing", without(&base, key)),
            ("null", with(&base, key, Value::Null)),
        ] {
            let (refused, seen) = attempt(rel, &host(case), fixture, args).await;
            assert!(
                refused && seen == 0,
                "{rel} {key} {case}: refused before any request"
            );
        }
    }
    for (key, below, min, max, above) in edges {
        for (case, value, refuse) in [
            ("below", below, true),
            ("min", min, false),
            ("max", max, false),
            ("above", above, true),
        ] {
            // Refused means no request went out: an admitted call to Overpass
            // still errors, on its recorded 502.
            let (_, seen) =
                attempt(rel, &host(case), fixture, with(&base, key, value.clone())).await;
            assert_eq!(seen, usize::from(!refuse), "{rel} {key} {case} {value}");
        }
    }
}

#[tokio::test]
async fn treq_geocode() {
    bounds(
        "maps/geocode.yaml",
        "geocode",
        json!({ "name": "Helsinki" }),
        &["name"],
        &[
            ("count", json!(0), json!(1), json!(100), json!(101)),
            (
                "name",
                json!(""),
                json!("H"),
                json!("H".repeat(200)),
                json!("H".repeat(201)),
            ),
        ],
    )
    .await;
}

#[tokio::test]
async fn treq_nominatim_reverse() {
    bounds(
        "maps/nominatim_reverse.yaml",
        "nominatim_reverse",
        json!({ "latitude": 60.1699, "longitude": 24.9384 }),
        &["latitude", "longitude"],
        &[
            ("latitude", json!(-90.5), json!(-90), json!(90), json!(90.5)),
            (
                "longitude",
                json!(-180.5),
                json!(-180),
                json!(180),
                json!(180.5),
            ),
            ("zoom", json!(-1), json!(0), json!(18), json!(19)),
        ],
    )
    .await;
}

#[tokio::test]
async fn treq_osrm_path_values() {
    bounds(
        "maps/osrm_route.yaml",
        "osrm_route",
        json!({ "from_latitude": 60.1699, "from_longitude": 24.9384, "to_latitude": 60.4518, "to_longitude": 22.2666 }),
        &["from_latitude", "from_longitude", "to_latitude", "to_longitude"],
        &[("to_latitude", json!(-90.5), json!(-90), json!(90), json!(90.5))],
    )
    .await;
}

#[tokio::test]
async fn treq_overpass_ql_values() {
    bounds(
        "maps/overpass_nearby.yaml",
        "overpass_nearby",
        json!({ "latitude": 60.1699, "longitude": 24.9384, "category": "cafe", "radius": 500, "limit": 20 }),
        &["latitude", "longitude", "category", "radius", "limit"],
        &[
            ("radius", json!(0), json!(1), json!(5000), json!(5001)),
            ("limit", json!(0), json!(1), json!(50), json!(51)),
        ],
    )
    .await;
}

#[tokio::test]
async fn w2_weather_needs_both_coordinates() {
    bounds(
        "knowledge/weather.yaml",
        "weather",
        json!({ "latitude": 60.1699, "longitude": 24.9384 }),
        &["latitude", "longitude"],
        &[("forecast_days", json!(0), json!(1), json!(16), json!(17))],
    )
    .await;
}

#[tokio::test]
async fn tenum_overpass_categories_are_literal_and_closed() {
    let base = json!({ "latitude": 60.1699, "longitude": 24.9384, "category": "cafe", "radius": 500, "limit": 20 });
    let (refused, seen) = attempt(
        "maps/overpass_nearby.yaml",
        "tenum-inject.test",
        "overpass_nearby",
        with(&base, "category", json!("x];out;")),
    )
    .await;
    assert!(
        refused && seen == 0,
        "a value outside the enum never reaches the QL"
    );
    let expected = [
        "cafe",
        "restaurant",
        "bar",
        "pub",
        "fast_food",
        "pharmacy",
        "hospital",
        "clinic",
        "doctors",
        "dentist",
        "atm",
        "bank",
        "fuel",
        "charging_station",
        "parking",
        "toilets",
        "drinking_water",
        "post_office",
        "police",
        "library",
        "school",
    ];
    let shipped = as_shipped("maps/overpass_nearby.yaml");
    assert_eq!(
        shipped.schema.input["properties"]["category"]["enum"],
        json!(expected),
        "the enum is exactly the design's list"
    );
    for (i, category) in expected.iter().enumerate() {
        let stub = Stub::start(recorded("overpass_nearby")).await;
        let capability = shipped_with(&stub, &format!("tenum-{i}.test"));
        let _ = backend(capability)
            .call_tool("overpass_nearby", with(&base, "category", json!(category)))
            .await;
        let data = stub.seen()[0]
            .query
            .iter()
            .find(|(k, _)| k == "data")
            .map(|(_, v)| v.clone())
            .expect("data");
        assert!(
            data.contains(&format!("[amenity={category}]")),
            "{category}: {data}"
        );
    }
}

fn shipped_with(stub: &Stub, host: &str) -> CapabilityDefinition {
    shipped("maps/overpass_nearby.yaml", host, stub)
}
