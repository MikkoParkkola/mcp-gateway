// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Map tools' per-tool rows (T, W, U1, P2): the shipped YAMLs, their endpoint
//! pointed at a stub that replays the recorded provider answer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use crate::capability::maps_harness::{Names, Reply, Stub, executor};
use crate::capability::parser::parse_capability_text;
use crate::capability::{
    CapabilityBackend, CapabilityDefinition, compute_capability_hash, rewrite_with_pin,
};

const RUN: &str = "run-44178019895";
const UA: &str = "mcp-gateway/4.0 (+https://github.com/MikkoParkkola/mcp-gateway)";
const OSM: &str = "© OpenStreetMap contributors";
const OPEN_METEO: &str = "Data by Open-Meteo.com (CC BY 4.0)";

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The recorded answer `name`, replayed with its recorded status and content
/// type (from the run's MANIFEST).
fn recorded(name: &str) -> Reply {
    let dir = repo("tests/fixtures/maps").join(RUN);
    let body = std::fs::read_to_string(dir.join(format!("{name}.json"))).expect("fixture body");
    let manifest = std::fs::read_to_string(dir.join("MANIFEST")).expect("MANIFEST");
    let line = manifest
        .lines()
        .find(|l| l.split(' ').next() == Some(name))
        .unwrap_or_else(|| panic!("{name} in MANIFEST"));
    // name time status content-type... url
    let fields: Vec<&str> = line.split(' ').collect();
    let status: u16 = fields[2].parse().expect("status");
    let url_at = fields.len() - 1;
    let content_type = fields[3..url_at].join(" ");
    Reply::Body {
        status,
        content_type,
        body,
    }
}

/// The shipped capability `rel` (under `capabilities/`), its endpoint's origin
/// replaced by `http://<host>:<stub port>`, re-pinned in memory and parsed as
/// the loader parses it.
fn shipped(rel: &str, host: &str, stub: &Stub) -> CapabilityDefinition {
    let text = std::fs::read_to_string(repo("capabilities").join(rel)).expect("shipped YAML");
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("endpoint:"))
        .expect("an endpoint line");
    let url = line.trim_start()["endpoint:".len()..]
        .trim()
        .trim_matches('"');
    let rest = url.split_once("://").expect("scheme").1;
    let origin = &url[..url.len() - rest.len() + rest.find('/').unwrap_or(rest.len())];
    let swapped = text.replacen(origin, &format!("http://{host}:{}", stub.port), 1);
    let pinned = if swapped.starts_with("sha256:") {
        rewrite_with_pin(&swapped, &compute_capability_hash(&swapped))
    } else {
        swapped
    };
    parse_capability_text(&pinned, Path::new(rel)).expect("the shipped capability loads")
}

/// A backend serving `capability`.
fn backend(capability: CapabilityDefinition) -> CapabilityBackend {
    let backend = CapabilityBackend::new("maps", Arc::new(executor(Names::default())));
    backend.register_capability(capability).expect("registered");
    backend
}

/// One call of `tool` (shipped as `rel`) with `args` against the recorded
/// answer `fixture`: the request the stub saw, and the result.
async fn call(
    rel: &str,
    host: &str,
    fixture: &str,
    args: Value,
) -> (crate::capability::maps_harness::Seen, crate::Result<Value>) {
    let stub = Stub::start(recorded(fixture)).await;
    let capability = shipped(rel, host, &stub);
    let name = capability.name.clone();
    let b = backend(capability);
    let result = b
        .call_tool(&name, args)
        .await
        .map(|r| serde_json::to_value(r).expect("json"));
    let seen = stub.seen();
    assert_eq!(seen.len(), 1, "{rel}: one request");
    (seen[0].clone(), result)
}

/// The result's `structuredContent`.
fn structured(result: &crate::Result<Value>) -> Value {
    result.as_ref().expect("a result")["structuredContent"].clone()
}

fn query(
    seen: &crate::capability::maps_harness::Seen,
) -> std::collections::BTreeMap<String, String> {
    seen.query.iter().cloned().collect()
}

fn map(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn user_agent(seen: &crate::capability::maps_harness::Seen) -> String {
    seen.headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

// ── T rows: the request built and the recorded answer through the tool ──

#[tokio::test]
async fn t_geocode() {
    let (seen, result) = call(
        "maps/geocode.yaml",
        "t-geocode.test",
        "geocode",
        json!({ "name": "Helsinki", "count": 5 }),
    )
    .await;
    assert_eq!(seen.path, "/v1/search");
    assert_eq!(query(&seen), map(&[("name", "Helsinki"), ("count", "5")]));
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    let first = &out["results"][0];
    assert_eq!(first["name"], "Helsinki");
    assert!((first["latitude"].as_f64().expect("lat") - 60.17).abs() < 0.01);
    assert!((first["longitude"].as_f64().expect("lon") - 24.94).abs() < 0.01);
    assert_eq!(out["attribution"], OPEN_METEO);
}

#[tokio::test]
async fn t_geocode_none_has_no_results_and_still_its_credit() {
    let (_, result) = call(
        "maps/geocode.yaml",
        "t-geocode-none.test",
        "geocode_none",
        json!({ "name": "Qxzvqzzyx" }),
    )
    .await;
    let out = structured(&result);
    assert!(
        out.get("results").is_none(),
        "no match sends no results: {out}"
    );
    assert_eq!(out["attribution"], OPEN_METEO);
}

#[tokio::test]
async fn t_nominatim_search() {
    let (seen, result) = call(
        "maps/nominatim_search.yaml",
        "t-nsearch.test",
        "nominatim_search",
        json!({ "q": "Helsinki Cathedral", "limit": 5 }),
    )
    .await;
    assert_eq!(seen.path, "/search");
    assert_eq!(
        query(&seen),
        map(&[
            ("q", "Helsinki Cathedral"),
            ("format", "jsonv2"),
            ("limit", "5")
        ])
    );
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    assert!(
        out["results"].as_array().is_some_and(|r| !r.is_empty()),
        "{out}"
    );
    assert!(
        out["results"][0]["display_name"]
            .as_str()
            .is_some_and(|n| n.contains("Helsin"))
    );
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
async fn t_nominatim_reverse() {
    let (seen, result) = call(
        "maps/nominatim_reverse.yaml",
        "t-nreverse.test",
        "nominatim_reverse",
        json!({ "latitude": 60.1699, "longitude": 24.9384, "zoom": 18 }),
    )
    .await;
    assert_eq!(seen.path, "/reverse");
    assert_eq!(
        query(&seen),
        map(&[
            ("lat", "60.1699"),
            ("lon", "24.9384"),
            ("zoom", "18"),
            ("format", "jsonv2")
        ])
    );
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    assert!(
        out["display_name"]
            .as_str()
            .is_some_and(|n| n.contains("Helsin")),
        "{out}"
    );
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
async fn t_photon() {
    let (seen, result) = call(
        "maps/photon_search.yaml",
        "t-photon.test",
        "photon_search",
        json!({ "q": "Helsinki Cathedral", "limit": 5 }),
    )
    .await;
    assert_eq!(seen.path, "/api/");
    assert_eq!(
        query(&seen),
        map(&[("q", "Helsinki Cathedral"), ("limit", "5")])
    );
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    assert_eq!(out["type"], "FeatureCollection");
    assert!(out["features"].as_array().is_some_and(|f| !f.is_empty()));
    assert_eq!(out["attribution"], OSM);
}

#[tokio::test]
async fn t_osrm() {
    let (seen, result) = call(
        "maps/osrm_route.yaml",
        "t-osrm.test",
        "osrm_route",
        json!({
            "from_latitude": 60.1699, "from_longitude": 24.9384,
            "to_latitude": 60.4518, "to_longitude": 22.2666
        }),
    )
    .await;
    assert_eq!(
        seen.path,
        "/route/v1/driving/24.9384,60.1699;22.2666,60.4518"
    );
    assert_eq!(query(&seen), map(&[("overview", "false")]));
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    assert_eq!(out["code"], "Ok");
    assert!(
        out["routes"][0]["distance"]
            .as_f64()
            .is_some_and(|d| d > 100_000.0),
        "{out}"
    );
    assert_eq!(out["attribution"], OSM);
}

/// Overpass's recorded answer is its 502 at-capacity reply (the success
/// answer is recorded by the feature's own live run): the exact QL goes out,
/// and the 502 surfaces as an error with no credit.
#[tokio::test]
async fn t_overpass_at_capacity() {
    let (seen, result) = call(
        "maps/overpass_nearby.yaml",
        "t-overpass.test",
        "overpass_nearby",
        json!({ "latitude": 60.1699, "longitude": 24.9384, "category": "cafe", "radius": 500, "limit": 20 }),
    )
    .await;
    assert_eq!(seen.path, "/api/interpreter");
    assert_eq!(
        query(&seen),
        map(&[(
            "data",
            "[out:json][timeout:25];nwr(around:500,60.1699,24.9384)[amenity=cafe];out center 20;"
        )])
    );
    assert_eq!(user_agent(&seen), UA);
    let text = match &result {
        Err(e) => e.to_string(),
        Ok(v) => {
            assert_eq!(v["isError"], true, "a 502 is an error: {v}");
            v.to_string()
        }
    };
    assert!(text.contains("502"), "the status surfaces: {text}");
    assert!(!text.contains(OSM), "no credit on an error: {text}");
}

#[tokio::test]
async fn t_weather() {
    let (seen, result) = call(
        "knowledge/weather.yaml",
        "t-weather.test",
        "weather",
        json!({ "latitude": 60.1699, "longitude": 24.9384 }),
    )
    .await;
    assert_eq!(seen.path, "/v1/forecast");
    let q = query(&seen);
    assert_eq!(q.get("latitude").map(String::as_str), Some("60.1699"));
    assert_eq!(q.get("longitude").map(String::as_str), Some("24.9384"));
    assert!(
        !q.contains_key("forecast_days"),
        "W5: left out, so Open-Meteo's default"
    );
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    // W3/W5: the provider's real shape, its daily series 7 long, as the
    // description says Open-Meteo sends when forecast_days is left out.
    assert_eq!(out["daily"]["time"].as_array().map(Vec::len), Some(7));
    assert!(out["current"]["temperature_2m"].is_number(), "{out}");
    assert_eq!(out["attribution"], OPEN_METEO);
}

// ── P2, W1, K2, LD5: the shipped catalogue, as literals ───────────────

/// The shipped file `rel`, parsed as the loader parses it (pin checked).
fn as_shipped(rel: &str) -> CapabilityDefinition {
    let text = std::fs::read_to_string(repo("capabilities").join(rel)).expect("shipped YAML");
    parse_capability_text(&text, Path::new(rel)).expect("the shipped file loads")
}

#[test]
fn p2_each_paced_provider_has_its_host_and_interval() {
    for (rel, host, interval) in [
        ("maps/geocode.yaml", "geocoding-api.open-meteo.com", 250),
        ("knowledge/weather.yaml", "api.open-meteo.com", 250),
        (
            "maps/nominatim_search.yaml",
            "nominatim.openstreetmap.org",
            1000,
        ),
        (
            "maps/nominatim_reverse.yaml",
            "nominatim.openstreetmap.org",
            1000,
        ),
        ("maps/photon_search.yaml", "photon.komoot.io", 1000),
        ("maps/overpass_nearby.yaml", "overpass-api.de", 2000),
        ("maps/osrm_route.yaml", "router.project-osrm.org", 1000),
        (
            "entertainment/musicbrainz_search.yaml",
            "musicbrainz.org",
            1000,
        ),
    ] {
        let capability = as_shipped(rel);
        let provider = capability.providers.get("primary").expect("primary");
        let url = if provider.config.endpoint.is_empty() {
            &provider.config.base_url
        } else {
            &provider.config.endpoint
        };
        let key = crate::capability::pacing::host_key(url).expect("a host");
        assert_eq!((rel, key.host.as_str()), (rel, host));
        assert_eq!(
            (rel, provider.rate_limit.map(|r| r.interval_ms)),
            (rel, Some(interval))
        );
    }
    let musicbrainz =
        std::fs::read_to_string(repo("capabilities/entertainment/musicbrainz_search.yaml"))
            .expect("musicbrainz");
    assert!(
        !musicbrainz.contains("1 req/sec"),
        "the metadata note moved into rate_limit"
    );
}

#[test]
fn w1_weather_takes_coordinates_and_says_so() {
    let weather = as_shipped("knowledge/weather.yaml");
    let input = &weather.schema.input;
    assert!(
        input["properties"].get("location").is_none(),
        "location is cut"
    );
    assert_eq!(input["required"], json!(["latitude", "longitude"]));
    assert!(weather.description.contains(
        "To look up a place by name, call geocode first, then pass its latitude and longitude here."
    ));
    assert!(
        weather
            .description
            .contains("The free tier is non-commercial; commercial use needs an Open-Meteo plan.")
    );
    assert!(
        !input["properties"]["forecast_days"]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("default: 3"),
        "W5: the old default text is gone"
    );
    assert_eq!(weather.attribution.as_deref(), Some(OPEN_METEO));
}

#[test]
fn k2_the_catalogue_readme_carries_both_licence_lines() {
    let readme = std::fs::read_to_string(repo("capabilities/README.md")).expect("README");
    for line in [
        "free tier is non-commercial; commercial use needs an Open-Meteo plan",
        "the public demo server is non-commercial; commercial use needs your own OSRM server",
    ] {
        assert!(readme.contains(line), "README: {line}");
    }
    let osrm = as_shipped("maps/osrm_route.yaml");
    assert!(osrm.description.contains(
        "The public demo server is non-commercial; commercial use needs your own OSRM server."
    ));
    let geocode = as_shipped("maps/geocode.yaml");
    assert!(
        geocode
            .description
            .contains("The free tier is non-commercial; commercial use needs an Open-Meteo plan.")
    );
}

#[test]
fn ld5_every_shipped_file_loads_the_six_new_by_name() {
    let mut files = Vec::new();
    let mut stack = vec![repo("capabilities")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                files.push(path);
            }
        }
    }
    assert_eq!(
        files.len(),
        149,
        "143 shipped before plus the six map tools"
    );
    let mut paced_notes = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("read");
        let capability = parse_capability_text(&text, path)
            .unwrap_or_else(|e| panic!("{} loads: {e}", path.display()));
        // An informational note no field reads: metadata is lenient.
        let raw: Value = crate::yaml::from_str(&text).expect("YAML");
        if raw["metadata"].get("rate_limit").is_some() {
            paced_notes.push(capability.name.clone());
        }
    }
    let maps: std::collections::BTreeSet<String> = std::fs::read_dir(repo("capabilities/maps"))
        .expect("maps dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        maps,
        [
            "geocode.yaml",
            "nominatim_reverse.yaml",
            "nominatim_search.yaml",
            "osrm_route.yaml",
            "overpass_nearby.yaml",
            "photon_search.yaml",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    // metadata stays lenient: the 26 informational rate notes still load.
    assert_eq!(paced_notes.len(), 26, "{paced_notes:?}");
}

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

// ── W4, K4 ─────────────────────────────────────────────────────

#[tokio::test]
async fn w4_geocode_then_weather_carries_the_coordinates() {
    let (_, found) = call(
        "maps/geocode.yaml",
        "w4-geocode.test",
        "geocode",
        json!({ "name": "Helsinki" }),
    )
    .await;
    let first = structured(&found)["results"][0].clone();
    let (seen, _) = call(
        "knowledge/weather.yaml",
        "w4-weather.test",
        "weather",
        json!({ "latitude": first["latitude"], "longitude": first["longitude"] }),
    )
    .await;
    let q = query(&seen);
    assert_eq!(q.get("latitude").map(String::as_str), Some("60.16952"));
    assert_eq!(q.get("longitude").map(String::as_str), Some("24.93545"));
}

#[test]
fn k4_each_recorded_url_is_the_request_its_row_asserts() {
    let manifest = std::fs::read_to_string(repo("tests/fixtures/maps").join(RUN).join("MANIFEST"))
        .expect("MANIFEST");
    let urls: std::collections::BTreeMap<&str, &str> = manifest
        .lines()
        .skip(1)
        .filter_map(|l| Some((l.split(' ').next()?, l.rsplit(' ').next()?)))
        .collect();
    let parsed = |name: &str| {
        let url = url::Url::parse(urls[name]).expect("url");
        let q: std::collections::BTreeMap<String, String> =
            url.query_pairs().into_owned().collect();
        (url.path().to_owned(), q)
    };
    assert_eq!(
        parsed("geocode"),
        (
            "/v1/search".to_owned(),
            map(&[("name", "Helsinki"), ("count", "5")])
        )
    );
    assert_eq!(
        parsed("nominatim_search"),
        (
            "/search".to_owned(),
            map(&[
                ("q", "Helsinki Cathedral"),
                ("format", "jsonv2"),
                ("limit", "5")
            ])
        )
    );
    assert_eq!(
        parsed("nominatim_reverse"),
        (
            "/reverse".to_owned(),
            map(&[
                ("lat", "60.1699"),
                ("lon", "24.9384"),
                ("format", "jsonv2"),
                ("zoom", "18")
            ])
        )
    );
    assert_eq!(
        parsed("photon_search"),
        (
            "/api/".to_owned(),
            map(&[("q", "Helsinki Cathedral"), ("limit", "5")])
        )
    );
    assert_eq!(
        parsed("overpass_nearby"),
        (
            "/api/interpreter".to_owned(),
            map(&[(
                "data",
                "[out:json][timeout:25];nwr(around:500,60.1699,24.9384)[amenity=cafe];out center 20;"
            )])
        )
    );
    assert_eq!(
        parsed("osrm_route"),
        (
            "/route/v1/driving/24.9384,60.1699;22.2666,60.4518".to_owned(),
            map(&[("overview", "false")])
        )
    );
}

// ── LD7: a refused file is not silent at runtime ─────────────────────

/// The gateway's own catalogue load logs a strict-key refusal at WARN,
/// naming the file, the key and the nearest valid key; the file's neighbour
/// still loads.
#[test]
fn ld7_a_catalogue_load_logs_the_refused_file_at_warn() {
    let dir = tempfile::TempDir::new().expect("dir");
    let typo = dir.path().join("typo.yaml");
    std::fs::write(
        &typo,
        "name: typo\ndescription: d\nproviders:\n  primary:\n    service: rest\n    rate_lmit:\n      \
         interval_ms: 1000\n    config:\n      base_url: https://typo.test\n      path: /x\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("fine.yaml"),
        "name: fine\ndescription: d\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: https://fine.test\n      path: /x\n",
    )
    .expect("write");
    let backend = CapabilityBackend::new("maps", Arc::new(executor(Names::default())));
    let (loaded, warnings) = crate::test_log_capture::capture_warnings(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(backend.load_from_directory(dir.path().to_str().expect("utf-8")))
    });
    assert_eq!(
        loaded.expect("the directory loads"),
        1,
        "the neighbour loads"
    );
    assert!(backend.has_capability("fine") && !backend.has_capability("typo"));
    for part in [
        typo.display().to_string(),
        "key `rate_lmit` is not a capability provider field".to_owned(),
        "Did you mean: rate_limit?".to_owned(),
    ] {
        assert!(
            warnings.contains(&part),
            "the warning names {part}: {warnings}"
        );
    }
}
