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
/// The feature's own live run: the first to record Overpass's success.
const PR_RUN: &str = "run-44215521926";
const UA: &str = "mcp-gateway/4.0 (+https://github.com/MikkoParkkola/mcp-gateway)";
const OSM: &str = "© OpenStreetMap contributors";
const OPEN_METEO: &str = "Data by Open-Meteo.com (CC BY 4.0)";

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The recorded answer `name`, replayed with its recorded status and content
/// type (from the run's MANIFEST).
fn recorded(name: &str) -> Reply {
    recorded_in(RUN, name)
}

/// The MANIFEST line of `name` in the recording `run`, split on spaces:
/// name, time, status, content type (one or more words), then the URL.
fn manifest_fields(run: &str, name: &str) -> Vec<String> {
    let manifest = std::fs::read_to_string(repo("tests/fixtures/maps").join(run).join("MANIFEST"))
        .expect("MANIFEST");
    manifest
        .lines()
        .find(|l| l.split(' ').next() == Some(name))
        .unwrap_or_else(|| panic!("{name} in MANIFEST"))
        .split(' ')
        .map(str::to_owned)
        .collect()
}

/// As [`recorded`], from the recording `run`.
fn recorded_in(run: &str, name: &str) -> Reply {
    let dir = repo("tests/fixtures/maps").join(run);
    let body = std::fs::read_to_string(dir.join(format!("{name}.json"))).expect("fixture body");
    let fields = manifest_fields(run, name);
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
    call_in(RUN, rel, host, fixture, args).await
}

/// As [`call`], replaying the answer recorded in `run`.
async fn call_in(
    run: &str,
    rel: &str,
    host: &str,
    fixture: &str,
    args: Value,
) -> (crate::capability::maps_harness::Seen, crate::Result<Value>) {
    let stub = Stub::start(recorded_in(run, fixture)).await;
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

/// Overpass's success answer, from the feature's own live run: the same QL
/// goes out, and the twenty cafes it found come back with the credit.
#[tokio::test]
async fn t_overpass_success() {
    let (seen, result) = call_in(
        PR_RUN,
        "maps/overpass_nearby.yaml",
        "t-overpass-ok.test",
        "overpass_nearby",
        json!({ "latitude": 60.1699, "longitude": 24.9384, "category": "cafe", "radius": 500, "limit": 20 }),
    )
    .await;
    // The path and query are those of the request Overpass answered 200, as
    // the record job's MANIFEST wrote its URL down. The MANIFEST records no
    // method, body or headers: GET, no body and the User-Agent are the
    // shipped tool's own request, checked against the workflow's values.
    let fields = manifest_fields(PR_RUN, "overpass_nearby");
    let sent = url::Url::parse(fields.last().expect("url")).expect("recorded URL");
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, sent.path());
    // As sorted lists, not maps: a duplicated parameter stays visible.
    let mut got = seen.query.clone();
    got.sort();
    let mut want: Vec<(String, String)> = sent.query_pairs().into_owned().collect();
    want.sort();
    assert_eq!(got, want);
    assert!(seen.body.is_empty(), "no body: {:?}", seen.body);
    assert_eq!(user_agent(&seen), UA);
    let out = structured(&result);
    let elements = out["elements"].as_array().expect("elements");
    assert_eq!(elements.len(), 20, "the recorded twenty: {out}");
    assert!(
        elements.iter().all(|e| e["tags"]["amenity"] == "cafe"),
        "every element is a cafe: {out}"
    );
    assert_eq!(out["attribution"], OSM);
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

/// Overpass may queue a query for a free slot and then run it for up to the
/// query's own `[timeout:N]`: the success run 44215521926 recorded took about
/// 37 s against N = 25. The provider's request timeout leaves room for both,
/// at least twice N, and stays under 60 s, the common MCP client default
/// (the TypeScript SDK's), so a slow answer reaches the caller as the
/// gateway's provider error before the client gives up on its own. The 30 s
/// default cut two live attempts at 30.1 s.
#[test]
fn t_overpass_timeout_outlasts_its_query_and_beats_the_client() {
    let capability = as_shipped("maps/overpass_nearby.yaml");
    let provider = capability.providers.get("primary").expect("primary");
    let query = provider.config.params.get("data").expect("the query");
    let server_secs: u64 = query
        .split_once("[timeout:")
        .and_then(|(_, rest)| rest.split_once(']'))
        .and_then(|(secs, _)| secs.parse().ok())
        .expect("the query names its [timeout:N]");
    assert!(
        provider.timeout >= 2 * server_secs,
        "a provider timeout of {} s is under twice the query's {server_secs} s",
        provider.timeout
    );
    assert!(
        provider.timeout < 60,
        "a provider timeout of {} s does not answer before a 60 s client gives up",
        provider.timeout
    );
    assert_eq!((server_secs, provider.timeout), (25, 55));
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

// ── T-schemas: every recorded success fits its shipped schema ────────

#[test]
fn t_schemas_each_recorded_success_validates_against_its_shipped_schema() {
    for (run, count) in [(RUN, 7), (PR_RUN, 8)] {
        schemas_of(run, count);
    }
}

/// T-schemas for one recording `run` holding `count` successes.
fn schemas_of(run: &str, count: usize) {
    let dir = repo("tests/fixtures/maps").join(run);
    // Every recorded 200 is checked: a new recording must be mapped here.
    let tool_of = |fixture: &str| match fixture {
        "geocode" | "geocode_none" => "maps/geocode.yaml",
        "nominatim_search" => "maps/nominatim_search.yaml",
        "nominatim_reverse" => "maps/nominatim_reverse.yaml",
        "photon_search" => "maps/photon_search.yaml",
        "overpass_nearby" => "maps/overpass_nearby.yaml",
        "osrm_route" => "maps/osrm_route.yaml",
        "weather" => "knowledge/weather.yaml",
        other => panic!("recorded fixture {other} maps to no shipped tool"),
    };
    let manifest = std::fs::read_to_string(dir.join("MANIFEST")).expect("MANIFEST");
    let successes: Vec<(&str, &str)> = manifest
        .lines()
        .skip(1)
        .filter(|l| l.split(' ').nth(2) == Some("200"))
        .map(|l| {
            let fixture = l.split(' ').next().expect("name");
            (tool_of(fixture), fixture)
        })
        .collect();
    assert_eq!(
        successes.len(),
        count,
        "premise: {run}'s recorded successes"
    );
    for (rel, fixture) in successes {
        let capability = as_shipped(rel);
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(format!("{fixture}.json"))).expect("fixture"),
        )
        .expect("JSON");
        let published = crate::capability::apply_attribution(&capability, raw);
        let verdict = crate::capability::validate_output(&published, &capability.schema.output);
        assert!(
            verdict.is_valid(),
            "{run} {fixture} against {rel}: {:?}",
            verdict.violations
        );
    }
}

#[path = "maps_tools_refusal_tests.rs"]
mod refusal;
