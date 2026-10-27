// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A preview reports the name and version the server gives for itself,
//! marked as the server's own claim and cleaned for display, from either
//! protocol era.

use super::{
    IntoResponse, Json, Log, MODERN_VERSIONS, Response, StatusCode, Value, answer, confirmed, json,
    router_with, stub_with,
};

/// The `package` block of a confirmed preview of a stub answering `reply`.
async fn package_from(reply: fn(&Value) -> Response) -> Value {
    let log = Log::default();
    let url = stub_with(&log, reply).await;
    let (router, _store) = router_with(false).await;
    let (status, body) = confirmed(&router, &json!({"name": "who", "url": url})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["preview"]
            .as_object()
            .is_some_and(|p| p.contains_key("package")),
        "the package key is always present: {body}"
    );
    body["preview"]["package"].clone()
}

/// A legacy stub whose `initialize` reports `info` as its `serverInfo`.
fn legacy(request: &Value, info: Value) -> Response {
    if request.get("method").and_then(Value::as_str) == Some("initialize") {
        return Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": info,
        }}))
        .into_response();
    }
    answer(request)
}

/// A modern stub whose discover answer carries `info` in its `_meta`.
fn modern(request: &Value, info: Value) -> Response {
    let id = request["id"].clone();
    match request.get("method").and_then(Value::as_str) {
        Some("server/discover") => Json(json!({"jsonrpc": "2.0", "id": id, "result": {
            "capabilities": {"tools": {}},
            "supportedVersions": MODERN_VERSIONS,
            "_meta": {"io.modelcontextprotocol/serverInfo": info},
        }}))
        .into_response(),
        Some("initialize") => Json(json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}}))
        .into_response(),
        _ => answer(request),
    }
}

#[tokio::test]
async fn a_legacy_server_reports_its_name_and_version() {
    let package =
        package_from(|r| legacy(r, json!({"name": "notes-server", "version": "1.2.3"}))).await;
    assert_eq!(
        package,
        json!({"name": "notes-server", "version": "1.2.3",
               "source": "reported_by_server", "truncated": false})
    );
}

#[tokio::test]
async fn a_modern_server_reports_its_name_and_version_from_meta() {
    let package =
        package_from(|r| modern(r, json!({"name": "notes-modern", "version": "2.0.0"}))).await;
    assert_eq!(
        package,
        json!({"name": "notes-modern", "version": "2.0.0",
               "source": "reported_by_server", "truncated": false})
    );
}

/// Each field stands alone: a usable name with a non-string version keeps
/// the name, and the version is null.
#[tokio::test]
async fn a_name_without_a_usable_version_keeps_the_name() {
    let package = package_from(|r| legacy(r, json!({"name": "half", "version": 7}))).await;
    assert_eq!(package["name"], "half");
    assert_eq!(package["version"], Value::Null);
    let package = package_from(|r| modern(r, json!({"version": "3"}))).await;
    assert_eq!(package["name"], Value::Null);
    assert_eq!(package["version"], "3");
}

/// Nothing usable, from either era: `package` is null, never omitted.
#[tokio::test]
async fn nothing_usable_is_a_null_package() {
    assert_eq!(
        package_from(|r| legacy(r, json!("not an object"))).await,
        Value::Null
    );
    assert_eq!(package_from(|r| modern(r, json!({}))).await, Value::Null);
    // Only format and control characters: empty once cleaned, so missing.
    assert_eq!(
        package_from(|r| legacy(
            r,
            json!({"name": "\u{202e}\u{200b}\n", "version": "\u{2028}"})
        ))
        .await,
        Value::Null
    );
}

/// Spoofing text is stripped and a long name is capped, the same for both
/// eras. The closures capture nothing (`package_from` takes a `fn`), so each
/// builds its own text.
#[tokio::test]
async fn reported_text_is_cleaned_in_both_eras() {
    fn dirty() -> Value {
        json!({
            "name": format!("evil\u{202e}gpj.exe\u{0007}{}", "n".repeat(10_000)),
            "version": " 1.0\u{200d} ",
        })
    }
    let a = package_from(|r| legacy(r, dirty())).await;
    let b = package_from(|r| modern(r, dirty())).await;
    for package in [a, b] {
        let name = package["name"].as_str().expect("a name");
        assert!(name.starts_with("evilgpj.exe"), "{name}");
        assert_eq!(name.chars().count(), 128, "capped at 128 chars");
        assert_eq!(package["version"], "1.0");
        assert_eq!(package["truncated"], true);
    }
}
