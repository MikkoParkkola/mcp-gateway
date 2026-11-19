// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `/ui/api/status` as a non-admin sees it: the same answer with the admin
//! fields redacted.

use super::*;

/// A non-admin gets counts only, plus its own `access` report (which pages and
/// tabs it may open, with fixed reasons): no backend name and no other field.
#[tokio::test]
async fn ui_status_redacts_for_a_non_admin() {
    for (fixture, caller) in [
        (Fixture::AuthOn, Caller::Auditor),
        (Fixture::AuthOff, Caller::AnonOff),
    ] {
        let gw = gateway(fixture).await;
        let (status, _, body) = send(
            &gw,
            request(&Method::GET, "/ui/api/status", caller, Payload::None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{caller:?}");
        let text = String::from_utf8_lossy(&body);
        let json: Value = serde_json::from_slice(&body).expect("status is JSON");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "access",
                "auth",
                "degraded_count",
                "healthy_count",
                "server_count",
                "ui_api_version",
                "uptime_secs",
                "version"
            ],
            "{caller:?} got a field beyond the counts: {text}"
        );
        // `auth` states only three facts about the caller, never a
        // backend detail.
        let auth = json["auth"].as_object().expect("auth is an object");
        let mut facts: Vec<&str> = auth.keys().map(String::as_str).collect();
        facts.sort_unstable();
        assert_eq!(
            facts,
            ["admin", "enabled", "signed_in"],
            "{caller:?}: {text}"
        );
        assert!(
            auth.values().all(Value::is_boolean),
            "{caller:?}: every auth fact is a boolean: {text}"
        );
        assert_eq!(
            json["server_count"], 1,
            "the fixture's backend is counted: {text}"
        );
        // V2 (MIK-9681.CLIUX.20): the counts-only view carries the UI API version, the literal 1.
        assert_eq!(json["ui_api_version"], 1, "{caller:?}: {text}");
        assert!(
            !text.contains("docs"),
            "{caller:?} got the backend name: {text}"
        );
    }
    // Positive control: the same fixture names the backend to an admin.
    let gw = gateway(Fixture::AuthOn).await;
    let (status, _, body) = send(
        &gw,
        request(&Method::GET, "/ui/api/status", Caller::Admin, Payload::None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).expect("status is JSON");
    assert_eq!(json["servers"][0]["name"], "docs", "{json}");
    // V2: the full view carries it too.
    assert_eq!(json["ui_api_version"], 1, "{json}");
}

/// V4 (MIK-9681.CLIUX.20): the number `--version` prints after `UI API ` is the number the status route serves, so the
/// two cannot drift apart. (V3, the builder's two views, is covered by V2: the route builds both, full for the admin
/// and counts-only for everyone else.)
#[tokio::test]
async fn the_version_line_and_the_status_route_agree() {
    use clap::CommandFactory;
    let line = mcp_gateway::cli::Cli::command().render_version();
    let printed: u64 = line
        .split("(UI API ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no UI API version in {line:?}"));
    let gw = gateway(Fixture::AuthOff).await;
    let (status, _, body) = send(
        &gw,
        request(
            &Method::GET,
            "/ui/api/status",
            Caller::AnonOff,
            Payload::None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).expect("status is JSON");
    assert_eq!(json["ui_api_version"].as_u64(), Some(printed), "{json}");
}
