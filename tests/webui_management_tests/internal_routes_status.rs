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
}
