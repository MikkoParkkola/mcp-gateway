// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hand-written facts about the UI access matrix's expectation, moved out of
//! `ui_access_matrix_tests.rs` for the file-size ceiling.

use super::*;

/// Callers whose role reads only their own grants and audit events: with a
/// store, their snapshot differs from an auditor's, who reads every event.
const OWN_ROWS_ONLY: &[&str] = &[
    "StandardKey",
    "OidcDeveloper",
    "OidcDeveloperNoSubject",
    "OidcDeveloperNoIssuer",
    "OidcUnmapped",
    "AdminKeyUnmapped",
];

/// The seeded events reach an admin's snapshot, so the "+store" cells pin
/// who is shown which store rows (not only that a store is attached).
#[tokio::test]
async fn the_seeded_store_reaches_the_snapshot() {
    let fx = fixture(Gateway::On, true).await;
    seed_store(&fx.state);
    let router = create_router(Arc::clone(&fx.state));
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    let (status, body) = send(&router, request(Caller::AdminKey, req, &fx, None)).await;
    assert_eq!(status, StatusCode::OK);
    let body = String::from_utf8_lossy(&body);
    for (event_id, _) in SEEDED_EVENTS {
        assert!(
            body.contains(event_id),
            "{event_id} is not in the snapshot: {body}"
        );
    }
}

/// Hand-written facts about the expectation, so a probe that lost its
/// credential cannot make the generated table green on both sides.
#[test]
fn the_expectation_holds_known_answers() {
    let expected = expected();
    let get = |path: &str, shape: &str, caller: &str| {
        expected
            .get(&format!("{path}\tGET\t{shape}\t{caller}"))
            .unwrap_or_else(|| panic!("no cell for {path} {shape} {caller}"))
            .clone()
    };
    for path in paths() {
        let admin = get(path, "plain", "AdminKey");
        assert!(
            !admin.starts_with("401") && !admin.starts_with("403"),
            "an admin key is refused on {path}: {admin}"
        );
        if path != routes::DASHBOARD {
            let anonymous = get(path, "plain", "NoKey");
            assert!(
                anonymous.starts_with("401") || anonymous == "405",
                "no credential is not refused on {path}: {anonymous}"
            );
        }
    }
    // A Developer reads its own Activity, not another Developer's record;
    // an Auditor reads both.
    let receipt = routes::UI_ACTIVITY_RECEIPT;
    assert_eq!(get(receipt, "other-receipt", "OidcDeveloper"), "404");
    assert!(get(receipt, "other-receipt", "OidcAuditor").starts_with("200"));
    assert!(get(routes::UI_ACTIVITY, "plain", "StandardKey").starts_with("403"));
    // The list: every seeded call for the callers that read all of Activity,
    // only its own for the Developer.
    let all = "200:tool_0,tool_1,tool_2";
    for caller in [
        "AdminKey",
        "AdminKeyUnmapped",
        "Bearer",
        "Session",
        "OidcAdmin",
        "OidcAuditor",
    ] {
        assert_eq!(get(routes::UI_ACTIVITY, "plain", caller), all, "{caller}");
    }
    assert_eq!(
        get(routes::UI_ACTIVITY, "plain", "OidcDeveloper"),
        "200:tool_0"
    );
    // The CSV export carries the same scope as the list.
    for caller in ["AdminKey", "OidcAdmin", "OidcAuditor"] {
        assert_eq!(
            get(routes::UI_ACTIVITY_EXPORT, "csv", caller),
            all,
            "{caller}"
        );
    }
    assert_eq!(
        get(routes::UI_ACTIVITY_EXPORT, "csv", "OidcDeveloper"),
        "200:tool_0"
    );
    // A body that parses reaches the guards of the writes that parse first:
    // a non-admin is refused there, and a control-plane write with a store
    // reaches its role check (this build then refuses the write itself).
    let post = |path: &str, shape: &str, caller: &str| {
        expected
            .get(&format!("{path}\tPOST\t{shape}\t{caller}"))
            .unwrap_or_else(|| panic!("no cell for POST {path} {shape} {caller}"))
            .clone()
    };
    for path in [routes::UI_BACKENDS, routes::UI_PREVIEWS] {
        assert!(
            post(path, "valid", "StandardKey").starts_with("403"),
            "{path}"
        );
    }
    // A caller limited to its own rows never reads the auditor's full view.
    for &caller in OWN_ROWS_ONLY {
        for shape in ["plain+store", "bad-query+store"] {
            assert_ne!(
                get(routes::UI_CONTROL_PLANE, shape, caller),
                get(routes::UI_CONTROL_PLANE, shape, "OidcAuditor"),
                "{shape} {caller}"
            );
        }
    }
    // With the seeded store, the roles still see different snapshots.
    let seeded = |caller: &str| get(routes::UI_CONTROL_PLANE, "plain+store", caller);
    assert_ne!(seeded("OidcAdmin"), seeded("OidcDeveloper"));
    assert_ne!(seeded("OidcAuditor"), seeded("OidcDeveloper"));
    for path in STORE_WRITES {
        assert!(
            post(path, "valid+store", "OidcAuditor").starts_with("403"),
            "{path}"
        );
        assert_eq!(post(path, "valid+store", "AdminKey"), "409", "{path}");
    }
}
