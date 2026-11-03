// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.8: where an admin is served on the INTERNAL routes whose
//! admin cell in the parent table is not served, and that a non-admin stays
//! refused, changing nothing, once that state exists.

use super::*;

const MUTATION: &str = "tests/webui_management_tests/backend_mutation.rs";
const EVENTS_ADMIN: &str = "tests/mik_7630_events_admin.rs";
const EVENTS_RECONCILE: &str = "tests/mik_7630_events_reconcile.rs";
const CP_AUTHORITY: &str = "tests/e2min_control_plane_authority.rs";
const ACTIVITY_LIST: &str = "src/gateway/ui/activity/list_tests.rs";
const ACTIVITY_EXPORT: &str = "src/gateway/ui/activity/export_tests.rs";
const ACTIVITY_RECEIPT: &str = "src/gateway/ui/activity/receipt_tests.rs";
const HISTORY_ROUTES: &str = "src/gateway/router/history_route_tests.rs";
const HISTORY_PARAMS: &str = "src/gateway/ui/history_tests.rs";
const EDITOR: &str = "tests/webui_management_tests/capability_editor.rs";
const CAPABILITIES: &str = "tests/webui_management_tests/capabilities.rs";
const UI_TOOL_CALL: &str = "src/gateway/router/ui_tool_call_tests.rs";
const ADOPT_ROUTE: &str = "tests/discovery_adopt_route.rs";
const DECISIONS_ROUTE: &str = "src/gateway/ui/decisions_tests.rs";
const DISCOVERY_WIRING: &str = "src/gateway/ui/discovery_wiring_tests.rs";
const CP_WRITES: &[Citation] = &[(
    CP_AUTHORITY,
    "admin_grant_and_policy_writes_are_refused_and_point_at_config",
)];

/// MIK-8044.SURF.8: where the admin's SERVED answer is pinned for every row
/// whose admin cell above is not served (this fixture lacks the state those
/// handlers need). Each cited test asserts the served status and its effect;
/// the assertions are listed in handoff/mik-8044-surf4b-design.md r3.
/// (test file, test fn) that pins a served answer.
type Citation = (&'static str, &'static str);

const SERVED_BY: &[(&str, Method, &[Citation])] = &[
    // The table sends no If-Match, so its admin answer is 428; these tests
    // send the base and pin the served save and delete.
    (
        "/ui/api/capabilities/{name}",
        Method::PUT,
        &[(EDITOR, "test_save_answers_the_next_base")],
    ),
    (
        "/ui/api/capabilities/{name}",
        Method::DELETE,
        &[(CAPABILITIES, "test_capability_create_read_delete_lifecycle")],
    ),
    // The table's body names no find, so its admin answer is 422; this test
    // adopts real finds from a client file and pins the served 201.
    // The table's fixture never starts the decision set, so its admin
    // answer is 503; this test starts it over a real log and pins the 200.
    (
        "/ui/api/decisions",
        Method::GET,
        &[(
            DECISIONS_ROUTE,
            "an_admin_is_served_the_open_decisions_and_no_one_else",
        )],
    ),
    // As the list: the table's fixture never starts the set, so its admin
    // answer is 503; this test starts it and pins the served count.
    (
        "/ui/api/decisions/count",
        Method::GET,
        &[(
            DECISIONS_ROUTE,
            "the_count_is_the_lists_length_and_revision_for_an_admin_only",
        )],
    ),
    // The table's fixture attaches no discovery cache, so its admin answer
    // is 503; this test attaches one and pins the served 200.
    (
        "/ui/api/discovery",
        Method::GET,
        &[(
            DISCOVERY_WIRING,
            "the_production_router_reads_the_cache_from_meta_mcp",
        )],
    ),
    (
        "/ui/api/discovery/adopt",
        Method::POST,
        &[(
            ADOPT_ROUTE,
            "an_adopted_find_is_a_disabled_backend_with_its_secret_in_the_store",
        )],
    ),
    (
        "/ui/api/reload",
        Method::POST,
        &[(
            MUTATION,
            "test_reload_endpoint_returns_structured_outcome_for_profile_change",
        )],
    ),
    // The table sends no body, so its admin answer is 400; this test sends a
    // call and pins the served 200 with the tool's result and its receipt.
    (
        "/ui/api/tools/call",
        Method::POST,
        &[(
            UI_TOOL_CALL,
            "t1_a_declared_read_runs_and_returns_its_receipt",
        )],
    ),
    (
        "/ui/api/backends",
        Method::POST,
        &[(
            MUTATION,
            "test_add_backend_persists_and_duplicate_returns_409",
        )],
    ),
    (
        "/ui/api/backends/{name}",
        Method::PATCH,
        &[(MUTATION, "test_patch_backend_updates_description")],
    ),
    (
        "/ui/api/backends/{name}",
        Method::DELETE,
        &[(MUTATION, "test_add_remove_backend_lifecycle")],
    ),
    (
        "/ui/api/events/dead-letters",
        Method::GET,
        &[(EVENTS_ADMIN, "dead_letters_replay_through_admin_route_only")],
    ),
    (
        "/ui/api/events/dead-letters/replay",
        Method::POST,
        &[(
            EVENTS_ADMIN,
            "bulk_replay_replays_only_the_named_subscription",
        )],
    ),
    (
        "/ui/api/events/dead-letters/{id}/replay",
        Method::POST,
        &[(EVENTS_ADMIN, "dead_letters_replay_through_admin_route_only")],
    ),
    (
        "/ui/api/events/held",
        Method::GET,
        &[(
            EVENTS_RECONCILE,
            "a_held_subscription_is_listed_with_its_queued_record",
        )],
    ),
    // This fixture has no transparency log; the served answers are pinned
    // against real log files in the Activity unit tests.
    (
        "/ui/api/activity",
        Method::GET,
        &[(
            ACTIVITY_LIST,
            "l1_l2_admin_and_mapped_auditor_read_every_row",
        )],
    ),
    (
        "/ui/api/activity/export",
        Method::GET,
        &[(
            ACTIVITY_EXPORT,
            "e2_ndjson_without_a_key_is_409_and_csv_still_works",
        )],
    ),
    (
        "/ui/api/activity/{id}",
        Method::GET,
        &[(
            ACTIVITY_RECEIPT,
            "c3_links_mid_segment_and_across_a_seam_verify",
        )],
    ),
    (
        "/ui/api/events/leases",
        Method::GET,
        &[(EVENTS_ADMIN, "the_lease_listing_is_admin_only")],
    ),
    ("/ui/api/control-plane/grants", Method::POST, CP_WRITES),
    ("/ui/api/control-plane/policies", Method::POST, CP_WRITES),
    ("/ui/api/control-plane/decisions", Method::POST, CP_WRITES),
    // The admin's 200 with a counter store attached, and the 400
    // for an unsupported query, which this fixture's row also records.
    (
        "/ui/api/markers",
        Method::GET,
        &[(HISTORY_ROUTES, "t41_both_routes_are_admin_only")],
    ),
    (
        "/ui/api/metrics/series",
        Method::GET,
        &[
            (HISTORY_ROUTES, "t41_both_routes_are_admin_only"),
            (
                HISTORY_ROUTES,
                "t34_the_series_route_answers_points_and_the_previous_period",
            ),
            (
                HISTORY_PARAMS,
                "t38_a_bad_metric_or_window_names_the_allowed_values",
            ),
        ],
    ),
];

/// Whether `status` on `path` is a served admin answer: success, or `/sse`'s
/// 410, which is its deliberate pointer to `POST /mcp` (that route only).
fn is_served(path: &str, status: u16) -> bool {
    matches!(status, 200..=299) || (path == "/sse" && status == 410)
}

/// Every row whose admin cell is not served names where the served answer is
/// pinned, and nothing else does; every cited test exists. A name pins the
/// mention only: the design records what each cited test asserts, and a seat
/// confirmed it at source (MIK-8044.SURF.8 r3).
#[test]
fn every_unserved_admin_cell_names_the_test_that_serves_it() {
    // The admin's answer on the richest fixture the row has: the configured
    // column where there is one. The control plane's configured 409 is its
    // served refusal, pinned with its reason code by the cited test.
    let unserved: BTreeSet<(String, String)> = all_rows()
        .filter(|r| !is_served(r.path, r.configured.map_or(r.base[3], |c| c[2])))
        .map(|r| (r.path.to_owned(), r.method.to_string()))
        .collect();
    let cited: BTreeSet<(String, String)> = SERVED_BY
        .iter()
        .map(|(path, method, _)| ((*path).to_owned(), method.to_string()))
        .collect();
    assert_eq!(
        unserved, cited,
        "rows without a served citation, or citations without a row"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (path, method, tests) in SERVED_BY {
        assert!(!tests.is_empty(), "{method} {path} cites nothing");
        for (file, name) in *tests {
            let text = std::fs::read_to_string(root.join(file))
                .unwrap_or_else(|e| panic!("{method} {path}: cannot read {file}: {e}"));
            assert!(
                text.contains(&format!("fn {name}(")),
                "{method} {path}: {file} has no `fn {name}`"
            );
        }
    }
}

/// The R12 posture: auth on with the Auditor key, a config path and a reload
/// context, and `docs` both registered and written in the config file, so a
/// PATCH or DELETE that got through would change the file.
async fn writable() -> (
    Arc<AppState>,
    Arc<LiveConfig>,
    Gateway,
    std::path::PathBuf,
    TempDir,
) {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("gateway.yaml");
    let mut initial = Config::default();
    initial.backends.insert(
        "docs".to_string(),
        serde_json::from_value(json!({"http_url": "http://127.0.0.1:9/docs"}))
            .expect("docs backend"),
    );
    write_owner_only(&config_path, crate::yaml::to_string(&initial).unwrap()).unwrap();
    let (mut state, live, _store) =
        make_app_state_with_reload(initial, None, config_path.clone()).await;
    {
        let seat = Arc::get_mut(&mut state).expect("test AppState should be uniquely owned");
        seat.live_config = std::sync::Arc::new(mcp_gateway::gateway::test_helpers::live_config(
            (*seat.live_config.get()).clone(),
            Arc::new(ResolvedAuthConfig::from_config(
                &auth_on(),
                crate::record_key::RECORD_KEY,
            )),
        ));
    }
    register_http_backend(&state, "docs");
    let gw = Gateway {
        router: create_router(Arc::clone(&state)),
        caps: TempDir::new().expect("capability dir"),
        _store: TempDir::new().expect("store dir"),
    };
    (state, live, gw, config_path, tmp)
}

/// Stage an unapplied change on disk: a defined routing profile made the
/// default, and a new backend `staged`. A reload that ran would publish the
/// profile and register `staged`.
fn stage(config_path: &std::path::Path) {
    let mut staged = Config::load(Some(config_path)).expect("the fixture config loads");
    staged.routing_profiles.insert(
        "staged-profile".to_string(),
        mcp_gateway::routing_profile::RoutingProfileConfig {
            description: "staged".to_string(),
            ..mcp_gateway::routing_profile::RoutingProfileConfig::default()
        },
    );
    staged.default_routing_profile = "staged-profile".to_string();
    staged.backends.insert(
        "staged".to_string(),
        serde_json::from_value(json!({"http_url": "http://127.0.0.1:9/staged"}))
            .expect("staged backend"),
    );
    write_owner_only(config_path, crate::yaml::to_string(&staged).unwrap()).unwrap();
}

const WRITES: [(Method, &str, Payload); 4] = [
    (Method::POST, "/ui/api/reload", Payload::None),
    (Method::POST, "/ui/api/backends", Payload::Json(ADD_BACKEND)),
    (
        Method::PATCH,
        "/ui/api/backends/docs",
        Payload::Json(UPDATE_BACKEND),
    ),
    (Method::DELETE, "/ui/api/backends/docs", Payload::None),
];

/// MIK-8044.SURF.8 R12: with the state the admin is served from in place (a
/// config path and a reload context), a non-admin is still refused, and the
/// refusal changes nothing. The statuses are the INTERNAL contract above
/// (anonymous with auth on 401, Auditor 403).
#[tokio::test]
async fn a_non_admin_is_refused_with_the_served_state_present_and_changes_nothing() {
    let (state, live, gw, config_path, _tmp) = writable().await;
    let docs_before = state.backends.get("docs").expect("docs is registered");

    stage(&config_path);
    let on_disk = std::fs::read(&config_path).expect("read config");
    let profile_before = live.get().default_routing_profile.clone();

    for (method, uri, payload) in &WRITES {
        for (caller, want) in [(Caller::AnonOn, 401), (Caller::Auditor, 403)] {
            let (status, _, body) = send(&gw, request(method, uri, caller, *payload)).await;
            let text = String::from_utf8_lossy(&body);
            assert_eq!(
                status.as_u16(),
                want,
                "{method} {uri} as {caller:?}: {text}"
            );
            assert_eq!(
                std::fs::read(&config_path).expect("read config"),
                on_disk,
                "{method} {uri} as {caller:?} changed the config file"
            );
            assert_eq!(
                live.get().default_routing_profile,
                profile_before,
                "{method} {uri} as {caller:?} published a reload"
            );
            assert!(
                state.backends.get("staged").is_none() && state.backends.get("probe").is_none(),
                "{method} {uri} as {caller:?} registered a backend"
            );
            assert!(
                state
                    .backends
                    .get("docs")
                    .is_some_and(|now| Arc::ptr_eq(&now, &docs_before)),
                "{method} {uri} as {caller:?} removed or replaced `docs`"
            );
        }
    }
}

/// Positive control for R12: on the same posture an admin's PATCH and DELETE
/// of `docs` do change the config file, so the bytes R12 compares can move.
#[tokio::test]
async fn an_admin_write_on_the_r12_posture_changes_the_config_file() {
    let (state, _live, gw, config_path, _tmp) = writable().await;
    let before = std::fs::read(&config_path).expect("read config");
    let (status, _, body) = send(
        &gw,
        request(
            &Method::PATCH,
            "/ui/api/backends/docs",
            Caller::Admin,
            Payload::Json(UPDATE_BACKEND),
        ),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    let patched = std::fs::read(&config_path).expect("read config");
    assert_ne!(patched, before, "an admin PATCH left the file unchanged");
    let (status, _, body) = send(
        &gw,
        request(
            &Method::DELETE,
            "/ui/api/backends/docs",
            Caller::Admin,
            Payload::None,
        ),
    )
    .await;
    assert_eq!(status.as_u16(), 204, "{}", String::from_utf8_lossy(&body));
    let deleted = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        !deleted.contains("docs"),
        "an admin DELETE left docs: {deleted}"
    );
    assert!(
        state.backends.get("docs").is_none(),
        "an admin DELETE left docs registered"
    );
}

/// Positive control for R12's reload invariants: on the same posture, with
/// the same staged change, an admin's reload publishes the profile to the
/// returned `LiveConfig` and registers `staged`, so the live and registry
/// checks R12 makes can move.
#[tokio::test]
async fn an_admin_reload_on_the_r12_posture_publishes_the_staged_change() {
    let (state, live, gw, config_path, _tmp) = writable().await;
    stage(&config_path);
    let (status, _, body) = send(
        &gw,
        request(
            &Method::POST,
            "/ui/api/reload",
            Caller::Admin,
            Payload::None,
        ),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(live.get().default_routing_profile, "staged-profile");
    assert!(
        state.backends.get("staged").is_some(),
        "an admin reload did not register the staged backend"
    );
}
