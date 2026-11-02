// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A UI request is judged by the role mapping of the generation pinned on it
//! when it arrived (ADR-023), not by one a reload published afterwards.
//!
//! Each row drives the UI routes alone, with the generation and the caller
//! set on the request by hand, as the pin and authentication would, while the
//! live config holds a different mapping. The caller is an OIDC identity
//! without the admin flag, so only the mapping can admit it. The answer under
//! one generation pinned and the other live must equal the answer when the
//! pinned one is also live: forward and reverse, so a check that reads the
//! live config fails one row, and one that admits on either generation fails
//! the other. Answers compare as the access matrix records them.
//!
//! The control-plane export status has no row: its one check is
//! `ReadInventory`, which every role holds, so no two mappings answer it
//! differently. The family guard (`boundary_pins::pinned_role_mapping`)
//! covers its read instead.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use serde_json::Value;

use super::{DEV, Fixture, Gateway, ISSUER, cell, fixture, rule, seed_store, send, valid_body};
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::control_plane::ControlPlaneRole;
use crate::gateway::routes;
use crate::key_server::oidc::VerifiedIdentity;

/// The caller's group, mapped differently by each generation.
const GROUP: &str = "pinned-row";

/// The fixture's config with `GROUP` mapped to `role`, or to nothing.
fn mapping(fx: &Fixture, role: Option<ControlPlaneRole>) -> Config {
    let mut config = (*fx.state.live_config.get()).clone();
    config.control_plane.role_mapping.rules =
        role.map(|r| vec![rule(GROUP, r)]).unwrap_or_default();
    config
}

/// The caller: [`DEV`], whose own call the seeded log holds.
fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: DEV.to_string(),
        email: format!("{DEV}@example.test"),
        name: None,
        groups: vec![GROUP.to_string()],
        issuer: ISSUER.to_string(),
    }
}

/// `method path` with `pinned` on the request while `live` is published, as
/// the access matrix would record the answer.
async fn answer(
    fx: &Fixture,
    (method, path): (&str, &str),
    pinned: &Config,
    live: &Config,
) -> String {
    fx.state.live_config.set(live.clone());
    let uri = match path {
        p if p == routes::UI_ACTIVITY => format!("{p}?server=srv"),
        p if p == routes::UI_ACTIVITY_EXPORT => format!("{p}?format=csv&server=srv"),
        p => p.replace("{id}", &fx.other_receipt),
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .extension(LiveConfig::new(pinned.clone()).generation())
        .extension(crate::gateway::auth::AuthenticatedClient {
            authenticated: true,
            // No credential was presented, so no principal.
            principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
            ..crate::gateway::auth::anonymous_client()
        })
        .extension(identity());
    let body = match valid_body(path) {
        Some(body) if method == "POST" => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        _ => Body::empty(),
    };
    let router = crate::gateway::ui::api_router().with_state(Arc::clone(&fx.state));
    let (status, bytes) = send(&router, builder.body(body).expect("request builds")).await;
    if path == routes::UI_STATUS {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    cell(path, status, &bytes)
}

/// `method path` follows the pinned mapping in both directions; returns the
/// answers under `Admin` and under `Developer`.
async fn follows_the_pin(method: &str, path: &str) -> (String, String) {
    let fx = fixture(Gateway::On, true).await;
    seed_store(&fx.state);
    let admin = mapping(&fx, Some(ControlPlaneRole::Admin));
    let developer = mapping(&fx, Some(ControlPlaneRole::Developer));
    let under_admin = answer(&fx, (method, path), &admin, &admin).await;
    let under_developer = answer(&fx, (method, path), &developer, &developer).await;
    assert_ne!(
        under_admin, under_developer,
        "premise: the two mappings answer {method} {path} differently"
    );
    assert_eq!(
        answer(&fx, (method, path), &admin, &developer).await,
        under_admin,
        "{method} {path}: pinned Admin, live Developer, answered by the live mapping"
    );
    assert_eq!(
        answer(&fx, (method, path), &developer, &admin).await,
        under_developer,
        "{method} {path}: pinned Developer, live Admin, answered by the live mapping"
    );
    (under_admin, under_developer)
}

#[tokio::test]
async fn the_activity_list_follows_the_pinned_mapping() {
    let answers = follows_the_pin("GET", routes::UI_ACTIVITY).await;
    // Every seeded call for Admin; the caller's own alone for Developer.
    assert_eq!(
        answers,
        ("200:tool_0,tool_1,tool_2".into(), "200:tool_0".into())
    );
}

#[tokio::test]
async fn the_activity_export_follows_the_pinned_mapping() {
    let answers = follows_the_pin("GET", routes::UI_ACTIVITY_EXPORT).await;
    assert_eq!(
        answers,
        ("200:tool_0,tool_1,tool_2".into(), "200:tool_0".into())
    );
}

#[tokio::test]
async fn an_activity_receipt_follows_the_pinned_mapping() {
    // Another principal's receipt: Admin reads it, Developer finds nothing.
    let (admin, developer) = follows_the_pin("GET", routes::UI_ACTIVITY_RECEIPT).await;
    assert!(admin.starts_with("200:"), "{admin}");
    assert_eq!(developer, "404");
}

/// A write: Admin passes the role check to the store's refusal, Developer is
/// refused by the role check.
async fn a_write_follows_the_pinned_mapping(path: &str) {
    let (admin, developer) = follows_the_pin("POST", path).await;
    assert_eq!(admin, "409");
    assert!(developer.starts_with("403:"), "{developer}");
}

#[tokio::test]
async fn the_grant_write_follows_the_pinned_mapping() {
    a_write_follows_the_pinned_mapping(routes::UI_CONTROL_PLANE_GRANTS).await;
}

#[tokio::test]
async fn the_policy_write_follows_the_pinned_mapping() {
    a_write_follows_the_pinned_mapping(routes::UI_CONTROL_PLANE_POLICIES).await;
}

#[tokio::test]
async fn the_decision_write_follows_the_pinned_mapping() {
    a_write_follows_the_pinned_mapping(routes::UI_CONTROL_PLANE_DECISIONS).await;
}

/// The control: the snapshot already reads the pinned generation. Admin and
/// Developer differ in principal scope, so a live read would show.
#[tokio::test]
async fn the_snapshot_follows_the_pinned_mapping() {
    follows_the_pin("GET", routes::UI_CONTROL_PLANE).await;
}

/// Whether the status report opens `tab` of `page`.
fn tab_open(report: &str, page: &str, tab: &str) -> bool {
    let body: Value = serde_json::from_str(report).expect("status is JSON");
    body["access"]["pages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["id"] == page)
        .flat_map(|p| p["tabs"].as_array().into_iter().flatten())
        .find(|t| t["id"] == tab)
        .and_then(|t| t["open"].as_bool())
        .unwrap_or_else(|| panic!("no {page}/{tab} tab in the report: {report}"))
}

/// The status report decides the action tabs by the pinned mapping: open for
/// a pinned Admin while Developer is live, closed the other way round.
#[tokio::test]
async fn the_report_decides_the_action_tabs_by_the_pinned_mapping() {
    let fx = fixture(Gateway::On, true).await;
    let admin = mapping(&fx, Some(ControlPlaneRole::Admin));
    let developer = mapping(&fx, Some(ControlPlaneRole::Developer));
    let forward = answer(&fx, ("GET", routes::UI_STATUS), &admin, &developer).await;
    let reverse = answer(&fx, ("GET", routes::UI_STATUS), &developer, &admin).await;
    for page in ["access", "policies"] {
        assert!(tab_open(&forward, page, "actions"), "pinned Admin: {page}");
        assert!(
            !tab_open(&reverse, page, "actions"),
            "pinned Developer: {page}"
        );
    }
}

/// The status report decides Activity by the pinned mapping. Admin and
/// Developer both open it, so the pair is Admin against an unmapped caller.
#[tokio::test]
async fn the_report_decides_activity_by_the_pinned_mapping() {
    let fx = fixture(Gateway::On, true).await;
    let admin = mapping(&fx, Some(ControlPlaneRole::Admin));
    let unmapped = mapping(&fx, None);
    let forward = answer(&fx, ("GET", routes::UI_STATUS), &admin, &unmapped).await;
    let reverse = answer(&fx, ("GET", routes::UI_STATUS), &unmapped, &admin).await;
    assert!(tab_open(&forward, "activity", "status"), "pinned Admin");
    assert!(!tab_open(&reverse, "activity", "status"), "pinned unmapped");
}
