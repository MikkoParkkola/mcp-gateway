// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The status report against the guards: for every caller kind, each page
//! and tab `GET /ui/api/status` reports open or closed is what the pinned
//! matrix says that caller gets on the routes behind it. The report and the
//! guards read one table; this ties both to the independent oracle.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::Value;

use super::{
    ADMIN_KEY, CALLERS, Caller, DEV, Gateway, ISSUER, OTHER_DEV, STANDARD_KEY, STORE_WRITES,
    expected, fixture, request, send, session, valid_body,
};
use crate::gateway::router::create_router;
use crate::gateway::routes;
use crate::gateway::ui::plain_rows;

/// The shape whose cell shows whether `caller` passes `path`'s guard: a body
/// that reaches it, with a store where the role check sits behind one.
fn deciding_shape(path: &str, method: &str) -> &'static str {
    match method {
        "POST" if STORE_WRITES.contains(&path) => "valid+store",
        "POST" if valid_body(path).is_some() => "valid",
        "POST" | "PUT" | "PATCH" => "json",
        _ => "plain",
    }
}

/// Whether the matrix records `caller` passing the guard of `path` `method`.
fn passes(matrix: &BTreeMap<String, String>, path: &str, method: &str, caller: Caller) -> bool {
    let shape = deciding_shape(path, method);
    let cell = matrix
        .get(&format!("{path}\t{method}\t{shape}\t{caller:?}"))
        .unwrap_or_else(|| panic!("no matrix cell for {path} {method} {shape} {caller:?}"));
    !(cell.starts_with("401") || cell.starts_with("403"))
}

/// A tab's guard outcomes: its load rows', and all its rows'.
type LoadsAndAll = (Vec<bool>, Vec<bool>);

/// The tabs the report should show for `caller`, per page id, from the rows
/// and the matrix alone.
fn expected_tabs(
    matrix: &BTreeMap<String, String>,
    caller: Caller,
) -> BTreeMap<&'static str, BTreeMap<&'static str, bool>> {
    let rows = plain_rows();
    let mut tabs: BTreeMap<(&str, &str), LoadsAndAll> = BTreeMap::new();
    // A route the matrix cannot probe has no cells to check against.
    for (path, method, backs, load) in rows.iter().filter(|r| !super::STREAMED.contains(&r.0)) {
        let pass = passes(matrix, path, method, caller);
        for &(page, tab) in backs {
            let (loads, all) = tabs.entry((page, tab)).or_default();
            if *load {
                loads.push(pass);
            }
            all.push(pass);
        }
    }
    let mut pages: BTreeMap<&str, BTreeMap<&str, bool>> = BTreeMap::new();
    for ((page, tab), (loads, all)) in tabs {
        let open = if loads.is_empty() {
            all.iter().any(|&p| p)
        } else {
            loads.iter().all(|&p| p)
        };
        pages.entry(page).or_default().insert(tab, open);
    }
    pages
}

const REASONS: &[&str] = &[
    "needs an admin key",
    "needs an admin key or a mapped role",
    "needs a signed-in key",
    "authentication is off; these pages need an admin key",
    "not in this build",
];

/// Every caller kind: the report shows exactly the tabs the guards let it
/// open, a hidden page names one fixed reason, and the report names no key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_report_agrees_with_the_guards_for_every_caller() {
    let matrix = expected();
    for gateway in [Gateway::On, Gateway::OnPublicStatus, Gateway::Off] {
        let fx = fixture(gateway, false).await;
        let router = create_router(Arc::clone(&fx.state));
        let cookie = session(&fx.state);
        for &caller in CALLERS.iter().filter(|c| c.gateway() == gateway) {
            let req = (axum::http::Method::GET.as_str(), routes::UI_STATUS, "plain");
            let (status, body) = send(&router, request(caller, req, &fx, Some(&cookie))).await;
            let answer: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            match caller {
                // No credential with auth on: refused, or on a public status
                // path served without any access report.
                Caller::NoKey => {
                    assert_eq!(status, StatusCode::UNAUTHORIZED);
                    continue;
                }
                Caller::NoKeyPublicStatus => {
                    assert_eq!(status, StatusCode::OK);
                    assert!(answer.get("access").is_none(), "{answer}");
                    continue;
                }
                _ => assert_eq!(status, StatusCode::OK, "{caller:?}"),
            }
            let text = answer["access"].to_string();
            for secret in [ADMIN_KEY, STANDARD_KEY, ISSUER, DEV, OTHER_DEV] {
                assert!(
                    !text.contains(secret),
                    "{caller:?}: the report names {secret}"
                );
            }
            let want = expected_tabs(&matrix, caller);
            let pages = answer["access"]["pages"]
                .as_array()
                .unwrap_or_else(|| panic!("{caller:?}: no access report: {answer}"));
            for page in pages {
                let id = page["id"].as_str().expect("a page id");
                let got: BTreeMap<&str, bool> = page["tabs"]
                    .as_array()
                    .expect("tabs")
                    .iter()
                    .map(|t| (t["id"].as_str().expect("a tab id"), t["open"] == true))
                    .collect();
                let none = BTreeMap::new();
                let want_tabs = want.get(id).unwrap_or(&none);
                assert_eq!(&got, want_tabs, "{caller:?}: page {id}");
                let open = want_tabs.values().any(|&o| o);
                assert_eq!(page["open"] == true, open, "{caller:?}: page {id}");
                if open {
                    assert!(page.get("reason").is_none(), "{caller:?}: {id}");
                } else {
                    let reason = page["reason"].as_str().unwrap_or_default();
                    assert!(REASONS.contains(&reason), "{caller:?}: {id}: {reason:?}");
                    if gateway == Gateway::Off && !want_tabs.is_empty() {
                        assert_eq!(reason, REASONS[3], "{caller:?}: {id}");
                    }
                }
            }
        }
    }
}

/// An admin key sees every page that has a tab in this build, and every tab.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_key_reports_everything_open() {
    let fx = fixture(Gateway::On, false).await;
    let router = create_router(Arc::clone(&fx.state));
    let req = (axum::http::Method::GET.as_str(), routes::UI_STATUS, "plain");
    let (_, body) = send(&router, request(Caller::AdminKey, req, &fx, None)).await;
    let answer: Value = serde_json::from_slice(&body).expect("JSON");
    for page in answer["access"]["pages"].as_array().expect("pages") {
        let tabs = page["tabs"].as_array().expect("tabs");
        if tabs.is_empty() {
            assert_eq!(page["reason"], "not in this build", "{page}");
            continue;
        }
        assert_eq!(page["open"], true, "{page}");
        assert!(tabs.iter().all(|t| t["open"] == true), "{page}");
    }
}
