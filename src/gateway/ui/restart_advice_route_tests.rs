// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart keys on the two UI answers, rows R1-R4: a pending restart brings
//! `restart_advice` (plus `start_command` on Unix), a refused one brings
//! `start_refusal` alone, and an answer with nothing pending carries none.

use axum::extract::State;
use axum::http::Method;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::test_support::{BASE, Route, client, decode, set};
use crate::gateway::routes;
use crate::gateway::ui::guard::Guard;
use crate::gateway::ui::restart_confirm::Reason;

const RESTART_KEYS: [&str; 3] = ["restart_advice", "start_command", "start_refusal"];

/// BASE declaring two replicas: the modern protocol's per-process task store
/// makes a start of it refused, so a restart must not be advised.
fn two_replicas() -> String {
    format!("{BASE}server:\n  replicas: 2\n")
}

/// Save one field through the settings route and hand back its 200 body.
async fn save_field(route: &Route, id: &str, value: Value) -> Value {
    let (code, answer) = route.save(json!([set(id, &value)])).await;
    assert!(code.is_success(), "saving {id}: {code} {answer}");
    answer
}

/// Run the UI reload handler as an admin and hand back its 200 body.
async fn reload_body(route: &Route) -> Value {
    let admin = Guard::for_route(routes::UI_RELOAD, &Method::POST, Some(client(true)));
    let (code, answer) = decode(
        crate::gateway::ui::reload(State(route.state.clone()), admin)
            .await
            .into_response(),
    )
    .await;
    assert!(code.is_success(), "reload: {code} {answer}");
    answer
}

/// Which of the three restart keys `answer` carries, in key order.
fn carried(answer: &Value) -> Vec<&'static str> {
    RESTART_KEYS
        .into_iter()
        .filter(|k| answer.get(*k).is_some())
        .collect()
}

/// An advised answer: the platform's guidance, no refusal, and on Unix a
/// quoted start command ending in this route's absolute config path.
fn expect_advice(answer: &Value, route: &Route) {
    assert_eq!(
        answer["restart_advice"],
        json!(Reason::PLATFORM.recovery()),
        "{answer}"
    );
    assert!(answer.get("start_refusal").is_none(), "{answer}");
    if cfg!(windows) {
        assert!(answer.get("start_command").is_none(), "{answer}");
        return;
    }
    let config = std::path::absolute(route.path()).expect("an absolute config path");
    let tail = format!(" serve --config '{}'", config.display());
    match answer["start_command"].as_str() {
        Some(cmd) => assert!(cmd.starts_with('\'') && cmd.ends_with(&tail), "{cmd}"),
        None => panic!("no start command: {answer}"),
    }
    // The route serves the entry point's own command, not one it builds.
    let own =
        crate::gateway::ui::restart_confirm::restart_advice(true, None, Some(config.as_path()))
            .expect("a pending restart has advice");
    assert_eq!(answer["start_command"], own["start_command"], "{answer}");
}

#[tokio::test]
async fn r2_save_leaving_a_restart_pending_brings_the_advice() {
    let route = Route::new(BASE).await;
    let answer = save_field(&route, "auth.enabled", json!(true)).await;
    assert_eq!(
        answer["reload"]["restart_required"],
        json!(true),
        "{answer}"
    );
    expect_advice(&answer, &route);
}

#[tokio::test]
async fn r2_save_with_nothing_pending_brings_no_restart_key() {
    let route = Route::new(BASE).await;
    let answer = save_field(&route, "environment", json!("qa")).await;
    assert_eq!(answer["restart_required"], json!([]), "{answer}");
    assert_eq!(
        answer["reload"]["restart_required"],
        json!(false),
        "{answer}"
    );
    assert_eq!(carried(&answer), Vec::<&str>::new(), "{answer}");
}

#[tokio::test]
async fn r4_save_whose_restart_would_be_refused_brings_the_refusal_alone() {
    let route = Route::new(&two_replicas()).await;
    let answer = save_field(&route, "auth.enabled", json!(true)).await;
    let changes = answer["reload"]["changes"].as_str().unwrap_or_default();
    assert!(changes.contains("a restart would not start"), "{answer}");
    assert_eq!(carried(&answer), ["start_refusal"], "{answer}");
    let sentence = answer["start_refusal"].as_str().unwrap_or_default();
    assert!(sentence.contains("replicas"), "{sentence}");
}

#[tokio::test]
async fn r1_reload_leaving_a_restart_pending_brings_the_advice() {
    let route = Route::new(BASE).await;
    route.write(&BASE.replace("enabled: false", "enabled: true"));
    let answer = reload_body(&route).await;
    assert_eq!(answer["restart_required"], json!(true), "{answer}");
    expect_advice(&answer, &route);
}

#[tokio::test]
async fn r1_reload_with_nothing_pending_brings_no_restart_key() {
    let route = Route::new(BASE).await;
    route.write(&BASE.replace("\"dev\"", "\"qa\""));
    let answer = reload_body(&route).await;
    assert_eq!(answer["restart_required"], json!(false), "{answer}");
    assert_eq!(carried(&answer), Vec::<&str>::new(), "{answer}");
}

#[tokio::test]
async fn r3_reload_whose_restart_would_be_refused_brings_the_refusal_alone() {
    let base = two_replicas();
    let route = Route::new(&base).await;
    route.write(&base.replace("enabled: false", "enabled: true"));
    let answer = reload_body(&route).await;
    let changes = answer["changes"].as_str().unwrap_or_default();
    assert!(changes.contains("a restart would not start"), "{answer}");
    assert_eq!(carried(&answer), ["start_refusal"], "{answer}");
}

/// D1: a save is pending when its reload still needs a restart, not only
/// when this save listed a restart field: saving a live field while an
/// outside restart-only edit waits still brings the advice.
#[tokio::test]
async fn r2_save_of_a_live_field_with_an_earlier_restart_pending_brings_the_advice() {
    let route = Route::new(BASE).await;
    route.write(&BASE.replace("enabled: false", "enabled: true"));
    let answer = save_field(&route, "environment", json!("qa")).await;
    assert_eq!(answer["restart_required"], json!([]), "{answer}");
    assert_eq!(
        answer["reload"]["restart_required"],
        json!(true),
        "{answer}"
    );
    expect_advice(&answer, &route);
}
