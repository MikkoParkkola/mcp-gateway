// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a matrix cell must and must not notice in a body: a field added by a
//! later change, or a reworded message, moves no cell; a change to who sees what
//! or why does. Kept beside `ui_access_matrix_tests.rs` for the file-size ceiling.

use super::*;

/// One real answer through the matrix fixture: its status and body.
async fn answer(caller: Caller, req: (&str, &str, &str), store: bool) -> (StatusCode, Vec<u8>) {
    let fx = fixture(caller.gateway(), store).await;
    if store {
        seed_store(&fx.state);
    }
    let router = create_router(Arc::clone(&fx.state));
    let cookie = session(&fx.state);
    send(&router, request(caller, req, &fx, Some(&cookie))).await
}

/// `body` with one top-level field more, as a later change that adds a field
/// to this answer would send it.
fn with_added_field(body: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(body).expect("a JSON body");
    value
        .as_object_mut()
        .expect("a JSON object")
        .insert("added_by_a_later_change".to_string(), json!(1));
    serde_json::to_vec(&value).expect("serialises")
}

/// `body` with every `message` text reworded, at any depth.
fn reworded(body: &[u8]) -> Vec<u8> {
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    if key == "message" && child.is_string() {
                        *child = json!("reworded by a later change");
                    } else {
                        walk(child);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    let mut value: Value = serde_json::from_slice(body).expect("a JSON body");
    walk(&mut value);
    serde_json::to_vec(&value).expect("serialises")
}

/// The premise of each row: the answer is the one the row is about.
fn premise(req: (&str, &str, &str), want: StatusCode, got: StatusCode, body: &[u8]) {
    assert_eq!(
        got,
        want,
        "{req:?} answered {got}: {}",
        String::from_utf8_lossy(body)
    );
}

#[tokio::test]
async fn an_added_field_moves_no_receipt_cell() {
    let req = ("GET", routes::UI_ACTIVITY_RECEIPT, "other-receipt");
    let (status, body) = answer(Caller::AdminKey, req, false).await;
    premise(req, StatusCode::OK, status, &body);
    assert_eq!(
        cell(req.1, status, &body),
        cell(req.1, status, &with_added_field(&body))
    );
}

#[tokio::test]
async fn an_added_field_moves_no_control_plane_cell() {
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    let (status, body) = answer(Caller::AdminKey, req, true).await;
    premise(req, StatusCode::OK, status, &body);
    assert_eq!(
        cell(req.1, status, &body),
        cell(req.1, status, &with_added_field(&body))
    );
}

#[tokio::test]
async fn an_added_field_moves_no_refusal_cell() {
    let req = ("GET", routes::UI_ACTIVITY, "plain");
    let (status, body) = answer(Caller::StandardKey, req, false).await;
    premise(req, StatusCode::FORBIDDEN, status, &body);
    assert_eq!(
        cell(req.1, status, &body),
        cell(req.1, status, &with_added_field(&body))
    );
}

#[tokio::test]
async fn a_reworded_refusal_message_moves_no_cell() {
    let req = ("GET", routes::UI_ACTIVITY, "plain");
    let (status, body) = answer(Caller::NoKey, req, false).await;
    premise(req, StatusCode::UNAUTHORIZED, status, &body);
    let changed = reworded(&body);
    assert_ne!(
        body,
        changed,
        "the refusal carries no message text to reword: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(cell(req.1, status, &body), cell(req.1, status, &changed));
}

/// `body` with `plant` applied to its JSON; the row's premise is that the
/// plant changed something.
fn planted(body: &[u8], plant: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(body).expect("a JSON body");
    let before = value.clone();
    plant(&mut value);
    assert_ne!(before, value, "the plant changed nothing in {before}");
    serde_json::to_vec(&value).expect("serialises")
}

/// One planted change the cell must notice.
async fn moves(
    caller: Caller,
    req: (&str, &str, &str),
    store: bool,
    want: StatusCode,
    plant: impl FnOnce(&mut Value),
) {
    let (status, body) = answer(caller, req, store).await;
    premise(req, want, status, &body);
    let changed = planted(&body, plant);
    assert_ne!(
        cell(req.1, status, &body),
        cell(req.1, status, &changed),
        "{req:?} {caller:?}: the cell did not notice\nbefore: {}\nafter:  {}",
        String::from_utf8_lossy(&body),
        String::from_utf8_lossy(&changed)
    );
}

/// Replaces every string equal to `from` with `to`, at any depth.
fn swap_strings(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) if text.contains(from) => *text = text.replace(from, to),
        Value::Object(map) => map.values_mut().for_each(|v| swap_strings(v, from, to)),
        Value::Array(items) => items.iter_mut().for_each(|v| swap_strings(v, from, to)),
        _ => {}
    }
}

#[tokio::test]
async fn a_receipt_showing_another_callers_record_moves_its_cell() {
    let req = ("GET", routes::UI_ACTIVITY_RECEIPT, "other-receipt");
    moves(Caller::AdminKey, req, false, StatusCode::OK, |v| {
        swap_strings(v, OTHER_DEV, DEV);
    })
    .await;
}

#[tokio::test]
async fn a_snapshot_leaking_another_actors_event_moves_its_cell() {
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    moves(Caller::OidcDeveloper, req, true, StatusCode::OK, |v| {
        v["leaked"] = json!({ "event_id": SEEDED_EVENTS[1].0 });
    })
    .await;
}

#[tokio::test]
async fn an_action_allowed_flip_moves_the_snapshot_cell() {
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    moves(Caller::OidcDeveloper, req, true, StatusCode::OK, |v| {
        let first = v["authorizations"]
            .as_object_mut()
            .and_then(|actions| actions.values_mut().next())
            .expect("the snapshot lists its actions");
        let allowed = first["allowed"]
            .as_bool()
            .expect("an action says whether it is allowed");
        first["allowed"] = json!(!allowed);
    })
    .await;
}

#[tokio::test]
async fn status_reporting_admin_moves_its_cell() {
    let req = ("GET", routes::UI_STATUS, "plain");
    moves(Caller::StandardKey, req, false, StatusCode::OK, |v| {
        v["auth"]["admin"] = json!(true);
    })
    .await;
}

#[tokio::test]
async fn status_showing_the_full_view_moves_its_cell() {
    let req = ("GET", routes::UI_STATUS, "plain");
    moves(Caller::StandardKey, req, false, StatusCode::OK, |v| {
        v["servers"] = json!([]);
    })
    .await;
}

#[tokio::test]
async fn a_refusal_naming_another_reason_moves_its_cell() {
    let req = ("GET", routes::UI_ACTIVITY, "plain");
    moves(
        Caller::StandardKey,
        req,
        false,
        StatusCode::FORBIDDEN,
        |v| {
            v["error"] = json!("Authentication required");
        },
    )
    .await;
}

#[tokio::test]
async fn a_reason_code_change_with_the_same_text_moves_its_cell() {
    let req = ("POST", routes::UI_CONTROL_PLANE_GRANTS, "valid");
    moves(Caller::StandardKey, req, true, StatusCode::FORBIDDEN, |v| {
        v["reason_code"] = json!("CONTROL_RBAC_SOMETHING_ELSE");
    })
    .await;
}

#[tokio::test]
async fn a_duplicated_activity_row_moves_its_cell() {
    let req = ("GET", routes::UI_ACTIVITY, "plain");
    moves(Caller::OidcDeveloper, req, false, StatusCode::OK, |v| {
        let rows = v["rows"].as_array_mut().expect("the list has rows");
        let first = rows
            .iter()
            .find(|row| row["tool"].as_str().is_some_and(|t| t.starts_with("tool_")))
            .cloned()
            .expect("a seeded row");
        rows.push(first);
    })
    .await;
}
