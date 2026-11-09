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
