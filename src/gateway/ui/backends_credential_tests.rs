// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential in a backend's saved command or URL: refused by field on add,
//! update and preview; ordinary queries and templates pass. Uses the parent's
//! panel fixture.

use serde_json::json;

use super::*;

/// U1, U2, U5 (D-CLI r2): a credential in the saved URL or command is
/// refused by field before anything is stored or written, on add and on
/// update; the value is never echoed.
#[tokio::test]
async fn u1_a_credential_in_a_url_or_command_is_refused_by_field() {
    let panel = Panel::new().await;
    let before = panel.text();
    let userinfo = ["http://svc:", "pw-0123456789", "@127.0.0.1:9/mcp"].concat();
    for (body, field, code) in [
        (
            json!({"name": "b", "url": userinfo}),
            "url",
            "secret_in_url",
        ),
        (
            json!({"name": "b", "url": "http://127.0.0.1:9/mcp?api_key=k-0123456789"}),
            "url",
            "secret_in_url",
        ),
        (
            json!({"name": "b", "command": "npx tool --api-key=k-0123456789"}),
            "command",
            "secret_in_command",
        ),
    ] {
        let (status, answer) = panel.add_into(body, None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert_eq!(
            answer["refusals"],
            json!([{"reason": code, "field": field}]),
            "{answer}"
        );
        no_value(&answer, "k-0123456789");
        no_value(&answer, "pw-0123456789");
    }
    let (status, answer) = panel
        .update_seamed(
            "a",
            json!({"command": "npx tool --token k-0123456789"}),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(
        answer["refusals"],
        json!([{"reason": "secret_in_command", "field": "command"}]),
        "{answer}"
    );
    assert_eq!(panel.text(), before, "a refused save wrote");
    assert!(panel.entries().is_empty(), "a refused save stored");
}

/// U3 (D-CLI r2): an ordinary query and a template in a command are saved
/// as given.
#[tokio::test]
async fn u3_an_ordinary_query_and_a_template_pass() {
    let panel = Panel::new().await;
    let (status, answer) = panel
        .add_into(
            json!({"name": "q", "url": "http://127.0.0.1:9/mcp?transport=sse"}),
            None,
        )
        .await;
    assert!(status.is_success(), "{answer}");
    let (status, answer) = panel
        .add_into(
            json!({"name": "t", "command": "npx tool --token ${MY_TOKEN}"}),
            None,
        )
        .await;
    assert!(status.is_success(), "{answer}");
    let text = panel.text();
    assert!(
        text.contains("transport=sse") && text.contains("${MY_TOKEN}"),
        "{text}"
    );
}

/// U4 (D-CLI r2): the preview refuses a credential in the URL with the add's
/// answer, by field (it used to decline only, and the add then wrote it).
#[tokio::test]
async fn u4_the_preview_refuses_a_credential_in_the_url_like_the_add() {
    let panel = Panel::new().await;
    let body = json!({"name": "b", "url": "http://127.0.0.1:9/mcp?api_key=k-0123456789"});
    let request = serde_json::from_value(body.clone()).expect("preview body");
    let guard = Panel::guard(routes::UI_PREVIEWS, &axum::http::Method::POST);
    let (status, answer) = read(
        crate::gateway::ui::preview::preview_backend(
            State(Arc::clone(&panel.state)),
            axum::Extension(panel.state.live_config.generation()),
            guard,
            Json(request),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(
        answer["refusals"],
        json!([{"reason": "secret_in_url", "field": "url"}]),
        "{answer}"
    );
    let (_, added) = panel.add(body).await;
    assert_eq!(
        answer, added,
        "the preview and the add answered differently"
    );
}
