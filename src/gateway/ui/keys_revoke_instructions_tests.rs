// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a refused revocation tells the operator: keyedit's cause, its reason
//! and the config file's path, plus the expiry-first instructions only when
//! keyedit wrote them. Every row checks the file is untouched, that no
//! secret or digest reaches the answer, and that the answer is not cached.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, header};

use super::super::keys_create_fixture_tests::{ROOT, item, root_item, spec, yaml_of};
use super::keys_revoke_target_tests::{tag, target_setup};
use super::*;
use crate::config::ApiKeyConfig;
use crate::gateway::auth::SESSION_COOKIE;

const TARGET: &str = "target-secret";

/// The target's digest line, as every shaped entry below spells it.
fn digest_line() -> String {
    format!("      key_sha256: \"{}\"\n", spec(TARGET))
}

/// `target_setup`'s running tables, with the file swapped for `text`.
fn on_file(text: String) -> Setup {
    let mut setup = target_setup();
    setup.text = text;
    setup
}

/// Revoke `target` and return the 409 answer after the shared checks.
fn refused_answer(setup: Setup) -> (Fixture, serde_json::Value) {
    let fx = Fixture::new(setup);
    let body = json!({"revision": revision(&fx), "expected_key_tag": tag(TARGET)});
    let sent = delete(&fx, "target", Call::new(&body), None);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert!(
        !sent.body.contains(TARGET),
        "a secret leaked: {}",
        sent.body
    );
    assert!(
        !sent.body.contains(&spec(TARGET)),
        "a digest leaked: {}",
        sent.body
    );
    // The body names the config file: no cache may keep it.
    assert_eq!(sent.cache_control.as_deref(), Some("no-store"));
    let answer = sent.json();
    assert_eq!(answer["error"], "not_written", "{answer}");
    assert_eq!(answer["revoked"], false, "{answer}");
    let path = fx.path().display().to_string();
    assert_eq!(answer["path"], path.as_str(), "{answer}");
    (fx, answer)
}

/// keyedit's S9 text: carried as the reason and, word for word, as the
/// instructions.
fn instructed(answer: &serde_json::Value, code: &str) -> String {
    assert_eq!(answer["code"], code, "{answer}");
    let reason = answer["reason"].as_str().expect("a reason").to_owned();
    assert!(reason.starts_with("to revoke key `target`"), "{answer}");
    assert_eq!(answer["instructions"], answer["reason"], "{answer}");
    reason
}

#[test]
fn ri1_an_anchor_on_the_entry_gives_cause_path_and_instructions() {
    let entry = format!("    - &picked\n      name: target\n{}", digest_line());
    let (_, answer) = refused_answer(on_file(yaml_of(&[root_item(), entry])));
    instructed(&answer, "anchor");
}

#[test]
fn ri2_an_anchor_inside_the_entry_used_by_another_gives_instructions() {
    let target = format!(
        "    - name: target\n{}      backends: &every [\"*\"]\n",
        digest_line()
    );
    let root = format!(
        "    - name: root\n      admin: true\n      key_sha256: \"{}\"\n      backends: *every\n",
        spec(ROOT)
    );
    let (_, answer) = refused_answer(on_file(yaml_of(&[target, root])));
    instructed(&answer, "anchor");
}

#[test]
fn ri2b_a_shared_expiry_keeps_keyedits_unchecked_warning() {
    let target = format!(
        "    - name: target\n{}      expires_at: &until \"2099-01-01T00:00:00Z\"\n",
        digest_line()
    );
    let root = format!(
        "    - name: root\n      admin: true\n      key_sha256: \"{}\"\n      expires_at: *until\n",
        spec(ROOT)
    );
    let (_, answer) = refused_answer(on_file(yaml_of(&[target, root])));
    let reason = instructed(&answer, "anchor");
    assert!(
        reason.contains("no hand edit of its `expires_at` could be checked here"),
        "{answer}"
    );
}

#[test]
fn ri3_an_anchored_list_gives_expiry_only() {
    let entry = format!("    - name: target\n{}", digest_line());
    let anchored = yaml_of(&[root_item(), entry]).replace("  api_keys:\n", "  api_keys: &all\n");
    // An alias elsewhere names the list, so no hand deletion can be checked.
    let text = format!("{anchored}x-mirror: *all\n");
    let (_, answer) = refused_answer(on_file(text));
    let reason = instructed(&answer, "anchor");
    assert!(
        !reason.contains("; else "),
        "a deletion was offered: {answer}"
    );
}

#[test]
fn ri4_a_flow_list_gives_the_on_line_edit() {
    let text = format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  api_keys: [{{name: root, admin: true, key_sha256: \"{}\"}}, {{name: target, key_sha256: \"{}\"}}]\n",
        spec(ROOT),
        spec(TARGET)
    );
    let (_, answer) = refused_answer(on_file(text));
    let reason = instructed(&answer, "flow");
    assert!(reason.contains("on line"), "{answer}");
}

#[test]
fn ri5_a_flow_entry_in_a_block_list_gives_a_line_deletion() {
    let entry = format!("    - {{name: target, key_sha256: \"{}\"}}\n", spec(TARGET));
    let (_, answer) = refused_answer(on_file(yaml_of(&[root_item(), entry])));
    let reason = instructed(&answer, "flow");
    assert!(reason.contains("delete lines"), "{answer}");
}

#[test]
fn ri6_a_bare_carriage_return_gives_cause_and_path_but_no_instructions() {
    // The file must still load (the GET gives the revision the DELETE sends), so the
    // refusal comes from keyedit alone: a lone CR between two comment lines is a
    // comment to the loader however it reads the CR, and keyedit refuses it as "other".
    // (A second document refused earlier: the GET carried no revision.)
    let entry = format!("    - name: target\n{}", digest_line());
    let text = format!(
        "# kept by hand\r# for the revoke row\n{}",
        yaml_of(&[root_item(), entry])
    );
    let (_, answer) = refused_answer(on_file(text));
    assert_eq!(answer["code"], "other", "{answer}");
    let reason = answer["reason"].as_str().expect("a reason");
    assert!(!reason.starts_with("to revoke key"), "{answer}");
    // The refusal is the one this file was built for, not another "other".
    assert!(reason.contains("bare carriage return"), "{answer}");
    assert!(answer.get("instructions").is_none(), "{answer}");
}

/// A Refused answer that is not keyedit's: removing one of two keys from a
/// single-user gateway would turn it multi-user, so the route refuses
/// before keyedit runs. That answer must not grow keyedit's fields.
#[test]
fn ri7_a_refusal_that_is_not_keyedits_keeps_its_old_answer() {
    let entry = format!("    - name: target\n{}", digest_line());
    let mut setup = on_file(format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  single_user: true\n  enabled: true\n  api_keys:\n{}{entry}",
        root_item()
    ));
    setup.running.single_user = true;
    let (_, answer) = {
        let fx = Fixture::new(setup);
        let body = json!({"revision": revision(&fx), "expected_key_tag": tag(TARGET)});
        let sent = delete(&fx, "target", Call::new(&body), None);
        assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
        let answer = sent.json();
        (fx, answer)
    };
    assert_eq!(
        answer,
        json!({"error": "restart_required", "revoked": false})
    );
}

/// The secret of the key that mints S1's dashboard session.
const MINTER: &str = "s1-minting-secret";

/// A request from this machine with an optional bearer and session cookie.
fn local(method: &str, uri: &str, bearer: Option<&str>, cookie: Option<&str>) -> Request<Body> {
    local_with(method, uri, bearer, cookie, String::new())
}

fn local_with(
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: String,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_344))));
    if let Some(secret) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {secret}"));
    }
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    builder.body(Body::from(body)).expect("request builds")
}

/// `request` through the whole router, so the real auth middleware judges it.
fn routed(fx: &Fixture, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    fx.rt.block_on(async {
        let response = crate::gateway::router::create_router(fx.state.clone())
            .oneshot(request)
            .await
            .expect("the router is infallible");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    })
}

/// Whether `/ui/api/status` answers with the admin view for this caller.
fn admin_view(fx: &Fixture, bearer: Option<&str>, cookie: Option<&str>) -> bool {
    let (status, _, body) = routed(fx, local("GET", "/ui/api/status", bearer, cookie));
    status == StatusCode::OK
        && serde_json::from_str::<serde_json::Value>(&body)
            .is_ok_and(|view| view.get("tool_count").is_some())
}

/// S1 (pinning, no fix): admin key `k` mints a dashboard session; another
/// admin revokes `k` through this route; the session's next request is
/// refused, and the revoker's still succeeds. The revoker is not `k`, so
/// self-revoke stays out of this row.
#[test]
fn s1_a_session_ends_when_another_admin_revokes_its_key() {
    let mut setup = Setup {
        text: yaml_of(&[root_item(), item("k", MINTER, "      admin: true\n")]),
        ..Setup::default()
    };
    setup.running.api_keys.push(ApiKeyConfig {
        name: "k".into(),
        key_sha256: Some(spec(MINTER)),
        backends: vec!["*".into()],
        admin: true,
        ..Default::default()
    });
    let fx = Fixture::new(setup);
    let (status, _, minted) = routed(
        &fx,
        local("POST", "/ui/api/dashboard-link", Some(MINTER), None),
    );
    assert_eq!(status, StatusCode::OK, "{minted}");
    let minted: serde_json::Value = serde_json::from_str(&minted).expect("JSON");
    let link = minted["link"]
        .as_str()
        .and_then(|link| link.split_once("/dashboard?bootstrap="))
        .map(|(_, value)| value.to_owned())
        .expect("a link");
    let (status, headers, body) = routed(
        &fx,
        local("GET", &format!("/dashboard?bootstrap={link}"), None, None),
    );
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let session = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            cookie
                .split(';')
                .next()?
                .strip_prefix(&format!("{SESSION_COOKIE}="))
                .map(str::to_owned)
        })
        .expect("a session cookie");
    assert!(
        admin_view(&fx, None, Some(&session)),
        "the session works before the revoke"
    );

    let body = json!({"revision": revision(&fx), "expected_key_tag": tag(MINTER)});
    let (status, _, answer) = routed(
        &fx,
        local_with(
            "DELETE",
            "/ui/api/keys/k",
            Some(ROOT),
            None,
            body.to_string(),
        ),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    let answer: serde_json::Value = serde_json::from_str(&answer).expect("JSON");
    assert_eq!(answer["revoked"], true, "{answer}");

    let (status, _, body) = routed(&fx, local("GET", "/ui/api/status", None, Some(&session)));
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the revoked key's session lived on: {body}"
    );
    assert!(
        admin_view(&fx, Some(ROOT), None),
        "the revoker was refused afterwards"
    );
}
