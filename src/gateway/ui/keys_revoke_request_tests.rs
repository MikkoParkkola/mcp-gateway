// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2 request rows through the real UI router; DELETE is intentionally red.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::keys_create_fixture_tests::{Call, Fixture, Sent, Setup, admin_client};
use crate::gateway::auth::anonymous_client;
use crate::security::audit::CredentialKind;

// Reuse the create fixture and request/response types without its POST-only
// transport. Check bytes before status so a red response cannot hide a write.
fn delete(fx: &Fixture, name: &str, call: Call, if_match: Option<&str>) -> Sent {
    let before = fx.bytes();
    let sent = send_delete(fx, name, call, if_match);
    assert_eq!(fx.bytes(), before, "DELETE changed gateway.yaml");
    sent
}

fn send_delete(fx: &Fixture, name: &str, call: Call, if_match: Option<&str>) -> Sent {
    let mut request = Request::builder()
        .method("DELETE")
        .uri(format!("/ui/api/keys/{name}"))
        .header("content-type", "application/json")
        .extension(fx.live.generation())
        .extension(call.client);
    if let Some(revision) = if_match {
        request = request.header("if-match", revision);
    }
    fx.rt.block_on(async {
        let response = super::admin_audit::audited_api_router(&fx.state)
            .with_state(fx.state.clone())
            .oneshot(request.body(Body::from(call.body)).expect("request"))
            .await
            .expect("infallible");
        let status = response.status();
        let cache_control = response
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        Sent {
            status,
            body: String::from_utf8(bytes.to_vec()).expect("UTF-8"),
            cache_control,
            headers: Vec::new(),
            logs: String::new(),
        }
    })
}

fn revision(fx: &Fixture) -> String {
    fx.get()["revision"].as_str().expect("A12 revision").into()
}

#[test]
fn revoke_needs_gateway_admin_before_any_read() {
    let fx = Fixture::new(Setup::default());
    let mut standard = admin_client();
    standard.admin = false;
    let mut scoped = admin_client();
    scoped.backends = vec!["limited".into()];
    for client in [anonymous_client(), standard, scoped] {
        let mut call = Call::new(&json!({"revision": revision(&fx)}));
        call.client = client;
        let sent = delete(&fx, "root", call, None);
        // GET keys declares Admin(Forbidden), including no authenticated caller.
        assert_eq!(sent.status, StatusCode::FORBIDDEN, "{}", sent.body);
    }
}

#[test]
fn revoke_admits_static_bearer_and_an_unbound_admin_session() {
    for kind in [
        CredentialKind::StaticBearer,
        CredentialKind::DashboardSession,
    ] {
        let fx = Fixture::new(Setup::default());
        let mut call = Call::new(&json!({"revision": revision(&fx)}));
        call.client.credential_kind = kind;
        if kind == CredentialKind::DashboardSession {
            call.client.name = "dashboard".into();
            call.client.quota_principal =
                Some(crate::gateway::auth::QuotaPrincipal::dashboard_session());
            call.client.principal = crate::gateway::record_principal::InternalPrincipal::new(
                "dashboard-session".into(),
            );
        }
        // No named-key or bound-session extension: only approval needs one.
        let sent = delete(&fx, "absent", call, None);
        assert_ne!(sent.status, StatusCode::NOT_FOUND, "{}", sent.body);
        assert_ne!(sent.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_ne!(sent.status, StatusCode::UNAUTHORIZED);
        assert_ne!(sent.status, StatusCode::FORBIDDEN);
    }
}

#[test]
fn revoke_body_needs_a_string_revision() {
    let fx = Fixture::new(Setup::default());
    let current = revision(&fx);
    let bodies = [
        "{}".to_owned(),
        r#"{"revision":null}"#.into(),
        r#"{"revision":42}"#.into(),
        r#"{"revision":"#.into(),
        format!(r#"{{"revision":"{current}","revision":"{current}"}}"#),
        json!({"revision": current, "unknown": true}).to_string(),
    ];
    for body in bodies {
        let mut call = Call::new(&json!({}));
        call.body = body;
        let sent = delete(&fx, "root", call, None);
        assert_eq!(
            sent.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            sent.body
        );
    }
}

#[test]
fn revoke_with_any_unequal_revision_is_stale_before_compute() {
    let fx = Fixture::new(Setup::default());
    let old = revision(&fx);
    std::fs::write(fx.path(), format!("{}\n# newer revision\n", fx.text())).expect("edit");
    for supplied in ["", "nonsense", old.as_str()] {
        let current = revision(&fx);
        assert_ne!(supplied, current, "premise: unequal A12 revisions");
        let call = Call::new(&json!({"revision": supplied}));
        let sent = delete(&fx, "root", call, None);
        assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
        assert_eq!(
            sent.body,
            json!({"error": "stale", "current": current}).to_string()
        );
    }
}

#[test]
fn revoke_name_is_one_path_segment() {
    let fx = Fixture::new(Setup::default());
    let call = Call::new(&json!({"revision": revision(&fx)}));
    // root exists; root/missing does not. Never truncate to the existing root.
    let sent = delete(&fx, "root%2Fmissing", call, None);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(sent.json(), json!({"error": "target_binding_required"}));
}

#[test]
fn if_match_does_not_replace_the_body_revision() {
    let fx = Fixture::new(Setup::default());
    let current = revision(&fx);
    let sent = delete(&fx, "root", Call::new(&json!({})), Some(&current));
    assert_eq!(
        sent.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        sent.body
    );
}

#[path = "keys_revoke_target_tests.rs"]
mod keys_revoke_target_tests;

#[path = "keys_revoke_writer_tests.rs"]
mod keys_revoke_writer_tests;

#[path = "keys_revoke_outcome_tests.rs"]
mod keys_revoke_outcome_tests;
