// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R3 exact-target rows; DELETE is intentionally red until A52 lands.
use super::super::keys_create_fixture_tests::{ROOT, item, root_item, spec, yaml_of};
use super::*;
use crate::config::ApiKeyConfig;

pub(super) fn target_setup() -> Setup {
    let mut setup = Setup {
        text: yaml_of(&[root_item(), item("target", "target-secret", "")]),
        ..Setup::default()
    };
    setup.running.api_keys.push(ApiKeyConfig {
        name: "target".into(),
        key_sha256: Some(spec("target-secret")),
        backends: vec!["*".into()],
        ..Default::default()
    });
    setup
}

pub(super) fn tag(secret: &str) -> String {
    crate::gateway::auth::digest_tag_of(
        &crate::config::parse_api_key_digest(&spec(secret)).unwrap(),
    )
}

fn refuse(setup: Setup, name: &str, binding: Option<String>) -> Sent {
    let fx = Fixture::new(setup);
    let mut body = json!({"revision": revision(&fx)});
    if let Some(tag) = binding {
        body["expected_key_tag"] = json!(tag);
    }
    delete(&fx, name, Call::new(&body), None) // also asserts exact unchanged bytes
}

#[test]
fn a_duplicate_name_is_refused_without_removal() {
    // In the running table: a valid file cannot hold two entries of one name.
    let mut setup = target_setup();
    let mut duplicate = setup.running.api_keys[1].clone();
    duplicate.key_sha256 = Some(spec("duplicate-secret"));
    setup.running.api_keys.push(duplicate);
    let sent = refuse(setup, "target", None);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
}

/// A file that does not load (here: a duplicate name) has no A12 revision,
/// so no revoke can take the write path: the shared answer every config
/// writing route gives (503, "gateway.yaml could not be loaded"), nothing
/// written.
#[test]
fn an_unloadable_file_takes_no_revoke() {
    let mut setup = target_setup();
    setup.text.push_str(&item("target", "duplicate-secret", ""));
    let fx = Fixture::new(setup);
    assert!(
        fx.get()["revision"].is_null(),
        "premise: no revision for an unloadable file"
    );
    let sent = delete(&fx, "target", Call::new(&json!({"revision": "any"})), None);
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    assert_eq!(
        sent.json(),
        json!({"error": "gateway.yaml could not be loaded"})
    );
}

#[test]
fn a_replaced_identity_is_refused() {
    let mut setup = target_setup();
    setup.running.api_keys[1].key_sha256 = Some(spec("replacement"));
    let sent = refuse(setup, "target", None);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
}

#[test]
fn an_old_profile_tag_against_a_same_name_replacement_is_target_changed() {
    let sent = refuse(target_setup(), "target", Some(tag("absent-old-secret")));
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(sent.json(), json!({"error": "target_changed"}));
}

#[test]
fn a_bound_tag_under_another_name_is_refused() {
    for name in ["target", "old-root-name"] {
        let sent = refuse(target_setup(), name, Some(tag(ROOT)));
        assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    }
}

/// A running gateway cannot hold a digest shared with another key's current
/// or previous slot or with the bearer: each such table is refused at load.
/// So `identity_in_use` is defensive, and its refusal is judged on the pure
/// selection in `keys_revoke_select_tests`.
#[test]
fn no_identity_collision_can_be_running() {
    for slot in ["current", "previous", "bearer"] {
        let mut setup = target_setup();
        let mut other = setup.running.api_keys[1].clone();
        other.name = "other".into();
        match slot {
            "current" => other.key_sha256 = Some(spec("target-secret")),
            "previous" => {
                other.key_sha256 = Some(spec("other-secret"));
                other.previous_key_sha256 = Some(spec("target-secret"));
                other.previous_expires_at = Some("2099-01-01T00:00:00Z".parse().expect("time"));
            }
            _ => {
                other.key_sha256 = Some(spec("other-secret"));
                setup.running.bearer_token = Some("target-secret".into());
            }
        }
        setup.running.api_keys.push(other);
        let built = crate::gateway::auth::ResolvedAuthConfig::try_from_config(
            &setup.running,
            &crate::config::EnvOverlay::none(),
            crate::gateway::record_principal::TEST_RECORD_KEY,
        );
        assert!(built.is_err(), "{slot}: a colliding table loaded");
    }
}

#[test]
fn an_absent_unbound_target_needs_a_binding() {
    let sent = refuse(target_setup(), "absent", None);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(sent.json(), json!({"error": "target_binding_required"}));
}

#[test]
fn the_authorizer_survives_and_self_revoke_needs_no_second_login() {
    let mut setup = target_setup();
    setup
        .text
        .push_str(&item("survivor", "survivor-secret", ""));
    let mut survivor = setup.running.api_keys[1].clone();
    survivor.name = "survivor".into();
    survivor.key_sha256 = Some(spec("survivor-secret"));
    setup.running.api_keys.push(survivor);
    let fx = Fixture::new(setup);
    for (name, secret, removed) in [
        (
            "target",
            "target-secret",
            item("target", "target-secret", ""),
        ),
        ("root", ROOT, root_item()),
    ] {
        let before = fx.text();
        let mut call =
            Call::new(&json!({"revision": revision(&fx), "expected_key_tag": tag(secret)}));
        call.client = fx
            .live
            .generation()
            .auth()
            .validate_token(ROOT)
            .expect("A authenticates");
        let sent = send_delete(&fx, name, call, None);
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
        assert_eq!(fx.bytes(), before.replacen(&removed, "", 1).as_bytes());
        assert_eq!(
            sent.json(),
            json!({"name": name, "revoked": true, "revision": revision(&fx)})
        );
        assert!(fx.live.generation().auth().validate_token(secret).is_none());
        if name == "target" {
            // A's next request is authenticated afresh against the published generation.
            let mut next = Call::new(&json!({"revision": revision(&fx)}));
            next.client = fx
                .live
                .generation()
                .auth()
                .validate_token(ROOT)
                .expect("A survives K");
            let accepted = delete(&fx, "absent", next, None);
            assert_eq!(accepted.status, StatusCode::CONFLICT, "{}", accepted.body);
            assert_eq!(accepted.json(), json!({"error": "target_binding_required"}));
        }
    }
}
