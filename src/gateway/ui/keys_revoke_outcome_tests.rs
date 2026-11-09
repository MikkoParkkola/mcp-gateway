// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R4/R7/R10: red A52 outcomes, through the audited DELETE router.
use super::super::keys_create_fixture_tests::{ROOT, spec};
use super::keys_revoke_target_tests::{tag, target_setup};
use super::*;
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};
use crate::config_persistence::journal::{self, fault};
use crate::config_reload::{ReloadContext, refuse_hook, write_order};
use std::sync::{Arc, Mutex};

fn revoke(fx: &Fixture, name: &str, secret: &str) -> Sent {
    send_delete(
        fx,
        name,
        Call::new(&json!({"revision": revision(fx), "expected_key_tag": tag(secret)})),
        None,
    )
}

#[test]
fn a_keychain_backed_target_revokes_by_its_resolved_digest() {
    const VAR: &str = "MCPGW_R4_OUTCOME_DIGEST";
    if std::env::var_os(VAR).is_none() {
        // Isolate the ambient value in a child; never mutate the runner's environment.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("a_keychain_backed_target_revokes_by_its_resolved_digest")
            .env(VAR, spec("ambient"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    {
        let reference = format!("env:{VAR}");
        let fx = Fixture::new(target_setup());
        let env_path = fx.dir.path().join("revoke.env");
        crate::gateway::test_helpers::write_owner_only(
            &env_path,
            format!(
                "{VAR}={}\nMCPGW_R4_ROOT={}\n",
                spec("target-secret"),
                spec(ROOT)
            ),
        )
        .unwrap();
        let overlay = Arc::new(EnvOverlay::from_paths(&[env_path.clone()]));
        let env = Arc::new(LiveEnv::new(
            overlay,
            ResolvedEnvFiles::new(vec![env_path.clone()], false),
        ));
        let text = fx
            .text()
            .replace(&spec("target-secret"), &reference)
            .replace(&spec(ROOT), "env:MCPGW_R4_ROOT");
        let text = format!(
            "env_files:\n  - {}\n{text}",
            serde_json::to_string(&env_path.to_string_lossy().as_ref()).unwrap()
        );
        crate::gateway::test_helpers::write_owner_only(&fx.path(), &text).unwrap();
        let ctx = ReloadContext::new(
            fx.path(),
            fx.live.clone(),
            fx.state.backends.clone(),
            Default::default(),
            std::time::Duration::from_secs(60),
        )
        .unwrap()
        .with_env(env);
        fx.state.meta_mcp.set_reload_context(Arc::new(ctx));
        let wrong = revoke(&fx, "target", "ambient");
        // RED R4: ambient resolution must not select or mutate the overlay identity.
        assert_eq!(fx.text(), text);
        assert_eq!(wrong.status, StatusCode::CONFLICT);
        assert_eq!(wrong.json()["error"], "target_changed");
        let sent = revoke(&fx, "target", "target-secret");
        // RED R4: the secret-reference overlay resolves; unrelated env root survives verbatim.
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
        assert_eq!(
            fx.text(),
            text.replace(
                &super::super::keys_create_fixture_tests::item("target", "target-secret", "")
                    .replace(&spec("target-secret"), &reference),
                ""
            )
        );
        assert!(fx.live.generation().auth().validate_token(ROOT).is_some());
        assert!(
            fx.live
                .generation()
                .auth()
                .validate_token("target-secret")
                .is_none()
        );
    }
}

#[test]
fn differing_file_and_live_identities_refuse_even_when_the_tag_matches_one() {
    for secret in ["target-secret", "replacement"] {
        let mut setup = target_setup();
        setup.running.api_keys[1].key_sha256 = Some(spec("replacement"));
        let fx = Fixture::new(setup);
        let before = fx.bytes();
        let sent = revoke(&fx, "target", secret);
        // RED R4: matching either side cannot authorize a replacement identity.
        assert_eq!(fx.bytes(), before);
        assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    }
}

#[test]
fn success_is_a_no_store_200_with_exactly_name_revoked_revision() {
    let fx = Fixture::new(target_setup());
    let sent = revoke(&fx, "target", "target-secret");
    // RED R7: only the exact delivered receipt is success; no private extra fields.
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    assert_eq!(sent.cache_control.as_deref(), Some("no-store"));
    assert_eq!(
        sent.json(),
        json!({"name": "target", "revoked": true, "revision": revision(&fx)})
    );
}

#[test]
fn a_fault_after_commit_never_answers_revoked() {
    // After the commit only: a failed write is before it, rolls back and is
    // the writer's ordinary not_written answer (the audited writer has no
    // injectable write fault; FailWrite belongs to the commit primitive).
    for phase in ["journal-confirm", "reload", "postcondition"] {
        let fx = Fixture::new(target_setup());
        let path = crate::identity_grants::journal::resolved(&fx.path());
        let old = fx.live.generation();
        let live = fx.live.clone();
        let reached = Arc::new(Mutex::new(None));
        let seen = reached.clone();
        let journal_path = journal::journal_path(&path);
        write_order::on(
            &path,
            if phase == "postcondition" {
                "reload"
            } else {
                "commit"
            },
            Arc::new(move || {
                if phase == "reload" {
                    *seen.lock().unwrap() = Some(refuse_hook::arm("R7 reload"));
                }
                if phase == "journal-confirm" {
                    std::fs::remove_file(&journal_path).unwrap();
                    std::fs::create_dir(&journal_path).unwrap();
                }
                if phase == "postcondition" {
                    live.publish(old.clone());
                }
            }),
        );
        let sent = revoke(&fx, "target", "target-secret");
        let steps = write_order::take(&path);
        // RED R7: prove the fault's phase was reached; a missing route cannot pass.
        if phase == "reload" {
            assert!(
                reached
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
        } else {
            assert!(steps.contains(if phase == "postcondition" {
                &"reload"
            } else {
                &"commit"
            }));
        }
        assert!(!sent.status.is_success(), "{phase}: {}", sent.body);
        assert_ne!(sent.json()["revoked"], true, "{phase}");
        // RED R7: journal confirmation / receipt failure follows a landed removal.
        if matches!(phase, "journal-confirm" | "postcondition") {
            assert!(!fx.text().contains("name: target"));
            assert_eq!(sent.json()["error"], "state_uncertain", "{phase}");
        }
    }
}

#[test]
fn a_missing_audit_log_refuses_before_any_write() {
    let fx = Fixture::new(Setup {
        audit_log: false,
        ..target_setup()
    });
    let before = fx.bytes();
    let sent = revoke(&fx, "target", "target-secret");
    // RED R7: no-log outer middleware runs the handler; the writer must refuse.
    assert_eq!(fx.bytes(), before);
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    assert_ne!(sent.json()["revoked"], true);
}

#[test]
fn single_user_two_to_one_is_refused_and_says_not_revoked() {
    let mut setup = target_setup();
    setup.running.single_user = true;
    setup.text = setup
        .text
        .replace("  enabled: true", "  enabled: true\n  single_user: true");
    let fx = Fixture::new(setup);
    let before = fx.bytes();
    let sent = revoke(&fx, "target", "target-secret");
    // RED R10: posture refusal is explicitly not a revoke, with no durable edit.
    assert_eq!(fx.bytes(), before);
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(sent.json()["revoked"], false);
}

#[test]
fn removing_the_last_root_can_succeed_and_auth_stays_enabled() {
    let fx = Fixture::new(Setup::default());
    let sent = revoke(&fx, "root", ROOT);
    // RED R10: multi-user last-root removal succeeds without disabling authentication.
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.body);
    assert_eq!(sent.json()["revoked"], true);
    assert!(fx.live.generation().auth().enabled);
    let app = super::super::admin_audit::audited_api_router(&fx.state)
        .with_state(fx.state.clone())
        .layer(axum::middleware::from_fn_with_state(
            crate::gateway::router::build_auth_state(&fx.state),
            crate::gateway::auth::auth_middleware,
        ));
    let request = Request::builder()
        .uri("/ui/api/keys")
        .header("authorization", format!("Bearer {ROOT}"))
        .extension(fx.live.generation())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        fx.rt.block_on(app.oneshot(request)).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
