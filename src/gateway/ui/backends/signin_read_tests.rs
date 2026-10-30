// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backends read: the one sign-in predicate, evaluated once and shown by
//! every consumer the same way.

use super::fixture::Gw;
use crate::oauth::client::sign_in::SignIn;

/// Every state, and whether a person must sign in for it with no wait
/// recorded. A wait always needs one.
fn truth_table() -> [(SignIn, &'static str, bool); 7] {
    let held = SignIn::SignedIn { expires_at: None };
    [
        (SignIn::NotOAuth, "not_o_auth", false),
        (SignIn::NotYetChecked, "not_yet_checked", false),
        (held, "signed_in", false),
        (SignIn::Expired, "expired", true),
        (SignIn::NeverSignedIn, "never_signed_in", true),
        (
            SignIn::ReSignInAfterUpgrade,
            "re_sign_in_after_upgrade",
            true,
        ),
        (SignIn::WaitingElsewhere, "waiting_elsewhere", true),
    ]
}

// S5: the expected value comes from the written table, not from a consumer.
// `Refused` precedence is covered by the server-state rows.
#[tokio::test]
async fn needs_sign_in_agrees_across_every_variant() {
    let gw = Gw::new().await;
    for wait in [false, true] {
        for (status, _word, needs) in truth_table() {
            gw.backend.sign_in_status.set(status);
            gw.backend
                .shared_entry_for_test()
                .auth_wait
                .set_for_test(wait);
            let expected = needs || wait;

            assert_eq!(
                gw.backend.needs_sign_in(),
                expected,
                "{status:?} wait={wait}"
            );
            let row = gw.row().await;
            assert_eq!(
                row["needs_sign_in"], expected,
                "{status:?} wait={wait}: {row}"
            );
        }
    }
}

// The serialized word of every variant but `NotOAuth` (which omits the field),
// in the read.
#[tokio::test]
async fn the_read_names_each_variant_in_snake_case() {
    let gw = Gw::new().await;
    for (status, word, _) in truth_table() {
        if status == SignIn::NotOAuth {
            continue;
        }
        gw.backend.sign_in_status.set(status);
        let row = gw.row().await;
        assert_eq!(row["sign_in"]["status"], word, "{row}");
    }
}

/// A plan the runtime policy denies: it asks to mount the host root.
fn denied_plan() -> crate::runtime::RuntimePlan {
    use crate::runtime::{
        RuntimeAvailability, RuntimeIntent, RuntimeMount, RuntimeMountMode, RuntimePlanner,
    };
    let mut intent = RuntimeIntent::named("denied");
    intent.image = Some("ghcr.io/example/filesystem:1".to_owned());
    intent.requested_mounts = vec![RuntimeMount {
        source: "/".to_owned(),
        target: "/host".to_owned(),
        mode: RuntimeMountMode::ReadOnly,
    }];
    let plan = RuntimePlanner::new(RuntimeAvailability::with_docker()).plan(&intent);
    assert!(plan.is_denied(), "the fixture plan is denied");
    plan
}

/// S5, `Refused`: a runtime-refused backend that also needs a sign-in keeps
/// `state: "refused"` and still reports `needs_sign_in: true`. The precedence
/// of `Refused` over `NeedsSignIn` is pinned on `decide` by
/// `api4_1_precedence_worst_first` and `api4_1_refused_names_the_denial_reasons`
/// in `src/backend/server_state_tests.rs`; this row pins it on the read.
#[tokio::test]
async fn a_refused_backend_keeps_its_state_and_still_needs_sign_in() {
    let gw = Gw::new().await;
    let config = crate::config::BackendConfig {
        oauth: Some(crate::config::OAuthConfig {
            enabled: true,
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: None,
            shared_account: false,
        }),
        ..crate::config::BackendConfig::default()
    };
    let refused = crate::backend::Backend::new_with_runtime_plan(
        "refused-one",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
        Some(denied_plan()),
    );
    refused.sign_in_status.set(SignIn::NeverSignedIn);
    gw.add_backend(refused);

    let row = gw.row_named("refused-one").await;

    assert_eq!(row["state"], "refused", "{row}");
    assert_eq!(row["needs_sign_in"], true, "{row}");
}
