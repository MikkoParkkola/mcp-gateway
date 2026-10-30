// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backends read: the one sign-in predicate, evaluated once and shown by
//! every consumer the same way.

use std::sync::atomic::Ordering;

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
                .store(wait, Ordering::Relaxed);
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
