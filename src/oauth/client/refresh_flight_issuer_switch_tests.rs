// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sign-in confirmed under another issuer while a call of the old issuer's
//! client is already past its entry check: nothing of the old issuer is handed
//! back, the install is not acknowledged, and the status stays the new one's.
//! And the detached step's other hand-back recheck: nothing held is handed to
//! work a restart revoked.

use std::sync::Arc;

use super::*;
use crate::oauth::client::sign_in::{SignIn, SignInStatus};
use crate::test_pause::within;
use crate::test_wait::HANG_BOUND;

/// The key a confirm under the other issuer is saved under.
const OTHER_ISSUER_KEY: &str = "flight-backend-other-issuer";

/// A refresh is held at the token endpoint when the confirm under the other
/// issuer lands; then the exchange answers. Neither `get_token` nor the
/// detached step hands the refreshed token back. Red today: both return it.
#[tokio::test]
async fn a_refresh_in_flight_across_an_issuer_switch_hands_back_no_token() {
    for detached in [false, true] {
        let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
        let dir = tempfile::tempdir().unwrap();
        let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
        let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
        let owned = client(dir.path(), &server)
            .with_sign_in_status(Arc::clone(&cell))
            .with_login_gate(Arc::clone(&gate));
        hold(&owned, &token("a1", Some("r1"), true));
        let ask = async {
            if detached {
                let deadline = tokio::time::Instant::now() + HANG_BOUND;
                owned
                    .get_token_detached(false, gate.epoch(), &gate.cohort(), deadline)
                    .await
            } else {
                headless(&owned).await
            }
        };
        let switch = async {
            server.arrivals(1, HANG_BOUND).await;
            cell.record_install(OTHER_ISSUER_KEY);
            server.release.notify_one();
        };

        let (handed, ()) = tokio::join!(ask, switch);

        assert_eq!(
            server.requests(),
            1,
            "detached={detached}: the exchange ran"
        );
        let refused = handed.expect_err("no old-issuer token after the switch");
        assert!(
            matches!(refused, Error::AuthorizationRequired { .. }),
            "detached={detached}: {refused}"
        );
    }
}

/// An adopt has read this client's own install when the confirm under the
/// other issuer lands. It neither acknowledges the new install nor hands back
/// the token it read. Red today: it loops, acknowledges the new count, and
/// returns the old issuer's token.
#[tokio::test]
async fn an_adopt_racing_an_issuer_switch_acknowledges_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), false));
    cell.record_install(&owned.credential_key().unwrap());
    let (reached, release) = owned.adopt_pause.arm();
    let adopt = tokio::task::spawn_blocking(move || {
        let adopted = owned.adopt_installed();
        (owned, adopted)
    });
    within("the adopt parks after its read", reached.notified()).await;

    cell.record_install(OTHER_ISSUER_KEY);
    release.notify_one();

    let (owned, adopted) = adopt.await.expect("the adopt ran");
    assert_eq!(adopted, None, "nothing of the old issuer is handed back");
    assert!(owned.install_stale(), "the new install is not acknowledged");
}

/// A publish by the old issuer's client (a refresh that was already in flight
/// ends with one), after a sign-in under the other issuer was confirmed and
/// published, leaves the status as that sign-in published it. Red today: it
/// writes the old credential's expiry.
#[tokio::test]
async fn an_old_issuer_publish_keeps_the_new_sign_ins_status() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), false));
    cell.record_install(OTHER_ISSUER_KEY);
    cell.set_held(Some(4_000_000_000), false);
    let published = cell.snapshot();

    owned.publish_sign_in();

    assert_eq!(
        cell.snapshot(),
        published,
        "the new sign-in's status stands"
    );
}

/// A background renewal of the old issuer's credential, once a sign-in under
/// the other issuer is confirmed, sends nothing: the old refresh token stays
/// unspent until a re-discovery settles which issuer serves. Red today: the
/// renewal refreshes the old credential.
#[tokio::test]
async fn a_background_renewal_after_an_issuer_switch_sends_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), true));
    cell.record_install(OTHER_ISSUER_KEY);

    let renewal = owned.attempt_background_renewal().await;

    assert!(
        matches!(renewal, crate::oauth::client::renewal::Renewal::Deferred),
        "the renewal waits"
    );
    assert_eq!(server.requests(), 0, "nothing was sent");
}

/// An install under the client's own issuer whose token cannot be read leaves
/// a provider-changed reason standing: only an adopt that took a token ends
/// it. Red today: the reason is cleared before the read.
#[tokio::test]
async fn a_failed_adopt_keeps_the_provider_changed_reason() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    cell.record_install(&owned.credential_key().unwrap());
    cell.raise_provider_changed();

    assert_eq!(owned.adopt_installed(), None, "nothing was stored");

    assert_eq!(cell.snapshot(), SignIn::ProviderChanged);
}

/// A restart revoked the detached step after it set out: a held token, cached
/// or adopted, is not handed back, as a refreshed one never was. Red today:
/// both are returned.
#[tokio::test]
async fn a_revoked_detached_step_hands_back_no_held_token() {
    for adopt in [false, true] {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().unwrap();
        let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
        let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
        let owned = client(dir.path(), &server)
            .with_sign_in_status(Arc::clone(&cell))
            .with_login_gate(Arc::clone(&gate));
        hold(&owned, &token("a1", Some("r1"), false));
        if adopt {
            cell.record_install(&owned.credential_key().unwrap());
        }
        let since = gate.epoch();
        gate.cancel_and_join().await;

        let deadline = tokio::time::Instant::now() + HANG_BOUND;
        let refused = owned
            .get_token_detached(false, since, &gate.cohort(), deadline)
            .await
            .expect_err("nothing held after the restart");

        assert!(
            matches!(refused, Error::AuthorizationCancelled { .. }),
            "adopt={adopt}: {refused}"
        );
        assert_eq!(server.requests(), 0, "adopt={adopt}: nothing was sent");
    }
}
