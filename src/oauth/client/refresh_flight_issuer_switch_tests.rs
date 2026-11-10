// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sign-in confirmed under another issuer while a call of the old issuer's
//! client is already past its entry check: nothing of the old issuer is handed
//! back, the install is not acknowledged, and the status stays the new one's.
//! And the detached step's other hand-back recheck: nothing held is handed to
//! work a restart revoked.

use std::sync::Arc;

use super::*;
use crate::oauth::client::grants::Adopt;
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
/// other issuer lands. It neither acknowledges the new install nor keeps the
/// token it read cached: it answers `Moved`. Red before the adopt checked the
/// issuer: it looped, acknowledged the new count, and returned the old token.
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
    assert_eq!(
        adopted,
        Adopt::Moved,
        "nothing of the old issuer is handed back"
    );
    assert!(owned.install_stale(), "the new install is not acknowledged");
    assert!(
        owned.current_token.read().is_none(),
        "nothing of the old issuer stays cached"
    );
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

    assert_eq!(
        owned.adopt_installed(),
        Adopt::Nothing,
        "nothing was stored"
    );

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

/// A confirm under the other issuer lands while `get_token` (and the detached
/// step, as an interactive caller) holds an adopt after its read: the call
/// answers the sign-in wait, the cache holds nothing of the old issuer, no
/// refresh is sent and no login of the old issuer starts. Red before the adopt
/// step checked the issuer: the old cached token was handed back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_during_an_adopt_leaves_nothing_of_the_old_issuer() {
    for detached in [false, true] {
        let server = TokenServer::start(&[]).await;
        let dir = tempfile::tempdir().unwrap();
        let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
        let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
        let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let browser = Arc::clone(&opened);
        let owned = client(dir.path(), &server)
            .with_sign_in_status(Arc::clone(&cell))
            .with_login_gate(Arc::clone(&gate))
            .with_open_browser(Arc::new(move |_: &str| {
                browser.store(true, std::sync::atomic::Ordering::SeqCst);
                false
            }));
        hold(&owned, &token("a1", Some("r1"), false));
        cell.record_install(&owned.credential_key().unwrap());
        let (reached, release) = owned.adopt_pause.arm();
        let (since, cohort) = (gate.epoch(), gate.cohort());
        let asked = tokio::task::spawn_blocking(move || {
            let deadline = tokio::time::Instant::now() + HANG_BOUND;
            let answer = futures::executor::block_on(async {
                if detached {
                    owned
                        .get_token_detached(true, since, &cohort, deadline)
                        .await
                } else {
                    crate::oauth::login_gate::non_interactive(owned.get_token()).await
                }
            });
            (owned, answer)
        });
        within("the adopt parks after its read", reached.notified()).await;

        cell.record_install(OTHER_ISSUER_KEY);
        release.notify_one();

        let (owned, answer) = asked.await.expect("the call ran");
        let refused = answer.expect_err("nothing of the old issuer is handed back");
        assert!(
            matches!(refused, Error::AuthorizationRequired { .. }),
            "detached={detached}: {refused}"
        );
        assert!(
            owned.current_token.read().is_none(),
            "detached={detached}: nothing of the old issuer stays cached"
        );
        assert_eq!(
            server.requests(),
            0,
            "detached={detached}: nothing was sent"
        );
        assert!(
            !opened.load(std::sync::atomic::Ordering::SeqCst),
            "detached={detached}: no login of the old issuer started"
        );
    }
}

/// A sign-in confirmed after an earlier install under the other issuer
/// publishes its own state. Red before the install was recorded first: the
/// publish was checked against the earlier install and dropped.
#[tokio::test]
async fn a_confirm_after_an_install_elsewhere_publishes_its_own_state() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    cell.record_install(OTHER_ISSUER_KEY);
    let cancel = tokio_util::sync::CancellationToken::new();
    let by = tokio::time::Instant::now() + HANG_BOUND;

    owned
        .save_confirmed(
            crate::oauth::client::sign_in::PendingGrant::from_token(token("a1", Some("r1"), false)),
            &cancel,
            by,
        )
        .await
        .expect("the confirm saves");

    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { .. }),
        "{:?}",
        cell.snapshot()
    );
}

/// An adopt under the client's own issuer while a provider-changed reason
/// stands ends the reason and publishes the adopted token's state. Red before
/// the republish: the status read `NeverSignedIn` while the token served.
#[tokio::test]
async fn an_adopt_that_ends_provider_changed_publishes_the_token() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), false));
    cell.record_install(&owned.credential_key().unwrap());
    cell.raise_provider_changed();

    let handed = headless(&owned).await.expect("the install is adopted");

    assert_eq!(handed, "a1");
    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { .. }),
        "{:?}",
        cell.snapshot()
    );
}

/// A publish holds its issuer check and its write together: no install can
/// land between them. Red before the single step: the check and the write
/// were separate, and an install landed while the publish was held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_install_lands_between_a_publish_check_and_its_write() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), false));
    let (reached, release) = owned.publish_pause.arm();
    let publisher = tokio::task::spawn_blocking(move || owned.publish_sign_in());
    within("the publish parks after its check", reached.notified()).await;

    let landed = cell.try_record_install_for_test(OTHER_ISSUER_KEY);
    release.notify_one();
    publisher.await.expect("the publish ran");

    assert!(!landed, "an install landed inside a publish");
}

/// A client built after a sign-in under the other issuer was confirmed (a
/// backend restart): it has acknowledged that install, so no adopt runs. Its
/// own entry check answers the sign-in wait, and no login of its discovered
/// (old) issuer starts. Red without the entry check: an interactive call fell
/// through to a login of the old issuer.
#[tokio::test]
async fn a_client_built_after_a_switch_starts_no_login_of_the_old_issuer() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    cell.record_install(OTHER_ISSUER_KEY);
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let browser = Arc::clone(&opened);
    let owned = client(dir.path(), &server)
        .with_sign_in_status(Arc::clone(&cell))
        .with_open_browser(Arc::new(move |_: &str| {
            browser.store(true, std::sync::atomic::Ordering::SeqCst);
            false
        }));
    assert!(
        !owned.install_stale(),
        "control: the install is acknowledged"
    );

    let refused = tokio::time::timeout(HANG_BOUND, owned.get_token())
        .await
        .expect("the call answers within the bound")
        .expect_err("no token while the issuers differ");

    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
    assert!(
        !opened.load(std::sync::atomic::Ordering::SeqCst),
        "no login of the old issuer started"
    );
}

/// A refresh whose caller passed its entry check before a sign-in under the
/// other issuer was confirmed (it waited on the refresh lock meanwhile):
/// nothing is sent, and the call answers the sign-in wait. Red before the
/// grant took the issuer proof: the adopt was refused and read as leave to
/// refresh, so the old issuer's refresh token was spent.
#[tokio::test]
async fn a_refresh_after_a_switch_spends_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), true));
    cell.record_install(OTHER_ISSUER_KEY);

    let refused = owned
        .refresh_token()
        .await
        .expect_err("no refresh of the old issuer");

    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
    assert_eq!(server.requests(), 0, "the old refresh token was not sent");
}

/// An adopt that finds no stored token while the install is under the other
/// issuer answers `Moved`, so no caller falls through to a login of the old
/// issuer. Red before the check ran ahead of the missing-record exit: it
/// answered `Nothing`.
#[tokio::test]
async fn an_adopt_with_nothing_stored_after_a_switch_answers_moved() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    cell.record_install(OTHER_ISSUER_KEY);

    assert_eq!(owned.adopt_installed(), Adopt::Moved);
}

/// A login this client would lead, while the install is under the other
/// issuer, ends with the sign-in wait before any link opens. Red before the
/// login took the issuer proof: it led a login of the old issuer.
#[tokio::test]
async fn a_led_login_after_a_switch_opens_nothing() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    cell.record_install(OTHER_ISSUER_KEY);
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let browser = Arc::clone(&opened);
    let owned = client(dir.path(), &server)
        .with_sign_in_status(Arc::clone(&cell))
        .with_login_gate(Arc::new(crate::oauth::login_gate::LoginGate::default()))
        .with_open_browser(Arc::new(move |_: &str| {
            browser.store(true, std::sync::atomic::Ordering::SeqCst);
            false
        }));

    let refused = tokio::time::timeout(HANG_BOUND, owned.authorize_shared(true, None))
        .await
        .expect("the login answers within the bound")
        .expect_err("no login of the old issuer");

    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
    assert!(
        !opened.load(std::sync::atomic::Ordering::SeqCst),
        "no link of the old issuer opened"
    );
}

/// A joiner whose shared login stored a token while a sign-in under the other
/// issuer was confirmed answers the sign-in wait, which a caller retries, not
/// a hard error. Red before the adopt was typed: the refused adopt read as
/// "the login stored no token".
#[tokio::test]
async fn a_joiner_after_a_switch_answers_the_sign_in_wait() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
    let crate::oauth::login_gate::Begin::Lead(lead) = gate.begin(None, None) else {
        panic!("no login in flight, so the test leads");
    };
    let owned = client(dir.path(), &server)
        .with_sign_in_status(Arc::clone(&cell))
        .with_login_gate(Arc::clone(&gate));
    let key = owned.credential_key().unwrap();

    let (joined, ()) = tokio::join!(owned.authorize_shared(true, None), async {
        tokio::task::yield_now().await;
        owned
            .storage
            .save(&key, RESOURCE, &token("a1", Some("r1"), false))
            .unwrap();
        cell.record_install(OTHER_ISSUER_KEY);
        lead.end(None);
    });

    let refused = joined.expect_err("nothing of the old issuer");
    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
}

/// A background renewal holds between its refresh and its client-credentials
/// grant when a sign-in under the other issuer is confirmed: the grant sends
/// nothing. Red before the proof was spent at the grant: the renewal's opening
/// check was reused, and the old issuer's grant was sent.
#[tokio::test]
async fn a_renewal_that_spans_a_switch_sends_no_grant() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let mut owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    owned.auth_metadata.as_mut().unwrap().grant_types_supported =
        vec!["client_credentials".to_owned()];
    hold(&owned, &token("a1", None, true));
    let (reached, release) = owned.renewal_pause.arm();
    let switch = async {
        within("the renewal parks before its grant", reached.notified()).await;
        cell.record_install(OTHER_ISSUER_KEY);
        release.notify_one();
    };

    let (renewal, ()) = tokio::join!(owned.attempt_background_renewal(), switch);

    assert!(
        !matches!(renewal, crate::oauth::client::renewal::Renewal::Renewed),
        "nothing was renewed"
    );
    assert_eq!(server.requests(), 0, "no grant of the old issuer was sent");
}

/// A joiner whose shared login stored nothing while a sign-in under the other
/// issuer was confirmed answers the sign-in wait, not a hard error. Red before
/// the adopt checked the issuer ahead of its load: it answered "the login
/// stored no token".
#[tokio::test]
async fn a_joiner_with_nothing_stored_after_a_switch_answers_the_sign_in_wait() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let gate = Arc::new(crate::oauth::login_gate::LoginGate::default());
    let crate::oauth::login_gate::Begin::Lead(lead) = gate.begin(None, None) else {
        panic!("no login in flight, so the test leads");
    };
    let owned = client(dir.path(), &server)
        .with_sign_in_status(Arc::clone(&cell))
        .with_login_gate(Arc::clone(&gate));

    let (joined, ()) = tokio::join!(owned.authorize_shared(true, None), async {
        tokio::task::yield_now().await;
        cell.record_install(OTHER_ISSUER_KEY);
        lead.end(None);
    });

    let refused = joined.expect_err("nothing of the old issuer");
    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
}

/// A joiner's adopt that reads nothing stored after a sign-in under the other
/// issuer was confirmed between its issuer check and its read answers
/// `Moved`, not `Nothing`. Red before the empty read checked the issuer again:
/// it answered `Nothing`, which a joiner reports as a hard error.
#[tokio::test]
async fn an_empty_read_after_a_switch_answers_moved() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    let (reached, release) = owned.stored_read_pause.arm();
    let adopt = tokio::task::spawn_blocking(move || owned.adopt_stored_login_for_test());
    within("the adopt parks after its read", reached.notified()).await;

    cell.record_install(OTHER_ISSUER_KEY);
    release.notify_one();

    assert_eq!(
        adopt.await.expect("the adopt ran"),
        Adopt::Moved,
        "a switch after the check is not read as nothing stored"
    );
}

/// A stored token the adopt read just before a sign-in under the other issuer
/// was confirmed is not cached: `cache_if_current` refuses it and the adopt
/// answers `Moved`.
#[tokio::test]
async fn a_token_read_before_a_switch_is_not_cached() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    let key = owned.credential_key().unwrap();
    owned
        .storage
        .save(&key, RESOURCE, &token("a1", Some("r1"), false))
        .unwrap();
    let (reached, release) = owned.stored_read_pause.arm();
    let adopt = tokio::task::spawn_blocking(move || {
        let adopted = owned.adopt_stored_login_for_test();
        (owned, adopted)
    });
    within("the adopt parks after its read", reached.notified()).await;

    cell.record_install(OTHER_ISSUER_KEY);
    release.notify_one();

    let (owned, adopted) = adopt.await.expect("the adopt ran");
    assert_eq!(adopted, Adopt::Moved);
    assert!(owned.current_token.read().is_none(), "nothing cached");
}

/// A refresh already sent when a sign-in under the other issuer is confirmed:
/// its answer is not handed back, not cached, and the status stays the new
/// sign-in's. Red before a refreshed token was cached through the checked
/// step: the old issuer's new token stayed cached.
#[tokio::test]
async fn a_switch_while_a_refresh_is_in_flight_installs_nothing_old() {
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    hold(&owned, &token("a1", Some("r1"), true));
    let switch = async {
        server.arrivals(1, HANG_BOUND).await;
        cell.record_install(OTHER_ISSUER_KEY);
        cell.set_held(Some(4_000_000_000), false);
        server.release.notify_one();
    };

    let (handed, ()) = tokio::join!(headless(&owned), switch);

    assert_eq!(server.requests(), 1, "the refresh was in flight");
    let refused = handed.expect_err("no old-issuer token after the switch");
    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{refused}"
    );
    let cached = owned
        .current_token
        .read()
        .as_ref()
        .map(|token| token.access_token.clone());
    assert_ne!(
        cached.as_deref(),
        Some("a2"),
        "the old issuer's answer is not cached"
    );
    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { expires_at: Some(at) }
            if at == std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000)),
        "the new sign-in's status stands: {:?}",
        cell.snapshot()
    );
}

/// A background renewal reads its client's registration when it spends its
/// proof, not when it took it: a sign-in under the same issuer that
/// re-registered the client meanwhile is the id the grant sends. Red before
/// the grant reloaded the registration: the old in-memory id was sent.
#[tokio::test]
async fn a_renewal_sends_the_registration_current_at_its_grant() {
    let server = TokenServer::start(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let mut owned = client(dir.path(), &server).with_sign_in_status(Arc::clone(&cell));
    owned.auth_metadata.as_mut().unwrap().grant_types_supported =
        vec!["client_credentials".to_owned()];
    *owned.client_id_source.write() = Some(ClientIdSource::Registered);
    hold(&owned, &token("a1", None, true));
    let key = owned.credential_key().unwrap();
    let (reached, release) = owned.renewal_pause.arm();
    let reregister = async {
        within("the renewal parks before its grant", reached.notified()).await;
        owned
            .storage
            .save_client_id(&key, RESOURCE, "rotated-client")
            .unwrap();
        release.notify_one();
    };

    let (_renewal, ()) = tokio::join!(owned.attempt_background_renewal(), reregister);

    assert_eq!(
        *server.client_ids.lock().unwrap(),
        vec!["rotated-client".to_owned()],
        "the grant sends the registration current at its request"
    );
}

/// A client-credentials grant already sent when a sign-in under the other
/// issuer is confirmed: the renewal is deferred, not renewed, and logs no
/// renewal; nothing of the old issuer is cached, and the status stays the new
/// sign-in's. Red before the grant checked its cache write: it reported the
/// old issuer's answer as renewed.
#[test]
fn a_switch_while_a_client_credentials_grant_is_in_flight_renews_nothing() {
    use crate::oauth::client::renewal::Renewal;
    let ((renewal, cached, status, requests), logged) =
        crate::test_log_capture::capture_at(tracing::Level::INFO, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(async {
                let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
                let dir = tempfile::tempdir().unwrap();
                let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
                let mut owned = client(dir.path(), &server);
                if let Some(meta) = owned.auth_metadata.as_mut() {
                    meta.grant_types_supported = vec!["client_credentials".to_string()];
                }
                let owned = owned.with_sign_in_status(Arc::clone(&cell));
                let switch = async {
                    server.arrivals(1, HANG_BOUND).await;
                    cell.record_install(OTHER_ISSUER_KEY);
                    cell.set_held(Some(4_000_000_000), false);
                    server.release.notify_one();
                };
                let (renewal, ()) = tokio::join!(owned.attempt_background_renewal(), switch);
                let cached = owned.current_token.read().is_some();
                (renewal, cached, cell.snapshot(), server.requests())
            })
        });

    assert_eq!(requests, 1, "the grant was in flight");
    assert_eq!(
        renewal,
        Renewal::Deferred,
        "nothing of the old issuer is renewed"
    );
    assert!(!cached, "the old issuer's answer is not cached");
    assert!(
        !logged.contains("Token renewed via client_credentials"),
        "no renewal is logged: {logged}"
    );
    assert!(
        matches!(status, SignIn::SignedIn { expires_at: Some(at) }
            if at == std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000)),
        "the new sign-in's status stands: {status:?}"
    );
}
