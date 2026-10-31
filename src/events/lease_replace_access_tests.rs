// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who may read under a lease: after a restart no file holds the token, a 401
//! wipes the lease, another principal cannot touch it, each principal's
//! listener reads with its own token, and a revoked subscriber's listener
//! closes. Moved from `lease_replace_tests.rs` for the file-size ceiling.

use super::*;

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// LEASE-T5: a lease is memory only. After a restart the subscription row is
/// still there and waits in "credential needed", and no file the store
/// wrote holds the token or its claims.
#[tokio::test]
async fn lease_t5_after_a_restart_the_row_needs_a_credential_and_no_file_holds_the_token() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let leased = token(Some(in_an_hour()));
    let secret = leased.to_string();
    let claims = secret.split('.').nth(1).expect("a JWT payload").to_owned();
    lease_as(&f, &handle, leased).await;
    let key = lease_key(&f, "p");
    assert!(
        f.hub.leases.held_generation(&key).is_some(),
        "premise: leased"
    );
    let Fixture { hub, dir, .. } = f;
    drop(hub);
    let reopened = EventsHub::open(&crate::config::EventsConfig::default(), dir.path())
        .expect("the store reopens");
    assert!(
        reopened
            .store
            .subscriptions()
            .iter()
            .any(|s| s.name == "backend.pt.tools_changed"),
        "premise: the row survives the restart"
    );
    assert_eq!(reopened.leases.held_generation(&key), None);
    assert_eq!(
        reopened.leases.state(&key).await,
        crate::events::lease::LeaseState::CredentialNeeded
    );
    let files = files_under(dir.path());
    assert!(
        !files.is_empty(),
        "premise: the scan reads the store's files"
    );
    for file in files {
        let bytes = std::fs::read(&file).expect("readable");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&secret) && !text.contains(&claims),
            "{} holds the leased token",
            file.display()
        );
    }
}

/// LEASE-T4 end to end: a backend that answers the leased token with 401
/// wipes the lease at once, through the listener's own send (not a direct
/// call), and the admin view shows the row's credential as rejected.
#[tokio::test]
async fn lease_t4_a_401_from_the_backend_wipes_the_lease_and_shows_it_rejected() {
    let (a, b) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([a.to_string(), b.to_string()]).await;
    let f = fixture_with(&format!(
        "backends:\n  pt:\n    http_url: {}\n    streamable_http: true\n    \
         identity_propagation:\n      \
         strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n",
        peer.url
    ));
    let handle = subscribe(&f, "p", "pt", "p");
    let _listening = parked_listener(&f).await;
    // A token the backend does not accept: its first request is refused.
    lease_as(&f, &handle, token(Some(in_an_hour() + 120))).await;
    let key = lease_key(&f, "p");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while f.hub.leases.state(&key).await != LeaseState::CredentialRejected
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        f.hub.leases.state(&key).await,
        LeaseState::CredentialRejected,
        "the backend's 401 wiped the lease"
    );
    assert_eq!(f.hub.leases.held_generation(&key), None);
    let listed = f.hub.list_leases().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["state"], "credential_rejected");
    assert!(
        peer.streams.try_recv().is_err(),
        "no stream opened under it"
    );
}

/// LEASE-T2, held lease: another principal's lease call on P's row is
/// refused and leaves P's held lease exactly as it was, the same generation.
#[tokio::test]
async fn lease_t2_another_principals_call_leaves_a_held_lease_untouched() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    lease_as(&f, &handle, token(Some(in_an_hour()))).await;
    let key = lease_key(&f, "p");
    let before = f
        .hub
        .leases
        .held_generation(&key)
        .expect("premise: p holds a lease");
    let refused = f
        .hub
        .lease(
            Some("q"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour() + 60))),
        )
        .await
        .expect_err("not q's row");
    assert_eq!(refused.code, -32012);
    assert_eq!(
        f.hub.leases.held_generation(&key),
        Some(before),
        "p's lease is untouched: same generation"
    );
}

/// LEASE-T2, listener half: two principals lease their own tokens on one
/// backend. Each listener presents only its own principal's token (the peer
/// tells the streams apart by the token they carry), and a notice read on
/// Q's stream reaches Q's row alone, stamped with Q's lease.
#[tokio::test]
async fn lease_t2_each_principals_listener_reads_with_its_own_token_only() {
    let (p_token, q_token) = (token(Some(in_an_hour())), token(Some(in_an_hour() + 60)));
    let mut peer = two_token_peer([p_token.to_string(), q_token.to_string()]).await;
    let (f, _p_handle, _listening) = leased_listener(&mut peer, p_token).await;
    let q_handle = subscribe(&f, "q", "pt", "q");
    let q_key = lease_key(&f, "q");
    // Started as the hub starts a stored row, as `parked_listener` starts p.
    f.hub.replay_starts().await;
    f.hub
        .lease(
            Some("q"),
            "pt",
            Some(&json!({ "subscription": q_handle })),
            Some(q_token),
        )
        .await
        .expect("leased");
    assert_eq!(
        peer.next().await,
        Some(Stream::Opened(1)),
        "q's listener opened under q's token, never p's"
    );
    let mut intake = f.hub.take_intake();
    assert!(peer.push_tools_changed(1), "premise: q's stream is open");
    assert!(fan_out_next(&f, &mut intake).await, "q's notice was read");
    let q_stamp = crate::events::observation::lease_stamp(
        f.hub
            .leases
            .held_generation(&q_key)
            .expect("q holds a lease"),
    );
    assert_eq!(
        outbox_rows(&f),
        [("sub_q_pt".to_owned(), Some(q_stamp))],
        "q's notice reached q's row alone, under q's lease"
    );
}

/// ISO-T6 end to end: a subscriber who loses access is revoked by the sweep's
/// admission pass, and its listener's session on the backend closes though
/// the backend never sends a byte; nothing is read for it after.
#[tokio::test]
async fn iso_t6_a_revoked_subscribers_listener_closes_on_a_silent_backend() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let p_token = token(Some(in_an_hour()));
    let mut peer =
        two_token_peer([p_token.to_string(), token(Some(in_an_hour())).to_string()]).await;
    let (f, _handle, (listeners, _backend)) = leased_listener(&mut peer, p_token).await;
    let mut intake = f.hub.take_intake();
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    f.hub.revoke_inadmissible(None).await;
    assert!(f.hub.store.subscriptions().is_empty(), "premise: revoked");
    assert_eq!(
        peer.next().await,
        Some(Stream::Closed(0)),
        "the silent backend's session closed"
    );
    assert!(!peer.push_tools_changed(0), "no stream is left to read on");
    assert!(intake.try_recv().is_err(), "nothing was read for p");
    assert!(outbox_rows(&f).is_empty(), "nothing queued for p");
    assert!(
        listeners
            .entry_for(&crate::events::upstream_listener::ListenerKey {
                backend: "pt".into(),
                obs: Some(lease_key(&f, "p").obs),
            })
            .is_none(),
        "no listener is left for p to reconnect with"
    );
}

/// ISO-T6, pushed: a reconcile of the backend (the path a reload or a
/// credential change takes) revokes a subscriber who lost admission at once.
/// The fixture starts no worker, so no sweep can run: the listener's session
/// closes on the push alone, and nothing is read for it after.
#[tokio::test]
async fn iso_t6_a_pushed_revocation_closes_the_listener_without_the_sweep() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let p_token = token(Some(in_an_hour()));
    let mut peer =
        two_token_peer([p_token.to_string(), token(Some(in_an_hour())).to_string()]).await;
    let (f, _handle, (listeners, _backend)) = leased_listener(&mut peer, p_token).await;
    let mut intake = f.hub.take_intake();
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    f.hub.reconcile_backend("pt");
    assert_eq!(
        peer.next().await,
        Some(Stream::Closed(0)),
        "the push closed the session with no sweep running"
    );
    assert!(f.hub.store.subscriptions().is_empty(), "p's row is revoked");
    assert!(!peer.push_tools_changed(0), "no stream is left to read on");
    assert!(intake.try_recv().is_err(), "nothing was read for p");
    assert!(
        listeners
            .entry_for(&crate::events::upstream_listener::ListenerKey {
                backend: "pt".into(),
                obs: Some(lease_key(&f, "p").obs),
            })
            .is_none(),
        "no listener is left for p"
    );
}
