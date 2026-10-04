// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[tokio::test]
async fn test_session_creation() {
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig::default();
    let multiplexer = NotificationMultiplexer::new(backends, config);

    let (session_id, _rx) = multiplexer.get_or_create_session(None);
    assert!(session_id.starts_with("gw-"));
    assert!(multiplexer.has_session(&session_id));
    assert_eq!(multiplexer.session_count(), 1);

    multiplexer.remove_session(&session_id);
    assert!(!multiplexer.has_session(&session_id));
    assert_eq!(multiplexer.session_count(), 0);
}

#[tokio::test]
async fn test_notification_send() {
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig::default();
    let multiplexer = NotificationMultiplexer::new(backends, config);

    let (session_id, mut rx) = multiplexer.get_or_create_session(Some("test-session"));

    let notification = TaggedNotification {
        source: "test-backend".to_string(),
        event_type: "notification".to_string(),
        data: json!({"message": "hello"}),
        event_id: Some("evt-1".to_string()),
    };

    assert!(multiplexer.send_to_session(&session_id, notification.clone()));

    let received = rx.recv().await.unwrap();
    assert_eq!(received.source, "test-backend");
    assert_eq!(received.event_type, "notification");
}

#[tokio::test]
async fn test_broadcast() {
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig::default();
    let multiplexer = NotificationMultiplexer::new(backends, config);

    let (_id1, mut rx1) = multiplexer.get_or_create_session(Some("session-1"));
    let (_id2, mut rx2) = multiplexer.get_or_create_session(Some("session-2"));

    let notification = TaggedNotification {
        source: "global".to_string(),
        event_type: "broadcast".to_string(),
        data: json!({"alert": "system"}),
        event_id: None,
    };

    multiplexer.broadcast(notification);

    let r1 = rx1.recv().await.unwrap();
    let r2 = rx2.recv().await.unwrap();
    assert_eq!(r1.source, "global");
    assert_eq!(r2.source, "global");
}

// ── Session reaper tests ─────────────────────────────────────────────

/// GIVEN a session with no active receivers and an elapsed TTL
/// WHEN `reap_expired_sessions` runs
/// THEN the session is removed
#[test]
fn reap_expired_sessions_removes_abandoned_sessions_past_ttl() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

    let (id, rx) = multiplexer.get_or_create_session(Some("expired-session"));
    assert_eq!(multiplexer.session_count(), 1);

    // Drop the receiver so receiver_count() == 0
    drop(rx);

    // WHEN: reap with zero TTL (everything is expired)
    let (captured, guard) = crate::gateway::session_id::log_capture::capture_debug();
    multiplexer.reap_expired_sessions(Duration::ZERO);
    drop(guard);

    // THEN
    assert_eq!(
        multiplexer.session_count(),
        0,
        "expired abandoned session must be reaped"
    );
    assert!(!multiplexer.has_session(&id));
    // F9-T7c: the reaper names the session by fingerprint only.
    crate::gateway::session_id::log_capture::assert_fingerprinted(
        &captured.text(),
        "Reaping expired streaming session",
        &id,
    );
}

/// GIVEN a session with an active receiver (SSE client still connected)
/// WHEN `reap_expired_sessions` runs with zero TTL
/// THEN the session is preserved because a client is still attached
#[test]
fn reap_expired_sessions_preserves_sessions_with_active_receivers() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

    let (id, _rx) = multiplexer.get_or_create_session(Some("active-session"));
    // `_rx` is still alive → receiver_count() == 1

    // WHEN: reap with zero TTL
    multiplexer.reap_expired_sessions(Duration::ZERO);

    // THEN: session survives because client is still connected
    assert_eq!(
        multiplexer.session_count(),
        1,
        "session with active receiver must be preserved"
    );
    assert!(multiplexer.has_session(&id));
}

/// GIVEN two sessions — one abandoned/expired, one with an active receiver
/// WHEN `reap_expired_sessions` runs
/// THEN only the abandoned session is removed
#[test]
fn reap_expired_sessions_selectively_removes_only_abandoned_sessions() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

    let (abandoned_id, rx_abandoned) = multiplexer.get_or_create_session(Some("abandoned"));
    let (active_id, _rx_active) = multiplexer.get_or_create_session(Some("active"));
    assert_eq!(multiplexer.session_count(), 2);

    drop(rx_abandoned); // No more receivers on abandoned session

    // WHEN
    multiplexer.reap_expired_sessions(Duration::ZERO);

    // THEN
    assert_eq!(multiplexer.session_count(), 1);
    assert!(
        !multiplexer.has_session(&abandoned_id),
        "abandoned session must be reaped"
    );
    assert!(
        multiplexer.has_session(&active_id),
        "active session must survive"
    );
}

/// GIVEN a session with no active receivers but within its TTL
/// WHEN `reap_expired_sessions` runs with a long TTL
/// THEN the session is NOT removed (TTL not yet elapsed)
#[test]
fn reap_expired_sessions_respects_ttl_for_recently_created_sessions() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = NotificationMultiplexer::new(backends, StreamingConfig::default());

    let (id, rx) = multiplexer.get_or_create_session(Some("young-session"));
    drop(rx); // No receivers, but session was just created

    // WHEN: reap with a 30-minute TTL — session is seconds old
    multiplexer.reap_expired_sessions(Duration::from_secs(1800));

    // THEN: session is preserved because it hasn't exceeded the TTL
    assert_eq!(multiplexer.session_count(), 1);
    assert!(multiplexer.has_session(&id));
}

/// GIVEN the multiplexer wrapped in Arc
/// WHEN `spawn_reaper_on` is called and sufficient time passes
/// THEN expired abandoned sessions are cleaned up automatically
#[tokio::test]
async fn spawn_reaper_on_reaps_sessions_automatically() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig {
        // Very short TTL and interval for the test
        session_ttl: Duration::from_millis(50),
        session_reaper_interval: Duration::from_millis(20),
        ..StreamingConfig::default()
    };

    let multiplexer = Arc::new(NotificationMultiplexer::new(backends, config));
    multiplexer.spawn_reaper_on(Arc::new(SessionLifecycle::new()));

    let (id, rx) = multiplexer.get_or_create_session(Some("auto-reap-session"));
    drop(rx); // Drop receiver immediately

    assert_eq!(multiplexer.session_count(), 1);

    // WHEN: wait for the reaper to fire (TTL=50ms, interval=20ms)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // THEN
    assert_eq!(
        multiplexer.session_count(),
        0,
        "reaper must have cleaned up expired session"
    );
    assert!(!multiplexer.has_session(&id));
}

/// T8 of the `MIK-7215.CONTROL.4` test plan.
///
/// GIVEN a lifecycle holding a key whose deadline has already passed
/// WHEN the host reaper tick runs
/// THEN the key is reclaimed — the tick sweeps the lifecycle, not just the
/// session map. Reaping is unconditional (D5): nothing here tells the tick
/// whether a request for that key is still in flight.
#[tokio::test]
async fn spawn_reaper_on_sweeps_the_session_lifecycle() {
    // GIVEN: a key whose deadline is the Unix epoch, i.e. long past.
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    lifecycle.track("stale-identity", 0);
    assert_eq!(lifecycle.tracked_count(), 1);

    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig {
        session_reaper_interval: Duration::from_millis(20),
        ..StreamingConfig::default()
    };
    let multiplexer = Arc::new(NotificationMultiplexer::new(backends, config));

    // WHEN: the host tick runs.
    multiplexer.spawn_reaper_on(Arc::clone(&lifecycle));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // THEN: the tick reclaimed it.
    assert_eq!(
        lifecycle.tracked_count(),
        0,
        "the reaper tick must sweep the lifecycle, not only the session map"
    );
}

/// MIK-7215.CONTROL.5, gap G2: a session the reaper removes is a real end,
/// so the session-end handlers fire for its id.
#[tokio::test]
async fn the_reaper_fires_session_end_handlers_for_a_reaped_session() {
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    let ended = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&ended);
    lifecycle.register_session_end("record", move |id| seen.lock().push(id.to_owned()));

    let config = StreamingConfig {
        session_reaper_interval: Duration::from_millis(20),
        session_ttl: Duration::from_millis(1),
        ..StreamingConfig::default()
    };
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        config,
    ));
    let (id, receiver) = multiplexer.get_or_create_session(None);
    drop(receiver);

    multiplexer.spawn_reaper_on(Arc::clone(&lifecycle));
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(!multiplexer.has_session(&id), "the session was reaped");
    assert_eq!(ended.lock().as_slice(), [id], "its end was announced once");
}

/// GIVEN the multiplexer dropped while reaper task is running
/// WHEN the Arc is dropped
/// THEN the reaper task exits cleanly (no panic, no leak)
#[tokio::test]
async fn spawn_reaper_on_exits_when_multiplexer_is_dropped() {
    // GIVEN
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig {
        session_reaper_interval: Duration::from_millis(10),
        ..StreamingConfig::default()
    };

    let multiplexer = Arc::new(NotificationMultiplexer::new(backends, config));
    multiplexer.spawn_reaper_on(Arc::new(SessionLifecycle::new()));

    // WHEN: drop the only strong reference
    drop(multiplexer);

    // THEN: give the task a tick to observe the weak ref is gone — no panic
    tokio::time::sleep(Duration::from_millis(50)).await;
    // If we reach here without a panic, the reaper exited cleanly.
}

/// MIK-7215.CONTROL.5, gap G2 (#2567): a hardened resume is activity. A session
/// resumed after its TTL from creation, and reaped at once, survives.
#[tokio::test]
async fn a_hardened_resume_keeps_a_busy_session_from_the_reaper() {
    let m =
        NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
    let owner = SessionOwner::Credential("alice".to_owned());
    let (id, receiver) = m.get_or_create_session_for(None, &owner);
    drop(receiver);
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert!(m.resume_session_scoped(Some(&id), &owner, None).is_some());

    assert!(
        m.reap_expired_sessions(Duration::from_millis(50))
            .is_empty(),
        "a session resumed just now is not idle"
    );
}

/// The direct backend route acts under a presented session without resuming
/// its stream; that use is activity too.
#[tokio::test]
async fn a_direct_backend_request_keeps_a_busy_session_from_the_reaper() {
    let m =
        NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
    let owner = SessionOwner::Credential("alice".to_owned());
    let (id, receiver) = m.get_or_create_session_for(None, &owner);
    drop(receiver);
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert!(m.touch_if_owned(&id, &owner));

    assert!(
        m.reap_expired_sessions(Duration::from_millis(50))
            .is_empty(),
        "a session used just now is not idle"
    );
}

/// MIK-7883.SCAN.1: a non-message event goes out as the whole tagged
/// notification, `source` and `event_id` included, so the judge scans them.
/// A configured `arg_keys` name equal to `source` that names another tenant
/// is withheld under `block`; with no judge both pass (the control).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_non_message_event_is_judged_with_its_wrapper_fields() {
    use crate::gateway::outbound::{RejectionAudit, SessionJudge};
    use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
    use crate::security::firewall::{Firewall, FirewallConfig};

    let note = |source: &str| TaggedNotification {
        source: source.to_string(),
        event_type: "notification".to_string(),
        data: json!({"note": "x"}),
        event_id: None,
    };
    let session = |judged: bool| {
        let multiplexer = NotificationMultiplexer::new(
            Arc::new(BackendRegistry::new()),
            StreamingConfig::default(),
        );
        if judged {
            let firewall = Firewall::from_config(
                FirewallConfig {
                    tenant_guard: TenantGuardConfig {
                        enabled: false,
                        window_secs: 3600,
                        arg_keys: vec!["source".to_string()],
                        cross_tenant_reads: CrossTenantReads::Block,
                        ..TenantGuardConfig::default()
                    },
                    ..FirewallConfig::default()
                },
                None,
            );
            let judge = SessionJudge::new(
                Some(Arc::new(firewall)),
                Arc::new(RejectionAudit::new(None, 1)),
                None,
            )
            .expect("the guard judges");
            multiplexer.set_read_judge(judge);
        }
        let (id, rx) = multiplexer.get_or_create_session(Some("s"));
        multiplexer.bind_session_reader(&id, "api_key:one".to_owned());
        (multiplexer, id, rx)
    };

    let (plain, id, _rx) = session(false);
    assert!(plain.send_to_session(&id, note("cust-a")), "control: first");
    assert!(
        plain.send_to_session(&id, note("cust-b")),
        "control: second"
    );

    let (judged, id, _rx) = session(true);
    assert!(judged.send_to_session(&id, note("cust-a")), "first read");
    assert!(
        !judged.send_to_session(&id, note("cust-b")),
        "another tenant named by `source` must be withheld under block"
    );
}
