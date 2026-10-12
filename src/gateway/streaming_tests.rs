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

/// A session whose stream is judged by an observing tenant guard and logged to
/// a `FailClosed` audit log, with its SSE body open. The temp dir keeps the log
/// alive; the caller decides when appends start failing.
#[cfg(feature = "firewall")]
#[allow(clippy::type_complexity)]
fn judged_sse() -> (
    tempfile::TempDir,
    Arc<crate::security::TransparencyLogger>,
    Arc<NotificationMultiplexer>,
    String,
    axum::body::BodyDataStream,
) {
    use crate::gateway::outbound::{RejectionAudit, SessionJudge};
    use crate::security::TransparencyLogger;
    use crate::security::audit::AuditFailurePolicy;
    use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::security::transparency_log::TransparencyLogConfig;
    use axum::response::IntoResponse;

    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir.path().join("audit.jsonl").display().to_string(),
            key_id: "r2".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .unwrap()
        .with_failure_policy(AuditFailurePolicy::FailClosed),
    );
    let firewall = Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                enabled: false,
                window_secs: 3600,
                arg_keys: vec!["customer_id".to_string()],
                cross_tenant_reads: CrossTenantReads::Observe,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    );
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    multiplexer.set_read_judge(
        SessionJudge::new(
            Some(Arc::new(firewall)),
            Arc::new(RejectionAudit::new(None, 1)),
            Some(Arc::clone(&log)),
        )
        .expect("the guard judges"),
    );
    let (id, _rx) = multiplexer.get_or_create_session(Some("s"));
    multiplexer.bind_session_reader(&id, "api_key:one".to_owned());
    let sse = create_sse_response(
        Arc::clone(&multiplexer),
        id.clone(),
        None,
        Duration::from_secs(3600),
    )
    .expect("the session exists");
    let body = sse.into_response().into_body().into_data_stream();
    (dir, log, multiplexer, id, body)
}

/// MIK-7848.READS.2, the destructive-confirmation case: with every audit
/// append failing under `FailClosed`, an item that names a tenant is withheld
/// at write (the control), but the `elicitation/create` confirmation prompt
/// names none, attempts no record, and reaches the stream. So a failing log
/// cannot hide the prompt and time the gate out into a legacy proceed.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_failing_audit_log_cannot_withhold_the_confirmation_prompt() {
    use crate::gateway::proxy::ProxyManager;
    use futures::StreamExt;

    let (_dir, log, multiplexer, id, mut body) = judged_sse();
    log.set_append_failure_for_test(true);

    let control = TaggedNotification {
        source: "demo".to_string(),
        event_type: "message".to_string(),
        data: json!({"jsonrpc": "2.0", "method": "notifications/x",
            "params": {"customer_id": "cust-b"}}),
        event_id: None,
    };
    assert!(
        multiplexer.send_to_session(&id, control),
        "the control is queued"
    );
    let proxy = ProxyManager::new(Arc::clone(&multiplexer));
    // The production gate builds and sends the prompt; nobody answers it, so
    // it is cut off once the stream has been read.
    let asked = tokio::time::timeout(
        Duration::from_secs(2),
        crate::gateway::destructive_confirmation::require_destructive_confirmation(
            &proxy,
            &id,
            "kill server 'payments'",
        ),
    );

    let mut seen = String::new();
    let read = async {
        while let Some(chunk) = body.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            if seen.contains("elicitation/create") {
                break;
            }
        }
    };
    let (_, _) = tokio::join!(asked, tokio::time::timeout(Duration::from_secs(2), read));

    assert!(
        seen.contains("elicitation/create"),
        "the prompt was withheld: {seen}"
    );
    assert!(
        seen.contains("cannot be undone"),
        "the prompt is the gate's own: {seen}"
    );
    assert!(
        !seen.contains("cust-b"),
        "control: a tenant item is withheld: {seen}"
    );
    assert_eq!(
        log.append_attempts_for_test(),
        1,
        "only the control tried a record"
    );
}

/// MIK-7975 WAIT.1: a server-to-client request whose stream item is withheld
/// for a failed audit write fails its waiter at once, not at its timeout. The
/// prompt's schema names a tenant, so it attempts a record, which fails closed.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_withheld_request_fails_its_waiter_at_once() {
    use crate::gateway::proxy::ProxyManager;
    use futures::StreamExt;

    let (_dir, log, multiplexer, id, mut body) = judged_sse();
    log.set_append_failure_for_test(true);
    let proxy = ProxyManager::new(Arc::clone(&multiplexer));
    let ask = crate::protocol::ElicitationCreateParams {
        mode: None,
        message: "Pick an account".to_string(),
        requested_schema: Some(json!({"customer_id": "cust-b"})),
        url: None,
    };
    let asked = proxy.forward_elicitation_with_response(&id, &ask, Duration::from_secs(30));
    // The stream must be read for its loop to judge, record and withhold.
    let read = async { while body.next().await.is_some() {} };
    let answer = tokio::select! {
        answer = tokio::time::timeout(Duration::from_secs(5), asked) => answer,
        () = read => panic!("the stream ended"),
    };
    assert!(
        matches!(
            answer,
            Ok(Err(crate::gateway::proxy::SamplingError::SendFailed))
        ),
        "the waiter was not failed at once: {answer:?}"
    );
    assert!(
        log.append_attempts_for_test() >= 1,
        "no record was attempted"
    );
}

/// MIK-7975 WAIT.1, the bridge's sender: a bridged request withheld at write
/// ends its wait at once, as a wait nothing came back to. Not `NoSession`:
/// the legacy bridge reads that as "no session at all" and re-asks round one.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_withheld_bridged_request_ends_its_wait_at_once() {
    use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
    use crate::gateway::proxy::ProxyManager;
    use futures::StreamExt;

    let (_dir, log, multiplexer, id, mut body) = judged_sse();
    log.set_append_failure_for_test(true);
    let proxy = ProxyManager::new(Arc::clone(&multiplexer));
    let params = json!({"customer_id": "cust-b"});
    let asked = proxy.send_request(&id, "bridge-1", "elicitation/create", Some(params));
    let read = async { while body.next().await.is_some() {} };
    let answer = tokio::select! {
        answer = tokio::time::timeout(Duration::from_secs(5), asked) => answer,
        () = read => panic!("the stream ended"),
    };
    assert!(
        matches!(answer, Ok(Err(DeliveryError::TimedOut))),
        "the bridged wait was not ended at once: {answer:?}"
    );
}

/// MIK-7975 WAIT.1: the watch fails a request only when every copy the send
/// reached was withheld, whatever order the send and the reports arrive in.
#[tokio::test]
async fn a_request_fails_only_when_every_copy_is_withheld() {
    let failed = |watch: &DeliveryWatch| futures::FutureExt::now_or_never(watch.failed()).is_some();
    let one_written = DeliveryWatch::default();
    one_written.sent(2);
    one_written.report(false);
    one_written.report(true);
    assert!(!failed(&one_written), "a copy was written");

    let all_withheld = DeliveryWatch::default();
    all_withheld.sent(2);
    all_withheld.report(false);
    assert!(!failed(&all_withheld), "one copy is still outstanding");
    all_withheld.report(false);
    assert!(failed(&all_withheld), "every copy was withheld");

    let reported_first = DeliveryWatch::default();
    reported_first.report(false);
    reported_first.report(false);
    assert!(
        !failed(&reported_first),
        "the send has not counted its copies"
    );
    reported_first.sent(2);
    assert!(
        failed(&reported_first),
        "both copies were withheld before the count"
    );
}

/// MIK-7918 AC1, the sampling case: backend sampling content can name a
/// tenant (here in a tool schema it offers), so under a failing `FailClosed`
/// log the request is withheld at write and its waiter fails at once.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_withheld_sampling_request_fails_its_waiter_at_once() {
    use crate::gateway::proxy::ProxyManager;
    use futures::StreamExt;

    let (_dir, log, multiplexer, id, mut body) = judged_sse();
    log.set_append_failure_for_test(true);
    let proxy = ProxyManager::new(Arc::clone(&multiplexer));
    let ask: crate::protocol::SamplingCreateMessageParams = serde_json::from_value(json!({
        "messages": [{"role": "user", "content": {"type": "text", "text": "Summarize"}}],
        "maxTokens": 16,
        "tools": [{"name": "lookup", "inputSchema": {"customer_id": "cust-b"}}]
    }))
    .expect("sampling params");
    let asked = proxy.forward_sampling_with_response(&id, &ask, Duration::from_secs(30));
    let mut seen = String::new();
    let read = async {
        while let Some(chunk) = body.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        }
    };
    let answer = tokio::select! {
        answer = tokio::time::timeout(Duration::from_secs(5), asked) => answer,
        () = read => panic!("the stream ended"),
    };
    assert!(
        matches!(
            answer,
            Ok(Err(crate::gateway::proxy::SamplingError::SendFailed))
        ),
        "the sampling waiter was not failed at once: {answer:?}"
    );
    assert!(
        !seen.contains("sampling/createMessage"),
        "the withheld request reached the stream: {seen}"
    );
    assert!(
        log.append_attempts_for_test() >= 1,
        "no record was attempted"
    );
}

/// MIK-7918 AC2: a confirmation prompt withheld at write reached nobody. The
/// gate must read that as `Undelivered`, never as `Unsupported` (a prompt that
/// may have been seen). The stream here reports its copy withheld directly.
#[tokio::test]
async fn a_withheld_confirmation_prompt_reads_as_undelivered() {
    use crate::gateway::destructive_confirmation::{
        ConfirmationOutcome, require_destructive_confirmation,
    };
    use crate::gateway::proxy::ProxyManager;

    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    let (id, mut rx) = multiplexer.get_or_create_session(Some("s"));
    let proxy = ProxyManager::new(Arc::clone(&multiplexer));
    let stream = async {
        let frame = rx.recv().await.expect("the prompt is queued");
        frame
            .watch
            .as_ref()
            .expect("a request carries a watch")
            .report(false);
    };
    let asked = require_destructive_confirmation(&proxy, &id, "kill server 'payments'");
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(asked, stream)
    })
    .await
    .expect("the withheld prompt ends the wait at once");
    assert_eq!(outcome, ConfirmationOutcome::Undelivered);
}

#[path = "streaming_tests/relay_commit.rs"]
mod relay_commit;

#[path = "streaming_tests/listen_graceful.rs"]
mod listen_graceful;

#[path = "streaming_tests/credential_at_write.rs"]
mod credential_at_write;

/// MIK-8288: session expiry follows the runtime's clock, the same clock the
/// reaper's ticker runs on, so a test can drive a TTL on a paused clock
/// instead of racing it on wall time. Red while expiry read the std clock:
/// the advance moved the ticker's time and not the session's age.
#[tokio::test(start_paused = true)]
async fn session_expiry_follows_a_paused_clock() {
    let ttl = Duration::from_secs(60);
    let m =
        NotificationMultiplexer::new(Arc::new(BackendRegistry::new()), StreamingConfig::default());
    let owner = SessionOwner::Credential("alice".to_owned());
    let (id, receiver) = m.get_or_create_session_for(None, &owner);
    drop(receiver);
    assert!(
        m.reap_expired_sessions(ttl).is_empty(),
        "premise: a new session is not expired"
    );
    tokio::time::advance(ttl + Duration::from_millis(1)).await;
    let reaped = m.reap_expired_sessions(ttl);
    assert_eq!(
        reaped,
        vec![id],
        "the session's age did not follow the paused clock"
    );
}
