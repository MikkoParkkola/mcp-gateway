// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::events::client::Answer;

const POLICY: Retry = Retry {
    base: Duration::from_secs(10),
    max_attempts: 5,
    window: Duration::from_secs(900),
};

#[allow(clippy::unnecessary_wraps, reason = "judge reads the client's Result")]
fn status(code: u16) -> Result<Answer, CallbackFailure> {
    Ok(Answer {
        status: code,
        retry_after: None,
        body: Vec::new(),
    })
}

#[test]
fn delivered_gone_and_too_large_are_final() {
    let now = Utc::now();
    assert!(matches!(
        judge(&status(204), 1, now, now, POLICY, 0.5).0,
        Settle::Delivered
    ));
    for (code, want) in [(410, DeadReason::Gone), (413, DeadReason::TooLarge)] {
        let (settle, _) = judge(&status(code), 1, now, now, POLICY, 0.5);
        assert!(
            matches!(settle, Settle::Dead { reason, .. } if reason == want),
            "{code}"
        );
    }
}

#[test]
fn other_failures_retry_with_bounded_backoff_then_exhaust() {
    let now = Utc::now();
    let (settle, category) = judge(&status(503), 2, now, now, POLICY, 1.0);
    assert_eq!(category, "http_5xx");
    let Settle::Retry { next, .. } = settle else {
        panic!("retried");
    };
    assert_eq!(next - now, chrono::Duration::seconds(30), "base x 3");
    let (settle, category) = judge(&Err(CallbackFailure::Timeout), 5, now, now, POLICY, 0.0);
    assert_eq!(category, "timeout");
    assert!(matches!(
        settle,
        Settle::Dead {
            reason: DeadReason::Exhausted,
            ..
        }
    ));
    let late = now + chrono::Duration::seconds(900);
    let (settle, _) = judge(&status(307), 1, now, late, POLICY, 0.0);
    assert!(
        matches!(
            settle,
            Settle::Dead {
                reason: DeadReason::Exhausted,
                ..
            }
        ),
        "window over"
    );
}

#[test]
fn retry_after_is_honoured_inside_the_window() {
    let now = Utc::now();
    let answer = Ok(Answer {
        status: 429,
        retry_after: Some(Duration::from_secs(5000)),
        body: Vec::new(),
    });
    let (settle, _) = judge(&answer, 1, now, now, POLICY, 0.0);
    let Settle::Retry { next, .. } = settle else {
        panic!("retried");
    };
    assert_eq!(
        next - now,
        chrono::Duration::seconds(900),
        "clamped to the window"
    );
}

#[test]
fn an_attempt_past_its_bounds_is_overdue_before_it_is_sent() {
    let first = Utc::now();
    let inside = first + chrono::Duration::seconds(899);
    let after = first + chrono::Duration::seconds(900);
    assert!(
        !overdue(1, first, after, POLICY),
        "a first attempt always goes"
    );
    assert!(
        !overdue(5, first, inside, POLICY),
        "the last allowed attempt"
    );
    assert!(overdue(6, first, inside, POLICY), "past max_attempts");
    assert!(
        overdue(2, first, after, POLICY),
        "a retry at the window's end"
    );
}

/// A callback that counts the connections made to it; the handshake never
/// completes, which is all the test needs to see.
async fn counting_callback() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

/// One subscription to `port` and one pending record for it.
fn queued(hub: &EventsHub, port: u16, event_id: &str) {
    use crate::events::outbox::{Enqueued, OutboxCaps, OutboxState};
    use crate::events::records::Subscription;
    use crate::events::store::{Caps, TailPolicy};
    let now = Utc::now();
    let sub = Subscription {
        v: 1,
        id: "sub_worker".into(),
        principal: "p".into(),
        api_key: None,
        credential_kind: Some(crate::security::audit::CredentialKind::None),
        credential_principal: None,
        binding: None,
        legacy_api_key_name: None,
        read_key: None,
        url: format!("https://127.0.0.1:{port}/cb"),
        name: "webhook.c.r.received".into(),
        arguments: serde_json::json!({}),
        secret: format!("whsec_{}=", "A".repeat(43)),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + chrono::Duration::hours(1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
    };
    let tail = TailPolicy {
        ttl: Duration::from_secs(3600),
        max: 10,
        max_per_principal: 10,
    };
    let caps = Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(sub, true, caps, chrono::Duration::zero(), now, tail)
        .expect("io")
        .expect("admitted");
    let record = OutboxRecord {
        v: 1,
        event_id: event_id.into(),
        subscription_id: "sub_worker".into(),
        name: "webhook.c.r.received".into(),
        backend: "b".into(),
        owner_scoped: false,
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        attribution: None,
        attribution_keys: Vec::new(),
    };
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    assert_eq!(
        hub.store.enqueue(record, caps).expect("io"),
        Enqueued::Written
    );
}

/// A second pending record for the subscription `queued` made.
fn queued_event(hub: &EventsHub, event_id: &str) {
    use crate::events::outbox::{OutboxCaps, OutboxState};
    let now = Utc::now();
    let record = OutboxRecord {
        v: 1,
        event_id: event_id.into(),
        subscription_id: "sub_worker".into(),
        name: "webhook.c.r.received".into(),
        backend: "b".into(),
        owner_scoped: false,
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        attribution: None,
        attribution_keys: Vec::new(),
    };
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    hub.store.enqueue(record, caps).expect("io");
}

/// SAFETY.2 (MIK-7784): an attempt whose audit record the log refuses is not
/// sent (no `POST`) and goes back to retry; with a working log the same attempt
/// connects to the callback.
#[tokio::test]
async fn an_attempt_the_audit_log_refuses_is_not_sent() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("log"),
    );
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: Some(Arc::clone(&log)),
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
    };
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_refused");
    log.set_append_failure_for_test(true);
    hub.attempt(&services, "evt_refused").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no POST without a record"
    );
    let later = Utc::now() + chrono::Duration::minutes(5);
    let due = hub
        .store
        .due(later, &std::collections::HashSet::new())
        .expect("io");
    assert_eq!(due.ready.len(), 1, "the record waits for a retry");
    assert_eq!(
        due.ready[0].last_status.as_deref(),
        Some("audit_unavailable")
    );
    assert_eq!(due.ready[0].attempt, 1);

    // The control: with the log working, the same flow reaches the callback.
    log.set_append_failure_for_test(false);
    queued_event(&hub, "evt_sent");
    hub.attempt(&services, "evt_sent").await;
    assert!(
        accepted.load(Ordering::SeqCst) >= 1,
        "the attempt connects once the record is written"
    );
}
