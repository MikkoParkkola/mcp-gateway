// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
use super::*;
use crate::events::client::Answer;
#[cfg(feature = "cost-governance")]
use fixtures::budgeted;
use fixtures::{
    Flipping, Offering, audit_actions, config_default, counting_callback, descriptor,
    logged_services, offer, queued, queued_as, queued_event, queued_stamped, queued_with,
};

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
    assert_eq!(
        next - now,
        crate::duration_bound::delta!(seconds, 30),
        "base x 3"
    );
    let (settle, category) = judge(&Err(CallbackFailure::Timeout), 5, now, now, POLICY, 0.0);
    assert_eq!(category, "timeout");
    assert!(matches!(
        settle,
        Settle::Dead {
            reason: DeadReason::Exhausted,
            ..
        }
    ));
    let late = now + crate::duration_bound::delta!(seconds, 900);
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
        crate::duration_bound::delta!(seconds, 900),
        "clamped to the window"
    );
}

#[test]
fn an_attempt_past_its_bounds_is_overdue_before_it_is_sent() {
    let first = Utc::now();
    let inside = first + crate::duration_bound::delta!(seconds, 899);
    let after = first + crate::duration_bound::delta!(seconds, 900);
    assert!(
        !overdue(1, 1, first, after, POLICY),
        "a first attempt always goes"
    );
    assert!(
        !overdue(5, 5, first, inside, POLICY),
        "the last allowed attempt"
    );
    assert!(overdue(6, 6, first, inside, POLICY), "past max_attempts");
    assert!(
        overdue(2, 2, first, after, POLICY),
        "a retry at the window's end"
    );
    // MIK-7944 .2: unsent claims number the attempt but not the limit, and
    // never lift the window.
    assert!(
        !overdue(6, 1, first, inside, POLICY),
        "one send of six claims"
    );
    assert!(
        overdue(2, 1, first, after, POLICY),
        "an unsent retry ages out"
    );
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
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    };
    let (port, accepted) = counting_callback().await;
    offer(&hub, &["webhook.c.r.received"]);
    queued(&hub, port, "evt_refused");
    log.set_append_failure_for_test(true);
    hub.attempt(&services, "evt_refused").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "no POST without a record"
    );
    let later = Utc::now() + crate::duration_bound::delta!(minutes, 5);
    let due = hub
        .store
        .due(later, &std::collections::HashSet::new(), hub.dead_policy())
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

/// MIK-7894: a pending record for a backend event type no source offers any
/// more (a reload made the backend ineligible and its withdrawal failed) is
/// refused, not sent. The control: the same record under a webhook type a
/// source offers reaches the callback.
#[tokio::test]
async fn a_backend_type_no_source_offers_is_not_sent() {
    use std::sync::atomic::Ordering;
    for (name, sent) in [
        ("webhook.c.r.received", true),
        ("backend.b.resource_updated", false),
    ] {
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
            audit: Some(log),
            provenance: None,
            public_provenance: None,
            #[cfg(feature = "cost-governance")]
            budget: None,
            credentials: crate::events::LiveCredentials::default(),
            record_key: Some(crate::gateway::record_principal::test_key_arc()),
        };
        let (port, accepted) = counting_callback().await;
        offer(&hub, &["webhook.c.r.received"]);
        queued_as(&hub, port, "evt", name);
        hub.attempt(&services, "evt").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(accepted.load(Ordering::SeqCst) >= 1, sent, "{name}");
        // Refused, not held: the backend subscription goes (MIK-7976 WORKER.3).
        assert_eq!(hub.store.subscriptions().is_empty(), !sent, "{name}");
    }
}

/// MIK-7842 AUDIT.3: an ending the audit log refuses (here an overdue record)
/// is not buried unrecorded; it goes back to retry and is recorded once the
/// log recovers.
#[tokio::test]
async fn an_overdue_ending_the_audit_log_refuses_is_retried_not_buried() {
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
        retry_max_attempts: 0,
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
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    };
    offer(&hub, &["webhook.c.r.received"]);
    queued(&hub, 9, "evt_overdue");
    log.set_append_failure_for_test(true);
    hub.attempt(&services, "evt_overdue").await;
    let later = Utc::now() + crate::duration_bound::delta!(minutes, 5);
    let due = hub
        .store
        .due(later, &std::collections::HashSet::new(), hub.dead_policy())
        .expect("io");
    assert_eq!(due.ready.len(), 1, "still pending, not buried");
    assert_eq!(
        due.ready[0].last_status.as_deref(),
        Some("audit_unavailable")
    );
    // MIK-7944 .2: the refused ending sent nothing, so it is no send.
    assert_eq!(due.ready[0].unsent, 1);

    // AUDIT.1, AUDIT.2: with the log back, the ending is recorded with the
    // documented values for a record fan-out never stamped and a send that
    // never built a body.
    log.set_append_failure_for_test(false);
    queued_event(&hub, "evt_overdue_two");
    hub.attempt(&services, "evt_overdue_two").await;
    let written = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    let line = written
        .lines()
        .find(|l| l.contains("evt_overdue_two"))
        .expect("the ending is recorded");
    assert!(
        line.contains("\"firewall_verdict\":\"unrecorded\""),
        "{line}"
    );
    assert!(line.contains("\"body_sha256\":\"\""), "{line}");
}

/// MIK-7894: eligibility is read again after the waits for the record, as the
/// signing row is. A source that turns its verdict to `-32012` after the first
/// check (a reload during the `sending` record's write) gets no POST and no
/// charge; the attempt on record ends `access_revoked`. The control: a source
/// that keeps admitting is charged and reaches the callback.
#[tokio::test]
async fn eligibility_lost_after_the_sending_record_is_not_sent_or_charged() {
    use std::sync::atomic::Ordering;
    for (admits, sent) in [(usize::MAX, true), (1, false)] {
        let dir = tempfile::tempdir().expect("dir");
        let config = crate::config::EventsConfig {
            callback_allow_private: vec!["127.0.0.0/8".into()],
            cost_per_delivery_usd: 0.01,
            ..crate::config::EventsConfig::default()
        };
        let hub = EventsHub::open(&config, dir.path()).expect("hub");
        let source = Arc::new(Flipping {
            admits,
            asked: std::sync::atomic::AtomicUsize::new(0),
            free: &[],
        });
        hub.register_source(Arc::clone(&source) as Arc<dyn crate::events::EventSource>);
        #[allow(unused_mut, reason = "set only with cost-governance")]
        let mut services = logged_services(dir.path());
        #[cfg(feature = "cost-governance")]
        let registry = budgeted(&mut services);
        let (port, accepted) = counting_callback().await;
        queued_as(&hub, port, "evt_flip", "probe.flip");
        hub.attempt(&services, "evt_flip").await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            accepted.load(Ordering::SeqCst) >= 1,
            sent,
            "admits {admits}"
        );
        #[cfg(feature = "cost-governance")]
        assert_eq!(
            registry.snapshot().contains_key("events:probe.flip"),
            sent,
            "charged only when sent (admits {admits})"
        );
        if sent {
            continue;
        }
        assert_eq!(source.asked.load(Ordering::SeqCst), 2, "asked again");
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
        assert!(log.contains("\"status\":\"sending\""), "{log}");
        let ended = audit_actions(dir.path(), "events.delivery_outcome");
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert_eq!(ended[0]["status"], "access_revoked");
        assert!(
            hub.store.subscriptions().is_empty(),
            "the refused subscription is revoked"
        );
    }
}

/// MIK-7976 WORKER.1, WORKER.2: a pending record whose type its source has
/// withdrawn (the source switched off, here replaced by one offering nothing)
/// is not sent and not charged, and its attempt ends on record. The control:
/// with the type still offered the same record is charged and sent.
#[tokio::test]
async fn a_type_no_source_offers_any_more_is_not_sent_or_charged() {
    use crate::events::types::SourceKind;
    use std::sync::atomic::Ordering;
    for (withdrawn, sent) in [(false, true), (true, false)] {
        let dir = tempfile::tempdir().expect("dir");
        let config = crate::config::EventsConfig {
            callback_allow_private: vec!["127.0.0.0/8".into()],
            cost_per_delivery_usd: 0.01,
            ..crate::config::EventsConfig::default()
        };
        let hub = EventsHub::open(&config, dir.path()).expect("hub");
        hub.register_source(Arc::new(Offering {
            kind: SourceKind::GatewayOperational,
            names: vec!["probe.gone"],
        }));
        #[allow(unused_mut, reason = "set only with cost-governance")]
        let mut services = logged_services(dir.path());
        #[cfg(feature = "cost-governance")]
        let registry = budgeted(&mut services);
        let (port, accepted) = counting_callback().await;
        queued_as(&hub, port, "evt_gone", "probe.gone");
        if withdrawn {
            hub.register_source(Arc::new(Offering {
                kind: SourceKind::GatewayOperational,
                names: Vec::new(),
            }));
        }
        hub.attempt(&services, "evt_gone").await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            accepted.load(Ordering::SeqCst) >= 1,
            sent,
            "POST (withdrawn {withdrawn})"
        );
        #[cfg(feature = "cost-governance")]
        assert_eq!(
            registry.snapshot().contains_key("events:probe.gone"),
            sent,
            "charged only when sent (withdrawn {withdrawn})"
        );
        if sent {
            continue;
        }
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
        assert!(
            log.lines()
                .any(|l| l.contains("evt_gone") && l.contains("\"status\":\"source_unavailable\"")),
            "the refused attempt is on record: {log}"
        );
    }
}

#[cfg(feature = "cost-governance")]
#[path = "worker_charge_tests.rs"]
mod charge;

#[path = "worker_burial_tests.rs"]
mod burial;

#[path = "worker_vault_fence_tests.rs"]
mod vault_fence;

#[path = "worker_audit_order_tests.rs"]
mod audit_order;
#[path = "worker_hold_tests.rs"]
mod hold;

#[path = "worker_recheck_tests.rs"]
mod recheck;

#[path = "worker_owner_tests.rs"]
mod owner;

#[path = "worker_clock_tests.rs"]
mod clock;

#[path = "worker_fixtures_tests.rs"]
mod fixtures;
