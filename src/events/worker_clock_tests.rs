// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P3: the events store and worker on a host clock before 1970.
//! Rows E1a-E1d, E3, E3b, E3c and E5 of the P3 design's test plan. The clock
//! override is per thread, so each row forces it on the thread that reads:
//! the test's own (a current-thread runtime runs the attempt there too).

use std::sync::Arc;

use chrono::Utc;

use super::{counting_callback, logged_services, offer, queued, queued_with};
use crate::clock::test_clock::{Forced, before_epoch};
use crate::duration_bound::delta;
use crate::events::EventsHub;
use crate::events::outbox::{OutboxRecord, OutboxState};

const NAME: &str = "webhook.c.r.received";

/// The real time, through the one clock reader (outside any forced clock).
fn now() -> chrono::DateTime<Utc> {
    crate::clock::utc_now().expect("a readable clock")
}

fn private_callbacks() -> crate::config::EventsConfig {
    crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    }
}

/// A record as stored on disk.
fn stored(dir: &std::path::Path, event_id: &str) -> OutboxRecord {
    let file = dir.join("outbox").join(OutboxRecord::file(event_id));
    serde_json::from_slice(&std::fs::read(file).expect("read")).expect("record")
}

/// Run `attempt` with this thread's clock failing from pause point `slot`
/// on. The returned guard keeps it failing until dropped.
async fn clock_fails_at(
    slot: &crate::test_pause::Slot,
    attempt: impl std::future::Future<Output = ()>,
) -> Forced {
    let (reached, release) = slot.arm();
    let drive = async {
        reached.notified().await;
        let clock = before_epoch();
        release.notify_one();
        clock
    };
    let ((), clock) =
        crate::test_pause::within("the attempt", async { tokio::join!(attempt, drive) }).await;
    clock
}

/// E1a: a commanded removal (a reload withdrawing the type) on an
/// unreadable clock still removes the row and cancels its records, and
/// stamps no tail end: the opt-in's tail dates from the opt-in itself, not
/// from 1970.
#[tokio::test]
async fn a_withdrawal_on_an_unreadable_clock_removes_without_stamping_the_tail() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    queued(&hub, 9, "evt_a");
    let row = hub.store.get("sub_worker").expect("premise: admitted");
    {
        let _clock = before_epoch();
        assert!(
            hub.withdraw_rows(std::slice::from_ref(&row)),
            "a withdrawal refused on an unreadable clock"
        );
    }
    assert!(hub.store.get("sub_worker").is_none(), "row removed");
    assert!(
        !dir.path()
            .join("outbox")
            .join(OutboxRecord::file("evt_a"))
            .exists(),
        "its pending record cancelled"
    );
    assert!(
        hub.store.is_verified(
            &row.principal,
            &row.url,
            now(),
            crate::events::tail_policy(&config)
        ),
        "the tail was stamped as ended in 1970"
    );
}

/// E1d: a store opened on an unreadable clock keeps every row, and an
/// in-flight record recovered at open keeps its own date, not 1970.
#[tokio::test]
async fn a_store_opened_on_an_unreadable_clock_keeps_its_dates() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    queued(&hub, 9, "evt_d");
    assert!(matches!(
        hub.store.claim("evt_d", now()).expect("io"),
        crate::events::store::Claim::Ready(_)
    ));
    let before = stored(dir.path(), "evt_d");
    assert_eq!(before.state, OutboxState::InFlight, "premise: in flight");
    drop(hub);
    let reopened = {
        let _clock = before_epoch();
        EventsHub::open(&config, dir.path()).expect("reopen")
    };
    assert!(reopened.store.get("sub_worker").is_some(), "row kept");
    let after = stored(dir.path(), "evt_d");
    assert_eq!(after.state, OutboxState::Pending, "recovered");
    assert_eq!(
        after.next_attempt_at, before.next_attempt_at,
        "the recovered record was re-dated on an unreadable clock"
    );
}

/// E1b: a hold pass on an unreadable clock changes nothing (no `held_until`
/// near the epoch, which would bury the row once the clock reads) and
/// reports an error, so its caller retries; on a readable clock the same
/// pass holds the row with a real bound.
#[tokio::test]
async fn a_hold_pass_on_an_unreadable_clock_changes_nothing() {
    use crate::events::store::{Held, Judged};
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    queued(&hub, 9, "evt_b");
    let judge = |_: &crate::events::records::Subscription| {
        Some(Judged {
            held: Some(Held {
                reason: "not offered",
                key: None,
            }),
            ..Judged::default()
        })
    };
    let bound = delta!(hours, 1);
    let skipped = {
        let _clock = before_epoch();
        hub.store
            .apply_holds(&judge, crate::clock::utc_now(), bound)
    };
    assert!(skipped.is_err(), "the caller is told to retry");
    let row = hub.store.get("sub_worker").expect("row");
    assert_eq!(row.held_until, None, "a hold dated on an unreadable clock");
    assert!(hub.store.held("sub_worker").is_none(), "nothing held");
    // Recovery: the next pass on a readable clock holds it, with a real bound.
    hub.store
        .apply_holds(&judge, crate::clock::utc_now(), bound)
        .expect("io");
    let held_until = hub
        .store
        .get("sub_worker")
        .and_then(|r| r.held_until)
        .expect("held");
    assert!(held_until > now(), "a real bound");
}

/// E1b: a hold that has already lapsed is not revived by a resume pass on
/// an unreadable clock: at 1969 every row reads live, and the resume would
/// clear the lapsed `held_until`.
#[tokio::test]
async fn a_lapsed_hold_is_not_revived_on_an_unreadable_clock() {
    use crate::events::store::{Held, Judged};
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    queued(&hub, 9, "evt_l");
    let hold = |_: &crate::events::records::Subscription| {
        Some(Judged {
            held: Some(Held {
                reason: "not offered",
                key: None,
            }),
            ..Judged::default()
        })
    };
    // Held two hours ago for one hour: lapsed an hour ago.
    hub.store
        .apply_holds(&hold, Ok(now() - delta!(hours, 2)), delta!(hours, 1))
        .expect("io");
    let lapsed = hub.store.get("sub_worker").and_then(|r| r.held_until);
    assert!(lapsed.is_some_and(|at| at < now()), "premise: lapsed");
    let resume = |_: &crate::events::records::Subscription| Some(Judged::default());
    {
        let _clock = before_epoch();
        let skipped = hub
            .store
            .apply_holds(&resume, crate::clock::utc_now(), delta!(hours, 1));
        assert!(skipped.is_err(), "the caller is told to retry");
    }
    assert_eq!(
        hub.store.get("sub_worker").and_then(|r| r.held_until),
        lapsed,
        "a lapsed hold was revived on an unreadable clock"
    );
}

/// E1c: a burial on an unreadable clock is deferred: the record stays
/// pending with its reason and its date, with no 1969 `dead_at` and nothing
/// evicted. Recovery: the next attempt on a readable clock buries it, dated.
#[tokio::test]
async fn a_burial_on_an_unreadable_clock_waits_for_a_readable_one() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = Arc::new(logged_services(dir.path()));
    offer(&hub, &[NAME]);
    queued(&hub, 9, "evt_c");
    // In flight, as the worker holds it when it settles.
    assert!(matches!(
        hub.store.claim("evt_c", now()).expect("io"),
        crate::events::store::Claim::Ready(_)
    ));
    let record = stored(dir.path(), "evt_c");
    assert_eq!(record.state, OutboxState::InFlight, "premise: claimed");
    let gone = crate::events::store::Settle::Dead {
        reason: crate::events::outbox::DeadReason::Gone,
        status: None,
    };
    {
        let _clock = before_epoch();
        hub.settle(&services, &record, gone).await;
    }
    assert!(
        hub.store.dead_letter_by_id("evt_c").is_none(),
        "buried on an unreadable clock"
    );
    let left = stored(dir.path(), "evt_c");
    assert_eq!(left.state, OutboxState::Pending, "never left in flight");
    assert_eq!(
        left.dead_as,
        Some(crate::events::outbox::DeadReason::Gone),
        "the burial is remembered"
    );
    assert_eq!(left.next_attempt_at, record.next_attempt_at, "date kept");
    // Recovery: the next attempt buries it, dated by a readable clock.
    hub.attempt(&services, "evt_c").await;
    let dead = hub.store.dead_letter_by_id("evt_c").expect("buried");
    assert!(
        dead.dead_at > now() - delta!(minutes, 5),
        "dated 1969: {}",
        dead.dead_at
    );
}

/// Queue a record already sent once, first tried 30 days ago: past any
/// retry window, so a readable clock would bury it `exhausted`.
fn queued_overdue(hub: &EventsHub, port: u16, event_id: &str) {
    queued_with(hub, port, event_id, NAME, |_, record| {
        record.attempt = 1;
        record.first_attempt_at = Some(now() - delta!(days, 30));
    });
}

/// What an attempt the clock refused must leave: pending, unsent and
/// uncounted, with its own date, and nothing sent or buried.
fn assert_kept_unsent(
    hub: &EventsHub,
    dir: &std::path::Path,
    before: &OutboxRecord,
    event_id: &str,
    posts: usize,
) {
    assert_eq!(posts, 0, "sent on an unreadable clock");
    assert!(
        hub.store.dead_letter_by_id(event_id).is_none(),
        "buried on an unreadable clock"
    );
    let after = stored(dir, event_id);
    assert_eq!(after.state, OutboxState::Pending, "never left in flight");
    assert_eq!(after.last_status.as_deref(), Some("clock_unreadable"));
    assert_eq!(after.next_attempt_at, before.next_attempt_at, "date kept");
    assert_eq!(after.sends(), before.sends(), "an unsent attempt counted");
}

/// The delivery-outcome audit rows for `event_id`.
fn outcomes(dir: &std::path::Path, event_id: &str) -> Vec<serde_json::Value> {
    super::audit_actions(dir, "events.delivery_outcome")
        .into_iter()
        .filter(|r| r["event_id"] == event_id)
        .collect()
}

/// E3: the clock reads at the claim, then fails before the retry window is
/// judged. The overdue record is neither sent nor buried.
#[tokio::test]
async fn an_overdue_record_is_neither_sent_nor_buried_when_the_clock_fails_after_the_claim() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued_overdue(&hub, port, "evt_e3");
    let before = stored(dir.path(), "evt_e3");
    let clock = Box::pin(clock_fails_at(
        &hub.after_claim,
        hub.attempt(&services, "evt_e3"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_e3", posts);
}

/// E3b: the clock reads through the claim, the first window check and the
/// attempt record, then fails at the last retry-window read. The record is
/// kept unsent, and the attempt on record is closed `clock_unreadable`,
/// undated.
#[tokio::test]
async fn a_clock_that_fails_at_the_last_window_read_sends_and_buries_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        cost_per_delivery_usd: 0.01,
        ..private_callbacks()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    #[cfg_attr(not(feature = "cost-governance"), allow(unused_mut))]
    let mut services = logged_services(dir.path());
    // The signer refuses on the same clock, so what tells this check apart
    // is the charge it prevents: nothing is charged for an unsent attempt.
    #[cfg(feature = "cost-governance")]
    let registry = super::budgeted(&mut services);
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_e3b");
    let before = stored(dir.path(), "evt_e3b");
    let clock = Box::pin(clock_fails_at(
        &hub.before_window,
        hub.attempt(&services, "evt_e3b"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_e3b", posts);
    let rows = outcomes(dir.path(), "evt_e3b");
    assert_eq!(rows.len(), 1, "the attempt on record is closed: {rows:?}");
    assert_eq!(rows[0]["status"], "clock_unreadable");
    assert_eq!(rows[0]["timestamp"], serde_json::Value::Null, "{}", rows[0]);
    assert_eq!(rows[0]["clock_invalid"], true, "{}", rows[0]);
    #[cfg(feature = "cost-governance")]
    assert!(
        !registry.snapshot().contains_key(&format!("events:{NAME}")),
        "charged for an attempt that was never sent"
    );
}

/// E3c: the clock reads through the last window check, then fails at the
/// signer. Nothing is sent; the record keeps its retry date and its send
/// count, and its subscription's failure window does not move.
#[tokio::test]
async fn a_signer_that_cannot_read_the_clock_sends_nothing_and_counts_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    // One counted failure would suspend the row, so a refusal that moved
    // the failure window fails this row.
    let config = crate::config::EventsConfig {
        suspend_min_attempts: 1,
        ..private_callbacks()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_e3c");
    let before = stored(dir.path(), "evt_e3c");
    let clock = Box::pin(clock_fails_at(
        &hub.before_send,
        hub.attempt(&services, "evt_e3c"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_e3c", posts);
    let row = hub.store.get("sub_worker").expect("row");
    assert!(row.active, "suspended for a send it never made");
}

/// A refusal judged on an unreadable clock may be the clock's (every
/// expiring credential then reads expired), and a revocation deletes the row
/// for good: on such a clock the row and its records are kept. On a readable
/// clock the same revocation deletes them.
#[tokio::test]
async fn a_revocation_on_an_unreadable_clock_keeps_the_row() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    queued(&hub, 9, "evt_r");
    let row = hub.store.get("sub_worker").expect("premise: admitted");
    let record = dir.path().join("outbox").join(OutboxRecord::file("evt_r"));
    {
        let _clock = before_epoch();
        hub.revoke(&row).await;
    }
    assert!(
        hub.store.get("sub_worker").is_some(),
        "revoked on a refusal the clock may have caused"
    );
    assert!(record.exists(), "its pending record was cancelled");
    hub.revoke(&row).await;
    assert!(hub.store.get("sub_worker").is_none(), "control: revoked");
}

/// E5: the expiry watermark does not move on an unreadable clock (it was
/// set to 1970, so the next readable tick rescanned every deadline).
#[tokio::test]
async fn the_expiry_watermark_holds_on_an_unreadable_clock() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    queued(&hub, 9, "evt_w");
    hub.stop_expired_keys().await;
    let seen = hub.runtime.expiry_seen.lock().at;
    {
        let _clock = before_epoch();
        hub.stop_expired_keys().await;
    }
    assert_eq!(
        hub.runtime.expiry_seen.lock().at,
        seen,
        "the watermark moved on an unreadable clock"
    );
}

/// The live config with one API key `k` for `secret`, expiring at `expires_at`.
fn keyed(secret: &str, expires_at: chrono::DateTime<Utc>) -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.auth.api_keys = vec![crate::config::ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: Some(expires_at),
        name: "k".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }];
    config
}

/// The same refusal end to end, on a subscription held by an expiring API
/// key: a clock that fails after the claim reads the key as expired, and the
/// row is kept, nothing sent. Recovery: on a readable clock the key, still
/// valid, is admitted and the event is sent, the row kept; once the key has
/// truly expired, the refusal stands and the row is revoked.
#[tokio::test]
async fn an_expiring_key_refused_by_an_unreadable_clock_keeps_its_subscription() {
    const SECRET: &str = "clock-revoke-secret";
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    services.live.set(keyed(SECRET, now() + delta!(days, 7)));
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued_with(&hub, port, "evt_k", NAME, |sub, _| {
        sub.credential_kind = Some(crate::security::audit::CredentialKind::ApiKey);
        sub.api_key = Some(crate::events::records::ApiKeyRef {
            name: "k".to_owned(),
            principal: crate::gateway::auth::principal_of(SECRET),
        });
    });
    let posts = || accepted.load(std::sync::atomic::Ordering::SeqCst);

    let clock = Box::pin(clock_fails_at(
        &hub.after_claim,
        hub.attempt(&services, "evt_k"),
    ))
    .await;
    drop(clock);
    assert!(
        hub.store.get("sub_worker").is_some(),
        "revoked on a refusal the clock caused"
    );
    let kept = stored(dir.path(), "evt_k");
    assert_eq!(kept.state, OutboxState::Pending, "never left in flight");
    assert_eq!(
        kept.last_status.as_deref(),
        Some("clock_unreadable"),
        "judged a refusal that stands"
    );
    assert_eq!(posts(), 0, "sent on an unreadable clock");

    // Readable, the key is still valid: admitted and sent, the row kept.
    Box::pin(hub.attempt(&services, "evt_k")).await;
    crate::test_pause::within("the post", async {
        while posts() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(hub.store.get("sub_worker").is_some(), "a valid key kept");

    // The key has truly expired: the refusal stands and the row goes.
    services.live.set(keyed(SECRET, now() - delta!(minutes, 1)));
    Box::pin(hub.attempt(&services, "evt_k")).await;
    assert!(
        hub.store.get("sub_worker").is_none(),
        "a refusal that still stands was not revoked"
    );
}

/// The access re-check after the attempt is on record: the clock fails there
/// (and stays failed through the revocation guard). The check is `Undated`:
/// the attempt is closed `clock_unreadable`, the record kept unsent with its
/// date, the row kept, and nothing sent.
#[tokio::test]
async fn an_undated_recheck_after_the_attempt_is_on_record_keeps_everything() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_rc");
    let before = stored(dir.path(), "evt_rc");
    let clock = Box::pin(clock_fails_at(
        &hub.before_recheck,
        hub.attempt(&services, "evt_rc"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_rc", posts);
    assert!(hub.store.get("sub_worker").is_some(), "the row was revoked");
    let rows = outcomes(dir.path(), "evt_rc");
    assert_eq!(rows.len(), 1, "the attempt on record is closed: {rows:?}");
    assert_eq!(rows[0]["status"], "clock_unreadable");
}

/// A dead-letter replay whose access check the clock cannot judge (the lease
/// reads, then the clock fails at the check) is refused as unavailable, a
/// transient fault, never as access revoked.
#[tokio::test]
async fn a_replay_the_clock_cannot_judge_is_unavailable_not_revoked() {
    use crate::events::admin::ReplayRefusal;
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = Arc::new(logged_services(dir.path()));
    assert!(hub.runtime.services.set(Arc::clone(&services)).is_ok());
    offer(&hub, &[NAME]);
    queued(&hub, 9, "evt_rp");
    let record = stored(dir.path(), "evt_rp");
    let gone = crate::events::store::Settle::Dead {
        reason: crate::events::outbox::DeadReason::Gone,
        status: None,
    };
    hub.settle(&services, &record, gone).await;
    assert!(
        hub.store.dead_letter_by_id("evt_rp").is_some(),
        "premise: buried"
    );
    let actor = crate::events::governance::Actor {
        who: crate::security::audit::AuditWho::gateway(),
    };
    let secs = crate::clock::unix_secs().expect("a readable clock");
    let refused = {
        let _clock = crate::clock::test_clock::queued(&[Some(secs), None]);
        hub.replay_dead("evt_rp", &actor).await
    };
    assert_eq!(refused, Err(ReplayRefusal::Unavailable));
    // A clock that cannot date the lease at all: transient too, never a
    // subscription gone.
    let refused = {
        let _clock = before_epoch();
        hub.replay_dead("evt_rp", &actor).await
    };
    assert_eq!(refused, Err(ReplayRefusal::Unavailable));
}

/// Fan-out matched an occurrence on one reading and stamped the record with
/// it; the outbox takes the record on that reading, never a second read, so
/// a clock that fails in between cannot drop it uncounted.
#[tokio::test]
async fn the_outbox_takes_a_record_on_its_fan_out_reading() {
    use crate::events::outbox::{Enqueued, OutboxCaps};
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    queued(&hub, 9, "evt_q1");
    let record = OutboxRecord {
        event_id: "evt_q2".into(),
        ..stored(dir.path(), "evt_q1")
    };
    let _clock = before_epoch();
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    assert_eq!(
        hub.store.enqueue(record, caps).expect("io"),
        Enqueued::Written,
        "dropped on a second read of the clock"
    );
}

/// A webhook-kind source offering [`NAME`] that admits its first `admits`
/// checks, then answers `then`.
struct ClockBlind {
    admits: usize,
    asked: std::sync::atomic::AtomicUsize,
    then: fn() -> crate::events::types::RpcError,
}

impl ClockBlind {
    /// Admits `admits` checks, then cannot judge on the clock.
    fn after(admits: usize) -> Arc<Self> {
        Arc::new(Self {
            admits,
            asked: std::sync::atomic::AtomicUsize::new(0),
            then: crate::events::types::RpcError::clock_unreadable,
        })
    }
}

#[async_trait::async_trait]
impl crate::events::EventSource for ClockBlind {
    fn kind(&self) -> crate::events::types::SourceKind {
        crate::events::types::SourceKind::Webhook
    }
    fn descriptors(&self) -> Vec<crate::events::types::EventDescriptor> {
        vec![super::descriptor(
            NAME,
            crate::events::types::SourceKind::Webhook,
        )]
    }
    fn matches(
        &self,
        _principal: &str,
        _arguments: &serde_json::Value,
        _event: &crate::events::fanout::SourceEvent,
    ) -> bool {
        true
    }
    async fn authorize(
        &self,
        _principal: &str,
        _name: &str,
        _arguments: &serde_json::Value,
    ) -> Result<(), crate::events::types::RpcError> {
        let asked = self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if asked < self.admits {
            Ok(())
        } else {
            Err((self.then)())
        }
    }
}

/// A source that cannot judge on the clock, at the attempt's first source
/// check (`admits` 0) or at the re-check after the attempt is on record
/// (`admits` 1): neither an admission nor a refusal. Nothing is sent or
/// revoked, the record is kept unsent with its date, and the row stays.
#[tokio::test]
async fn a_source_that_cannot_judge_on_the_clock_sends_and_revokes_nothing() {
    for admits in [0, 1] {
        let dir = tempfile::tempdir().expect("dir");
        let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
        let services = logged_services(dir.path());
        hub.register_source(ClockBlind::after(admits));
        let (port, accepted) = counting_callback().await;
        queued(&hub, port, "evt_cb");
        let before = stored(dir.path(), "evt_cb");
        Box::pin(hub.attempt(&services, "evt_cb")).await;
        let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert_kept_unsent(&hub, dir.path(), &before, "evt_cb", posts);
        assert!(
            hub.store.get("sub_worker").is_some(),
            "revoked on a verdict the clock could not judge (admits {admits})"
        );
    }
}

/// Fan-out to a source that cannot judge on the clock: the row is kept and
/// the occurrence dropped and counted as a clock drop.
#[tokio::test]
async fn fan_out_to_a_source_that_cannot_judge_on_the_clock_counts_a_drop() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    hub.register_source(ClockBlind::after(0));
    queued(&hub, 9, "evt_fo");
    let event = crate::events::fanout::SourceEvent {
        kind: crate::events::types::SourceKind::Webhook,
        name: NAME.into(),
        backend: "b".into(),
        scope: crate::events::types::Visibility::Owner,
        owner: None,
        upstream_id: "u1".into(),
        occurred_at: now(),
        data: serde_json::json!({}),
        lifecycle_key: None,
    };
    hub.fan_out(&services, &event).await;
    assert_eq!(hub.runtime.clock_drops(), 1, "the drop is counted");
    assert!(hub.store.get("sub_worker").is_some(), "the row was revoked");
}

/// A refusal judged on a readable clock whose revocation finds the clock
/// unreadable: the row is kept by the revocation guard, and the record goes
/// back to pending unsent and uncounted, since nothing was sent.
#[tokio::test]
async fn a_refusal_whose_revocation_cannot_read_the_clock_counts_no_send() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    hub.register_source(Arc::new(ClockBlind {
        admits: 0,
        asked: std::sync::atomic::AtomicUsize::new(0),
        then: crate::events::types::RpcError::forbidden,
    }));
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_rv");
    let before = stored(dir.path(), "evt_rv");
    // The credential check admits on any clock here; the source's refusal
    // stands, and the clock fails from the claim on.
    let _admits = crate::events::services::forced_verdict::answer(
        crate::events::services::AccessVerdict::Admits,
    );
    let clock = Box::pin(clock_fails_at(
        &hub.after_claim,
        hub.attempt(&services, "evt_rv"),
    ))
    .await;
    drop(clock);
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(
        hub.store.get("sub_worker").is_some(),
        "revoked on an unreadable clock"
    );
    let after = stored(dir.path(), "evt_rv");
    assert_eq!(after.state, OutboxState::Pending);
    assert_eq!(after.last_status.as_deref(), Some("access_revoked"));
    assert_eq!(after.sends(), before.sends(), "a refusal counted as a send");
}

/// A source that answers a plain internal error (a store it could not read)
/// gives no verdict, at either check: nothing is sent or revoked, and the
/// record goes back to pending unsent and uncounted, to retry later.
#[tokio::test]
async fn a_source_error_delivers_nothing_and_settles_unsent() {
    for admits in [0, 1] {
        let dir = tempfile::tempdir().expect("dir");
        let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
        let services = logged_services(dir.path());
        hub.register_source(Arc::new(ClockBlind {
            admits,
            asked: std::sync::atomic::AtomicUsize::new(0),
            then: crate::events::types::RpcError::internal,
        }));
        let (port, accepted) = counting_callback().await;
        queued(&hub, port, "evt_se");
        let before = stored(dir.path(), "evt_se");
        Box::pin(hub.attempt(&services, "evt_se")).await;
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "delivered on a source error (admits {admits})"
        );
        assert!(hub.store.get("sub_worker").is_some(), "revoked");
        let after = stored(dir.path(), "evt_se");
        assert_eq!(after.state, OutboxState::Pending);
        assert_eq!(after.last_status.as_deref(), Some("source_unavailable"));
        assert_eq!(after.sends(), before.sends(), "counted as a send");
        assert!(
            after.next_attempt_at > before.next_attempt_at,
            "retried at once"
        );
    }
}
