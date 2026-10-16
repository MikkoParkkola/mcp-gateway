// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8377 RED rows: a stream's request-time identity is judged again at
//! every decision (design d3.4 §3). Red on the base, where `live()` checks
//! only the adapter window and the digest reads the attach-time agent; each
//! names the mutant that must turn it red again once MIK-8377 lands.

use std::sync::Arc;

use super::audience_ear::{Attach, Ear, EventOutcome};
use super::audience_fixture::{World, tool};
use super::audience_guard_8377_tests::{VALID_FOR, agent, certified, ended_unwritten, with_cert};
use crate::gateway::oauth::AgentRegistry;
use crate::gateway::streaming::{DeadReason, HeldSource, LiveCtx, ViewSubject};
use crate::security::caller_identity::CallerIdentityConfig;

fn alpha(read: &str, write: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", write),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

fn now() -> u64 {
    crate::clock::unix_secs().expect("clock after 1970")
}

/// R-LIVE.1-cert on listen (the matrix row's): one second past the
/// certificate's `notAfter` the next change closes the stream (killer M5:
/// the `notAfter` clause skipped).
#[tokio::test]
async fn r_live_1_cert_listen() {
    let w = World::start().await;
    let not_after = now() + VALID_FOR;
    let mut ear = w.listen_with("k-std", with_cert(not_after)).await;
    let clock = crate::clock::test_clock::at_secs(not_after + 1);
    w.store_shared("alpha", alpha("r2", "w"));
    assert!(
        ended_unwritten(&mut ear, &w).await,
        "past notAfter the listen stream is closed"
    );
    drop(clock);
}

/// R-LIVE.1-cert on GET (the matrix row's): past `notAfter` the change is
/// not written and the stream ends (killer M5).
#[tokio::test]
async fn r_live_1_cert_get() {
    let w = World::start().await;
    let not_after = now() + VALID_FOR;
    let mut ear = w.sse_with("k-std", with_cert(not_after)).await;
    let clock = crate::clock::test_clock::at_secs(not_after + 1);
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "past notAfter the change is not written"
    );
    assert!(
        !ear.is_open(&w).await,
        "past notAfter the GET stream is closed"
    );
    drop(clock);
}

/// R-LIVE.1-cert counter: the death is counted once, as `reason="cert"`.
#[cfg(feature = "metrics")]
#[test]
fn r_live_1_cert_metric_a_lapsed_certificate_is_counted_once_as_cert() {
    let series = super::audience_guard_8377_tests::deaths_counted(|| async {
        let w = World::start().await;
        let not_after = now() + VALID_FOR;
        let mut ear = w.listen_with("k-std", with_cert(not_after)).await;
        let clock = crate::clock::test_clock::at_secs(not_after + 1);
        w.store_shared("alpha", alpha("r2", "w"));
        assert!(
            ended_unwritten(&mut ear, &w).await,
            "past notAfter the stream is closed"
        );
        drop(clock);
    });
    super::audience_guard_8377_tests::assert_one_death(&series, "cert");
}

/// R-LIVE.1-clock: a clock that reads before 1970 cannot show the
/// certificate valid, so both streams close. The bearer is an API key with
/// no expiry, whose check reads no clock, so the forced clock reaches only
/// the certificate clause (killer M6: an unreadable clock read as 0).
#[tokio::test]
async fn r_live_1_clock_an_unreadable_clock_closes_a_certified_stream() {
    let w = World::start().await;
    let (mut listen, mut get) = certified(&w, now() + VALID_FOR).await;
    let clock = crate::clock::test_clock::before_epoch();
    w.store_shared("alpha", alpha("r2", "w"));
    assert!(
        ended_unwritten(&mut listen, &w).await,
        "an unreadable clock closes the listen stream"
    );
    assert_eq!(
        get.told(&w).await,
        0,
        "an unreadable clock writes nothing on GET"
    );
    assert!(
        !get.is_open(&w).await,
        "an unreadable clock closes the GET stream"
    );
    drop(clock);
}

/// R-LIVE.1-clock counter: that death is the certificate's, not the bearer's.
#[cfg(feature = "metrics")]
#[test]
fn r_live_1_clock_metric_an_unreadable_clock_is_counted_as_cert() {
    let series = super::audience_guard_8377_tests::deaths_counted(|| async {
        let w = World::start().await;
        let mut ear = w.listen_with("k-std", with_cert(now() + VALID_FOR)).await;
        let clock = crate::clock::test_clock::before_epoch();
        w.store_shared("alpha", alpha("r2", "w"));
        assert!(
            ended_unwritten(&mut ear, &w).await,
            "an unreadable clock closes the stream"
        );
        drop(clock);
    });
    super::audience_guard_8377_tests::assert_one_death(&series, "cert");
}

/// R-LIVE.1-attach: a certificate already past `notAfter` at attach gets
/// no stream; the route answers it as it answers an invalid credential
/// (killer M5).
async fn refused_like_an_invalid_credential(route: Attach) {
    let w = World::start().await;
    let dead = w.attach_raw(route, "k-std", with_cert(now() - 1)).await;
    let invalid = w.attach_raw(route, "k-not-a-key", |_| {}).await;
    assert_eq!(
        invalid.0,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: an invalid credential is 401 on {route:?}"
    );
    assert_eq!(
        dead, invalid,
        "a certificate dead at attach is refused as an invalid credential on {route:?}"
    );
}

#[tokio::test]
async fn r_live_1_attach_get_past_not_after_is_refused() {
    refused_like_an_invalid_credential(Attach::Get).await;
}

#[tokio::test]
async fn r_live_1_attach_listen_past_not_after_is_refused() {
    refused_like_an_invalid_credential(Attach::Listen).await;
}

/// Both routes' streams for `token`.
async fn both(w: &World, token: &str) -> [Ear; 2] {
    [w.listen(token).await, w.sse(token).await]
}

/// What a change tells each of `ears`.
async fn told(w: &World, ears: &mut [Ear; 2]) -> [usize; 2] {
    [ears[0].told(w).await, ears[1].told(w).await]
}

/// Whether each of `ears` is still open.
async fn open(w: &World, ears: &mut [Ear; 2]) -> [bool; 2] {
    [!ears[0].closed(w).await, ears[1].is_open(w).await]
}

/// R-AGENT.3: an agent narrowed after attach is judged by its live scopes,
/// not the attach-time ones. Registry replacement notifies nothing, so the
/// row makes each decision itself: the first after narrowing tells the lost
/// tool once; then a change to the withdrawn `read` tells nothing, a change
/// to the still-visible `write` tells, and neither stream closes (killer
/// M9: the digest reads the attach-time agent).
#[tokio::test]
async fn r_agent_3_a_narrowed_agent_is_judged_by_its_live_scopes() {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let mut ears = both(&w, &token).await;

    agent(&registry, "a1", &["tools:alpha:write"]);
    assert!(
        !w.served_names(&token).await.contains(&"read".to_string()),
        "premise: the narrowed agent no longer sees read through POST"
    );
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(
        told(&w, &mut ears).await,
        [1, 1],
        "premise: the lost tool is told once"
    );
    w.store_shared("alpha", alpha("r3", "w"));
    assert_eq!(
        told(&w, &mut ears).await,
        [0, 0],
        "a change to a tool the live scopes withdrew tells nothing"
    );
    w.store_shared("alpha", alpha("r3", "w2"));
    assert_eq!(
        told(&w, &mut ears).await,
        [1, 1],
        "a still-visible change is told"
    );
    assert_eq!(
        open(&w, &mut ears).await,
        [true, true],
        "a narrowed agent stays open"
    );
}

/// R-AGENT.3-widen: an agent widened past its attach-time scopes is shown
/// what it gained (killer M11: the digest takes the live scopes cut to the
/// attach-time ones).
#[tokio::test]
async fn r_agent_3_widen_a_widened_agent_is_told_what_it_gained() {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:write"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let mut ears = both(&w, &token).await;

    agent(&registry, "a1", &["tools:alpha:*"]);
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(told(&w, &mut ears).await, [1, 1], "the view gained read");
    w.store_shared("alpha", alpha("r3", "w"));
    assert_eq!(
        told(&w, &mut ears).await,
        [1, 1],
        "read is in the live view"
    );
}

/// R-AGENT.3-list (GET only; a listener's record is its own, which no
/// listing reaches): after narrowing, a `tools/list` in the stream's session
/// records the narrowed view, so a change to the withdrawn `read` tells
/// nothing and a change to `write` tells once (killer M10: the view key
/// hashes the attach-time scopes, so the listing misses the stream's record).
#[tokio::test]
async fn r_agent_3_list_a_listing_after_narrowing_refreshes_the_get_stream() {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    let mut ear = w.sse(&token).await;
    let session = ear.session_id().to_string();

    agent(&registry, "a1", &["tools:alpha:write"]);
    let listed = w
        .post_session(&token, &session, "tools/list", serde_json::json!({}))
        .await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("premise: listed {listed}"))
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        !names.contains(&"read"),
        "premise: the listing shows no read: {names:?}"
    );
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "the listing already recorded the narrowed view"
    );
    w.store_shared("alpha", alpha("r2", "w2"));
    assert_eq!(ear.told(&w).await, 1, "a still-visible change is told");
}

/// The R-AGENT.3-queued gateway: `a1` registered with every `alpha` tool.
/// Returns the registry, `a1`'s token and the world.
async fn queued_world() -> (Arc<AgentRegistry>, String, World) {
    let registry = Arc::new(AgentRegistry::new());
    let token = agent(&registry, "a1", &["tools:alpha:*"]);
    let w = World::start_agents(Arc::clone(&registry)).await;
    (registry, token, w)
}

/// R-AGENT.3-queued on listen: a change judged while the agent was wide,
/// parked before the listener's admission while it is narrowed back, is
/// not written; the stream stays open and is told the next visible change
/// (killer M9 at admit time: the attach-time scopes would see `read`).
#[tokio::test]
async fn r_agent_3_queued_listen_a_change_parked_across_narrowing_is_not_written() {
    let (registry, token, w) = queued_world().await;
    let mut ear = w.listen(&token).await;
    agent(&registry, "a1", &["tools:alpha:write"]);
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(ear.told(&w).await, 1, "premise: the narrowed view is told");
    agent(&registry, "a1", &["tools:alpha:*"]);

    let (reached, release) = crate::gateway::subscription_registry::before_listen_admit().arm();
    w.store_shared("alpha", alpha("r3", "w"));
    let (parked, ()) = tokio::join!(ear.told(&w), async {
        crate::test_pause::within("the change reaching the listen admit", reached.notified()).await;
        agent(&registry, "a1", &["tools:alpha:write"]);
        release.notify_one();
    });
    assert_eq!(
        parked, 0,
        "the parked change is judged under the live scopes"
    );
    w.store_shared("alpha", alpha("r3", "w2"));
    assert_eq!(ear.told(&w).await, 1, "the next visible change is told");
    assert!(!ear.closed(&w).await, "the stream stays open");
}

/// R-AGENT.3-queued on GET: the same, with the change parked at the write
/// check (killer M9 at write time).
#[tokio::test]
async fn r_agent_3_queued_get_a_change_parked_across_narrowing_is_not_written() {
    let (registry, token, w) = queued_world().await;
    let mut ear = w.sse(&token).await;
    agent(&registry, "a1", &["tools:alpha:write"]);
    w.store_shared("alpha", alpha("r2", "w"));
    assert_eq!(ear.told(&w).await, 1, "premise: the narrowed view is told");
    agent(&registry, "a1", &["tools:alpha:*"]);

    let (reached, release) = w.state.multiplexer.before_write_check.arm();
    w.store_shared("alpha", alpha("r3", "w"));
    crate::test_pause::within("the change reaching the write check", reached.notified()).await;
    agent(&registry, "a1", &["tools:alpha:write"]);
    release.notify_one();
    assert_eq!(
        ear.told(&w).await,
        0,
        "the parked change is judged under the live scopes"
    );
    w.store_shared("alpha", alpha("r3", "w2"));
    assert_eq!(ear.told(&w).await, 1, "the next visible change is told");
    assert!(ear.is_open(&w).await, "the stream stays open");
}

/// R-LIVE.1-queued on listen: a change parked before the listener's
/// admission while the certificate lapses ends the stream with no frame for
/// it, counted once as `cert` (killer M5 at admit time).
#[cfg(feature = "metrics")]
#[test]
fn r_live_1_queued_listen_a_change_parked_past_not_after_is_not_written() {
    let series = super::audience_guard_8377_tests::deaths_counted(|| async {
        let w = World::start().await;
        let not_after = now() + VALID_FOR;
        let mut ear = w.listen_with("k-std", with_cert(not_after)).await;
        let (reached, release) = crate::gateway::subscription_registry::before_listen_admit().arm();
        w.store_shared("alpha", alpha("r2", "w"));
        let Ear::Listen(events) = &mut ear else {
            unreachable!("a listen stream")
        };
        // The guard is handed out of the controller, so it outlives the
        // admission the release lets run.
        let (outcome, clock) = tokio::join!(events.next(), async {
            crate::test_pause::within("the change reaching the listen admit", reached.notified())
                .await;
            let clock = crate::clock::test_clock::at_secs(not_after + 1);
            release.notify_one();
            clock
        });
        assert_eq!(outcome, EventOutcome::Eof, "no frame for the parked change");
        drop(clock);
    });
    super::audience_guard_8377_tests::assert_one_death(&series, "cert");
}

/// R-LIVE.1-queued on GET: a change decided owed while the certificate was
/// valid, parked at the write check while it lapses, is not written; the
/// stream ends, counted once as `cert` (killer M5 at write time).
#[cfg(feature = "metrics")]
#[test]
fn r_live_1_queued_get_a_change_parked_past_not_after_is_not_written() {
    let series = super::audience_guard_8377_tests::deaths_counted(|| async {
        let w = World::start().await;
        let not_after = now() + VALID_FOR;
        let mut ear = w.sse_with("k-std", with_cert(not_after)).await;
        let (reached, release) = w.state.multiplexer.before_write_check.arm();
        w.store_shared("alpha", alpha("r2", "w"));
        crate::test_pause::within("the change reaching the write check", reached.notified()).await;
        let clock = crate::clock::test_clock::at_secs(not_after + 1);
        release.notify_one();
        assert_eq!(ear.told(&w).await, 0, "no frame for the parked change");
        assert!(!ear.is_open(&w).await, "the stream ends");
        drop(clock);
    });
    super::audience_guard_8377_tests::assert_one_death(&series, "cert");
}

// Unit rows on `live()` (the lead's Q1 carve-out): no running gateway
// reaches the agent-mismatch or proxy-peer clauses. Agent auth is restart-only
// and validates the agent on every request, the session owner binds the
// agent's subject and the bearer's digest (so another agent's bearer cannot
// resume the session), and `trusted_proxies` is build-time only.

/// The attach-time snapshot of `client_id`, as the agent middleware builds it.
fn attached(client_id: &str) -> crate::gateway::oauth::AgentIdentity {
    crate::gateway::oauth::AgentIdentity {
        client_id: client_id.to_string(),
        agent_name: client_id.to_string(),
        scopes: Vec::new(),
        raw_scopes: Vec::new(),
        quota_principal: None,
    }
}

/// A live validation of `client_id`'s token.
fn validated(client_id: &str) -> crate::gateway::oauth::ValidatedToken {
    let registry = AgentRegistry::new();
    let token = agent(&registry, client_id, &["tools:alpha:*"]);
    crate::gateway::oauth::validate_agent_token(&token, &registry).expect("a valid agent token")
}

/// What `subject` makes of a decision whose caller validated as `agent`,
/// under `identity`.
fn judged(
    subject: &ViewSubject,
    agent: Option<&crate::gateway::oauth::ValidatedToken>,
    identity: &CallerIdentityConfig,
) -> Result<(), DeadReason> {
    subject.live(&LiveCtx {
        agent,
        caller_identity: identity,
        cf_verifier: None,
    })
}

fn snapshot(client_id: &str) -> ViewSubject {
    ViewSubject {
        oauth_agent: Some(attached(client_id)),
        ..ViewSubject::default()
    }
}

/// R-AGENT.4: a stream attached with no agent whose caller now validates as
/// one is dead (killer M1: `(None, Some(_))` accepted).
#[test]
fn r_agent_4_an_agent_that_appears_is_dead() {
    let live = validated("a1");
    assert_eq!(
        judged(
            &ViewSubject::default(),
            Some(&live),
            &CallerIdentityConfig::default()
        ),
        Err(DeadReason::Agent)
    );
}

/// R-AGENT.5: a stream attached as agent A whose bearer now validates as B
/// is dead (killer M2: the `client_id` compare always true).
#[test]
fn r_agent_5_another_agent_is_dead() {
    let live = validated("b1");
    assert_eq!(
        judged(
            &snapshot("a1"),
            Some(&live),
            &CallerIdentityConfig::default()
        ),
        Err(DeadReason::Agent)
    );
}

/// R-AGENT.6: a stream attached as agent A whose caller now validates as no
/// agent is dead (killer M3: `(Some(_), None)` accepted). Route-unreachable:
/// `current_caller` refuses a bearer that is no agent while agent auth is on.
#[test]
fn r_agent_6_an_agent_that_disappears_is_dead() {
    assert_eq!(
        judged(&snapshot("a1"), None, &CallerIdentityConfig::default()),
        Err(DeadReason::Agent)
    );
}

/// Control for the agent rows: the same agent is live.
#[test]
fn r_agent_control_the_same_agent_is_live() {
    let live = validated("a1");
    assert_eq!(
        judged(
            &snapshot("a1"),
            Some(&live),
            &CallerIdentityConfig::default()
        ),
        Ok(())
    );
}

/// R-PROXY.2-peer: a stream admitted from a trusted proxy is dead once that
/// proxy is no longer in `trusted_proxies`, never re-judged as the key's own
/// subject (killer M7: the proxy clause skipped).
#[test]
fn r_proxy_2_peer_a_stream_from_an_untrusted_proxy_is_dead() {
    let peer: std::net::SocketAddr = "10.0.0.9:443".parse().expect("an address");
    let subject = ViewSubject {
        identity_source: HeldSource::TrustedProxy { peer },
        ..ViewSubject::default()
    };
    assert_eq!(
        judged(&subject, None, &CallerIdentityConfig::default()),
        Err(DeadReason::Proxy)
    );
    let trusted = CallerIdentityConfig {
        trusted_proxies: vec![peer.ip()],
        ..CallerIdentityConfig::default()
    };
    assert_eq!(
        judged(&subject, None, &trusted),
        Ok(()),
        "control: still trusted"
    );
}

/// R-LIVE.1-unit: past `notAfter` the subject is dead as `Cert` (killer M5).
#[test]
fn r_live_1_unit_a_lapsed_certificate_is_dead_as_cert() {
    let subject = ViewSubject {
        cert_not_after: Some(now() - 1),
        ..ViewSubject::default()
    };
    assert_eq!(
        judged(&subject, None, &CallerIdentityConfig::default()),
        Err(DeadReason::Cert)
    );
}

/// R-METRIC: each death the route rows cannot reach is counted once under
/// its own label (killer M8: two labels swapped).
#[cfg(feature = "metrics")]
#[test]
fn r_metric_agent_and_proxy_deaths_are_counted_under_their_labels() {
    let series = super::audience_guard_8377_tests::deaths_counted(|| async {
        let live = validated("b1");
        judged(
            &snapshot("a1"),
            Some(&live),
            &CallerIdentityConfig::default(),
        )
        .expect_err("premise: another agent is dead")
        .count();
        let peer: std::net::SocketAddr = "10.0.0.9:443".parse().expect("an address");
        let proxied = ViewSubject {
            identity_source: HeldSource::TrustedProxy { peer },
            ..ViewSubject::default()
        };
        judged(&proxied, None, &CallerIdentityConfig::default())
            .expect_err("premise: an untrusted proxy is dead")
            .count();
    });
    for reason in ["agent", "proxy"] {
        let one: Vec<String> = series
            .iter()
            .filter(|l| l.contains(&format!("reason=\"{reason}\"")))
            .cloned()
            .collect();
        super::audience_guard_8377_tests::assert_one_death(&one, reason);
    }
    assert_eq!(series.len(), 2, "no other series: {series:?}");
}
