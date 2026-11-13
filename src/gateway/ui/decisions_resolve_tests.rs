// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resolve route: the frame (permission, strict body, one status per
//! state, the scope digest, the mutex) and the deny.

use super::*;

// ---- POST /ui/api/decisions/{id}/resolve: the frame ----

async fn resolve(
    state: &Arc<AppState>,
    admin: bool,
    id: &str,
    body: impl AsRef<[u8]>,
) -> (StatusCode, Value) {
    let guard = Guard::for_route(
        routes::UI_DECISIONS_RESOLVE,
        &Method::POST,
        Some(client(admin)),
    );
    let response = resolve_decision(
        State(Arc::clone(state)),
        axum::Extension(state.live_config.generation()),
        guard,
        axum::extract::Path(id.to_owned()),
        axum::body::Bytes::copy_from_slice(body.as_ref()),
    )
    .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn accept_body(digest: &str) -> Value {
    json!({"action": "accept", "reason": "needed", "scope_digest": digest, "ttl_seconds": 3600})
}

fn deny_body(digest: &str) -> Value {
    json!({"action": "deny", "reason": "not needed", "scope_digest": digest})
}

/// What a test keeps alive beside its state: the temp dir, the fixture's
/// store dir and the governance log the deny is recorded in.
type Kept = (
    tempfile::TempDir,
    crate::gateway::router::tests::FixtureDir,
    Arc<TransparencyLogger>,
);

/// A started gateway with one open access request; its id and digest.
async fn one_request() -> (Arc<AppState>, Arc<TransparencyLogger>, String, String, Kept) {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let (governance, cp_store) = governance_in(&dir);
    let (state, store) = state_with_store(&log, &cp_store).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(
        &state.meta_mcp,
        None,
        shutdown,
        state.control_plane_store.clone(),
    );
    let body = served_when(&state, |body| scope_len(body) == 1).await;
    let item = &body["decisions"][0];
    let id = item["id"].as_str().expect("an id").to_owned();
    let digest = item["scope_digest"].as_str().expect("a digest").to_owned();
    (state, log, id, digest, (dir, store, governance))
}

#[tokio::test]
async fn resolve_answers_one_status_per_state_and_writes_nothing() {
    let (state, _log, id, digest, _keep) = one_request().await;
    assert_eq!(digest.len(), 64, "{digest}");

    let (status, body) = resolve(&state, false, &id, deny_body(&digest).to_string()).await;
    assert_ne!(status, StatusCode::OK, "a non-admin is refused: {body}");
    assert_ne!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused before the body: {body}"
    );

    for bad in [
        "not json".to_owned(),
        json!({"action": "deny", "reason": "r", "scope_digest": digest, "extra": 1}).to_string(),
        json!({"action": "deny", "reason": " ", "scope_digest": digest}).to_string(),
        json!({"action": "deny", "reason": "not needed\n", "scope_digest": digest}).to_string(),
        json!({"action": "deny", "reason": "r", "scope_digest": "abc"}).to_string(),
        json!({"action": "deny", "reason": "r", "scope_digest": digest.to_uppercase()}).to_string(),
        json!({"action": "accept", "reason": "r", "scope_digest": digest}).to_string(),
        json!({"action": "accept", "reason": "r", "scope_digest": digest,
               "ttl_seconds": 60, "permanent": true})
        .to_string(),
        json!({"action": "deny", "reason": "r", "scope_digest": digest,
               "ttl_seconds": 60})
        .to_string(),
    ] {
        let (status, body) = resolve(&state, true, &id, &bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
        assert_eq!(body["error"], "invalid_body", "{bad}");
    }

    let (status, body) = resolve(&state, true, "no-such-id", deny_body(&digest).to_string()).await;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );

    let outdated = "0".repeat(64);
    let (status, body) = resolve(&state, true, &id, deny_body(&outdated).to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "scope_changed");
    assert_eq!(body["scope_digest"], json!(digest));

    let (status, body) = resolve(&state, true, &id, accept_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "not_available_yet");
}

#[tokio::test]
async fn an_open_item_of_another_kind_is_not_resolvable() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let (state, _store) = state_with(&log).await;
    let shared = Arc::new(Shared::with_key([7; 32]));
    let now = crate::clock::utc_now().expect("a readable clock");
    let id = shared.update(|set| {
        set.set_health(Source::Access, Health::Ready);
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_discovery(Vec::new(), Vec::new(), 0, now);
        let change = crate::decisions::CapabilityChange {
            file: "/c/a.yaml".to_owned(),
            actual: "h1".to_owned(),
            loaded_as: Some("stripe.charges".to_owned()),
            content: "name: stripe.charges\ndescription: d\n".to_owned(),
        };
        set.set_capability_changes("caps", vec![change], now);
        set.list()[0]["id"].as_str().expect("an id").to_owned()
    });
    state.meta_mcp.set_decisions(shared);
    let body = deny_body(&"0".repeat(64)).to_string();
    let (status, body) = resolve(&state, true, &id, &body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "not_resolvable", "{body}");
}

/// While a source replays, the items are partial: a resolve answers 503
/// naming it, never `not_found` for a request it cannot see yet.
#[tokio::test]
async fn a_resolve_while_a_source_replays_is_unavailable() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let (state, _store) = state_with(&log).await;
    let shared = Arc::new(Shared::with_key([7; 32]));
    shared.update(|set| {
        set.set_health(Source::ControlPlane, Health::Ready);
        set.set_health(Source::Capability, Health::Absent);
        set.discovery_down();
    });
    state.meta_mcp.set_decisions(shared);
    let body = deny_body(&"0".repeat(64)).to_string();
    let (status, body) = resolve(&state, true, "any-id", &body).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn the_digest_follows_the_scope_not_the_arrival_order() {
    let (state, log, id, digest, _keep) = one_request().await;
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.refunds", now));
    let body = served_when(&state, |body| scope_len(body) == 2).await;
    let after = body["decisions"][0]["scope_digest"]
        .as_str()
        .expect("digest");
    assert_ne!(after, digest, "a wider scope is a new digest");

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the listed digest is stale: {body}"
    );
    assert_eq!(body["scope"].as_array().map(Vec::len), Some(2), "{body}");
}

#[tokio::test]
async fn two_resolves_do_not_overlap() {
    let (state, _log, id, digest, _keep) = one_request().await;
    let decisions = state.meta_mcp.decisions().expect("decisions");
    let held = decisions.resolving().await;
    let state2 = Arc::clone(&state);
    let body = accept_body(&digest).to_string();
    let pending = tokio::spawn(async move { resolve(&state2, true, &id, body).await });
    // A deterministic handoff, not a wait: this runtime has one thread, so one
    // yield runs the spawned resolve until it first returns Pending. Every step
    // before the mutex is synchronous, so without the mutex it would finish in
    // that one poll; with it, it is parked until `held` drops.
    tokio::task::yield_now().await;
    assert!(
        !pending.is_finished(),
        "a resolve ran while another held the mutex"
    );
    drop(held);
    let (status, _) = pending.await.expect("joined");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn one_more_refusal_of_a_listed_capability_is_a_changed_request() {
    let (state, log, id, digest, _keep) = one_request().await;
    let later = crate::clock::utc_now().expect("a readable clock")
        + crate::duration_bound::delta!(seconds, 5);
    write(&log, note("stripe.charges", later));
    let body = served_when(&state, |body| {
        body["decisions"][0]["refused_calls"] == json!(2)
    })
    .await;
    assert_eq!(scope_len(&body), 1, "the scope did not widen: {body}");
    let after = body["decisions"][0]["scope_digest"]
        .as_str()
        .expect("digest");
    assert_ne!(
        after, digest,
        "a refusal the admin never saw is a new digest"
    );

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "scope_changed");
    assert_eq!(body["scope_digest"], json!(after));
}

// ---- deny ----

/// The UI decisions the governance audit kept, newest first.
fn kept_decisions(state: &AppState) -> Vec<crate::control_plane::ControlPlaneAuditEvent> {
    let store = state.control_plane_store.as_ref().expect("a store");
    store
        .read_audit(&crate::control_plane::AuditFilter::new(200))
        .expect("the audit reads")
        .events
        .into_iter()
        .filter(|event| event.ui_decision.is_some())
        .collect()
}

fn open_count(body: &Value) -> usize {
    body["decisions"].as_array().map_or(0, Vec::len)
}

#[tokio::test]
async fn a_deny_records_one_audit_event_and_the_item_is_gone_now_and_after_a_restart() {
    let (state, log, id, digest, _keep) = one_request().await;
    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["action"], "deny");

    let (_, listed) = get(&state, true).await;
    assert_eq!(open_count(&listed), 0, "gone at once: {listed}");
    let kept = kept_decisions(&state);
    assert_eq!(kept.len(), 1, "one atomic record: {kept:?}");
    assert_eq!(json!(kept[0].event_id), body["event_id"]);
    assert_eq!(
        kept[0].action,
        crate::control_plane::ControlPlaneAction::MutateGrant
    );
    let caller = crate::gateway::ui::control_plane::mutations::actor_from_client(
        Some(&client(true)),
        None,
        &Default::default(),
    );
    assert_eq!(
        kept[0].actor_id, caller.actor_id,
        "the record names the caller"
    );
    assert_eq!(kept[0].reason, "not needed");

    // A restart: a new set over the same logs replays the refusal and the
    // decision, and the request stays closed.
    let store = state.control_plane_store.clone().expect("a store");
    let (state2, _store2) = state_with_store(&log, &store).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(
        &state2.meta_mcp,
        None,
        shutdown,
        state2.control_plane_store.clone(),
    );
    let after = served_when(&state2, |body| body["missing_kinds"] == json!([])).await;
    assert_eq!(open_count(&after), 0, "closed after the replay: {after}");
}

#[tokio::test]
async fn a_deny_closes_the_refusals_it_was_shown_and_not_a_later_one() {
    let (state, log, id, digest, _keep) = one_request().await;
    // The refusal the admin saw was written at `now`; a later one carries
    // the same time and must still reopen the request.
    let (status, _) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let body = served_when(&state, |body| open_count(body) == 1).await;
    assert_eq!(body["decisions"][0]["refused_calls"], json!(1), "{body}");
}

/// A later refusal reopens a denied request under the same id: a retry of
/// the first deny still gets the first outcome, and the reopened request
/// can be denied again.
#[tokio::test]
async fn a_reopened_request_can_be_denied_again() {
    let (state, log, id, digest, _keep) = one_request().await;
    let (status, first) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    let body = served_when(&state, |body| open_count(body) == 1).await;
    assert_eq!(body["decisions"][0]["id"], json!(id), "the same id: {body}");
    let reopened = body["decisions"][0]["scope_digest"]
        .as_str()
        .expect("a digest")
        .to_owned();
    assert_ne!(reopened, digest);

    let (status, again) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["already_recorded"], json!(true));
    assert_eq!(again["event_id"], first["event_id"]);

    let (status, second) = resolve(&state, true, &id, deny_body(&reopened).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_ne!(second["already_recorded"], json!(true), "{second}");
    assert_ne!(second["event_id"], first["event_id"]);
    let (_, listed) = get(&state, true).await;
    assert_eq!(open_count(&listed), 0, "{listed}");
    assert_eq!(kept_decisions(&state).len(), 2);

    // A late retry of the first deny still gets the first outcome.
    let (status, late) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{late}");
    assert_eq!(late["event_id"], first["event_id"]);
    assert_eq!(kept_decisions(&state).len(), 2, "a retry appends nothing");
}

#[tokio::test]
async fn a_deny_of_a_two_capability_request_closes_both_in_one_record() {
    let dir = tempfile::tempdir().expect("dir");
    let log = log_in(&dir, 1 << 20, 12);
    let now = crate::clock::utc_now().expect("a readable clock");
    write(&log, note("stripe.charges", now));
    write(&log, note("stripe.refunds", now));
    let (_governance, cp_store) = governance_in(&dir);
    let (state, _store) = state_with_store(&log, &cp_store).await;
    let (_stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _tick = start(
        &state.meta_mcp,
        None,
        shutdown,
        state.control_plane_store.clone(),
    );
    let body = served_when(&state, |body| scope_len(body) == 2).await;
    let id = body["decisions"][0]["id"].as_str().expect("id").to_owned();
    let digest = body["decisions"][0]["scope_digest"]
        .as_str()
        .expect("d")
        .to_owned();

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, listed) = get(&state, true).await;
    assert_eq!(open_count(&listed), 0, "{listed}");
    let kept = kept_decisions(&state);
    assert_eq!(kept.len(), 1, "{kept:?}");
    let decision = kept[0].ui_decision.as_ref().expect("a decision");
    assert_eq!(decision.entries.len(), 2);

    // A later refusal of one capability reopens only that one.
    write(&log, note("stripe.refunds", now));
    let body = served_when(&state, |body| open_count(body) == 1).await;
    assert_eq!(scope_len(&body), 1, "{body}");
}

/// A deny whose record cannot be appended answers 503 `audit_unavailable`,
/// closes nothing and records no outcome, so the next deny writes it.
#[tokio::test]
async fn a_deny_whose_record_cannot_be_written_closes_nothing() {
    let (state, _log, id, digest, (_dir, _store, governance)) = one_request().await;
    governance.fail_next_append_of_kind_for_test("control_plane_audit");
    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "audit_unavailable");
    let (_, listed) = get(&state, true).await;
    assert_eq!(open_count(&listed), 1, "still open: {listed}");
    assert!(kept_decisions(&state).is_empty(), "nothing written");

    let (status, body) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "the next deny writes it: {body}");
    assert_eq!(kept_decisions(&state).len(), 1);
}

#[tokio::test]
async fn a_retry_of_a_deny_answers_the_recorded_outcome_and_writes_nothing() {
    let (state, _log, id, digest, _keep) = one_request().await;
    let (status, first) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, again) = resolve(&state, true, &id, deny_body(&digest).to_string()).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["event_id"], first["event_id"]);
    assert_eq!(again["already_recorded"], json!(true));
    assert_eq!(kept_decisions(&state).len(), 1, "a retry appends nothing");

    let other = "1".repeat(64);
    let (status, body) = resolve(&state, true, &id, deny_body(&other).to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "already_resolved");
}
