// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B S7a (test plan v2 §5): a stored read by a caller whose key
//! excludes the task's target must not touch that target's warm per-user
//! slot. Two scoped keys carry one verified identity, so they share the
//! task's owner and the slot's principal (design §4.0): `INCLUDED` is scoped
//! to the target, `EXCLUDED` to another backend.
//!
//! Touch is observed without a new seam: the slot is aged past the idle
//! window, the read runs, then a real idle eviction runs. A touched slot
//! survives it; an untouched one is evicted.

use std::time::Duration;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::slot_verdict_http_tests::{CLOSED, Gateway, gateway_tuned};
use super::{OUTPUT, modern_meta};
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    Asked, BACKEND, BINDING, CallerSlot, Surfaced, TOOL, Warmth, rearm_alpha_slot_with, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

const INCLUDED: &str = "s7a-included-key";
const EXCLUDED: &str = "s7a-excluded-key";
/// The backend the excluded key is scoped to instead of [`BACKEND`].
const ELSEWHERE: &str = "elsewhere_hub";
/// Past the idle window `EVICT_AFTER`, so an untouched slot is evicted.
const AGED: u64 = 400;
const EVICT_AFTER: Duration = Duration::from_secs(300);

fn key(secret: &str, name: &str, backend: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![backend.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// The two keys; `excluded_scope` is the backend the second key may reach.
fn auth(excluded_scope: &str) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![
            key(INCLUDED, "included", BACKEND),
            key(EXCLUDED, "excluded", excluded_scope),
        ],
        ..AuthConfig::default()
    }
}

/// The per-user fixture with `alpha`'s slot warm, behind the two keys.
async fn fixture() -> Gateway {
    fixture_scoped(ELSEWHERE).await
}

/// [`fixture`] with the second key scoped to `excluded_scope`.
async fn fixture_scoped(excluded_scope: &'static str) -> Gateway {
    gateway_tuned(
        (CallerSlot::Valid, &valid(), Warmth::Warm),
        CLOSED,
        Surfaced::Yes,
        (|_| {}, |_| {}),
        |state| {
            state.live_config = std::sync::Arc::new(crate::config_reload::LiveConfig::with_auth(
                (*state.live_config.get()).clone(),
                std::sync::Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
                    &auth(excluded_scope),
                    crate::gateway::record_principal::TEST_RECORD_KEY,
                )),
            ));
        },
    )
    .await
}

/// POST a modern request with `secret` as the bearer and the shared verified
/// identity riding as a request extension.
async fn send(gw: &Gateway, secret: &str, method: &str, name: &str, params: Value) -> Value {
    send_full(gw, secret, (method, name), params).await.1
}

/// [`send`] with the HTTP status. A body that is not JSON fails the row: no
/// answer is ever collapsed to `null`, so two broken answers cannot compare
/// equal.
async fn send_full(
    gw: &Gateway,
    secret: &str,
    (method, name): (&str, &str),
    params: Value,
) -> (u16, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {secret}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(identity());
    let response = gw.router.clone().oneshot(request).await.expect("an answer");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "{method}: the answer is not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, body)
}

async fn task_get(gw: &Gateway, secret: &str, id: &str) -> Value {
    send(
        gw,
        secret,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// A finished task of [`TOOL`] on [`BACKEND`], made by the included key.
async fn finished(gw: &Gateway, idempotency: &str) -> String {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(idempotency);
    let made = send(
        gw,
        INCLUDED,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: the included key made a task: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + Duration::from_secs(10);
    let control = loop {
        let got = task_get(gw, INCLUDED, &id).await;
        if got.to_string().contains(OUTPUT) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(OUTPUT),
        "premise: the included key is served its task's output: {control}"
    );
    id
}

fn backend(gw: &Gateway) -> std::sync::Arc<crate::backend::Backend> {
    gw.meta
        .backends
        .for_test()
        .get(BACKEND)
        .expect("the backend")
}

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

/// Drop the slot by a real idle eviction and re-attach its upstream, so the
/// next read of the task is cold (as `stored_read_lease_tests::evict_alpha`).
fn evict(gw: &Gateway) -> std::sync::Arc<Asked> {
    let slot = backend(gw);
    slot.age_per_user_slot_for_test(BINDING, AGED);
    slot.evict_idle_per_user_entries(EVICT_AFTER);
    assert!(
        !slot.holds_per_user_slot_for_test(BINDING),
        "premise: the real eviction dropped the slot"
    );
    rearm_alpha_slot_with(&slot, &valid(), false)
}

/// The three cold-path observables: resolutions; whether a cold claim was
/// made, read as a running lease (a failed fill) or a held caller view (a successful
/// one, which leaves no lease); and lists on `upstream`, the
/// transport [`evict`] re-armed (the fixture's first one is gone).
fn cold_marks(gw: &Gateway, upstream: &Asked) -> (usize, bool, usize) {
    let slot = backend(gw);
    let actor = identity().stable_actor_id();
    (
        gw.mints.load(std::sync::atomic::Ordering::SeqCst),
        slot.cold_lease_remaining(&actor).is_some() || slot.caller_slot_held(&actor).is_some(),
        upstream.lists(),
    )
}

/// Age the slot past the idle window, run `read`, then a real idle eviction:
/// whether the slot survived says whether `read` touched it.
async fn touched_by<F: std::future::Future<Output = Value>>(
    gw: &Gateway,
    read: F,
) -> (bool, Value) {
    let slot = backend(gw);
    slot.age_per_user_slot_for_test(BINDING, AGED);
    let answer = read.await;
    slot.evict_idle_per_user_entries(EVICT_AFTER);
    (slot.holds_per_user_slot_for_test(BINDING), answer)
}

/// S7a-0, step 0's positive witnesses (design §4.0). The excluded key's read
/// reaches the stored-read path for the same owner: it finds the task, so
/// the identity, not the key, owns it. The included key's call left a warm
/// slot, and the touch is observable: the included key's own read keeps the
/// aged slot alive through an idle eviction.
#[tokio::test]
async fn s7a_0_the_two_keys_share_the_owner_and_the_touch_is_observable() {
    let gw = fixture().await;
    let id = finished(&gw, "s7a-0").await;
    assert!(
        backend(&gw).holds_per_user_slot_for_test(BINDING),
        "S7a-0: the included key's call left a warm slot on {BACKEND}"
    );
    let unknown = task_get(&gw, EXCLUDED, "no-such-task-8387").await;
    let excluded = task_get(&gw, EXCLUDED, &id).await;
    // Ids blanked, so an echoed id cannot make the two answers differ.
    assert_ne!(
        excluded.to_string().replace(&id, "ID"),
        unknown.to_string().replace("no-such-task-8387", "ID"),
        "S7a-0: the excluded key found the task (one owner), so its answer is not an unknown task's"
    );
    let (kept, read) = touched_by(&gw, task_get(&gw, INCLUDED, &id)).await;
    assert!(
        kept,
        "S7a-0: the included key's read touched the aged slot (control): {read}"
    );
}

/// S7a-warm: the excluded key's stored read must leave the target's warm
/// slot untouched. RED on the tip: `claim_caller_view` reads the unscoped
/// registry and touches the slot (`task_replay.rs:221`) before any scope
/// check, so the aged slot survives the eviction.
#[tokio::test]
async fn s7a_warm_an_excluded_read_does_not_touch_the_targets_slot() {
    let gw = fixture().await;
    let id = finished(&gw, "s7a-warm").await;
    let (kept, read) = touched_by(&gw, task_get(&gw, EXCLUDED, &id)).await;
    assert!(
        !kept,
        "S7a-warm: the excluded target was touched: its aged slot survived the idle eviction; read: {read}"
    );
    assert!(
        !read.to_string().contains(OUTPUT),
        "S7a-warm: the excluded key is not served the output: {read}"
    );
}

/// S7a-cold, a guard (test plan v2): with the target's slot evicted, the
/// excluded key's stored read makes no credential resolution (the fixture's
/// mint counter: this backend's custody is the propagation mint, it has no
/// managed account), no cold claim and no upstream list. A managed-account
/// target's account resolution is outside this fixture (S7a-c-m1 below). Green on the tip: account resolution skips refused
/// targets (`task_replay.rs:136`) and `claim_caller_view` returns before
/// any claim (`:245`). The control, the included key's own cold read, moves
/// each mark on its own, so no assertion can pass on a dead observable.
/// Mutants: S7a-c-m2 (the `:245` return removed), and m3a/m3b (m2 observed
/// at the claim and list marks with the earlier assertions off). S7a-c-m1
/// (the `:136` filter removed) is equivalent here: the fixture's backend has
/// no account descriptor, so there is nothing to filter.
#[tokio::test]
async fn s7a_cold_an_excluded_read_resolves_claims_and_lists_nothing() {
    let gw = fixture().await;
    let id = finished(&gw, "s7a-cold").await;
    let upstream = evict(&gw);
    let (mints, claimed, lists) = cold_marks(&gw, &upstream);
    assert!(!claimed, "premise: no claim before the read");
    let read = task_get(&gw, EXCLUDED, &id).await;
    let (mints_after, claimed_after, lists_after) = cold_marks(&gw, &upstream);
    assert_eq!(
        mints_after, mints,
        "S7a-cold: resolve counter moved; read: {read}"
    );
    assert!(
        !claimed_after,
        "S7a-cold: cold claim made: a lease runs or the slot was re-established; read: {read}"
    );
    assert_eq!(
        lists_after, lists,
        "S7a-cold: list counter moved; read: {read}"
    );
    let control = task_get(&gw, INCLUDED, &id).await;
    let (mints_c, claimed_c, lists_c) = cold_marks(&gw, &upstream);
    assert!(
        mints_c > mints && claimed_c && lists_c > lists,
        "S7a-cold control: the included key's cold read moves every mark \
         (mints {mints}->{mints_c}, claimed {claimed_c}, lists {lists}->{lists_c}): {control}"
    );
}

/// The stored-read answer of the second key, ids blanked: `excluded_scope`
/// is its scope, and `unregister` drops the target from the registry after
/// the task has finished and before the read.
async fn second_key_answer(excluded_scope: &'static str, unregister: bool) -> String {
    let gw = fixture_scoped(excluded_scope).await;
    let id = finished(&gw, "s7a-twin").await;
    if unregister {
        assert!(
            gw.meta.backends.for_test().remove(BACKEND),
            "premise: {BACKEND} was registered"
        );
    }
    let (status, read) = send_full(
        &gw,
        EXCLUDED,
        ("tasks/get", &id),
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await;
    format!("{status} {read}").replace(&id, "<task>")
}

/// S7a-twin, the oracle row (lead, 2026-10-17): a stored task whose target is
/// registered but outside the reader's scope answers exactly as one whose
/// target is inside the scope but unregistered, PR-A's `beta` and `ghost`
/// cells on the stored-read path. Same method, arguments and target name;
/// only scope and registration differ, since an out-of-scope name is
/// judged out of scope before registration (`scoped_backends.rs:43`).
/// Mutant S7a-t-m1: S7's out-of-scope branch answers its own code.
#[tokio::test]
async fn s7a_twin_an_out_of_scope_target_answers_as_an_unregistered_one() {
    let out_of_scope = second_key_answer(ELSEWHERE, false).await;
    let unregistered = second_key_answer(BACKEND, true).await;
    assert_eq!(
        out_of_scope, unregistered,
        "S7a-twin: out-of-scope target vs unregistered target"
    );
}
